using System.Formats.Asn1;
using System.Net;
using System.Numerics;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Corvus.Core;

/// <summary>
/// One certificate of a certificate file: names, validity, key, SHA-256 and SHA-1 fingerprints (hex), the SHA-256 SPKI
/// pin (sha256/base64, the form of Android pin-set digests and OkHttp pins) and the extensions that place it in a chain.
/// Ca is null without a basic constraints extension; empty lists mean the extension is absent.
/// </summary>
public sealed record CertificateEntry(int Index, string Source, string Subject, string Issuer, string Serial, DateTime NotBefore, DateTime NotAfter,
    string Key, string SignatureAlgorithm, string Sha256, string Sha1, string Pin, IReadOnlyList<string> Names, bool? Ca, int? PathLength,
    IReadOnlyList<string> KeyUsage, IReadOnlyList<string> ExtendedKeyUsage, string? SubjectKeyId, string? AuthorityKeyId, IReadOnlyList<string> Urls,
    bool SelfIssued);

/// <summary>
/// A chain from a certificate that issues no other certificate of the file, leaf first, as far as the file's certificates
/// reach (indexes into the certificates). End names where it stops; Problems name links whose signature or constraints fail
/// or could not be checked. ThisMachine is the platform's verdict with its trust store, or null when not asked.
/// </summary>
public sealed record CertificateChain(IReadOnlyList<int> Path, string End, IReadOnlyList<string> Problems, string? ThisMachine);

/// <summary>A block that is not a certificate: a key (its type and pin, never its bytes), a request, a CRL, a signer, protected PKCS #12 contents.</summary>
public sealed record CertificateFileItem(string Kind, string Source, string? Detail);

/// <summary>
/// A certificate file read without the platform store: PEM (any number of blocks), DER X.509, PKCS #7 (.p7b, .p7c, a
/// signature block), PKCS #12 (.p12, .pfx; contents protected by a password other than the empty one are reported, not
/// read), certificate requests, CRLs and keys. Chains are built from the file's certificates by issuer name, key
/// identifier and verified signature. Damaged blocks are notes; nothing throws past <see cref="Read"/> except
/// <see cref="InvalidDataException"/> when no block could be read at all.
/// </summary>
public sealed class CertificateFile
{
    public const int MaxCertificates = 10_000, MaxMachineChecks = 20;
    private const int MaxBytes = 64 << 20, PemProbe = 16 << 10;

    private static readonly HashSet<string> Extensions = new(StringComparer.OrdinalIgnoreCase)
        { ".pem", ".crt", ".cer", ".der", ".p7b", ".p7c", ".p12", ".pfx", ".csr", ".crl", ".key", ".rsa", ".dsa", ".ec" };

    public string Format { get; private set; } = "";
    public List<CertificateEntry> Certificates { get; } = [];
    public List<CertificateChain> Chains { get; } = [];
    public List<CertificateFileItem> Items { get; } = [];
    public List<string> Notes { get; } = [];

    private readonly List<Parsed> _parsed = [];
    private readonly HashSet<string> _seen = new(StringComparer.Ordinal);

    private sealed record Parsed(byte[] Der, ReadOnlyMemory<byte> Tbs, string SignatureOid, ReadOnlyMemory<byte>? SignatureParameters, byte[] Signature,
        byte[] Issuer, byte[] Subject, byte[] Spki, CertificateEntry Entry);

    /// <summary>True when the name ends in an extension certificate, key, request and CRL files use.</summary>
    public static bool HasCertificateExtension(string name) => Extensions.Contains(System.IO.Path.GetExtension(name));

    /// <summary>True when the file may be a certificate file: a known extension, PEM text at its start, or one DER element spanning the whole file.</summary>
    public static bool Looks(ReadOnlySpan<byte> head, long length, string? name)
    {
        if (length is 0 or > MaxBytes) return false;
        if (Extensions.Contains(System.IO.Path.GetExtension(name ?? ""))) return true;
        if (PemAt(head) >= 0) return true;
        if (head.Length != length || head.Length < 2 || head[0] != 0x30) return false;
        try
        {
            AsnDecoder.ReadEncodedValue(head, AsnEncodingRules.BER, out _, out _, out int consumed);
            return consumed == head.Length;
        }
        catch (AsnContentException) { return false; }
    }

    /// <summary>Offset of the first "-----BEGIN " when only text precedes it within the first 16 KB; else -1.</summary>
    private static int PemAt(ReadOnlySpan<byte> head)
    {
        var probe = head[..Math.Min(head.Length, PemProbe)];
        int at = probe.IndexOf("-----BEGIN "u8);
        if (at < 0) return -1;
        foreach (var b in probe[..at])
            if (b < 0x09 || b is > 0x0D and < 0x20 || b == 0x7F) return -1;
        return at;
    }

    /// <summary>The certificates, chains and other blocks of <paramref name="data"/>; <paramref name="checkMachine"/> adds the platform's trust verdict per chain.</summary>
    public static CertificateFile Read(byte[] data, bool checkMachine, CancellationToken ct)
    {
        var f = new CertificateFile();
        if (data.Length > MaxBytes) throw new InvalidDataException($"over {MaxBytes >> 20} MB");
        if (PemAt(data) >= 0) f.ReadPem(data, ct);
        else f.Format = f.ReadDer(data, "file") ?? throw new InvalidDataException("not a certificate, PKCS #7, PKCS #12, request, CRL or key encoding");
        if (f.Certificates.Count == 0 && f.Items.Count == 0) throw new InvalidDataException("no block could be read" + (f.Notes.Count > 0 ? ": " + f.Notes[0] : ""));
        f.BuildChains(checkMachine, ct);
        return f;
    }

    private void ReadPem(byte[] data, CancellationToken ct)
    {
        Format = "PEM";
        var text = Encoding.Latin1.GetString(data);
        int at = 0, block = 0;
        while ((at = text.IndexOf("-----BEGIN ", at, StringComparison.Ordinal)) >= 0)
        {
            ct.ThrowIfCancellationRequested();
            int labelEnd = text.IndexOf("-----", at + 11, StringComparison.Ordinal);
            if (labelEnd < 0) break;
            var label = text[(at + 11)..labelEnd];
            var endMarker = "-----END " + label + "-----";
            int end = text.IndexOf(endMarker, labelEnd + 5, StringComparison.Ordinal);
            int line = 1 + text.AsSpan(0, at).Count('\n');
            block++;
            var source = $"PEM block {block} ({label}, line {line})";
            if (end < 0) { Notes.Add($"{source}: no END line"); break; }
            var body = text[(labelEnd + 5)..end];
            at = end + endMarker.Length;
            bool encrypted = body.Contains("Proc-Type:", StringComparison.Ordinal) && body.Contains("ENCRYPTED", StringComparison.Ordinal);
            var base64 = new StringBuilder(body.Length);
            foreach (var l in body.Split('\n'))
                if (!l.Contains(':')) base64.Append(l.Trim());
            var der = new byte[base64.Length];
            if (!Convert.TryFromBase64String(base64.ToString(), der, out int n)) { Notes.Add($"{source}: not valid base64"); continue; }
            der = der[..n];
            try { Block(label, der, source, encrypted); }
            catch (Exception ex) when (ex is CryptographicException or AsnContentException or ArgumentException or FormatException)
            {
                Notes.Add($"{source}: not read ({ex.Message})");
            }
        }
    }

    private void Block(string label, byte[] der, string source, bool encrypted)
    {
        switch (label)
        {
            case "CERTIFICATE" or "X509 CERTIFICATE":
                Add(der, source);
                break;
            case "TRUSTED CERTIFICATE":
                AsnDecoder.ReadEncodedValue(der, AsnEncodingRules.DER, out _, out _, out int consumed);
                Add(der[..consumed], source);
                if (consumed < der.Length) Notes.Add($"{source}: the OpenSSL trust settings after the certificate are not read");
                break;
            case "PKCS7" or "CMS":
                Pkcs7(der, source);
                break;
            case "CERTIFICATE REQUEST" or "NEW CERTIFICATE REQUEST":
                Request(der, source);
                break;
            case "X509 CRL":
                Crl(der, source);
                break;
            case "PUBLIC KEY":
                Items.Add(new("public key", source, $"{KeyName(der)}, pin {Pin(der)}"));
                break;
            case "RSA PUBLIC KEY":
                Items.Add(new("public key", source, "RSA, PKCS #1"));
                break;
            case "PRIVATE KEY":
                Items.Add(new("private key", source, Pkcs8Algorithm(der) + ", PKCS #8"));
                break;
            case "ENCRYPTED PRIVATE KEY":
                Items.Add(new("private key", source, "encrypted PKCS #8"));
                break;
            case "RSA PRIVATE KEY" or "EC PRIVATE KEY" or "DSA PRIVATE KEY" or "OPENSSH PRIVATE KEY":
                Items.Add(new("private key", source, label[..label.IndexOf(" PRIVATE", StringComparison.Ordinal)] + (encrypted ? ", encrypted" : "")));
                break;
            default:
                Items.Add(new("PEM block", source, "not read"));
                break;
        }
    }

    /// <summary>The format name of a DER encoding once read, or null when it is none of the encodings this reader knows.</summary>
    private string? ReadDer(byte[] der, string source)
    {
        if (Shape(der) is not { } shape) return null;
        try
        {
            switch (shape)
            {
                case "certificate": Add(der, source); return "DER certificate";
                case "pkcs7": Pkcs7(der, source); return "PKCS #7";
                case "pkcs12": Pkcs12(der, source); return "PKCS #12";
                case "request": Request(der, source); return "DER certificate request";
                case "crl": Crl(der, source); return "DER CRL";
                case "spki": Items.Add(new("public key", source, $"{KeyName(der)}, pin {Pin(der)}")); return "DER public key";
                case "pkcs8": Items.Add(new("private key", source, Pkcs8Algorithm(der) + ", PKCS #8")); return "DER private key";
            }
        }
        catch (Exception ex) when (ex is CryptographicException or AsnContentException or ArgumentException or FormatException)
        {
            Notes.Add($"{source}: {shape} not read ({ex.Message})");
            return shape;
        }
        return null;
    }

    /// <summary>Which structure a DER element has, by its first fields; null when none.</summary>
    private static string? Shape(byte[] der)
    {
        try
        {
            var outer = new AsnReader(der, AsnEncodingRules.BER).ReadSequence();
            var first = outer.PeekTag();
            if (first.HasSameClassAndValue(Asn1Tag.ObjectIdentifier))
                return outer.ReadObjectIdentifier() == "1.2.840.113549.1.7.2" ? "pkcs7" : null;
            if (first.HasSameClassAndValue(Asn1Tag.Integer))
            {
                var version = outer.ReadInteger();
                if (version == new BigInteger(3) && outer.HasData && outer.PeekTag().HasSameClassAndValue(Asn1Tag.Sequence)) return "pkcs12";
                if ((version.IsZero || version.IsOne) && outer.HasData && outer.PeekTag().HasSameClassAndValue(Asn1Tag.Sequence)) return "pkcs8";
                return null;
            }
            if (!first.HasSameClassAndValue(Asn1Tag.Sequence)) return null;
            var inner = outer.ReadSequence();
            if (!outer.HasData) return null;
            if (outer.PeekTag().HasSameClassAndValue(Asn1Tag.PrimitiveBitString))
            {
                // SubjectPublicKeyInfo: { AlgorithmIdentifier { OID, ... }, BIT STRING }.
                return inner.PeekTag().HasSameClassAndValue(Asn1Tag.ObjectIdentifier) ? "spki" : null;
            }
            outer.ReadSequence();
            if (!outer.HasData || !outer.PeekTag().HasSameClassAndValue(Asn1Tag.PrimitiveBitString)) return null;
            // Signed structures: { TBS, AlgorithmIdentifier, BIT STRING }; the TBS's first fields tell them apart.
            var tag = inner.PeekTag();
            if (tag.HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 0, true))) return "certificate";
            if (tag.HasSameClassAndValue(Asn1Tag.Sequence)) return "crl";
            if (!tag.HasSameClassAndValue(Asn1Tag.Integer)) return null;
            var integer = inner.ReadIntegerBytes();
            var next = inner.PeekTag();
            if (next.HasSameClassAndValue(Asn1Tag.Sequence))
            {
                // A request: { version 0, Name, SPKI, [0] }; a v1 certificate: { serial, AlgorithmIdentifier, Name, ... };
                // a CRL: { version, AlgorithmIdentifier, Name, Time, ... }.
                var second = inner.ReadSequence();
                bool algorithm = second.HasData && second.PeekTag().HasSameClassAndValue(Asn1Tag.ObjectIdentifier);
                if (!algorithm) return integer.Length == 1 && integer.Span[0] == 0 ? "request" : null;
                inner.ReadSequence();
                if (!inner.HasData) return null;
                var t = inner.PeekTag();
                return t.HasSameClassAndValue(Asn1Tag.UtcTime) || t.HasSameClassAndValue(Asn1Tag.GeneralizedTime) ? "crl" : "certificate";
            }
            return null;
        }
        catch (AsnContentException) { return null; }
    }

    private void Pkcs7(byte[] der, string source)
    {
        var cms = new SignedCms();
        cms.Decode(der);
        int n = 0;
        foreach (var cert in cms.Certificates)
        {
            n++;
            Add(cert.RawData, $"{source}, certificate {n}");
        }
        foreach (var signer in cms.SignerInfos)
        {
            var cert = signer.Certificate;
            var index = cert == null ? -1 : Certificates.FindIndex(c => c.Sha256 == Hex(SHA256.HashData(cert.RawData)));
            Items.Add(new("signer", source, cert == null ? $"{SignerId(signer)}; its certificate is not in the file"
                : $"#{index}, digest {signer.DigestAlgorithm.FriendlyName ?? signer.DigestAlgorithm.Value}"));
        }
        if (cms.SignerInfos.Count > 0)
            Notes.Add($"{source}: signed data ({cms.ContentInfo.ContentType.Value}); its signature covers content not in this file, so it is not verified here");
    }

    private static string SignerId(SignerInfo s) => s.SignerIdentifier.Type switch
    {
        SubjectIdentifierType.IssuerAndSerialNumber when s.SignerIdentifier.Value is System.Security.Cryptography.Xml.X509IssuerSerial i => $"signer {i.IssuerName} serial {i.SerialNumber}",
        SubjectIdentifierType.SubjectKeyIdentifier => $"signer key id {s.SignerIdentifier.Value}",
        _ => "signer",
    };

    private void Pkcs12(byte[] der, string source)
    {
        var info = Pkcs12Info.Decode(der, out _, skipCopy: true);
        if (info.IntegrityMode == Pkcs12IntegrityMode.Password)
            Notes.Add(info.VerifyMac(null) || info.VerifyMac("") ? $"{source}: MAC verified with an empty password" : $"{source}: MAC needs a password; not verified");
        else if (info.IntegrityMode == Pkcs12IntegrityMode.PublicKey) Notes.Add($"{source}: integrity by a public-key signature; not verified");
        int n = 0;
        foreach (var safe in info.AuthenticatedSafe) Safe(safe, $"{source}, contents {++n}", 0);
    }

    private void Safe(Pkcs12SafeContents safe, string source, int depth)
    {
        if (safe.ConfidentialityMode == Pkcs12ConfidentialityMode.Password && !Decrypt(safe))
        {
            Items.Add(new("protected contents", source, "encrypted with a password; not read"));
            return;
        }
        if (safe.ConfidentialityMode == Pkcs12ConfidentialityMode.PublicKey)
        {
            Items.Add(new("protected contents", source, "encrypted to a public key; not read"));
            return;
        }
        int n = 0;
        foreach (var bag in safe.GetBags())
        {
            var at = $"{source}, bag {++n}";
            switch (bag)
            {
                case Pkcs12CertBag { IsX509Certificate: true } cert:
                {
                    using var x = cert.GetCertificate();
                    Add(x.RawData, at);
                    break;
                }
                case Pkcs12CertBag cert: Items.Add(new("certificate", at, $"type {cert.GetCertificateType().Value}; not read")); break;
                case Pkcs12ShroudedKeyBag: Items.Add(new("private key", at, "encrypted PKCS #8")); break;
                case Pkcs12KeyBag key: Items.Add(new("private key", at, Pkcs8Algorithm(key.Pkcs8PrivateKey.ToArray()) + ", PKCS #8")); break;
                case Pkcs12SecretBag: Items.Add(new("secret", at, null)); break;
                case Pkcs12SafeContentsBag nested when depth < 4: Safe(nested.SafeContents!, at, depth + 1); break;
                default: Items.Add(new("bag", at, $"{bag.GetBagId().Value}; not read")); break;
            }
        }
    }

    private static bool Decrypt(Pkcs12SafeContents safe)
    {
        foreach (var password in new[] { null, "" })
            try { safe.Decrypt(password); return true; }
            catch (CryptographicException) { }
        return false;
    }

    private void Request(byte[] der, string source)
    {
        var outer = new AsnReader(der, AsnEncodingRules.DER).ReadSequence();
        var info = outer.ReadSequence();
        info.ReadInteger();
        var subject = new X500DistinguishedName(info.ReadEncodedValue().Span).Name;
        var spki = info.ReadEncodedValue().ToArray();
        Items.Add(new("certificate request", source, $"{subject}; {KeyName(spki)}, pin {Pin(spki)}"));
    }

    private void Crl(byte[] der, string source)
    {
        var tbs = new AsnReader(der, AsnEncodingRules.DER).ReadSequence().ReadSequence();
        if (tbs.PeekTag().HasSameClassAndValue(Asn1Tag.Integer)) tbs.ReadInteger();
        tbs.ReadSequence();
        var issuer = new X500DistinguishedName(tbs.ReadEncodedValue().Span).Name;
        var thisUpdate = Time(tbs);
        DateTime? nextUpdate = tbs.HasData && IsTime(tbs.PeekTag()) ? Time(tbs) : null;
        int revoked = 0;
        if (tbs.HasData && tbs.PeekTag().HasSameClassAndValue(Asn1Tag.Sequence))
            for (var list = tbs.ReadSequence(); list.HasData; list.ReadEncodedValue()) revoked++;
        Items.Add(new("CRL", source, $"{issuer}; this update {thisUpdate:yyyy-MM-dd HH:mm:ss}Z" +
            (nextUpdate is { } next ? $", next {next:yyyy-MM-dd HH:mm:ss}Z" : "") + $"; {revoked} revoked"));
    }

    private static bool IsTime(Asn1Tag t) => t.HasSameClassAndValue(Asn1Tag.UtcTime) || t.HasSameClassAndValue(Asn1Tag.GeneralizedTime);

    private static DateTime Time(AsnReader r) =>
        (r.PeekTag().HasSameClassAndValue(Asn1Tag.UtcTime) ? r.ReadUtcTime() : r.ReadGeneralizedTime()).UtcDateTime;

    private void Add(byte[] der, string source)
    {
        if (Certificates.Count >= MaxCertificates)
        {
            if (Certificates.Count == MaxCertificates && Notes.All(n => !n.StartsWith("certificates past", StringComparison.Ordinal)))
                Notes.Add($"certificates past {MaxCertificates:N0} not read");
            return;
        }
        var sha256 = Hex(SHA256.HashData(der));
        if (!_seen.Add(sha256)) { Notes.Add($"{source}: a repeat of an earlier certificate"); return; }
        var cert = new AsnReader(der, AsnEncodingRules.DER).ReadSequence();
        var tbs = cert.ReadEncodedValue();
        var algorithm = cert.ReadSequence();
        var signatureOid = algorithm.ReadObjectIdentifier();
        ReadOnlyMemory<byte>? parameters = algorithm.HasData ? algorithm.ReadEncodedValue() : null;
        var signature = cert.ReadBitString(out _);
        var t = new AsnReader(tbs, AsnEncodingRules.DER).ReadSequence();
        if (t.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 0, true))) t.ReadEncodedValue();
        t.ReadEncodedValue(); // serial
        t.ReadEncodedValue(); // signature algorithm
        var issuer = t.ReadEncodedValue().ToArray();
        t.ReadEncodedValue(); // validity
        var subject = t.ReadEncodedValue().ToArray();
        var spki = t.ReadEncodedValue().ToArray();

        using var x = X509CertificateLoader.LoadCertificate(der);
        if (x.SerialNumberBytes.Span is [>= 0x80, ..]) Notes.Add($"#{Certificates.Count}: negative serial number (RFC 5280 requires a positive one)");
        var names = new List<string>();
        var keyUsage = new List<string>();
        var eku = new List<string>();
        var urls = new List<string>();
        bool? ca = null;
        int? pathLength = null;
        string? ski = null, aki = null;
        int index = Certificates.Count;
        foreach (var e in x.Extensions)
        {
            try
            {
                switch (e.Oid?.Value)
                {
                    case "2.5.29.17": names.AddRange(GeneralNames(e.RawData)); break;
                    case "2.5.29.19":
                        var bc = new X509BasicConstraintsExtension(e, e.Critical);
                        ca = bc.CertificateAuthority;
                        pathLength = bc.HasPathLengthConstraint ? bc.PathLengthConstraint : null;
                        break;
                    case "2.5.29.15": keyUsage.AddRange(Usages(new X509KeyUsageExtension(e, e.Critical).KeyUsages)); break;
                    case "2.5.29.37": eku.AddRange(new X509EnhancedKeyUsageExtension(e, e.Critical).EnhancedKeyUsages.Cast<Oid>().Select(o => Eku(o.Value))); break;
                    case "2.5.29.14": ski = new X509SubjectKeyIdentifierExtension(e, e.Critical).SubjectKeyIdentifier; break;
                    case "2.5.29.35":
                        if (new X509AuthorityKeyIdentifierExtension(e.RawData, e.Critical).KeyIdentifier is { } id) aki = Hex(id.Span);
                        break;
                    case "1.3.6.1.5.5.7.1.1": urls.AddRange(AccessUrls(e.RawData)); break;
                    case "2.5.29.31": urls.AddRange(Uris(e.RawData).Select(u => "CRL " + u)); break;
                }
            }
            catch (Exception ex) when (ex is CryptographicException or AsnContentException or ArgumentException)
            {
                Notes.Add($"#{index}: extension {e.Oid?.Value} not read ({ex.Message})");
            }
        }
        var entry = new CertificateEntry(index, source, x.Subject, x.Issuer, x.SerialNumber, x.NotBefore.ToUniversalTime(), x.NotAfter.ToUniversalTime(),
            KeyName(spki), SignatureName(signatureOid), sha256, Hex(SHA1.HashData(der)), Pin(spki), names, ca, pathLength, keyUsage, eku, ski, aki, urls,
            issuer.AsSpan().SequenceEqual(subject));
        Certificates.Add(entry);
        _parsed.Add(new Parsed(der, tbs, signatureOid, parameters, signature, issuer, subject, spki, entry));
    }

    private void BuildChains(bool checkMachine, CancellationToken ct)
    {
        int count = _parsed.Count;
        var parent = new int?[count];
        var verified = new bool?[count];
        var subjects = _parsed.Select((p, i) => (Key: Convert.ToBase64String(p.Subject), i)).ToLookup(x => x.Key, x => x.i);
        for (int i = 0; i < count; i++)
        {
            ct.ThrowIfCancellationRequested();
            var child = _parsed[i];
            (int Index, bool? Ok)? pick = null;
            foreach (int j in subjects[Convert.ToBase64String(child.Issuer)])
            {
                var p = _parsed[j];
                if (j != i && child.Entry.AuthorityKeyId != null && p.Entry.SubjectKeyId != null
                    && !string.Equals(child.Entry.AuthorityKeyId, p.Entry.SubjectKeyId, StringComparison.OrdinalIgnoreCase)) continue;
                var ok = Verifies(child, p.Spki);
                if (pick == null || ok == true && pick.Value.Ok != true || ok == null && pick.Value.Ok == false) pick = (j, ok);
                if (ok == true && j != i) break;
            }
            if (pick is { } chosen) (parent[i], verified[i]) = (chosen.Index, chosen.Ok);
        }
        var issuers = new HashSet<int>(Enumerable.Range(0, count).Where(i => parent[i] is int p && p != i).Select(i => parent[i]!.Value));
        var covered = new HashSet<int>();
        var now = DateTime.UtcNow;
        var starts = Enumerable.Range(0, count).Where(i => !issuers.Contains(i)).ToList();
        foreach (int start in starts.Concat(Enumerable.Range(0, count)))
        {
            if (covered.Contains(start)) continue;
            ct.ThrowIfCancellationRequested();
            var path = new List<int> { start };
            var problems = new List<string>();
            string end;
            int cur = start;
            while (true)
            {
                covered.Add(cur);
                var e = _parsed[cur].Entry;
                if (e.NotAfter < now) problems.Add($"#{cur} expired {e.NotAfter:yyyy-MM-dd}");
                else if (e.NotBefore > now) problems.Add($"#{cur} not valid before {e.NotBefore:yyyy-MM-dd}");
                if (parent[cur] is not int p)
                {
                    end = $"issuer not in the file: {e.Issuer}";
                    break;
                }
                if (verified[cur] == false) problems.Add($"#{cur}: signature does not verify with the key of #{p}");
                else if (verified[cur] == null) problems.Add($"#{cur}: {e.SignatureAlgorithm} signature not checked");
                if (p == cur)
                {
                    end = verified[cur] == true ? "self-signed root" : "self-issued root";
                    break;
                }
                var issuer = _parsed[p].Entry;
                if (issuer.Ca == false) problems.Add($"#{p} issues #{cur} but is not a CA (basic constraints)");
                if (issuer.KeyUsage.Count > 0 && !issuer.KeyUsage.Contains("keyCertSign")) problems.Add($"#{p} issues #{cur} without keyCertSign");
                int below = path.Count - 1;
                if (issuer.PathLength is int limit && below > limit) problems.Add($"#{p} allows {limit} CA(s) below it; the chain has {below}");
                if (path.Contains(p))
                {
                    end = $"loop back to #{p}";
                    break;
                }
                path.Add(p);
                cur = p;
            }
            if (path.Count > 1 && Format == "PEM" && !path.SequenceEqual(path.Order()))
                problems.Add("the file lists these certificates in another order than leaf to root");
            string? machine = checkMachine && Chains.Count < MaxMachineChecks ? Machine(start) : null;
            Chains.Add(new CertificateChain(path, end, problems, machine));
        }
        if (checkMachine && Chains.Count > MaxMachineChecks) Notes.Add($"this machine's trust checked for the first {MaxMachineChecks} chains");
    }

    /// <summary>The platform's chain for a certificate with the file's certificates as intermediates: no downloads, no revocation, as of now.</summary>
    private string Machine(int start)
    {
        try
        {
            using var leaf = X509CertificateLoader.LoadCertificate(_parsed[start].Der);
            using var chain = new X509Chain();
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            chain.ChainPolicy.DisableCertificateDownloads = true;
            foreach (var p in _parsed) chain.ChainPolicy.ExtraStore.Add(X509CertificateLoader.LoadCertificate(p.Der));
            bool trusted = chain.Build(leaf);
            var root = chain.ChainElements.Count > 0 ? chain.ChainElements[^1].Certificate.GetNameInfo(X509NameType.SimpleName, false) : "?";
            var verdict = trusted ? $"trusted, root {root}"
                : $"not trusted ({string.Join(", ", chain.ChainStatus.Select(s => s.Status.ToString()).Distinct().Order(StringComparer.Ordinal))}), ends at {root}";
            foreach (var c in chain.ChainPolicy.ExtraStore) c.Dispose();
            foreach (var e in chain.ChainElements) e.Certificate.Dispose();
            return verdict;
        }
        catch (CryptographicException ex) { return $"not built: {ex.Message}"; }
    }

    /// <summary>True when the issuer's key verifies the certificate's signature, false when it does not, null when the algorithm or key is not supported here.</summary>
    private static bool? Verifies(Parsed child, byte[] issuerSpki)
    {
        try
        {
            var tbs = child.Tbs.Span;
            switch (child.SignatureOid)
            {
                case "1.2.840.113549.1.1.4" or "1.2.840.113549.1.1.5" or "1.2.840.113549.1.1.11" or "1.2.840.113549.1.1.12" or "1.2.840.113549.1.1.13":
                {
                    using var rsa = Rsa(issuerSpki);
                    return rsa?.VerifyData(tbs, child.Signature, RsaHash(child.SignatureOid), RSASignaturePadding.Pkcs1);
                }
                case "1.2.840.113549.1.1.10":
                {
                    if (Pss(child.SignatureParameters) is not { } hash) return null;
                    using var rsa = Rsa(issuerSpki);
                    return rsa?.VerifyData(tbs, child.Signature, hash, RSASignaturePadding.Pss);
                }
                case "1.2.840.10045.4.1" or "1.2.840.10045.4.3.2" or "1.2.840.10045.4.3.3" or "1.2.840.10045.4.3.4":
                {
                    using var ec = ECDsa.Create();
                    ec.ImportSubjectPublicKeyInfo(issuerSpki, out _);
                    var hash = child.SignatureOid switch
                    {
                        "1.2.840.10045.4.1" => HashAlgorithmName.SHA1,
                        "1.2.840.10045.4.3.2" => HashAlgorithmName.SHA256,
                        "1.2.840.10045.4.3.3" => HashAlgorithmName.SHA384,
                        _ => HashAlgorithmName.SHA512,
                    };
                    return ec.VerifyData(tbs, child.Signature, hash, DSASignatureFormat.Rfc3279DerSequence);
                }
                default:
                    return null;
            }
        }
        catch (Exception ex) when (ex is CryptographicException or AsnContentException or PlatformNotSupportedException or ArgumentException)
        {
            return null;
        }
    }

    private static HashAlgorithmName RsaHash(string oid) => oid switch
    {
        "1.2.840.113549.1.1.4" => HashAlgorithmName.MD5,
        "1.2.840.113549.1.1.5" => HashAlgorithmName.SHA1,
        "1.2.840.113549.1.1.11" => HashAlgorithmName.SHA256,
        "1.2.840.113549.1.1.12" => HashAlgorithmName.SHA384,
        _ => HashAlgorithmName.SHA512,
    };

    /// <summary>The hash of RSASSA-PSS parameters when MGF1 uses the same hash and the salt is the hash length (what the platform verifies); else null.</summary>
    private static HashAlgorithmName? Pss(ReadOnlyMemory<byte>? parameters)
    {
        if (parameters is not { } p) return null;
        var seq = new AsnReader(p, AsnEncodingRules.DER).ReadSequence();
        string hash = "1.3.14.3.2.26", mgfHash = "1.3.14.3.2.26";
        int salt = 20;
        if (seq.HasData && seq.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 0)))
            hash = seq.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0)).ReadSequence().ReadObjectIdentifier();
        if (seq.HasData && seq.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 1)))
        {
            var mgf = seq.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 1)).ReadSequence();
            if (mgf.ReadObjectIdentifier() != "1.2.840.113549.1.1.8") return null;
            mgfHash = mgf.ReadSequence().ReadObjectIdentifier();
        }
        if (seq.HasData && seq.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 2)))
        {
            var s = seq.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 2));
            if (!s.TryReadInt32(out salt)) return null;
        }
        (HashAlgorithmName Name, int Length)? h = hash switch
        {
            "1.3.14.3.2.26" => (HashAlgorithmName.SHA1, 20),
            "2.16.840.1.101.3.4.2.1" => (HashAlgorithmName.SHA256, 32),
            "2.16.840.1.101.3.4.2.2" => (HashAlgorithmName.SHA384, 48),
            "2.16.840.1.101.3.4.2.3" => (HashAlgorithmName.SHA512, 64),
            _ => null,
        };
        return h is { } x && mgfHash == hash && salt == x.Length ? x.Name : null;
    }

    /// <summary>An RSA key from a SubjectPublicKeyInfo of rsaEncryption or RSASSA-PSS, read from its modulus and exponent; null for other keys.</summary>
    private static RSA? Rsa(byte[] spki)
    {
        if (RsaParts(spki) is not { } parts) return null;
        var rsa = RSA.Create();
        rsa.ImportParameters(new RSAParameters { Modulus = parts.Modulus, Exponent = parts.Exponent });
        return rsa;
    }

    private static (byte[] Modulus, byte[] Exponent)? RsaParts(byte[] spki)
    {
        var seq = new AsnReader(spki, AsnEncodingRules.DER).ReadSequence();
        var oid = seq.ReadSequence().ReadObjectIdentifier();
        if (oid is not ("1.2.840.113549.1.1.1" or "1.2.840.113549.1.1.10")) return null;
        var key = new AsnReader(seq.ReadBitString(out _), AsnEncodingRules.DER).ReadSequence();
        var n = key.ReadIntegerBytes().ToArray().AsSpan();
        var e = key.ReadIntegerBytes().ToArray().AsSpan();
        while (n.Length > 1 && n[0] == 0) n = n[1..];
        while (e.Length > 1 && e[0] == 0) e = e[1..];
        return (n.ToArray(), e.ToArray());
    }

    /// <summary>The key of a SubjectPublicKeyInfo: algorithm with its size or curve ("RSA 2048", "EC P-256", "Ed25519"); the OID when not known.</summary>
    internal static string KeyName(byte[] spki)
    {
        try
        {
            var seq = new AsnReader(spki, AsnEncodingRules.DER).ReadSequence();
            var algorithm = seq.ReadSequence();
            var oid = algorithm.ReadObjectIdentifier();
            switch (oid)
            {
                case "1.2.840.113549.1.1.1" or "1.2.840.113549.1.1.10":
                    var bits = RsaParts(spki) is { } parts ? (int)new BigInteger(parts.Modulus, isUnsigned: true, isBigEndian: true).GetBitLength() : 0;
                    return (oid.EndsWith(".10", StringComparison.Ordinal) ? "RSA-PSS " : "RSA ") + bits;
                case "1.2.840.10045.2.1":
                    var curve = algorithm.HasData && algorithm.PeekTag().HasSameClassAndValue(Asn1Tag.ObjectIdentifier) ? algorithm.ReadObjectIdentifier() : "explicit parameters";
                    return "EC " + curve switch
                    {
                        "1.2.840.10045.3.1.7" => "P-256",
                        "1.3.132.0.34" => "P-384",
                        "1.3.132.0.35" => "P-521",
                        "1.3.132.0.10" => "secp256k1",
                        "1.2.840.10045.3.1.1" => "P-192",
                        "1.3.132.0.33" => "P-224",
                        _ => curve,
                    };
                case "1.3.101.112": return "Ed25519";
                case "1.3.101.113": return "Ed448";
                case "1.3.101.110": return "X25519";
                case "1.2.840.10040.4.1": return "DSA";
                default: return oid;
            }
        }
        catch (AsnContentException) { return "unreadable key"; }
    }

    private static string Pkcs8Algorithm(byte[] der)
    {
        try
        {
            var seq = new AsnReader(der, AsnEncodingRules.BER).ReadSequence();
            seq.ReadInteger();
            return seq.ReadSequence().ReadObjectIdentifier() switch
            {
                "1.2.840.113549.1.1.1" => "RSA",
                "1.2.840.113549.1.1.10" => "RSA-PSS",
                "1.2.840.10045.2.1" => "EC",
                "1.3.101.112" => "Ed25519",
                "1.3.101.113" => "Ed448",
                "1.2.840.10040.4.1" => "DSA",
                var other => other,
            };
        }
        catch (AsnContentException) { return "unknown algorithm"; }
    }

    /// <summary>The SHA-256 pin of a SubjectPublicKeyInfo, as Android pin-set digests and OkHttp write it: sha256/ and the base64 digest.</summary>
    public static string Pin(ReadOnlySpan<byte> spki) => "sha256/" + Convert.ToBase64String(SHA256.HashData(spki));

    private static string SignatureName(string oid) => oid switch
    {
        "1.2.840.113549.1.1.4" => "md5WithRSAEncryption",
        "1.2.840.113549.1.1.5" => "sha1WithRSAEncryption",
        "1.2.840.113549.1.1.11" => "sha256WithRSAEncryption",
        "1.2.840.113549.1.1.12" => "sha384WithRSAEncryption",
        "1.2.840.113549.1.1.13" => "sha512WithRSAEncryption",
        "1.2.840.113549.1.1.14" => "sha224WithRSAEncryption",
        "1.2.840.113549.1.1.10" => "RSASSA-PSS",
        "1.2.840.10045.4.1" => "ecdsa-with-SHA1",
        "1.2.840.10045.4.3.1" => "ecdsa-with-SHA224",
        "1.2.840.10045.4.3.2" => "ecdsa-with-SHA256",
        "1.2.840.10045.4.3.3" => "ecdsa-with-SHA384",
        "1.2.840.10045.4.3.4" => "ecdsa-with-SHA512",
        "1.3.101.112" => "ED25519",
        "1.3.101.113" => "ED448",
        "1.2.840.10040.4.3" => "dsaWithSHA1",
        "2.16.840.1.101.3.4.3.2" => "dsa_with_SHA256",
        _ => oid,
    };

    private static IEnumerable<string> Usages(X509KeyUsageFlags flags)
    {
        (X509KeyUsageFlags Flag, string Name)[] all =
        [
            (X509KeyUsageFlags.DigitalSignature, "digitalSignature"), (X509KeyUsageFlags.NonRepudiation, "nonRepudiation"),
            (X509KeyUsageFlags.KeyEncipherment, "keyEncipherment"), (X509KeyUsageFlags.DataEncipherment, "dataEncipherment"),
            (X509KeyUsageFlags.KeyAgreement, "keyAgreement"), (X509KeyUsageFlags.KeyCertSign, "keyCertSign"), (X509KeyUsageFlags.CrlSign, "cRLSign"),
            (X509KeyUsageFlags.EncipherOnly, "encipherOnly"), (X509KeyUsageFlags.DecipherOnly, "decipherOnly"),
        ];
        return all.Where(u => flags.HasFlag(u.Flag)).Select(u => u.Name);
    }

    private static string Eku(string? oid) => oid switch
    {
        "1.3.6.1.5.5.7.3.1" => "serverAuth",
        "1.3.6.1.5.5.7.3.2" => "clientAuth",
        "1.3.6.1.5.5.7.3.3" => "codeSigning",
        "1.3.6.1.5.5.7.3.4" => "emailProtection",
        "1.3.6.1.5.5.7.3.8" => "timeStamping",
        "1.3.6.1.5.5.7.3.9" => "OCSPSigning",
        "2.5.29.37.0" => "anyExtendedKeyUsage",
        _ => oid ?? "?",
    };

    /// <summary>GeneralNames as DNS:, IP:, email:, URI: entries; other forms by their tag.</summary>
    private static IEnumerable<string> GeneralNames(byte[] value)
    {
        var names = new List<string>();
        var seq = new AsnReader(value, AsnEncodingRules.DER).ReadSequence();
        while (seq.HasData)
        {
            var tag = seq.PeekTag();
            var raw = seq.ReadEncodedValue();
            if (tag.TagClass != TagClass.ContextSpecific) continue;
            names.Add(tag.TagValue switch
            {
                1 => "email:" + Ia5(raw, tag),
                2 => "DNS:" + Ia5(raw, tag),
                6 => "URI:" + Ia5(raw, tag),
                7 => "IP:" + Ip(raw, tag),
                4 => "DirName:" + new X500DistinguishedName(new AsnReader(raw, AsnEncodingRules.DER).ReadSequence(tag).ReadEncodedValue().Span).Name,
                _ => $"[{tag.TagValue}]",
            });
        }
        return names;
    }

    private static string Ia5(ReadOnlyMemory<byte> raw, Asn1Tag tag) =>
        Encoding.Latin1.GetString(new AsnReader(raw, AsnEncodingRules.DER).ReadOctetString(new Asn1Tag(TagClass.ContextSpecific, tag.TagValue)));

    private static string Ip(ReadOnlyMemory<byte> raw, Asn1Tag tag)
    {
        var b = new AsnReader(raw, AsnEncodingRules.DER).ReadOctetString(new Asn1Tag(TagClass.ContextSpecific, tag.TagValue));
        return b.Length is 4 or 16 ? new IPAddress(b).ToString() : Convert.ToHexString(b);
    }

    /// <summary>Authority information access entries as "OCSP url" and "caIssuers url".</summary>
    private static IEnumerable<string> AccessUrls(byte[] value)
    {
        var list = new List<string>();
        var seq = new AsnReader(value, AsnEncodingRules.DER).ReadSequence();
        while (seq.HasData)
        {
            var d = seq.ReadSequence();
            var method = d.ReadObjectIdentifier() switch { "1.3.6.1.5.5.7.48.1" => "OCSP", "1.3.6.1.5.5.7.48.2" => "caIssuers", var o => o };
            var tag = d.PeekTag();
            if (tag.TagClass == TagClass.ContextSpecific && tag.TagValue == 6) list.Add($"{method} {Ia5(d.ReadEncodedValue(), tag)}");
        }
        return list;
    }

    /// <summary>Every URI general name ([6]) anywhere in an extension value.</summary>
    private static IEnumerable<string> Uris(byte[] value)
    {
        var list = new List<string>();
        void Walk(ReadOnlyMemory<byte> data, int depth)
        {
            var r = new AsnReader(data, AsnEncodingRules.BER);
            while (r.HasData && depth < 8)
            {
                var tag = r.PeekTag();
                var raw = r.ReadEncodedValue();
                if (tag.TagClass == TagClass.ContextSpecific && tag.TagValue == 6 && !tag.IsConstructed) list.Add(Ia5(raw, tag));
                else if (tag.IsConstructed)
                {
                    AsnDecoder.ReadEncodedValue(raw.Span, AsnEncodingRules.BER, out int content, out int length, out _);
                    Walk(raw.Slice(content, length), depth + 1);
                }
            }
        }
        Walk(value, 0);
        return list;
    }

    private static string Hex(ReadOnlySpan<byte> b) => Convert.ToHexString(b);
}
