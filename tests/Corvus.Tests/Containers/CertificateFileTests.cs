using System.Diagnostics;
using System.Formats.Asn1;
using System.Numerics;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Corvus.Core;
using Corvus.Services.Analysis;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>summarize_file view=certificate: certificates, chains, pins and other blocks of PEM, DER, PKCS #7 and PKCS #12 files built here.</summary>
public sealed class CertificateFileTests(ITestOutputHelper output) : IDisposable
{
    private static readonly DateTimeOffset From = new(2020, 1, 1, 0, 0, 0, TimeSpan.Zero), Until = new(2120, 1, 1, 0, 0, 0, TimeSpan.Zero);
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    /// <summary>An RSA 2048 root (path length 1), an EC P-256 intermediate and an EC P-256 server leaf with names, usage and key identifiers.</summary>
    private sealed class Pki : IDisposable
    {
        public readonly RSA RootKey = RSA.Create(2048);
        public readonly ECDsa IntermediateKey = ECDsa.Create(ECCurve.NamedCurves.nistP256), LeafKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        public readonly X509Certificate2 Root, Intermediate, Leaf;

        public Pki()
        {
            var root = new CertificateRequest("CN=Example Root, O=Example", RootKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            root.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, true, 1, true));
            root.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
            root.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(root.PublicKey, false));
            Root = root.CreateSelfSigned(From, Until);

            var intermediate = new CertificateRequest("CN=Example Issuing CA, O=Example", IntermediateKey, HashAlgorithmName.SHA256);
            intermediate.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, true, 0, true));
            intermediate.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
            intermediate.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(intermediate.PublicKey, false));
            intermediate.CertificateExtensions.Add(X509AuthorityKeyIdentifierExtension.CreateFromCertificate(Root, true, false));
            // An RSA root signs an EC request through a generator; the issuer-certificate overload needs matching algorithms.
            Intermediate = intermediate.Create(Root.SubjectName, X509SignatureGenerator.CreateForRSA(RootKey, RSASignaturePadding.Pkcs1), From, Until, [0x10, 0x01])
                .CopyWithPrivateKey(IntermediateKey);

            var leaf = new CertificateRequest("CN=api.example.com", LeafKey, HashAlgorithmName.SHA256);
            var names = new SubjectAlternativeNameBuilder();
            names.AddDnsName("api.example.com");
            names.AddIpAddress(System.Net.IPAddress.Parse("192.0.2.1"));
            leaf.CertificateExtensions.Add(names.Build());
            leaf.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
            leaf.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension([new Oid("1.3.6.1.5.5.7.3.1")], false));
            leaf.CertificateExtensions.Add(X509AuthorityKeyIdentifierExtension.CreateFromCertificate(Intermediate, true, false));
            Leaf = leaf.Create(Intermediate, From, Until, [0x20, 0x02]);
        }

        public void Dispose()
        {
            foreach (var d in new IDisposable[] { Root, Intermediate, Leaf, RootKey, IntermediateKey, LeafKey }) d.Dispose();
        }
    }

    private static string PinOf(X509Certificate2 c) => "sha256/" + Convert.ToBase64String(SHA256.HashData(c.PublicKey.ExportSubjectPublicKeyInfo()));

    private CertificateFileView.Facts View(string path, long offset = 0, int? limit = null)
    {
        var f = FileInput.Open(path);
        f.Options = new FileViewOptions("certificate", Offset: offset, Limit: limit);
        return (CertificateFileView.Facts)new CertificateFileView().Inspect(f, default)!.Detail;
    }

    [Fact]
    public void A_pem_bundle_out_of_order_chains_leaf_to_root_with_pins_names_and_keys()
    {
        using var pki = new Pki();
        var path = _dir.File("server.pem");
        File.WriteAllText(path, "# server bundle\n" + pki.Leaf.ExportCertificatePem() + "\n" + pki.Root.ExportCertificatePem() + "\n"
            + pki.Intermediate.ExportCertificatePem() + "\n" + pki.LeafKey.ExportPkcs8PrivateKeyPem() + "\n" + pki.RootKey.ExportSubjectPublicKeyInfoPem() + "\n");
        var v = View(path);
        Assert.Equal(("PEM", 3L), (v.Format, v.Total));
        var (leaf, root, intermediate) = (v.Certificates[0], v.Certificates[1], v.Certificates[2]);
        Assert.Equal(("CN=api.example.com", "EC P-256", "ecdsa-with-SHA256", PinOf(pki.Leaf)), (leaf.Subject, leaf.Key, leaf.SignatureAlgorithm, leaf.Pin));
        Assert.Equal(["DNS:api.example.com", "IP:192.0.2.1"], leaf.Names);
        Assert.Equal(["serverAuth"], leaf.ExtendedKeyUsage);
        Assert.Equal((false, (string?)intermediate.SubjectKeyId), (leaf.Ca, leaf.AuthorityKeyId));
        Assert.Equal(("RSA 2048", "sha256WithRSAEncryption", true, 1, true), (root.Key, root.SignatureAlgorithm, root.Ca, root.PathLength, root.SelfIssued));
        Assert.Equal(["keyCertSign", "cRLSign"], root.KeyUsage);
        Assert.Equal(Convert.ToHexString(SHA256.HashData(pki.Root.RawData)), root.Sha256);
        Assert.Equal("1001", intermediate.Serial);

        var chain = Assert.Single(v.Chains);
        Assert.Equal([0, 2, 1], chain.Path);
        Assert.Equal("self-signed root", chain.End);
        Assert.Equal(["the file lists these certificates in another order than leaf to root"], chain.Problems);
        Assert.NotNull(chain.ThisMachine);
        Assert.Equal([("private key", "EC, PKCS #8"), ("public key", $"RSA 2048, pin {PinOf(pki.Root)}")], v.Items.Select(i => (i.Kind, i.Detail!)));
        Assert.DoesNotContain(v.Items, i => (i.Detail ?? "").Contains("MIG", StringComparison.Ordinal));

        var page = View(path, offset: 1, limit: 1);
        Assert.Equal((1, 2L), (page.Certificates.Count, page.Next));
        Assert.Equal("CN=Example Root, O=Example", page.Certificates[0].Subject);
    }

    [Fact]
    public void A_wrong_key_a_non_ca_issuer_an_expired_certificate_and_a_missing_issuer_are_named()
    {
        using var realRoot = RSA.Create(2048);
        using var impostorKey = RSA.Create(2048);
        using var notCaKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var childKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var rootName = new X500DistinguishedName("CN=Example Root, O=Example");
        var impostor = new CertificateRequest(rootName, impostorKey, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1).CreateSelfSigned(From, Until);
        var signedByOther = new CertificateRequest("CN=wrong key", childKey, HashAlgorithmName.SHA256)
            .Create(rootName, X509SignatureGenerator.CreateForRSA(realRoot, RSASignaturePadding.Pkcs1), From, Until, [1]);

        var notCaRequest = new CertificateRequest("CN=Not A CA", notCaKey, HashAlgorithmName.SHA256);
        notCaRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        var notCa = notCaRequest.CreateSelfSigned(From, Until);
        var underNotCa = new CertificateRequest("CN=under a leaf", childKey, HashAlgorithmName.SHA256)
            .Create(notCa.SubjectName, X509SignatureGenerator.CreateForECDsa(notCaKey), From, Until, [2]);

        var expired = new CertificateRequest("CN=expired", childKey, HashAlgorithmName.SHA256)
            .Create(new X500DistinguishedName("CN=Missing CA"), X509SignatureGenerator.CreateForECDsa(childKey),
                new DateTimeOffset(2000, 1, 1, 0, 0, 0, TimeSpan.Zero), new DateTimeOffset(2001, 1, 1, 0, 0, 0, TimeSpan.Zero), [0x7F]);

        var path = _dir.File("mixed.crt");
        // The platform encodes serials as positive; patching the serial 0x7F (after the version) to 0xFF makes it negative.
        var negative = expired.RawData;
        int serialAt = negative.AsSpan(4).IndexOf(new byte[] { 0x02, 0x01, 0x7F }) + 4;
        negative[serialAt + 2] = 0xFF;
        File.WriteAllText(path, string.Concat(new[] { signedByOther, impostor, underNotCa, notCa }.Select(c => c.ExportCertificatePem() + "\n"))
            + PemEncoding.WriteString("CERTIFICATE", negative));
        var v = View(path);
        Assert.Equal(3, v.Chains.Count);
        Assert.Equal([0, 1], v.Chains[0].Path);
        Assert.Equal("self-signed root", v.Chains[0].End);
        Assert.Contains("#0: signature does not verify with the key of #1", v.Chains[0].Problems);
        Assert.Equal([2, 3], v.Chains[1].Path);
        Assert.Contains("#3 issues #2 but is not a CA (basic constraints)", v.Chains[1].Problems);
        Assert.Equal([4], v.Chains[2].Path);
        Assert.Equal("issuer not in the file: CN=Missing CA", v.Chains[2].End);
        Assert.Equal(["#4 expired 2001-01-01"], v.Chains[2].Problems);
        Assert.Contains("#4: negative serial number (RFC 5280 requires a positive one)", v.Notes);
    }

    [Fact]
    public void Pkcs7_and_pkcs12_bundles_read_their_certificates_and_name_what_a_password_protects()
    {
        using var pki = new Pki();
        var collection = new X509Certificate2Collection { pki.Leaf, pki.Intermediate, pki.Root };
        var p7b = _dir.File("chain.p7b");
        File.WriteAllBytes(p7b, collection.Export(X509ContentType.Pkcs7)!);
        var v = View(p7b);
        Assert.Equal(("PKCS #7", 3L), (v.Format, v.Total));
        Assert.Equal("self-signed root", Assert.Single(v.Chains).End);

        using var withKey = pki.Leaf.CopyWithPrivateKey(pki.LeafKey);
        var open = _dir.File("open.pfx");
        File.WriteAllBytes(open, new X509Certificate2Collection { withKey, pki.Intermediate }.Export(X509ContentType.Pkcs12, "")!);
        var o = View(open);
        Assert.Equal(("PKCS #12", 2L), (o.Format, o.Total));
        Assert.Contains(o.Items, i => i.Kind == "private key");
        Assert.Contains(o.Notes, n => n.EndsWith("MAC verified with an empty password", StringComparison.Ordinal));

        var locked = _dir.File("locked.p12");
        File.WriteAllBytes(locked, new X509Certificate2Collection { withKey }.Export(X509ContentType.Pkcs12, "secret")!);
        var l = View(locked);
        Assert.Equal(0, l.Total);
        Assert.Contains(l.Items, i => i.Kind == "protected contents" && i.Detail == "encrypted with a password; not read");
        Assert.Contains(l.Notes, n => n.EndsWith("MAC needs a password; not verified", StringComparison.Ordinal));
    }

    [Fact]
    public void A_request_and_a_crl_read_as_der_and_pem()
    {
        using var pki = new Pki();
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        var request = new CertificateRequest("CN=device-17, O=Example", key, HashAlgorithmName.SHA384).CreateSigningRequest();
        var csr = _dir.File("device.csr");
        File.WriteAllBytes(csr, request);
        var r = View(csr);
        Assert.Equal("DER certificate request", r.Format);
        var pin = "sha256/" + Convert.ToBase64String(SHA256.HashData(key.ExportSubjectPublicKeyInfo()));
        Assert.Equal(("certificate request", $"CN=device-17, O=Example; EC P-384, pin {pin}"), (r.Items[0].Kind, r.Items[0].Detail!));

        var crl = new CertificateRevocationListBuilder();
        crl.AddEntry([0x20, 0x02], new DateTimeOffset(2024, 5, 1, 0, 0, 0, TimeSpan.Zero));
        crl.AddEntry([0x20, 0x03]);
        var der = crl.Build(pki.Intermediate, BigInteger.One, new DateTimeOffset(2030, 1, 1, 0, 0, 0, TimeSpan.Zero), HashAlgorithmName.SHA256,
            thisUpdate: new DateTimeOffset(2029, 1, 1, 0, 0, 0, TimeSpan.Zero));
        var file = _dir.File("issuing.crl");
        File.WriteAllText(file, PemEncoding.WriteString("X509 CRL", der));
        var c = View(file);
        Assert.Equal(("CRL", "CN=Example Issuing CA, O=Example; this update 2029-01-01 00:00:00Z, next 2030-01-01 00:00:00Z; 2 revoked"),
            (c.Items[0].Kind, c.Items[0].Detail!));
    }

    [Fact]
    public void The_overview_lists_the_view_and_its_highlights_only_for_certificate_files()
    {
        using var pki = new Pki();
        var pem = _dir.File("ca.pem");
        File.WriteAllText(pem, pki.Root.ExportCertificatePem());
        var summary = new InspectionService(new AssemblyWorkspace()).Summarize(null, pem, default, FileViewOptions.None);
        Assert.Contains("certificate", summary.Views.Keys);
        Assert.Contains(summary.Views["certificate"].Highlights, h => h.StartsWith("PEM: 1 certificate(s) in 1 chain(s)", StringComparison.Ordinal));

        var text = _dir.File("notes.txt");
        File.WriteAllText(text, "a plain note\n");
        Assert.DoesNotContain("certificate", new InspectionService(new AssemblyWorkspace()).Summarize(null, text, default, FileViewOptions.None).Views.Keys);
    }

    [Fact]
    [FuzzEntry(typeof(CertificateFile), typeof(CertificateFileView))]
    public void Fuzzed_certificate_files_never_throw()
    {
        using var pki = new Pki();
        using var withKey = pki.Leaf.CopyWithPrivateKey(pki.LeafKey);
        var pem = Encoding.ASCII.GetBytes(pki.Leaf.ExportCertificatePem() + "\n" + pki.Intermediate.ExportCertificatePem());
        var samples = new[] { pem, pki.Root.RawData, new X509Certificate2Collection { pki.Leaf, pki.Root }.Export(X509ContentType.Pkcs7)!,
            new X509Certificate2Collection { withKey }.Export(X509ContentType.Pkcs12, "")! };
        var path = _dir.File("fuzz.der");
        foreach (var sample in samples)
        {
            var failures = FormatFuzz.Run(sample, b =>
            {
                try { CertificateFile.Read(b, checkMachine: false, default); }
                catch (InvalidDataException) { }
                File.WriteAllBytes(path, b);
                try { new CertificateFileView().Inspect(FileInput.Open(path), default); }
                catch (ToolError e) when (e.Code == ErrorCode.MalformedInput) { }
            }, 100);
            Assert.True(failures.Count == 0, string.Join("\n", failures.Take(20)));
        }
    }

    // openssl (CORVUS_OPENSSL) reads every certificate file under CORVUS_CERT_FILES; compared: the set of certificates
    // (SHA-256 of each encoding, from crl2pkcs7) and for each its serial, validity, SHA-256 fingerprint and SPKI pin.
    [RequiresRealDataFact("CORVUS_OPENSSL", "CORVUS_CERT_FILES")]
    [Trait("Speed", "Slow")]
    public void Real_certificate_files_match_openssl()
    {
        var openssl = Environment.GetEnvironmentVariable("CORVUS_OPENSSL")!;
        var files = Directory.EnumerateFiles(Environment.GetEnvironmentVariable("CORVUS_CERT_FILES")!, "*", SearchOption.AllDirectories)
            .Where(CertificateFile.HasCertificateExtension).Order(StringComparer.Ordinal).ToList();
        int compared = 0, certificates = 0, unread = 0, unprinted = 0;
        var mismatches = new List<string>();
        // Bundles repeat across images; openssl prints each distinct certificate once.
        var printed = new Dictionary<string, (string Serial, DateTime NotBefore, DateTime NotAfter, string Fingerprint, string? Pin)?>(StringComparer.Ordinal);
        var clock = Stopwatch.StartNew();
        foreach (var file in files)
        {
            var bytes = File.ReadAllBytes(file);
            CertificateFile? ours = null;
            try { ours = CertificateFile.Read(bytes, checkMachine: false, default); }
            catch (InvalidDataException) { unread++; }
            var reference = OpenSslCertificates(openssl, file, bytes);
            if (reference == null) continue;
            compared++;
            var mine = ours?.Certificates.Select(c => c.Sha256).ToHashSet() ?? [];
            foreach (var missing in reference.Keys.Where(k => !mine.Contains(k))) mismatches.Add($"{Name(file)}: openssl reads {missing[..16]}, we do not");
            foreach (var extra in mine.Where(k => !reference.ContainsKey(k))) mismatches.Add($"{Name(file)}: we read {extra[..16]}, openssl does not");
            foreach (var c in ours?.Certificates.Where(c => reference.ContainsKey(c.Sha256)) ?? [])
            {
                certificates++;
                if (!printed.TryGetValue(c.Sha256, out var fields)) printed[c.Sha256] = fields = OpenSslFields(openssl, reference[c.Sha256], _dir.File("one.der"));
                if (fields is not { } r) { unprinted++; continue; }
                // openssl prints a negative serial with a sign; the entry keeps its two's-complement bytes.
                var serial = new BigInteger(Convert.FromHexString(c.Serial), isUnsigned: false, isBigEndian: true);
                var theirs = r.Serial.StartsWith('-') ? -BigInteger.Parse("0" + r.Serial[1..], System.Globalization.NumberStyles.HexNumber)
                    : BigInteger.Parse("0" + r.Serial, System.Globalization.NumberStyles.HexNumber);
                if (serial != theirs) mismatches.Add($"{Name(file)} #{c.Index}: serial {c.Serial} vs {r.Serial}");
                if (r.NotBefore != c.NotBefore || r.NotAfter != c.NotAfter) mismatches.Add($"{Name(file)} #{c.Index}: validity {c.NotBefore:o}..{c.NotAfter:o} vs {r.NotBefore:o}..{r.NotAfter:o}");
                if (r.Fingerprint != c.Sha256) mismatches.Add($"{Name(file)} #{c.Index}: fingerprint");
                if (r.Pin != null && r.Pin != c.Pin) mismatches.Add($"{Name(file)} #{c.Index}: pin {c.Pin} vs {r.Pin}");
            }
        }
        output.WriteLine($"{files.Count} files, {compared} read by openssl, {unread} not read here, {certificates} certificates compared ({printed.Count} distinct), {unprinted} openssl did not print, {clock.Elapsed.TotalSeconds:0.0} s");
        foreach (var m in mismatches.Take(50)) output.WriteLine(m);
        Assert.True(compared > 0, "openssl read no file");
        Assert.True(mismatches.Count == 0, string.Join("\n", mismatches.Take(50)));
        string Name(string f) => Path.GetFileName(f);
    }

    /// <summary>The certificates openssl reads from a PEM or DER file (encoding by SHA-256), or null when it reads none.</summary>
    private static Dictionary<string, byte[]>? OpenSslCertificates(string openssl, string file, byte[] bytes)
    {
        bool pem = bytes.AsSpan().IndexOf("-----BEGIN "u8) >= 0;
        var (code, stdout) = Run(openssl, pem ? ["crl2pkcs7", "-nocrl", "-certfile", file, "-outform", "DER"]
            : ["x509", "-inform", "DER", "-in", file, "-outform", "DER"]);
        if (code != 0 || stdout.Length == 0) return null;
        var certs = new Dictionary<string, byte[]>(StringComparer.Ordinal);
        if (pem)
        {
            var cms = new SignedCms();
            cms.Decode(stdout);
            // crl2pkcs7 copies each certificate's encoding; SignedCms keeps it.
            var reader = new AsnReader(stdout, AsnEncodingRules.BER).ReadSequence();
            reader.ReadObjectIdentifier();
            var signed = reader.ReadSequence(new Asn1Tag(TagClass.ContextSpecific, 0)).ReadSequence();
            signed.ReadInteger();
            signed.ReadSetOf();
            signed.ReadSequence();
            if (signed.HasData && signed.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.ContextSpecific, 0, true)))
                for (var set = signed.ReadSetOf(new Asn1Tag(TagClass.ContextSpecific, 0)); set.HasData;)
                {
                    var der = set.ReadEncodedValue().ToArray();
                    certs.TryAdd(Convert.ToHexString(SHA256.HashData(der)), der);
                }
        }
        else certs.TryAdd(Convert.ToHexString(SHA256.HashData(stdout)), stdout);
        return certs.Count == 0 ? null : certs;
    }

    /// <summary>What openssl x509 prints of one certificate, or null when it prints no serial (an encoding it reads in a bundle but not alone).</summary>
    private static (string Serial, DateTime NotBefore, DateTime NotAfter, string Fingerprint, string? Pin)? OpenSslFields(string openssl, byte[] der, string temp)
    {
        File.WriteAllBytes(temp, der);
        var (_, text) = Run(openssl, ["x509", "-inform", "DER", "-in", temp, "-noout", "-serial", "-startdate", "-enddate", "-fingerprint", "-sha256", "-pubkey"]);
        var lines = Encoding.ASCII.GetString(text).Split('\n', StringSplitOptions.TrimEntries);
        if (!lines.Any(l => l.StartsWith("serial=", StringComparison.Ordinal))) return null;
        string Value(string key) => lines.First(l => l.StartsWith(key, StringComparison.OrdinalIgnoreCase))[key.Length..];
        static DateTime Date(string s) => DateTime.ParseExact(string.Join(' ', s.Replace(" GMT", "").Split(' ', StringSplitOptions.RemoveEmptyEntries)),
            "MMM d HH:mm:ss yyyy", System.Globalization.CultureInfo.InvariantCulture, System.Globalization.DateTimeStyles.AdjustToUniversal | System.Globalization.DateTimeStyles.AssumeUniversal);
        var all = Encoding.ASCII.GetString(text);
        int begin = all.IndexOf("-----BEGIN PUBLIC KEY-----", StringComparison.Ordinal);
        string? pin = begin < 0 ? null : CertificateFile.Pin(Convert.FromBase64String(all.AsSpan(begin)[PemEncoding.Find(all.AsSpan(begin)).Base64Data].ToString()));
        return (Value("serial="), Date(Value("notBefore=")), Date(Value("notAfter=")), Value("sha256 Fingerprint=").Replace(":", ""), pin);
    }

    private static (int Code, byte[] Stdout) Run(string exe, string[] args)
    {
        var psi = new ProcessStartInfo(exe) { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false };
        foreach (var a in args) psi.ArgumentList.Add(a);
        using var p = Process.Start(psi)!;
        using var ms = new MemoryStream();
        var copy = p.StandardOutput.BaseStream.CopyToAsync(ms);
        _ = p.StandardError.ReadToEndAsync();
        p.WaitForExit();
        copy.Wait();
        return (p.ExitCode, ms.ToArray());
    }
}
