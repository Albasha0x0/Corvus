using System.Buffers.Binary;
using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;

namespace Corvus.Core;

/// <summary>Authenticode signature details; DigestMatches is false after a change, Problem is set when unreadable.</summary>
public sealed record CertificateInfo(
    bool Present,
    string? Signer = null,
    string? Issuer = null,
    string? Thumbprint = null,
    DateTime? NotBefore = null,
    DateTime? NotAfter = null,
    string? DigestAlgorithm = null,
    bool? DigestMatches = null,
    bool? SignatureValid = null,
    string? Chain = null,
    string? Problem = null,
    DateTime? Timestamp = null);

/// <summary>Reads and verifies a PE's Authenticode signature; malformed input is reported in Problem.</summary>
public static class Certificates
{
    private const int SecurityDirectory = 4;
    private const ushort WinCertTypePkcsSignedData = 2;
    private const string CodeSigning = "1.3.6.1.5.5.7.3.3";

    public static CertificateInfo Read(byte[] file) => Read(file, out _);

    private static CertificateInfo Read(byte[] file, out SignedCms? signed) =>
        Read(file, file.Length, (at, n) => file.AsSpan((int)at, n).ToArray(), (hash, at, n) => hash.AppendData(file, (int)at, (int)n), out signed);

    /// <summary>The Authenticode signature of a PE in a seekable stream, read in ranges.</summary>
    public static CertificateInfo Read(Stream file, ReadOnlySpan<byte> headers)
    {
        var buffer = new byte[1 << 20];
        byte[] Read(long at, int n)
        {
            var b = new byte[n];
            file.Position = at;
            file.ReadExactly(b);
            return b;
        }
        void Append(IncrementalHash hash, long at, long n)
        {
            file.Position = at;
            for (long done = 0; done < n;)
            {
                int got = file.Read(buffer, 0, (int)Math.Min(buffer.Length, n - done));
                if (got <= 0) throw new EndOfStreamException();
                hash.AppendData(buffer, 0, got);
                done += got;
            }
        }
        return Certificates.Read(headers, file.Length, Read, Append, out _);
    }

    /// <summary>The signature of the PE whose headers are <paramref name="headers"/>, its other bytes read by <paramref name="read"/> and hashed by <paramref name="append"/>.</summary>
    private static CertificateInfo Read(ReadOnlySpan<byte> headers, long fileLength, Func<long, int, byte[]> read, Action<IncrementalHash, long, long> append,
        out SignedCms? signed)
    {
        signed = null;
        var pe = PeImage.TryParse(headers);
        if (pe == null) return new CertificateInfo(false, Problem: "not a PE file");
        // A file offset, not an RVA.
        var (offset, size) = pe.Directory(headers, SecurityDirectory);
        if (offset == 0 || size == 0) return new CertificateInfo(false);
        if (offset < 8 || (long)offset + size > fileLength || size < 8)
            return new CertificateInfo(true, Problem: "the certificate table lies outside the file (truncated or corrupt)");

        var table = read(offset, (int)size);
        uint length = BinaryPrimitives.ReadUInt32LittleEndian(table);
        ushort type = BinaryPrimitives.ReadUInt16LittleEndian(table.AsSpan(6));
        if (type != WinCertTypePkcsSignedData || length < 8 || length > size)
            return new CertificateInfo(true, Problem: $"unsupported certificate entry (type {type}, length {length})");

        var cms = new SignedCms();
        try { cms.Decode(table.AsSpan(8, (int)length - 8)); }
        catch (CryptographicException ex) { return new CertificateInfo(true, Problem: $"signature unreadable: {ex.Message}"); }
        // SignedCms parses certificates lazily; damaged ones throw on first use.
        try
        {
            var info = Read(fileLength, append, pe, offset, size, cms);
            signed = cms;
            return info;
        }
        catch (Exception ex) when (ex is CryptographicException or AsnContentException)
        {
            return new CertificateInfo(true, Problem: $"signature unreadable: {ex.Message}");
        }
    }

    private static CertificateInfo Read(long fileLength, Action<IncrementalHash, long, long> append, PeImage pe, uint offset, uint size, SignedCms cms)
    {
        if (cms.SignerInfos.Count == 0) return new CertificateInfo(true, Problem: "the signature has no signer");

        var signer = cms.SignerInfos[0];
        var cert = signer.Certificate;
        var (algorithm, expected) = SignedDigest(cms.ContentInfo.Content);
        bool? matches = null;
        // A table inside the headers cannot be excluded from the hash.
        if (algorithm != null && expected != null && HashName(algorithm) is { } hash
            && offset >= pe.DirectoryEntryOffset(SecurityDirectory) + 8)
            matches = ImageDigest(fileLength, append, pe, offset, size, hash).AsSpan().SequenceEqual(expected);

        bool? valid;
        try { signer.CheckSignature(verifySignatureOnly: true); valid = true; }
        catch (CryptographicException) { valid = false; }

        var timestamp = SigningTime(signer);
        return new CertificateInfo(true, cert?.Subject, cert?.Issuer, cert?.Thumbprint, cert?.NotBefore.ToUniversalTime(), cert?.NotAfter.ToUniversalTime(),
            algorithm != null ? HashName(algorithm)?.Name ?? algorithm : null, matches, valid, cert == null ? null : DescribeChain(cert, cms.Certificates, timestamp),
            Timestamp: timestamp);
    }

    /// <summary>Timestamp from an RFC 3161 token or a legacy countersignature; null when absent.</summary>
    private static DateTime? SigningTime(SignerInfo signer)
    {
        try
        {
            foreach (var attribute in signer.UnsignedAttributes)
                if (attribute.Oid.Value == "1.3.6.1.4.1.311.3.3.1")
                    foreach (var value in attribute.Values)
                        if (Rfc3161TimestampToken.TryDecode(value.RawData, out var token, out _))
                            return token!.TokenInfo.Timestamp.UtcDateTime;
            foreach (var counter in signer.CounterSignerInfos)
                foreach (var attribute in counter.SignedAttributes)
                    foreach (var value in attribute.Values)
                        if (value is Pkcs9SigningTime time)
                            return time.SigningTime.ToUniversalTime();
        }
        catch (Exception ex) when (ex is CryptographicException or AsnContentException) { }
        return null;
    }

    /// <summary>Digest algorithm OID and digest from SpcIndirectDataContent { data, DigestInfo { algorithm, digest } }.</summary>
    private static (string? Algorithm, byte[]? Digest) SignedDigest(byte[] content)
    {
        try
        {
            var reader = new AsnReader(content, AsnEncodingRules.BER);
            if (reader.PeekTag().HasSameClassAndValue(Asn1Tag.PrimitiveOctetString))
                reader = new AsnReader(reader.ReadOctetString(), AsnEncodingRules.BER);
            var indirect = reader.ReadSequence();
            indirect.ReadEncodedValue(); // SpcAttributeTypeAndOptionalValue
            var digestInfo = indirect.ReadSequence();
            var algorithm = digestInfo.ReadSequence().ReadObjectIdentifier();
            return (algorithm, digestInfo.ReadOctetString());
        }
        catch (Exception ex) when (ex is AsnContentException or CryptographicException)
        {
            return (null, null);
        }
    }

    private static HashAlgorithmName? HashName(string oid) => oid switch
    {
        "1.3.14.3.2.26" => HashAlgorithmName.SHA1,
        "2.16.840.1.101.3.4.2.1" => HashAlgorithmName.SHA256,
        "2.16.840.1.101.3.4.2.2" => HashAlgorithmName.SHA384,
        "2.16.840.1.101.3.4.2.3" => HashAlgorithmName.SHA512,
        "1.2.840.113549.2.5" => HashAlgorithmName.MD5,
        _ => null,
    };

    /// <summary>Authenticode image digest: the file except CheckSum, the security directory entry and the certificate table.</summary>
    private static byte[] ImageDigest(long fileLength, Action<IncrementalHash, long, long> append, PeImage pe, uint certOffset, uint certSize, HashAlgorithmName algorithm)
    {
        using var hash = IncrementalHash.CreateHash(algorithm);
        int checksum = pe.ChecksumOffset;
        int entry = pe.DirectoryEntryOffset(SecurityDirectory);
        append(hash, 0, checksum);
        append(hash, checksum + 4, entry - (checksum + 4));
        append(hash, entry + 8, certOffset - (entry + 8));
        long after = (long)certOffset + certSize;
        if (after < fileLength) append(hash, after, fileLength - after);
        return hash.GetHashAndReset();
    }

    /// <summary>Null when the embedded signature is intact, chains to a root of <paramref name="organization"/> and is trusted here for code signing; else why not.</summary>
    public static string? VerifyPublisher(byte[] file, string organization) => VerifyPublisher(file, organization, out _);

    /// <summary>As <see cref="VerifyPublisher(byte[], string)"/>; <paramref name="note"/> names a check that could not be made (revocation).</summary>
    public static string? VerifyPublisher(byte[] file, string organization, out string? note)
    {
        note = null;
        var info = Read(file, out var cms);
        if (!info.Present) return "no embedded signature";
        if (info.Problem != null) return info.Problem;
        if (info.DigestMatches != true) return "the file does not match its signature (changed after signing)";
        if (info.SignatureValid != true) return "the signature does not verify";
        return CheckSigner(cms!, organization, out note);
    }

    /// <summary>Null when a PKCS #7 signer may sign code, is not revoked and chains to a root of <paramref name="organization"/>; else why not.</summary>
    /// <remarks>Revocation is checked online, or from cached data when CORVUS_OFFLINE is set; an unknown status is accepted and named in <paramref name="note"/>.</remarks>
    public static string? CheckSigner(SignedCms cms, string organization, out string? note)
    {
        note = null;
        try
        {
            if (cms.SignerInfos.Count == 0) return "the signature has no signer";
            var signer = cms.SignerInfos[0];
            signer.CheckSignature(verifySignatureOnly: true);
            var cert = signer.Certificate;
            if (cert == null) return "the signer certificate is missing";
            if (Organization(cert) != organization) return $"signed by '{cert.Subject}', not {organization}";
            if (!AllowsCodeSigning(cert)) return $"the signer certificate '{cert.Subject}' is not issued for code signing";
            bool offline = ReferencePacks.Offline;
            using var chain = Chain(cms.Certificates, SigningTime(signer), revocation: offline ? X509RevocationMode.Offline : X509RevocationMode.Online);
            chain.ChainPolicy.ApplicationPolicy.Add(new Oid(CodeSigning));
            chain.Build(cert);
            var status = chain.ChainStatus.Select(s => s.Status).Where(s => s != X509ChainStatusFlags.NoError).ToHashSet();
            if (status.Contains(X509ChainStatusFlags.Revoked)) return "a certificate in the signer's chain is revoked";
            bool unknown = status.Remove(X509ChainStatusFlags.RevocationStatusUnknown) | status.Remove(X509ChainStatusFlags.OfflineRevocation);
            if (status.Count > 0)
                return $"the signer's chain is not trusted on this machine ({string.Join(", ", status.Select(s => s.ToString()).Order(StringComparer.Ordinal))})";
            var root = chain.ChainElements[^1].Certificate;
            if (Organization(root) != organization) return $"the chain ends at '{root.Subject}', not a root of {organization}";
            if (unknown) note = offline ? "revocation not checked (CORVUS_OFFLINE=1 and no cached revocation data)" : "revocation not checked (no revocation data could be retrieved)";
            return null;
        }
        catch (Exception ex) when (ex is CryptographicException or AsnContentException)
        {
            return $"signature unreadable: {ex.Message}";
        }
    }

    private static string? Organization(X509Certificate2 cert)
    {
        foreach (var rdn in cert.SubjectName.EnumerateRelativeDistinguishedNames())
            if (rdn.GetSingleElementType().Value == "2.5.4.10") return rdn.GetSingleElementValue();
        return null;
    }

    /// <summary>True when the certificate's enhanced key usage lists code signing; a certificate without that extension is refused.</summary>
    internal static bool AllowsCodeSigning(X509Certificate2 cert) =>
        cert.Extensions.OfType<X509EnhancedKeyUsageExtension>().FirstOrDefault() is { } usage
        && usage.EnhancedKeyUsages.Cast<Oid>().Any(o => o.Value == CodeSigning);

    // Intermediates come from the signature, never the network; on Windows this leaves revocation data retrieval on.
    private static X509Chain Chain(X509Certificate2Collection extra, DateTime? timestamp, X509RevocationMode revocation = X509RevocationMode.NoCheck)
    {
        var chain = new X509Chain();
        chain.ChainPolicy.RevocationMode = revocation;
        chain.ChainPolicy.RevocationFlag = X509RevocationFlag.ExcludeRoot;
        chain.ChainPolicy.UrlRetrievalTimeout = TimeSpan.FromSeconds(5);
        chain.ChainPolicy.DisableCertificateDownloads = true;
        chain.ChainPolicy.ExtraStore.AddRange(extra);
        if (timestamp is { } at) chain.ChainPolicy.VerificationTime = at.ToLocalTime();
        return chain;
    }

    /// <summary>The signer's chain without revocation checks; a timestamped signature is verified at signing time, as Windows does.</summary>
    private static string DescribeChain(X509Certificate2 cert, X509Certificate2Collection extra, DateTime? timestamp)
    {
        try
        {
            using var chain = Chain(extra, timestamp);
            bool trusted = chain.Build(cert);
            var path = string.Join(" <- ", chain.ChainElements.Select(e => e.Certificate.GetNameInfo(X509NameType.SimpleName, false)));
            if (trusted)
                return timestamp is { } signed && cert.NotAfter.ToUniversalTime() < DateTime.UtcNow
                    ? $"trusted on this machine (timestamped {signed:yyyy-MM-dd}, while the certificate was valid; it has expired since): {path}"
                    : $"trusted on this machine: {path}";
            var problems = chain.ChainStatus.Select(s => s.Status.ToString()).Distinct();
            return $"not trusted on this machine ({string.Join(", ", problems)}): {path}";
        }
        catch (CryptographicException ex)
        {
            return $"chain could not be built: {ex.Message}";
        }
    }
}
