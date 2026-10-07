using System.Buffers.Binary;
using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;

namespace NetDecompilerMcp.Services.Analysis;

/// <summary>
/// An Authenticode signature: signer, issuer, thumbprint and validity of the signing certificate, the digest algorithm,
/// whether the signed digest matches the file's digest (false when the file changed after signing), whether the
/// signature over that digest verifies, and how the certificate chain builds on this machine. Present=false for an
/// unsigned file; Problem is set when the signature could not be read.
/// </summary>
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

/// <summary>
/// Reads the Authenticode signature from a PE's security directory (one WIN_CERT_TYPE_PKCS_SIGNED_DATA entry) and checks
/// it. Never throws on malformed input: damaged tables, PKCS#7 data and certificates are reported in Problem.
/// </summary>
public static class Certificates
{
    private const int SecurityDirectory = 4;
    private const ushort WinCertTypePkcsSignedData = 2;

    public static CertificateInfo Read(byte[] file)
    {
        var pe = PeImage.TryParse(file);
        if (pe == null) return new CertificateInfo(false, Problem: "not a PE file");
        var (offset, size) = pe.Directory(file, SecurityDirectory); // a file offset, not an RVA
        if (offset == 0 || size == 0) return new CertificateInfo(false);
        if (offset < 8 || (long)offset + size > file.Length || size < 8)
            return new CertificateInfo(true, Problem: "the certificate table lies outside the file (truncated or corrupt)");

        uint length = BinaryPrimitives.ReadUInt32LittleEndian(file.AsSpan((int)offset));
        ushort type = BinaryPrimitives.ReadUInt16LittleEndian(file.AsSpan((int)offset + 6));
        if (type != WinCertTypePkcsSignedData || length < 8 || length > size)
            return new CertificateInfo(true, Problem: $"unsupported certificate entry (type {type}, length {length})");

        var cms = new SignedCms();
        try { cms.Decode(file.AsSpan((int)offset + 8, (int)length - 8)); }
        catch (CryptographicException ex) { return new CertificateInfo(true, Problem: $"signature unreadable: {ex.Message}"); }
        // SignedCms parses the certificates lazily: a damaged one throws on first use, not in Decode
        try { return Read(file, pe, offset, size, cms); }
        catch (Exception ex) when (ex is CryptographicException or AsnContentException)
        {
            return new CertificateInfo(true, Problem: $"signature unreadable: {ex.Message}");
        }
    }

    private static CertificateInfo Read(byte[] file, PeImage pe, uint offset, uint size, SignedCms cms)
    {
        if (cms.SignerInfos.Count == 0) return new CertificateInfo(true, Problem: "the signature has no signer");

        var signer = cms.SignerInfos[0];
        var cert = signer.Certificate;
        var (algorithm, expected) = SignedDigest(cms.ContentInfo.Content);
        bool? matches = null;
        if (algorithm != null && expected != null && HashName(algorithm) is { } hash
            && offset >= pe.DirectoryEntryOffset(SecurityDirectory) + 8) // a table inside the headers cannot be hashed around
            matches = ImageDigest(file, pe, offset, size, hash).AsSpan().SequenceEqual(expected);

        bool? valid;
        try { signer.CheckSignature(verifySignatureOnly: true); valid = true; }
        catch (CryptographicException) { valid = false; }

        var timestamp = SigningTime(signer);
        return new CertificateInfo(true, cert?.Subject, cert?.Issuer, cert?.Thumbprint, cert?.NotBefore.ToUniversalTime(), cert?.NotAfter.ToUniversalTime(),
            algorithm != null ? HashName(algorithm)?.Name ?? algorithm : null, matches, valid, cert == null ? null : DescribeChain(cert, cms.Certificates, timestamp),
            Timestamp: timestamp);
    }

    /// <summary>
    /// The time a trusted timestamp authority vouches the file was signed: an RFC 3161 token (Microsoft's
    /// 1.3.6.1.4.1.311.3.3.1 attribute) or a legacy countersignature's signing time. Null when not timestamped.
    /// </summary>
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

    /// <summary>The digest algorithm OID and digest from SpcIndirectDataContent { data, DigestInfo { algorithm, digest } }.</summary>
    private static (string? Algorithm, byte[]? Digest) SignedDigest(byte[] content)
    {
        try
        {
            var reader = new AsnReader(content, AsnEncodingRules.BER);
            if (reader.PeekTag().HasSameClassAndValue(Asn1Tag.PrimitiveOctetString))
                reader = new AsnReader(reader.ReadOctetString(), AsnEncodingRules.BER);
            var indirect = reader.ReadSequence();
            indirect.ReadEncodedValue(); // SpcAttributeTypeAndOptionalValue (the PE image data link)
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

    /// <summary>
    /// The Authenticode image digest: the whole file except the optional header's CheckSum, the security directory
    /// entry, and the certificate table itself.
    /// </summary>
    internal static byte[] ImageDigest(byte[] file, PeImage pe, uint certOffset, uint certSize, HashAlgorithmName algorithm)
    {
        using var hash = IncrementalHash.CreateHash(algorithm);
        int checksum = pe.ChecksumOffset;
        int entry = pe.DirectoryEntryOffset(SecurityDirectory);
        hash.AppendData(file, 0, checksum);
        hash.AppendData(file, checksum + 4, entry - (checksum + 4));
        hash.AppendData(file, entry + 8, (int)certOffset - (entry + 8));
        long after = (long)certOffset + certSize;
        if (after < file.Length) hash.AppendData(file, (int)after, file.Length - (int)after);
        return hash.GetHashAndReset();
    }

    /// <summary>
    /// How the signer's chain builds here (revocation not checked: offline and deterministic). A timestamped signature is
    /// checked at its signing time, as Windows does: a certificate that has expired since still validates it.
    /// </summary>
    private static string DescribeChain(X509Certificate2 cert, X509Certificate2Collection extra, DateTime? timestamp)
    {
        try
        {
            using var chain = new X509Chain();
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            chain.ChainPolicy.ExtraStore.AddRange(extra);
            if (timestamp is { } at) chain.ChainPolicy.VerificationTime = at.ToLocalTime();
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
