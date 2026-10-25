using System.IO.Compression;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Corvus.Tests;

/// <summary>
/// An APK signed with a JAR (v1) signature by a new self-signed RSA key: what Android installs for targetSdkVersion 29
/// and below, where no v2 signature is required.
/// </summary>
internal static class SignedApk
{
    public static byte[] Build(params (string Name, byte[] Data)[] entries)
    {
        static string Digest(byte[] data) => Convert.ToBase64String(SHA256.HashData(data));
        var manifest = new StringBuilder("Manifest-Version: 1.0\r\nCreated-By: corvus-tests\r\n\r\n");
        var sections = new StringBuilder();
        foreach (var (name, data) in entries)
        {
            var section = $"Name: {name}\r\nSHA-256-Digest: {Digest(data)}\r\n\r\n";
            manifest.Append(section);
            // Each .SF entry digests the manifest section it names, blank line included.
            sections.Append($"Name: {name}\r\nSHA-256-Digest: {Digest(Encoding.UTF8.GetBytes(section))}\r\n\r\n");
        }
        var mf = Encoding.UTF8.GetBytes(manifest.ToString());
        var sf = Encoding.UTF8.GetBytes($"Signature-Version: 1.0\r\nSHA-256-Digest-Manifest: {Digest(mf)}\r\nCreated-By: corvus-tests\r\n\r\n{sections}");

        using var key = RSA.Create(2048);
        var request = new CertificateRequest("CN=corvus-tests", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using var cert = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(30));
        var cms = new SignedCms(new ContentInfo(sf), detached: true);
        cms.ComputeSignature(new CmsSigner(SubjectIdentifierType.IssuerAndSerialNumber, cert) { DigestAlgorithm = new Oid("2.16.840.1.101.3.4.2.1") });

        using var output = new MemoryStream();
        using (var zip = new ZipArchive(output, ZipArchiveMode.Create, leaveOpen: true))
        {
            foreach (var (name, data) in entries.Concat([("META-INF/MANIFEST.MF", mf), ("META-INF/CERT.SF", sf), ("META-INF/CERT.RSA", cms.Encode())]))
            {
                using var s = zip.CreateEntry(name, CompressionLevel.Optimal).Open();
                s.Write(data);
            }
        }
        return output.ToArray();
    }
}
