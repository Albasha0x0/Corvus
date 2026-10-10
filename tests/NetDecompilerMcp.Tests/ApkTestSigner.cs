using System.Buffers.Binary;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace NetDecompilerMcp.Tests;

/// <summary>
/// Signs test APKs the way apksigner lays them out: JAR signing, APK Signing Block v2 / v3 / v3.1 signers (with an
/// optional rotation lineage) and a v4 .idsig. Written from the format descriptions, separately from the verifier.
/// </summary>
internal static class ApkTestSigner
{
    public sealed record Key(X509Certificate2 Cert, AsymmetricAlgorithm Private, uint Algorithm)
    {
        public byte[] Sign(byte[] data) => Private switch
        {
            RSA rsa => rsa.SignData(data, Algorithm is 0x0102 or 0x0104 ? HashAlgorithmName.SHA512 : HashAlgorithmName.SHA256,
                Algorithm is 0x0101 or 0x0102 ? RSASignaturePadding.Pss : RSASignaturePadding.Pkcs1),
            ECDsa ec => ec.SignData(data, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence),
            _ => throw new NotSupportedException(),
        };

        public byte[] PublicKey => Cert.PublicKey.ExportSubjectPublicKeyInfo();
    }

    public static Key Rsa(string subject = "CN=Test Signer", uint algorithm = 0x0103)
    {
        var rsa = RSA.Create(2048);
        var request = new CertificateRequest(subject, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        return new(request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(30)), rsa, algorithm);
    }

    public static Key Ec(string subject = "CN=Test EC Signer")
    {
        var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest(subject, ec, HashAlgorithmName.SHA256);
        return new(request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(30)), ec, 0x0201);
    }

    public static readonly (string Name, byte[] Data)[] Entries =
    [
        ("AndroidManifest.xml", Encoding.UTF8.GetBytes(new string('m', 3000))),
        ("classes.dex", Enumerable.Range(0, 5000).Select(i => (byte)i).ToArray()),
        ("res/raw/data.bin", new byte[100]),
    ];

    public static byte[] Zip(IEnumerable<(string Name, byte[] Data)> entries)
    {
        var ms = new MemoryStream();
        using (var zip = new ZipArchive(ms, ZipArchiveMode.Create, leaveOpen: true))
            foreach (var (name, data) in entries)
            {
                using var s = zip.CreateEntry(name, CompressionLevel.NoCompression).Open();
                s.Write(data);
            }
        return ms.ToArray();
    }

    /// <summary>Entries plus META-INF/MANIFEST.MF, CERT.SF and the PKCS #7 block.</summary>
    public static (string, byte[])[] SignV1((string Name, byte[] Data)[] entries, Key key, string? apkSigned = "2, 3", bool wholeManifestDigest = true)
    {
        static string B64(byte[] data) => Convert.ToBase64String(SHA256.HashData(data));
        var manifest = new StringBuilder("Manifest-Version: 1.0\r\nCreated-By: test\r\n\r\n");
        var sections = new List<(string Name, string Text)>();
        foreach (var (name, data) in entries)
        {
            var section = $"Name: {name}\r\nSHA-256-Digest: {B64(data)}\r\n\r\n";
            sections.Add((name, section));
            manifest.Append(section);
        }
        var manifestBytes = Encoding.UTF8.GetBytes(manifest.ToString());
        var sf = new StringBuilder("Signature-Version: 1.0\r\nCreated-By: test\r\n");
        if (wholeManifestDigest) sf.Append($"SHA-256-Digest-Manifest: {B64(manifestBytes)}\r\n");
        if (apkSigned != null) sf.Append($"X-Android-APK-Signed: {apkSigned}\r\n");
        sf.Append("\r\n");
        foreach (var (name, text) in sections) sf.Append($"Name: {name}\r\nSHA-256-Digest: {B64(Encoding.UTF8.GetBytes(text))}\r\n\r\n");
        var sfBytes = Encoding.UTF8.GetBytes(sf.ToString());
        var cms = new SignedCms(new ContentInfo(sfBytes), detached: true);
        cms.ComputeSignature(new CmsSigner(SubjectIdentifierType.IssuerAndSerialNumber, key.Cert) { IncludeOption = X509IncludeOption.EndCertOnly });
        var blockName = key.Private is ECDsa ? "META-INF/CERT.EC" : "META-INF/CERT.RSA";
        return [.. entries, ("META-INF/MANIFEST.MF", manifestBytes), ("META-INF/CERT.SF", sfBytes), (blockName, cms.Encode())];
    }

    public sealed record SignerSpec(Key Key, int MinSdk = 24, int MaxSdk = int.MaxValue, byte[]? Lineage = null, bool StrippingProtection = false,
        bool BreakSignature = false, uint? AlgorithmOverride = null);

    /// <summary>Inserts an APK Signing Block holding the given blocks before the central directory.</summary>
    public static byte[] SignBlocks(byte[] zip, params (uint Id, bool V3, SignerSpec[] Signers)[] blocks)
    {
        var (cd, eocd) = Layout(zip);
        var digest256 = ContentDigest(zip, cd, eocd, HashAlgorithmName.SHA256);
        var digest512 = ContentDigest(zip, cd, eocd, HashAlgorithmName.SHA512);
        var pairs = new MemoryStream();
        foreach (var (id, v3, signers) in blocks)
        {
            var list = new MemoryStream();
            foreach (var s in signers) Lp(list, Signer(s, v3, s.Key.Algorithm is 0x0102 or 0x0104 ? digest512 : digest256));
            var value = Prefixed(list.ToArray());
            pairs.Write(U64((ulong)value.Length + 4));
            pairs.Write(U32(id));
            pairs.Write(value);
        }
        ulong size = (ulong)pairs.Length + 8 + 16;
        var block = new MemoryStream();
        block.Write(U64(size));
        block.Write(pairs.ToArray());
        block.Write(U64(size));
        block.Write("APK Sig Block 42"u8);
        var signed = new byte[zip.Length + block.Length];
        zip.AsSpan(0, (int)cd).CopyTo(signed);
        block.ToArray().CopyTo(signed, cd);
        zip.AsSpan((int)cd).CopyTo(signed.AsSpan((int)(cd + block.Length)));
        BinaryPrimitives.WriteUInt32LittleEndian(signed.AsSpan((int)(eocd + block.Length) + 16), (uint)(cd + block.Length));
        return signed;
    }

    public static (long Cd, long Eocd) Layout(byte[] zip)
    {
        long eocd = zip.Length - 22;
        while (BinaryPrimitives.ReadUInt32LittleEndian(zip.AsSpan((int)eocd)) != 0x06054b50) eocd--;
        return (BinaryPrimitives.ReadUInt32LittleEndian(zip.AsSpan((int)eocd + 16)), eocd);
    }

    /// <summary>The v2 content digest of an unsigned ZIP (its end record already points where the block will start).</summary>
    public static byte[] ContentDigest(byte[] zip, long cd, long eocd, HashAlgorithmName hash)
    {
        var chunks = new List<byte[]>();
        foreach (var (start, end) in new[] { (0L, cd), (cd, eocd), (eocd, (long)zip.Length) })
            for (long at = start; at < end; at += 1 << 20)
            {
                var chunk = zip.AsSpan((int)at, (int)Math.Min(1 << 20, end - at)).ToArray();
                chunks.Add(Hash(hash, [0xa5, .. U32((uint)chunk.Length), .. chunk]));
            }
        return Hash(hash, [0x5a, .. U32((uint)chunks.Count), .. chunks.SelectMany(c => c)]);
    }

    private static byte[] Hash(HashAlgorithmName h, byte[] data) => h == HashAlgorithmName.SHA512 ? SHA512.HashData(data) : SHA256.HashData(data);

    private static byte[] Signer(SignerSpec s, bool v3, byte[] digest)
    {
        uint algorithm = s.AlgorithmOverride ?? s.Key.Algorithm;
        var signedData = new MemoryStream();
        Lp(signedData, Prefixed(Pair(algorithm, digest)));
        Lp(signedData, Prefixed(s.Key.Cert.RawData));
        if (v3) { signedData.Write(U32((uint)s.MinSdk)); signedData.Write(U32((uint)s.MaxSdk)); }
        var attributes = new MemoryStream();
        if (s.StrippingProtection) Lp(attributes, [.. U32(0xbeeff00d), .. U32(3)]);
        if (s.Lineage != null) Lp(attributes, [.. U32(0x3ba06f8c), .. s.Lineage]);
        Lp(signedData, attributes.ToArray());
        var data = signedData.ToArray();
        var signature = s.Key.Sign(data);
        if (s.BreakSignature) signature[^1] ^= 1;
        var signer = new MemoryStream();
        Lp(signer, data);
        if (v3) { signer.Write(U32((uint)s.MinSdk)); signer.Write(U32((uint)s.MaxSdk)); }
        Lp(signer, Prefixed(Pair(algorithm, signature)));
        Lp(signer, s.Key.PublicKey);
        return signer.ToArray();
    }

    /// <summary>A proof-of-rotation attribute value: <paramref name="old"/> signs <paramref name="next"/>.</summary>
    public static byte[] Lineage(Key old, Key next, bool breakIt = false)
    {
        var value = new MemoryStream();
        value.Write(U32(1));
        var firstSigned = Prefixed([.. Prefixed(old.Cert.RawData), .. U32(0)]);
        Lp(value, [.. firstSigned, .. U32(0x7), .. U32(old.Algorithm), .. Prefixed([])]);
        var secondData = (byte[])[.. Prefixed(next.Cert.RawData), .. U32(old.Algorithm)];
        var signature = old.Sign(secondData);
        if (breakIt) signature[^1] ^= 1;
        Lp(value, [.. Prefixed(secondData), .. U32(0x7), .. U32(next.Algorithm), .. Prefixed(signature)]);
        return value.ToArray();
    }

    /// <summary>A v4 .idsig for <paramref name="apk"/> signed by <paramref name="key"/>.</summary>
    public static byte[] V4(byte[] apk, Key key, byte[] apkDigest, byte[]? rootOverride = null)
    {
        var root = rootOverride ?? MerkleRoot(apk);
        var signed = new MemoryStream();
        var der = key.Cert.RawData;
        int size = 4 + 8 + 4 + 1 + 4 + 0 + 4 + root.Length + 4 + apkDigest.Length + 4 + der.Length + 4;
        signed.Write(U32((uint)size));
        signed.Write(U64((ulong)apk.Length));
        signed.Write(U32(1));
        signed.WriteByte(12);
        Lp(signed, []);
        Lp(signed, root);
        Lp(signed, apkDigest);
        Lp(signed, der);
        Lp(signed, []);
        var signature = key.Sign(signed.ToArray());
        var file = new MemoryStream();
        file.Write(U32(2));
        Lp(file, [.. U32(1), 12, .. Prefixed([]), .. Prefixed(root)]);
        Lp(file, [.. Prefixed(apkDigest), .. Prefixed(der), .. Prefixed([]), .. Prefixed(key.PublicKey), .. U32(key.Algorithm), .. Prefixed(signature)]);
        Lp(file, []);
        return file.ToArray();
    }

    private static byte[] MerkleRoot(byte[] data)
    {
        byte[] Level(byte[] input)
        {
            int blocks = Math.Max(1, (input.Length + 4095) / 4096);
            var output = new List<byte>();
            for (int i = 0; i < blocks; i++)
            {
                var block = new byte[4096];
                input.AsSpan(i * 4096, Math.Min(4096, input.Length - i * 4096)).CopyTo(block);
                output.AddRange(SHA256.HashData(block));
            }
            return [.. output];
        }
        var level = Level(data);
        while (level.Length > 4096) level = Level(level);
        var top = new byte[4096];
        level.CopyTo(top, 0);
        return SHA256.HashData(top);
    }

    private static byte[] Pair(uint id, byte[] value) => [.. U32(id), .. Prefixed(value)];
    private static byte[] Prefixed(byte[] value) => [.. U32((uint)value.Length), .. value];
    private static void Lp(Stream s, byte[] value) => s.Write(Prefixed(value));
    private static byte[] U32(uint v) { var b = new byte[4]; BinaryPrimitives.WriteUInt32LittleEndian(b, v); return b; }
    private static byte[] U64(ulong v) { var b = new byte[8]; BinaryPrimitives.WriteUInt64LittleEndian(b, v); return b; }
}
