using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Xml;

namespace Corvus.Core.Documents;

/// <summary>
/// ECMA-376 document encryption (MS-OFFCRYPTO 2.3.4.5 standard and 2.3.4.10 agile): an encrypted OOXML package is opened
/// with the passwords olevba tries: Excel's and PowerPoint's built-in ones (which documents saved without a user password
/// carry) and five short numeric ones; any other password leaves it encrypted.
/// </summary>
internal static class OfficeCrypto
{
    public static readonly string[] Passwords = ["VelvetSweatshop", "/01Hannes Ruescher/01", "123", "1234", "12345", "123456", "4321"];

    /// <summary>The decrypted package, or null with the reason (unsupported version, not the default password, damaged).</summary>
    public static (byte[]? Package, string Reason) Decrypt(byte[] info, byte[] package, long max)
    {
        if (info.Length < 8 || package.Length < 8) return (null, "the EncryptionInfo stream is too short");
        int major = BinaryPrimitives.ReadUInt16LittleEndian(info), minor = BinaryPrimitives.ReadUInt16LittleEndian(info.AsSpan(2));
        long size = BinaryPrimitives.ReadInt64LittleEndian(package);
        if (size < 0 || size > max || size > package.Length - 8) return (null, $"the package declares {size:N0} bytes");
        try
        {
            if (!(major == 4 && minor == 4) && !(minor == 2 && major is 2 or 3 or 4)) return (null, $"encryption version {major}.{minor} is not read");
            foreach (var password in Passwords)
            {
                var (plain, how) = major == 4 && minor == 4 ? Agile(info, package, size, password) : Standard(info, package, size, password);
                if (plain != null || how != Wrong) return (plain, how);
            }
            return (null, "encrypted with a password other than the built-in and common ones");
        }
        catch (Exception ex) when (ex is CryptographicException or XmlException or FormatException or ArgumentException or IndexOutOfRangeException)
        {
            return (null, $"damaged encryption data: {ex.Message}");
        }
    }

    private const string Wrong = "wrong password";

    private static (byte[]?, string) Standard(byte[] info, byte[] package, long size, string password)
    {
        int headerSize = BinaryPrimitives.ReadInt32LittleEndian(info.AsSpan(8));
        var header = info.AsSpan(12, headerSize);
        int keyBits = BinaryPrimitives.ReadInt32LittleEndian(header[16..]);
        int algId = BinaryPrimitives.ReadInt32LittleEndian(header[8..]);
        if (algId is not (0x660E or 0x660F or 0x6610)) return (null, $"cipher 0x{algId:X4} is not AES");
        var verifier = info.AsSpan(12 + headerSize);
        var salt = verifier.Slice(4, 16).ToArray();
        var encryptedVerifier = verifier.Slice(20, 16).ToArray();
        var encryptedHash = verifier.Slice(40, 32).ToArray();
        byte[] h = SHA1.HashData([.. salt, .. Encoding.Unicode.GetBytes(password)]);
        Span<byte> buf = stackalloc byte[24];
        for (int i = 0; i < 50000; i++)
        {
            BinaryPrimitives.WriteInt32LittleEndian(buf, i);
            h.CopyTo(buf[4..]);
            h = SHA1.HashData(buf);
        }
        h = SHA1.HashData([.. h, 0, 0, 0, 0]);
        var x1 = new byte[64]; var x2 = new byte[64];
        for (int i = 0; i < 64; i++) { x1[i] = (byte)(0x36 ^ (i < h.Length ? h[i] : 0)); x2[i] = (byte)(0x5C ^ (i < h.Length ? h[i] : 0)); }
        var key = SHA1.HashData(x1).Concat(SHA1.HashData(x2)).Take(keyBits / 8).ToArray();
        using var aes = Aes.Create();
        aes.Key = key;
        var plainVerifier = aes.DecryptEcb(encryptedVerifier, PaddingMode.None);
        var plainHash = aes.DecryptEcb(encryptedHash, PaddingMode.None);
        if (!SHA1.HashData(plainVerifier).AsSpan().SequenceEqual(plainHash.AsSpan(0, 20))) return (null, Wrong);
        int length = (package.Length - 8) / 16 * 16;
        var plain = aes.DecryptEcb(package.AsSpan(8, length), PaddingMode.None);
        return (plain[..(int)size], $"standard encryption, password {Named(password)}");
    }

    private static readonly byte[] KeyValueBlock = [0x14, 0x6E, 0x0B, 0xE7, 0xAB, 0xAC, 0xD0, 0xD6];
    private static readonly byte[] VerifierInputBlock = [0xFE, 0xA7, 0xD2, 0x76, 0x3B, 0x4B, 0x9E, 0x79];
    private static readonly byte[] VerifierHashBlock = [0xD7, 0xAA, 0x0F, 0x6D, 0x30, 0x61, 0x34, 0x4E];

    private static (byte[]?, string) Agile(byte[] info, byte[] package, long size, string password)
    {
        var xml = new XmlDocument { XmlResolver = null };
        using (var reader = XmlReader.Create(new MemoryStream(info, 8, info.Length - 8), new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null }))
            xml.Load(reader);
        var keyData = (XmlElement)xml.GetElementsByTagName("keyData")[0]!;
        var encryptedKey = xml.GetElementsByTagName("encryptedKey", "http://schemas.microsoft.com/office/2006/keyEncryptor/password").OfType<XmlElement>().FirstOrDefault();
        if (encryptedKey == null) return (null, "no password key encryptor");
        if (keyData.GetAttribute("cipherAlgorithm") != "AES" || encryptedKey.GetAttribute("cipherAlgorithm") != "AES") return (null, "the cipher is not AES");
        Func<byte[], byte[]>? Hash(string name) => name switch
        {
            "SHA512" => SHA512.HashData, "SHA384" => SHA384.HashData, "SHA256" => SHA256.HashData, "SHA1" => SHA1.HashData, _ => null,
        };
        var keyHash = Hash(encryptedKey.GetAttribute("hashAlgorithm"));
        var dataHash = Hash(keyData.GetAttribute("hashAlgorithm"));
        if (keyHash == null || dataHash == null) return (null, "unsupported hash algorithm");
        var salt = Convert.FromBase64String(encryptedKey.GetAttribute("saltValue"));
        int spin = int.Parse(encryptedKey.GetAttribute("spinCount"), System.Globalization.CultureInfo.InvariantCulture);
        if (spin is < 0 or > 10_000_000) return (null, $"spin count {spin} out of range");
        int keyBytes = int.Parse(encryptedKey.GetAttribute("keyBits"), System.Globalization.CultureInfo.InvariantCulture) / 8;
        var h = keyHash([.. salt, .. Encoding.Unicode.GetBytes(password)]);
        var buf = new byte[4 + h.Length];
        for (int i = 0; i < spin; i++)
        {
            BinaryPrimitives.WriteInt32LittleEndian(buf, i);
            h.CopyTo(buf, 4);
            h = keyHash(buf);
        }
        byte[] Derive(byte[] block) => Fit(keyHash([.. h, .. block]), keyBytes, 0x36);
        byte[] Cbc(byte[] key, byte[] iv, byte[] data)
        {
            using var aes = Aes.Create();
            aes.Key = key;
            return aes.DecryptCbc(data.AsSpan(0, data.Length / 16 * 16), iv.AsSpan(0, 16), PaddingMode.None);
        }
        var verifierInput = Cbc(Derive(VerifierInputBlock), salt, Convert.FromBase64String(encryptedKey.GetAttribute("encryptedVerifierHashInput")));
        var verifierHash = Cbc(Derive(VerifierHashBlock), salt, Convert.FromBase64String(encryptedKey.GetAttribute("encryptedVerifierHashValue")));
        var expected = keyHash(verifierInput.AsSpan(0, Math.Min(verifierInput.Length, salt.Length)).ToArray());
        if (!verifierHash.AsSpan(0, Math.Min(expected.Length, verifierHash.Length)).SequenceEqual(expected.AsSpan(0, Math.Min(expected.Length, verifierHash.Length))))
            return (null, Wrong);
        var secret = Cbc(Derive(KeyValueBlock), salt, Convert.FromBase64String(encryptedKey.GetAttribute("encryptedKeyValue")))[..keyBytes];
        var dataSalt = Convert.FromBase64String(keyData.GetAttribute("saltValue"));
        int blockSize = int.Parse(keyData.GetAttribute("blockSize"), System.Globalization.CultureInfo.InvariantCulture);
        var output = new byte[size];
        using var cipher = Aes.Create();
        cipher.Key = secret;
        Span<byte> index = stackalloc byte[4];
        for (long at = 0, segment = 0; at < size; at += 4096, segment++)
        {
            BinaryPrimitives.WriteUInt32LittleEndian(index, (uint)segment);
            var iv = Fit(dataHash([.. dataSalt, .. index.ToArray()]), blockSize, 0x36);
            int n = (int)Math.Min(4096, package.Length - 8 - at) / 16 * 16;
            if (n <= 0) break;
            var plain = cipher.DecryptCbc(package.AsSpan((int)(8 + at), n), iv, PaddingMode.None);
            plain.AsSpan(0, (int)Math.Min(plain.Length, size - at)).CopyTo(output.AsSpan((int)at));
        }
        return (output, $"agile encryption, password {Named(password)}");
    }

    private static string Named(string password) => password switch
    {
        "VelvetSweatshop" => "VelvetSweatshop (Excel's built-in)", "/01Hannes Ruescher/01" => "/01Hannes Ruescher/01 (PowerPoint's built-in)", _ => $"'{password}'",
    };

    /// <summary>A hash cut or padded to <paramref name="length"/> bytes.</summary>
    private static byte[] Fit(byte[] b, int length, byte pad)
    {
        var r = new byte[length];
        for (int i = 0; i < length; i++) r[i] = i < b.Length ? b[i] : pad;
        return r;
    }
}
