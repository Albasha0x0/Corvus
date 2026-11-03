using System.Security.Cryptography;
using System.Text;

namespace Corvus.Tests;

/// <summary>Writer for agile (version 4.4) encrypted packages with chosen hash, key size and spin count.</summary>
internal static class AgileEncryptionFixtures
{
    /// <summary>The EncryptionInfo and EncryptedPackage streams of this package; edit rewrites the key encryptor attributes.</summary>
    public static (byte[] Info, byte[] Package) Build(
        byte[] package, string password, string hash = "SHA512", int keyBits = 256, int spin = 100,
        Func<string, string>? edit = null)
    {
        Func<byte[], byte[]> H = hash switch
        {
            "SHA1" => SHA1.HashData, "SHA256" => SHA256.HashData, "SHA384" => SHA384.HashData, _ => SHA512.HashData,
        };
        int keyBytes = keyBits / 8;
        byte[] Concat(params byte[][] parts) => [.. parts.SelectMany(p => p)];
        byte[] Fit(byte[] b, int n) { var r = new byte[n]; for (int i = 0; i < n; i++) r[i] = i < b.Length ? b[i] : (byte)0x36; return r; }
        byte[] Cbc(byte[] key, byte[] iv, byte[] data)
        {
            using var c = Aes.Create();
            c.Key = key;
            return c.EncryptCbc(data, iv, PaddingMode.None);
        }
        var keySalt = Enumerable.Range(1, 16).Select(i => (byte)(i * 5)).ToArray();
        var dataSalt = Enumerable.Range(1, 16).Select(i => (byte)(i * 9)).ToArray();
        var secret = Enumerable.Range(0, keyBytes).Select(i => (byte)(i * 3 + 1)).ToArray();
        var verifierInput = Enumerable.Range(0, 16).Select(i => (byte)(100 + i)).ToArray();
        var h = H(Concat(keySalt, Encoding.Unicode.GetBytes(password)));
        for (int i = 0; i < spin; i++) h = H(Concat(BitConverter.GetBytes(i), h));
        byte[] Derive(byte[] block) => Fit(H(Concat(h, block)), keyBytes);
        var verifierHash = H(verifierInput);
        Array.Resize(ref verifierHash, (verifierHash.Length + 15) / 16 * 16);
        string B64(byte[] b) => Convert.ToBase64String(b);
        var encryptedKey =
            $"<p:encryptedKey spinCount=\"{spin}\" saltSize=\"16\" blockSize=\"16\" keyBits=\"{keyBits}\" hashSize=\"{H([]).Length}\" cipherAlgorithm=\"AES\" cipherChaining=\"ChainingModeCBC\" hashAlgorithm=\"{hash}\" saltValue=\"{B64(keySalt)}\" " +
            $"encryptedVerifierHashInput=\"{B64(Cbc(Derive([0xFE, 0xA7, 0xD2, 0x76, 0x3B, 0x4B, 0x9E, 0x79]), keySalt, verifierInput))}\" " +
            $"encryptedVerifierHashValue=\"{B64(Cbc(Derive([0xD7, 0xAA, 0x0F, 0x6D, 0x30, 0x61, 0x34, 0x4E]), keySalt, verifierHash))}\" " +
            $"encryptedKeyValue=\"{B64(Cbc(Derive([0x14, 0x6E, 0x0B, 0xE7, 0xAB, 0xAC, 0xD0, 0xD6]), keySalt, secret))}\"/>";
        if (edit != null) encryptedKey = edit(encryptedKey);
        var xml = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>" +
            "<encryption xmlns=\"http://schemas.microsoft.com/office/2006/encryption\" xmlns:p=\"http://schemas.microsoft.com/office/2006/keyEncryptor/password\">" +
            $"<keyData saltSize=\"16\" blockSize=\"16\" keyBits=\"{keyBits}\" hashSize=\"{H([]).Length}\" cipherAlgorithm=\"AES\" cipherChaining=\"ChainingModeCBC\" hashAlgorithm=\"{hash}\" saltValue=\"{B64(dataSalt)}\"/>" +
            "<keyEncryptors><keyEncryptor uri=\"http://schemas.microsoft.com/office/2006/keyEncryptor/password\">" +
            encryptedKey + "</keyEncryptor></keyEncryptors></encryption>";
        var info = Concat([4, 0, 4, 0, 0x40, 0, 0, 0], Encoding.UTF8.GetBytes(xml));
        var encrypted = new MemoryStream();
        encrypted.Write(BitConverter.GetBytes((long)package.Length));
        for (int at = 0, segment = 0; at < package.Length; at += 4096, segment++)
        {
            int n = Math.Min(4096, package.Length - at);
            var chunk = new byte[(n + 15) / 16 * 16];
            Array.Copy(package, at, chunk, 0, n);
            encrypted.Write(Cbc(secret, Fit(H(Concat(dataSalt, BitConverter.GetBytes(segment))), 16), chunk));
        }
        return (info, encrypted.ToArray());
    }
}