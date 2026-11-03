using System.IO.Hashing;
using System.Security.Cryptography;
using System.Text;

namespace Corvus.Tests;

/// <summary>Stored RAR 5 archives with AES-256-CBC file data, optionally behind an encrypted header block.</summary>
internal static class RarEncryptedFixtures
{
    private static readonly byte[] Signature = "Rar!\x1A\x07\x01\x00"u8.ToArray();

    /// <summary>
    /// A RAR 5 archive of stored files encrypted under <paramref name="password"/>
    /// (PBKDF2-HMAC-SHA256, 2^<paramref name="kdfCount"/> iterations, with the
    /// password check value); every header block is encrypted too when
    /// <paramref name="encryptHeaders"/> is set.
    /// </summary>
    internal static byte[] Rar5(string password, bool encryptHeaders, params (string Name, byte[] Data)[] files) =>
        Rar5(password, encryptHeaders, 4, files);

    /// <summary>As <see cref="Rar5(string, bool, (string, byte[])[])"/> with an explicit iteration exponent.</summary>
    internal static byte[] Rar5(string password, bool encryptHeaders, int kdfCount, params (string Name, byte[] Data)[] files)
    {
        var salt = RandomNumberGenerator.GetBytes(16);
        var key = Pbkdf2(password, salt, 1 << kdfCount, 32);
        var check = Check(password, salt, kdfCount);
        var output = new MemoryStream();
        output.Write(Signature);
        if (encryptHeaders)
            output.Write(Block(4, [.. Vint(0), .. Vint(1), (byte)kdfCount, .. salt, .. check]));
        Append(output, Block(1, [.. Vint(0), .. Vint(0)]), key, encryptHeaders);
        foreach (var (name, data) in files)
        {
            var iv = RandomNumberGenerator.GetBytes(16);
            using var aes = Aes.Create();
            aes.Key = key;
            var packed = aes.EncryptCbc(data, iv, PaddingMode.Zeros);
            // Extra record: file encryption (type 1), version 0, flags 1 (check value present).
            var record = new List<byte>();
            record.AddRange(Vint(1));
            record.AddRange(Vint(0));
            record.AddRange(Vint(1));
            record.Add((byte)kdfCount);
            record.AddRange(salt);
            record.AddRange(iv);
            record.AddRange(check);
            var extra = Vint((ulong)record.Count).Concat(record).ToArray();
            var nameBytes = Encoding.UTF8.GetBytes(name);
            // File flags (checksum present), unpacked size, attributes, checksum, stored, host OS, name.
            var fields = new List<byte>();
            fields.AddRange(Vint(4));
            fields.AddRange(Vint((ulong)data.Length));
            fields.AddRange(Vint(0));
            fields.AddRange(BitConverter.GetBytes(Crc32.HashToUInt32(data)));
            fields.AddRange(Vint(0));
            fields.AddRange(Vint(0));
            fields.AddRange(Vint((ulong)nameBytes.Length));
            fields.AddRange(nameBytes);
            Append(output, Block(2, [.. fields], extra, packed.Length), key, encryptHeaders);
            output.Write(packed);
        }
        Append(output, Block(5, Vint(0)), key, encryptHeaders);
        return output.ToArray();
    }

    // Blocks after the encryption header carry a fresh IV and are padded with zeros.
    private static void Append(MemoryStream output, byte[] block, byte[] key, bool encrypt)
    {
        if (!encrypt) { output.Write(block); return; }
        var iv = RandomNumberGenerator.GetBytes(16);
        using var aes = Aes.Create();
        aes.Key = key;
        output.Write(iv);
        output.Write(aes.EncryptCbc(block, iv, PaddingMode.Zeros));
    }

    // A block is its CRC-32, then the header size and the header the CRC covers.
    private static byte[] Block(int type, byte[] fields, byte[]? extra = null, int data = 0)
    {
        var h = new List<byte>();
        h.AddRange(Vint((ulong)type));
        h.AddRange(Vint((ulong)((extra != null ? 1 : 0) | (data > 0 ? 2 : 0))));
        if (extra != null) h.AddRange(Vint((ulong)extra.Length));
        if (data > 0) h.AddRange(Vint((ulong)data));
        h.AddRange(fields);
        if (extra != null) h.AddRange(extra);
        var sized = Vint((ulong)h.Count).Concat(h).ToArray();
        return [.. BitConverter.GetBytes(Crc32.HashToUInt32(sized)), .. sized];
    }

    // The check value folds the key stream 32 iterations past the key to 8 bytes; 4 bytes of its SHA-256 follow.
    private static byte[] Check(string password, byte[] salt, int kdfCount)
    {
        var stream = Pbkdf2(password, salt, (1 << kdfCount) + 32, 32);
        var value = new byte[8];
        for (int i = 0; i < stream.Length; i++) value[i % 8] ^= stream[i];
        return [.. value, .. SHA256.HashData(value)[..4]];
    }

    private static byte[] Pbkdf2(string password, byte[] salt, int iterations, int length) =>
        Rfc2898DeriveBytes.Pbkdf2(Encoding.UTF8.GetBytes(password), salt, iterations, HashAlgorithmName.SHA256, length);

    private static byte[] Vint(ulong v)
    {
        var o = new List<byte>();
        do
        {
            byte b = (byte)(v & 0x7F);
            v >>= 7;
            o.Add((byte)(v != 0 ? b | 0x80 : b));
        } while (v != 0);
        return [.. o];
    }
}
