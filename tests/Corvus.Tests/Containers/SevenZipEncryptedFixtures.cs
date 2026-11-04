using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using SharpCompress.Compressors.LZMA;

namespace Corvus.Tests;

/// <summary>Builds stored 7z archives whose entries, and optionally the header, are packed behind the 7zAES coder, optionally after an LZMA or LZMA2 coder.</summary>
internal static class SevenZipEncryptedFixtures
{
    private const int CyclePower = 8;

    private static readonly byte[] AesId = [0x06, 0xF1, 0x07, 0x01];

    private sealed record Folder(long Pack, long Unpack, uint Crc, byte[]? Props, Lz? Compressor = null, long Mid = 0);

    private sealed record Lz(byte[] Id, byte[] Props);

    /// <summary>The compressor placed before 7zAES in a folder.</summary>
    internal enum Compression { None, Lzma, Lzma2 }

    /// <summary>A 7z with one folder per file; a null <paramref name="password"/> stores plainly, and <paramref name="encryptHeader"/> packs the header behind the coder.</summary>
    internal static byte[] Build(string? password, bool encryptHeader, params (string Name, byte[] Data)[] files) =>
        Build(password, encryptHeader, Compression.None, files);

    /// <summary>As above, with each folder compressed by <paramref name="compression"/> before it is encrypted.</summary>
    internal static byte[] Build(string? password, bool encryptHeader, Compression compression, params (string Name, byte[] Data)[] files)
    {
        var packed = new MemoryStream();
        var folders = new List<Folder>();
        foreach (var (_, data) in files)
        {
            var (squeezed, lz) = Compress(data, compression);
            var (cipher, props) = Pack(squeezed, password);
            packed.Write(cipher);
            folders.Add(new Folder(cipher.Length, data.Length, Crc32(data), props, lz, squeezed.Length));
        }

        var header = new MemoryStream();
        header.WriteByte(0x01);
        header.WriteByte(0x04);
        StreamsInfo(header, 0, folders, files: true);
        header.WriteByte(0x05);
        Number(header, (ulong)files.Length);
        var names = new MemoryStream();
        foreach (var (name, _) in files)
        {
            names.Write(Encoding.Unicode.GetBytes(name));
            names.Write([0, 0]);
        }
        header.WriteByte(0x11);
        Number(header, (ulong)names.Length + 1);
        header.WriteByte(0);
        names.WriteTo(header);
        header.WriteByte(0x00);
        header.WriteByte(0x00);

        byte[] next = header.ToArray();
        if (encryptHeader)
        {
            var (cipher, props) = Pack(next, password);
            long at = packed.Length;
            packed.Write(cipher);
            var encoded = new MemoryStream();
            encoded.WriteByte(0x17);
            StreamsInfo(encoded, (ulong)at, [new Folder(cipher.Length, next.Length, Crc32(next), props)], files: false);
            next = encoded.ToArray();
        }

        var body = packed.ToArray();
        var start = new byte[20];
        BinaryPrimitives.WriteInt64LittleEndian(start, body.Length);
        BinaryPrimitives.WriteInt64LittleEndian(start.AsSpan(8), next.Length);
        BinaryPrimitives.WriteUInt32LittleEndian(start.AsSpan(16), Crc32(next));
        var output = new MemoryStream();
        output.Write([0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C, 0, 4]);
        var startCrc = new byte[4];
        BinaryPrimitives.WriteUInt32LittleEndian(startCrc, Crc32(start));
        output.Write(startCrc);
        output.Write(start);
        output.Write(body);
        output.Write(next);
        return output.ToArray();
    }

    private static void StreamsInfo(Stream s, ulong packPos, List<Folder> folders, bool files)
    {
        s.WriteByte(0x06);
        Number(s, packPos);
        Number(s, (ulong)folders.Count);
        s.WriteByte(0x09);
        foreach (var f in folders) Number(s, (ulong)f.Pack);
        s.WriteByte(0x00);
        s.WriteByte(0x07);
        s.WriteByte(0x0B);
        Number(s, (ulong)folders.Count);
        s.WriteByte(0);
        foreach (var f in folders)
        {
            if (f.Compressor != null)
            {
                // LZMA or LZMA2 first in unpack order, 7zAES second, bound output to input.
                Number(s, 2);
                s.WriteByte((byte)(f.Compressor.Id.Length | 0x20));
                s.Write(f.Compressor.Id);
                Number(s, (ulong)f.Compressor.Props.Length);
                s.Write(f.Compressor.Props);
                s.WriteByte(0x24);
                s.Write(AesId);
                Number(s, (ulong)f.Props!.Length);
                s.Write(f.Props);
                Number(s, 0);
                Number(s, 1);
                continue;
            }
            Number(s, 1);
            if (f.Props == null)
            {
                // Copy coder: a 1-byte id, no properties.
                s.WriteByte(0x01);
                s.WriteByte(0x00);
                continue;
            }
            // 7zAES: a 4-byte id with properties.
            s.WriteByte(0x24);
            s.Write(AesId);
            Number(s, (ulong)f.Props.Length);
            s.Write(f.Props);
        }
        s.WriteByte(0x0C);
        foreach (var f in folders)
        {
            Number(s, (ulong)f.Unpack);
            if (f.Compressor != null) Number(s, (ulong)f.Mid);
        }
        // A header folder carries its checksum; file folders carry it per substream.
        if (!files) Crcs(s, folders);
        s.WriteByte(0x00);
        if (files)
        {
            s.WriteByte(0x08);
            Crcs(s, folders);
            s.WriteByte(0x00);
        }
        s.WriteByte(0x00);
    }

    private static void Crcs(Stream s, List<Folder> folders)
    {
        s.WriteByte(0x0A);
        s.WriteByte(1);
        foreach (var f in folders)
        {
            var crc = new byte[4];
            BinaryPrimitives.WriteUInt32LittleEndian(crc, f.Crc);
            s.Write(crc);
        }
    }

    private static (byte[] Data, Lz? Coder) Compress(byte[] data, Compression compression)
    {
        if (compression == Compression.None) return (data, null);
        if (compression == Compression.Lzma2) return (Lzma2Stored(data), new Lz([0x21], [0x18]));
        var output = new MemoryStream();
        byte[] props;
        using (var encoder = LzmaStream.Create(new LzmaEncoderProperties(), false, output))
        {
            encoder.Write(data);
            encoder.Flush();
            props = encoder.Properties;
        }
        return (output.ToArray(), new Lz([0x03, 0x01, 0x01], props));
    }

    // Chunks are stored, not compressed: the stream needs no LZMA2 encoder.
    private static byte[] Lzma2Stored(byte[] data)
    {
        var output = new MemoryStream();
        for (int at = 0; at < data.Length; at += 0x10000)
        {
            int size = Math.Min(0x10000, data.Length - at);
            // Control 1 resets the dictionary, 2 keeps it.
            output.WriteByte(at == 0 ? (byte)1 : (byte)2);
            output.WriteByte((byte)(size - 1 >> 8));
            output.WriteByte((byte)(size - 1));
            output.Write(data, at, size);
        }
        output.WriteByte(0);
        return output.ToArray();
    }

    // The coder properties carry the cycle power, an 8-byte salt and a 16-byte IV.
    private static (byte[] Cipher, byte[]? Props) Pack(byte[] data, string? password)
    {
        if (password == null) return (data, null);
        var salt = RandomNumberGenerator.GetBytes(8);
        var iv = RandomNumberGenerator.GetBytes(16);
        var passwordBytes = Encoding.Unicode.GetBytes(password);
        using var sha = SHA256.Create();
        var counter = new byte[8];
        for (long i = 0; i < 1L << CyclePower; i++)
        {
            sha.TransformBlock(salt, 0, salt.Length, null, 0);
            sha.TransformBlock(passwordBytes, 0, passwordBytes.Length, null, 0);
            BinaryPrimitives.WriteInt64LittleEndian(counter, i);
            sha.TransformBlock(counter, 0, 8, null, 0);
        }
        sha.TransformFinalBlock([], 0, 0);
        using var aes = Aes.Create();
        aes.Key = sha.Hash!;
        var padded = new byte[(data.Length + 15) / 16 * 16];
        data.CopyTo(padded, 0);
        var cipher = aes.EncryptCbc(padded, iv, PaddingMode.None);
        byte[] props = [CyclePower | 0xC0, (7 << 4) | 15, .. salt, .. iv];
        return (cipher, props);
    }

    private static void Number(Stream s, ulong value)
    {
        byte first = 0, mask = 0x80;
        int i;
        for (i = 0; i < 8; i++)
        {
            if (value < 1UL << 7 * (i + 1))
            {
                first |= (byte)(value >> 8 * i);
                break;
            }
            first |= mask;
            mask >>= 1;
        }
        s.WriteByte(first);
        for (int j = 0; j < i; j++) s.WriteByte((byte)(value >> 8 * j));
    }

    private static uint Crc32(ReadOnlySpan<byte> data)
    {
        uint crc = 0xFFFFFFFF;
        foreach (var b in data)
        {
            crc ^= b;
            for (int i = 0; i < 8; i++) crc = (crc & 1) != 0 ? crc >> 1 ^ 0xEDB88320 : crc >> 1;
        }
        return ~crc;
    }
}
