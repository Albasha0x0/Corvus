using System.Buffers.Binary;
using System.IO.Compression;
using System.IO.Hashing;

namespace Corvus.Core;

/// <summary>PNG files (ISO/IEC 15948) of 8-bit RGBA pixels, one unfiltered zlib stream.</summary>
internal static class PngWriter
{
    /// <summary>A PNG of <paramref name="width"/> by <paramref name="height"/> straight-alpha RGBA pixels, rows top to bottom.</summary>
    public static byte[] Rgba(int width, int height, ReadOnlySpan<byte> rgba)
    {
        if (width <= 0 || height <= 0 || rgba.Length != 4L * width * height) throw new ArgumentException($"{rgba.Length} bytes for {width}x{height} RGBA pixels");
        using var output = new MemoryStream();
        output.Write([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]);
        Span<byte> header = stackalloc byte[13];
        BinaryPrimitives.WriteInt32BigEndian(header, width);
        BinaryPrimitives.WriteInt32BigEndian(header[4..], height);
        // Bit depth 8, color type 6 (RGBA), deflate, adaptive filtering, no interlace.
        header[8] = 8;
        header[9] = 6;
        Chunk(output, "IHDR"u8, header);
        using (var packed = new MemoryStream())
        {
            using (var z = new ZLibStream(packed, CompressionLevel.Fastest, leaveOpen: true))
                for (int y = 0; y < height; y++)
                {
                    z.WriteByte(0);
                    z.Write(rgba.Slice(y * width * 4, width * 4));
                }
            Chunk(output, "IDAT"u8, packed.GetBuffer().AsSpan(0, (int)packed.Length));
        }
        Chunk(output, "IEND"u8, []);
        return output.ToArray();
    }

    /// <summary>Converts premultiplied RGBA to straight alpha in place, as Go's image/png does.</summary>
    public static void Unpremultiply(Span<byte> rgba)
    {
        for (int i = 0; i + 3 < rgba.Length; i += 4)
        {
            uint a = rgba[i + 3];
            if (a == 255) continue;
            if (a == 0) { rgba.Slice(i, 3).Clear(); continue; }
            for (int c = 0; c < 3; c++) rgba[i + c] = (byte)Math.Min(255u, rgba[i + c] * 0xFFFFu / a >> 8);
        }
    }

    private static void Chunk(Stream output, ReadOnlySpan<byte> type, ReadOnlySpan<byte> data)
    {
        Span<byte> word = stackalloc byte[4];
        BinaryPrimitives.WriteInt32BigEndian(word, data.Length);
        output.Write(word);
        output.Write(type);
        output.Write(data);
        var crc = new Crc32();
        crc.Append(type);
        crc.Append(data);
        BinaryPrimitives.WriteUInt32BigEndian(word, crc.GetCurrentHashAsUInt32());
        output.Write(word);
    }
}
