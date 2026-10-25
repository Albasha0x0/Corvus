using System.Buffers.Binary;
using System.IO.Compression;

namespace Corvus.Tests;

/// <summary>The pixels of an 8-bit, non-interlaced PNG (gray, gray-alpha, RGB or RGBA) as straight-alpha RGBA.</summary>
internal static class PngPixels
{
    public static (int Width, int Height, byte[] Rgba) Read(byte[] png)
    {
        Assert.True(png.AsSpan().StartsWith((ReadOnlySpan<byte>)[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]), "no PNG signature");
        int width = 0, height = 0, type = 0;
        using var idat = new MemoryStream();
        for (int p = 8; p + 8 <= png.Length;)
        {
            int length = BinaryPrimitives.ReadInt32BigEndian(png.AsSpan(p));
            string chunk = System.Text.Encoding.ASCII.GetString(png, p + 4, 4);
            var data = png.AsSpan(p + 8, length);
            if (chunk == "IHDR")
            {
                (width, height, type) = (BinaryPrimitives.ReadInt32BigEndian(data), BinaryPrimitives.ReadInt32BigEndian(data[4..]), data[9]);
                Assert.Equal((8, 0), (data[8], data[12]));
            }
            else if (chunk == "IDAT") idat.Write(data);
            p += 12 + length;
        }
        int channels = type switch { 0 => 1, 2 => 3, 4 => 2, 6 => 4, _ => throw new InvalidDataException($"PNG color type {type}") };
        idat.Position = 0;
        using var z = new ZLibStream(idat, CompressionMode.Decompress);
        using var raw = new MemoryStream();
        z.CopyTo(raw);
        var bytes = raw.ToArray();
        int stride = width * channels;
        var rows = new byte[stride * height];
        for (int y = 0; y < height; y++)
        {
            int filter = bytes[y * (stride + 1)];
            var src = bytes.AsSpan(y * (stride + 1) + 1, stride);
            var row = rows.AsSpan(y * stride, stride);
            var up = y > 0 ? rows.AsSpan((y - 1) * stride, stride) : new byte[stride];
            for (int x = 0; x < stride; x++)
            {
                int a = x >= channels ? row[x - channels] : 0, b = up[x], c = x >= channels ? up[x - channels] : 0;
                int predicted = filter switch
                {
                    0 => 0,
                    1 => a,
                    2 => b,
                    3 => (a + b) / 2,
                    4 => Paeth(a, b, c),
                    _ => throw new InvalidDataException($"PNG filter {filter}"),
                };
                row[x] = (byte)(src[x] + predicted);
            }
        }
        var rgba = new byte[4 * width * height];
        for (int i = 0; i < width * height; i++)
        {
            var px = rows.AsSpan(i * channels, channels);
            (rgba[4 * i], rgba[4 * i + 1], rgba[4 * i + 2], rgba[4 * i + 3]) = channels switch
            {
                1 => (px[0], px[0], px[0], (byte)255),
                2 => (px[0], px[0], px[0], px[1]),
                3 => (px[0], px[1], px[2], (byte)255),
                _ => (px[0], px[1], px[2], px[3]),
            };
        }
        return (width, height, rgba);
    }

    private static int Paeth(int a, int b, int c)
    {
        int p = a + b - c, pa = Math.Abs(p - a), pb = Math.Abs(p - b), pc = Math.Abs(p - c);
        return pa <= pb && pa <= pc ? a : pb <= pc ? b : c;
    }
}
