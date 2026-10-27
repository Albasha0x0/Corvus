// Deepmap-2 and KCBC decoding follows carfile-go 0.8.0, Copyright (c) 2026 devcxm. MIT License; the notice and
// license text are in THIRD-PARTY-NOTICES.md.
using System.Buffers.Binary;
using System.IO.Compression;
using Corvus.Core.Firmware;

namespace Corvus.Core.Mobile;

/// <summary>Asset catalog bitmaps (CELM) as premultiplied RGBA; damaged data throws InvalidDataException, unsupported NotSupportedException.</summary>
internal static class AssetCatalogBitmap
{
    private static readonly string[] Compressions =
        ["uncompressed", "rle", "zip", "lzvn", "lzfse", "jpeg-lzfse", "blurred", "astc", "palette-img", "hevc", "deepmap-lzfse", "deepmap-2", "dxtc"];

    public static string CompressionName(uint id) => id < Compressions.Length ? Compressions[id] : $"compression {id}";

    /// <summary>The premultiplied RGBA pixels, rows top to bottom, of a CELM payload's data (after its 16-byte header).</summary>
    public static byte[] Decode(uint compression, string pixelFormat, ReadOnlySpan<byte> data, int width, int height, long maxBytes)
    {
        int bpp = pixelFormat switch { "ARGB" => 4, "GA8 " => 2, _ => throw new NotSupportedException($"pixel format {pixelFormat.Trim()}") };
        if (width <= 0 || height <= 0) throw new InvalidDataException($"a {width}x{height} bitmap");
        if (4L * width * height > maxBytes) throw new InvalidDataException($"a {width}x{height} bitmap exceeds the {maxBytes:N0}-byte item limit");
        var stored = compression switch
        {
            0 => Tight(data.ToArray(), width, height, bpp),
            2 when Chunked(data) => Chunks(data, width, height, bpp, maxBytes, Gzip),
            2 => Tight(Gzip(data, maxBytes), width, height, bpp),
            4 when Chunked(data) => Chunks(data, width, height, bpp, maxBytes, (chunk, max) => Lzfse(chunk, max)),
            4 => Tight(Lzfse(data, maxBytes), width, height, bpp),
            11 => Deepmap2.Decode(data, width, height, bpp == 4 ? 4 : 2, maxBytes),
            _ => throw new NotSupportedException($"{CompressionName(compression)} compression"),
        };
        var rgba = new byte[4 * width * height];
        for (int s = 0, d = 0; d < rgba.Length; s += bpp, d += 4)
            if (bpp == 4) (rgba[d], rgba[d + 1], rgba[d + 2], rgba[d + 3]) = (stored[s + 2], stored[s + 1], stored[s], stored[s + 3]);
            else (rgba[d], rgba[d + 1], rgba[d + 2], rgba[d + 3]) = (stored[s], stored[s], stored[s], stored[s + 1]);
        return rgba;
    }

    private static bool Chunked(ReadOnlySpan<byte> data) => data.StartsWith("KCBC"u8);

    /// <summary>Rows of <paramref name="width"/> pixels without the alignment bytes a stored row may end with.</summary>
    private static byte[] Tight(byte[] pixels, int width, int height, int bpp)
    {
        int row = width * bpp;
        long expected = (long)row * height;
        if (pixels.Length == expected) return pixels;
        if (pixels.Length < expected || pixels.Length % height != 0) throw new InvalidDataException($"{pixels.Length:N0} bytes for {height:N0} rows of {row:N0} bytes");
        int stride = pixels.Length / height;
        var tight = new byte[expected];
        for (int y = 0; y < height; y++) pixels.AsSpan(y * stride, row).CopyTo(tight.AsSpan(y * row));
        return tight;
    }

    // KCBC chunk: magic, two words not read, its row count, its compressed length, then the compressed rows.
    private static byte[] Chunks(ReadOnlySpan<byte> data, int width, int height, int bpp, long maxBytes, Func<byte[], long, byte[]> expand)
    {
        int row = width * bpp;
        var tight = new byte[(long)row * height];
        int at = 0, rows = 0;
        while (rows < height)
        {
            if (data.Length - at < 20 || !data[at..].StartsWith("KCBC"u8)) throw new InvalidDataException($"no KCBC chunk at offset {at:N0}");
            int count = (int)Math.Min(BinaryPrimitives.ReadUInt32LittleEndian(data[(at + 12)..]), int.MaxValue);
            long length = BinaryPrimitives.ReadUInt32LittleEndian(data[(at + 16)..]);
            if (count <= 0 || count > height - rows) throw new InvalidDataException($"a KCBC chunk of {count:N0} rows at row {rows:N0} of {height:N0}");
            if (length > data.Length - at - 20) throw new InvalidDataException($"a KCBC chunk of {length:N0} bytes runs past the payload");
            var decoded = expand(data.Slice(at + 20, (int)length).ToArray(), maxBytes);
            if (decoded.Length % count != 0 || decoded.Length / count < row) throw new InvalidDataException($"a KCBC chunk expands to {decoded.Length:N0} bytes for {count:N0} rows");
            int stride = decoded.Length / count;
            for (int y = 0; y < count; y++) decoded.AsSpan(y * stride, row).CopyTo(tight.AsSpan((rows + y) * row));
            rows += count;
            at += 20 + (int)length;
        }
        if (at != data.Length) throw new InvalidDataException($"{data.Length - at:N0} bytes after the last KCBC chunk");
        return tight;
    }

    private static byte[] Gzip(ReadOnlySpan<byte> data, long maxBytes) => Gzip(data.ToArray(), maxBytes);

    private static byte[] Gzip(byte[] data, long maxBytes)
    {
        using var z = new GZipStream(new MemoryStream(data, writable: false), CompressionMode.Decompress);
        return Blob.ReadBounded(z, maxBytes) ?? throw new InvalidDataException($"zip data expands past {maxBytes:N0} bytes");
    }

    /// <summary>A whole LZFSE stream, sized by its block headers; more than <paramref name="maxBytes"/> is refused.</summary>
    internal static byte[] Lzfse(ReadOnlySpan<byte> data, long maxBytes)
    {
        long size = Firmware.Lzfse.DecodedSize(data) ?? throw new InvalidDataException("damaged LZFSE block headers");
        if (size > maxBytes || size > Array.MaxLength) throw new InvalidDataException($"LZFSE data of {size:N0} bytes exceeds {maxBytes:N0}");
        var buffer = new byte[size];
        if (Firmware.Lzfse.Decode(data, buffer) != size) throw new InvalidDataException("LZFSE data does not decode to its declared size");
        return buffer;
    }
}

/// <summary>Deepmap-2 bitmaps (undocumented CoreUI format) decoded to their stored pixels, rows top to bottom.</summary>
internal static class Deepmap2
{
    private const int Raw = 1, Default = 2, Lossless = 3, Palette = 4;

    private readonly record struct Layout(int Components, bool Alpha)
    {
        public int Residuals => Alpha ? Components - 1 : Components;
    }

    public static byte[] Decode(ReadOnlySpan<byte> data, int width, int height, int format, long maxBytes)
    {
        var (f, w, h, pixels) = data.StartsWith("KCBC"u8) ? Chunks(data, maxBytes) : Blob(data, maxBytes);
        if (f != format) throw new InvalidDataException($"deepmap-2 pixel format {f} for a {(format == 4 ? "ARGB" : "GA8")} rendition");
        if (w != width || h != height) throw new InvalidDataException($"a {w}x{h} deepmap-2 bitmap for a {width}x{height} rendition");
        return pixels;
    }

    private static Layout LayoutOf(int format) => format switch
    {
        1 => new(1, false),
        2 => new(2, true),
        3 => new(3, false),
        4 => new(4, true),
        _ => throw new NotSupportedException($"deepmap-2 pixel format {format}"),
    };

    private static (int Format, int Width, int Height, byte[] Pixels) Chunks(ReadOnlySpan<byte> data, long maxBytes)
    {
        int format = 0, width = 0, height = 0;
        var pixels = new List<byte[]>();
        for (int at = 0; at < data.Length;)
        {
            if (data.Length - at < 20 || !data[at..].StartsWith("KCBC"u8)) throw new InvalidDataException($"no KCBC chunk at offset {at:N0}");
            long rows = BinaryPrimitives.ReadUInt32LittleEndian(data[(at + 12)..]), length = BinaryPrimitives.ReadUInt32LittleEndian(data[(at + 16)..]);
            if (length > data.Length - at - 20) throw new InvalidDataException($"a KCBC chunk of {length:N0} bytes runs past the payload");
            var chunk = Blob(data.Slice(at + 20, (int)length), maxBytes);
            if (chunk.Height != rows) throw new InvalidDataException($"a KCBC chunk of {rows:N0} rows holds {chunk.Height:N0}");
            if (pixels.Count > 0 && (chunk.Width != width || chunk.Format != format)) throw new InvalidDataException("KCBC chunks of different widths or pixel formats");
            (format, width) = (chunk.Format, chunk.Width);
            height += chunk.Height;
            if (height > ushort.MaxValue) throw new InvalidDataException($"a deepmap-2 bitmap of more than {ushort.MaxValue:N0} rows");
            pixels.Add(chunk.Pixels);
            at += 20 + (int)length;
        }
        return (format, width, height, Concat(pixels));
    }

    private static byte[] Concat(List<byte[]> parts)
    {
        if (parts.Count == 1) return parts[0];
        var all = new byte[parts.Sum(p => (long)p.Length)];
        int at = 0;
        foreach (var p in parts)
        {
            p.CopyTo(all, at);
            at += p.Length;
        }
        return all;
    }

    // Container: version, encoding, length, 'dmp2', method, blob version, a byte, pixel format, width, height, data.
    private static (int Format, int Width, int Height, byte[] Pixels) Blob(ReadOnlySpan<byte> src, long maxBytes)
    {
        if (src.Length < 28) throw new InvalidDataException($"a deepmap-2 payload of {src.Length} bytes");
        if (BinaryPrimitives.ReadUInt32LittleEndian(src) != 1) throw new NotSupportedException($"deepmap-2 container version {BinaryPrimitives.ReadUInt32LittleEndian(src)}");
        ulong declared = BinaryPrimitives.ReadUInt64LittleEndian(src[8..]);
        if (declared > (ulong)(src.Length - 16) || declared < 12) throw new InvalidDataException($"a deepmap-2 container of {declared:N0} bytes in {src.Length - 16:N0}");
        src = src[..(16 + (int)declared)];
        if (!src[16..].StartsWith("dmp2"u8)) throw new InvalidDataException("no dmp2 magic");
        int method = src[20], format = src[23], width = BinaryPrimitives.ReadUInt16LittleEndian(src[24..]), height = BinaryPrimitives.ReadUInt16LittleEndian(src[26..]);
        if (src[21] != 1) throw new NotSupportedException($"deepmap-2 blob version {src[21]}");
        var layout = LayoutOf(format);
        if (width == 0 || height == 0) throw new InvalidDataException($"a {width}x{height} deepmap-2 bitmap");
        int bpp = layout.Components;
        long size = (long)width * height * bpp;
        if (size > maxBytes) throw new InvalidDataException($"a {width}x{height} deepmap-2 bitmap exceeds the {maxBytes:N0}-byte item limit");
        if (method == Raw)
        {
            if (src.Length - 28 != size) throw new InvalidDataException($"raw deepmap-2 data of {src.Length - 28:N0} bytes for {size:N0}");
            return (format, width, height, src[28..].ToArray());
        }
        if (src.Length < 32) throw new InvalidDataException($"deepmap-2 method {method} without its descriptor");
        uint descriptor = BinaryPrimitives.ReadUInt32LittleEndian(src[28..]);
        var payload = src[32..];
        switch (method)
        {
            case Default:
            {
                var pixels = new List<byte[]>();
                int rows = 0;
                // Each segment is a whole number of rows; its alignment to 16 bytes is cut.
                foreach (var decoded in Segments(payload, descriptor, ((PerRow(width, layout) * height) + 15) & ~15, shrink: false, maxBytes))
                {
                    int count = decoded.Length / PerRow(width, layout);
                    if (count == 0 || decoded.Length - count * PerRow(width, layout) >= 16) throw new InvalidDataException($"a default segment of {decoded.Length:N0} bytes is no whole number of rows");
                    pixels.Add(DefaultRows(decoded, width, count, layout));
                    rows += count;
                }
                return (format, width, rows, Concat(pixels));
            }
            case Lossless:
            {
                var pixels = Concat(Segments(payload, descriptor, (int)size, shrink: true, maxBytes));
                int row = width * bpp;
                if (pixels.Length == 0 || pixels.Length % row != 0) throw new InvalidDataException($"lossless data of {pixels.Length:N0} bytes is no whole number of {row}-byte rows");
                return (format, width, pixels.Length / row, pixels);
            }
            case Palette:
                return (format, width, height, PaletteImage(payload, descriptor, width, height, layout));
            default:
                throw new NotSupportedException($"deepmap-2 method {method}");
        }
    }

    // Default segment bytes per row: alpha, the predictor byte, and two bytes per residual component.
    private static int PerRow(int width, Layout layout) => (layout.Alpha ? width : 0) + 1 + 2 * layout.Residuals * width;

    /// <summary>The decoded segments; an LZVN segment, having no size, decodes into at most <paramref name="expected"/> bytes.</summary>
    private static List<byte[]> Segments(ReadOnlySpan<byte> src, uint first, int expected, bool shrink, long maxBytes)
    {
        var segments = new List<byte[]>();
        long length = first, produced = 0;
        while (true)
        {
            if (length == 0 || length > src.Length) throw new InvalidDataException($"segment {segments.Count} of {length:N0} bytes in {src.Length:N0}");
            if (produced >= maxBytes) throw new InvalidDataException($"deepmap-2 segments expand past {maxBytes:N0} bytes");
            var encoded = src[..(int)length];
            byte[] decoded;
            if (Firmware.Lzfse.Looks(encoded)) decoded = AssetCatalogBitmap.Lzfse(encoded, maxBytes - produced);
            else
            {
                var buffer = new byte[shrink ? expected - (int)Math.Min(produced, expected) : expected];
                decoded = buffer.AsSpan(0, Firmware.Lzfse.DecodeLzvn(encoded, buffer)).ToArray();
            }
            segments.Add(decoded);
            produced += decoded.Length;
            src = src[(int)length..];
            if (src.IsEmpty) return segments;
            if (src.Length < 4) throw new InvalidDataException("a segment length is cut short");
            length = BinaryPrimitives.ReadUInt32LittleEndian(src);
            src = src[4..];
        }
    }

    // Planes: alpha, row predictors, residual high and low bytes (low bit the sign); inverse YCoCg-R gives BGRA.
    private static byte[] DefaultRows(byte[] src, int width, int height, Layout layout)
    {
        int n = width * height, residuals = layout.Residuals, alphaBytes = layout.Alpha ? n : 0;
        var alpha = src.AsSpan(0, alphaBytes);
        var predictors = src.AsSpan(alphaBytes, height);
        var high = src.AsSpan(alphaBytes + height, residuals * n);
        var low = src.AsSpan(alphaBytes + height + residuals * n, residuals * n);
        var previous = new short[width * 3];
        var current = new short[width * 3];
        int bpp = layout.Components;
        var pixels = new byte[n * bpp];
        for (int y = 0; y < height; y++)
        {
            Array.Clear(current);
            for (int x = 0; x < width; x++)
                for (int c = 0; c < residuals; c++)
                {
                    int i = (y * width + x) * residuals + c;
                    int encoded = low[i] | high[i] << 8, value = encoded >> 1;
                    current[x * 3 + c] = unchecked((short)((encoded & 1) != 0 ? -value : value));
                }
            Unpredict(current, previous, predictors[y]);
            for (int x = 0; x < width; x++)
            {
                int s = x * 3, d = (y * width + x) * bpp;
                if (residuals == 1)
                {
                    pixels[d] = unchecked((byte)current[s]);
                    if (layout.Alpha) pixels[d + 1] = alpha[y * width + x];
                    continue;
                }
                short luma = current[s], co = unchecked((short)(current[s + 1] << 1)), cg = unchecked((short)(current[s + 2] << 1));
                short t = unchecked((short)(luma - cg / 2));
                short second = unchecked((short)(t + cg)), third = unchecked((short)(t - co / 2)), first = unchecked((short)(third + co));
                pixels[d] = unchecked((byte)first);
                pixels[d + 1] = unchecked((byte)second);
                pixels[d + 2] = unchecked((byte)third);
                if (layout.Alpha) pixels[d + 3] = alpha[y * width + x];
            }
            (previous, current) = (current, previous);
        }
        return pixels;
    }

    // Predictors: 0 none, 1 up when the luma changes more along the row above than down the column, else left, 2 left, 3 up, 4 the mean of left and up.
    private static void Unpredict(short[] row, short[] up, byte predictor)
    {
        static short Add(short a, int b) => unchecked((short)(a + b));
        switch (predictor)
        {
            case 1:
                for (int c = 0; c < 3; c++) row[c] = Add(row[c], up[c]);
                for (int i = 3; i < row.Length; i += 3)
                {
                    bool fromUp = Math.Abs(up[i] - up[i - 3]) > Math.Abs(row[i - 3] - up[i - 3]);
                    for (int c = 0; c < 3; c++) row[i + c] = Add(row[i + c], fromUp ? up[i + c] : row[i - 3 + c]);
                }
                break;
            case 2:
                for (int i = 3; i < row.Length; i++) row[i] = Add(row[i], row[i - 3]);
                break;
            case 3:
                for (int i = 0; i < row.Length; i++) row[i] = Add(row[i], up[i]);
                break;
            case 4:
                for (int c = 0; c < 3; c++) row[c] = Add(row[c], up[c]);
                for (int i = 3; i < row.Length; i++)
                {
                    int sum = row[i - 3] + up[i] + 1;
                    // An arithmetic shift rounds a negative sum toward zero after this correction.
                    if (sum < 0) sum++;
                    row[i] = Add(row[i], sum >> 1);
                }
                break;
        }
    }

    // Descriptor: palette size low 16 bits, palette components high 16; palette, then other planes and indices.
    private static byte[] PaletteImage(ReadOnlySpan<byte> payload, uint descriptor, int width, int height, Layout layout)
    {
        int count = (int)(descriptor & 0xFFFF), held = (int)(descriptor >> 16), bpp = layout.Components;
        if (count is 0 or > 256 || held == 0 || held > bpp) throw new InvalidDataException($"a palette of {count} entries holding {held} components");
        int paletteBytes = count * bpp;
        if (paletteBytes + 4 > payload.Length) throw new InvalidDataException("the palette runs past the payload");
        long encodedLength = BinaryPrimitives.ReadUInt32LittleEndian(payload[paletteBytes..]);
        if (encodedLength > payload.Length - paletteBytes - 4) throw new InvalidDataException("the palette index stream runs past the payload");
        int n = width * height, separate = bpp - held;
        var planes = new byte[separate * n + n];
        var encoded = payload.Slice(paletteBytes + 4, (int)encodedLength);
        int got = Firmware.Lzfse.Looks(encoded) ? Firmware.Lzfse.Decode(encoded, planes) : Firmware.Lzfse.DecodeLzvn(encoded, planes);
        if (got != planes.Length) throw new InvalidDataException($"palette planes decode to {got:N0} of {planes.Length:N0} bytes");
        var palette = payload[..paletteBytes];
        var pixels = new byte[n * bpp];
        for (int i = 0; i < n; i++)
        {
            int index = planes[separate * n + i];
            if (index >= count) throw new InvalidDataException($"palette index {index} of {count} at pixel {i}");
            palette.Slice(index * bpp, bpp).CopyTo(pixels.AsSpan(i * bpp));
            for (int c = 0; c < separate; c++) pixels[i * bpp + held + c] = planes[c * n + i];
        }
        return pixels;
    }
}
