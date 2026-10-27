using System.IO.Compression;

namespace Corvus.Core.Documents;

/// <summary>PDF stream filters applied in order; an image or crypt filter stops the chain and returns the data as stored.</summary>
internal static class PdfFilters
{
    /// <summary>The decoded bytes and the filters left undone (empty when fully decoded), or an error for damaged data.</summary>
    public static (byte[] Data, string? Stopped) Decode(byte[] data, PdfDict dict, Func<PdfValue?, PdfValue?> resolve, long max)
    {
        var filters = resolve(dict["Filter"] ?? dict["F"]) switch
        {
            PdfName n => [n.Value],
            PdfArray a => a.Items.Select(i => (resolve(i) as PdfName)?.Value ?? "?").ToList(),
            _ => new List<string>(),
        };
        var parms = resolve(dict["DecodeParms"] ?? dict["DP"]) switch
        {
            PdfDict d => [d],
            PdfArray a => a.Items.Select(i => resolve(i) as PdfDict).ToList(),
            _ => new List<PdfDict?>(),
        };
        for (int i = 0; i < filters.Count; i++)
        {
            var p = i < parms.Count ? parms[i] : null;
            byte[]? next = filters[i] switch
            {
                "FlateDecode" or "Fl" => Predict(Inflate(data, max), p, resolve),
                "LZWDecode" or "LZW" => Predict(Lzw(data, Int(resolve(p?["EarlyChange"]), 1) != 0, max), p, resolve),
                "ASCIIHexDecode" or "AHx" => AsciiHex(data),
                "ASCII85Decode" or "A85" => Ascii85(data),
                "RunLengthDecode" or "RL" => RunLength(data, max),
                _ => null,
            };
            if (next == null) return (data, string.Join(", ", filters.Skip(i)));
            data = next;
        }
        return (data, null);
    }

    private static int Int(PdfValue? v, int fallback) => v is PdfNumber n ? (int)n.Value : fallback;

    /// <summary>zlib data, or raw deflate when the zlib header is missing; what decodes before damage is kept.</summary>
    public static byte[] Inflate(byte[] data, long max)
    {
        bool zlib = data.Length >= 2 && (data[0] & 0x0F) == 8 && ((data[0] << 8) | data[1]) % 31 == 0;
        using var input = new MemoryStream(data, zlib ? 2 : 0, data.Length - (zlib ? 2 : 0), writable: false);
        using var inflater = new DeflateStream(input, CompressionMode.Decompress);
        using var output = new MemoryStream();
        var buffer = new byte[65536];
        try
        {
            int n;
            while ((n = inflater.Read(buffer, 0, buffer.Length)) > 0)
            {
                if (output.Length + n > max) throw new ToolError(ErrorCode.LimitExceeded, $"a stream inflates past the {max:N0}-byte item limit.");
                output.Write(buffer, 0, n);
            }
        }
        // A truncated or damaged tail keeps what decoded.
        catch (InvalidDataException) when (output.Length > 0) { }
        return output.ToArray();
    }

    /// <summary>PNG (10-15) and TIFF (2, 8-bit) predictors.</summary>
    private static byte[] Predict(byte[] data, PdfDict? p, Func<PdfValue?, PdfValue?> resolve)
    {
        int predictor = Int(resolve(p?["Predictor"]), 1);
        if (predictor < 2) return data;
        int colors = Math.Clamp(Int(resolve(p?["Colors"]), 1), 1, 32), bits = Math.Clamp(Int(resolve(p?["BitsPerComponent"]), 8), 1, 16);
        int columns = Math.Clamp(Int(resolve(p?["Columns"]), 1), 1, 1 << 20);
        int bpp = Math.Max(1, colors * bits / 8), row = (colors * bits * columns + 7) / 8;
        if (predictor == 2)
        {
            if (bits != 8) return data;
            var t = (byte[])data.Clone();
            for (int r = 0; r * row < t.Length; r++)
                for (int i = r * row + bpp; i < Math.Min((r + 1) * row, t.Length); i++) t[i] += t[i - bpp];
            return t;
        }
        var output = new MemoryStream();
        var prev = new byte[row];
        var cur = new byte[row];
        for (int at = 0; at + 1 <= data.Length; at += row + 1)
        {
            int type = data[at];
            int n = Math.Min(row, data.Length - at - 1);
            if (n <= 0) break;
            Array.Clear(cur);
            data.AsSpan(at + 1, n).CopyTo(cur);
            for (int i = 0; i < row; i++)
            {
                int left = i >= bpp ? cur[i - bpp] : 0, up = prev[i], ul = i >= bpp ? prev[i - bpp] : 0;
                cur[i] = type switch
                {
                    1 => (byte)(cur[i] + left),
                    2 => (byte)(cur[i] + up),
                    3 => (byte)(cur[i] + (left + up) / 2),
                    4 => (byte)(cur[i] + Paeth(left, up, ul)),
                    _ => cur[i],
                };
            }
            output.Write(cur, 0, n);
            (prev, cur) = (cur, prev);
        }
        return output.ToArray();
    }

    private static int Paeth(int a, int b, int c)
    {
        int p = a + b - c, pa = Math.Abs(p - a), pb = Math.Abs(p - b), pc = Math.Abs(p - c);
        return pa <= pb && pa <= pc ? a : pb <= pc ? b : c;
    }

    public static byte[] Lzw(byte[] data, bool earlyChange, long max)
    {
        var output = new MemoryStream();
        var table = new List<byte[]>(4096);
        void Reset()
        {
            table.Clear();
            for (int i = 0; i < 256; i++) table.Add([(byte)i]);
            // Codes 256 (clear) and 257 (end).
            table.Add([]); table.Add([]);
        }
        Reset();
        int width = 9, bitPos = 0;
        byte[]? previous = null;
        long totalBits = data.Length * 8L;
        while (bitPos + width <= totalBits)
        {
            int code = 0;
            for (int k = 0; k < width; k++, bitPos++) code = (code << 1) | ((data[bitPos >> 3] >> (7 - (bitPos & 7))) & 1);
            if (code == 256) { Reset(); width = 9; previous = null; continue; }
            if (code == 257) break;
            byte[] entry;
            if (code < table.Count) entry = table[code];
            else if (code == table.Count && previous != null) entry = [.. previous, previous[0]];
            else break;
            output.Write(entry);
            if (output.Length > max) throw new ToolError(ErrorCode.LimitExceeded, $"a stream decodes past the {max:N0}-byte item limit.");
            if (previous != null && table.Count < 4096) table.Add([.. previous, entry[0]]);
            previous = entry;
            int next = table.Count + (earlyChange ? 1 : 0);
            width = next >= 2048 ? 12 : next >= 1024 ? 11 : next >= 512 ? 10 : 9;
        }
        return output.ToArray();
    }

    public static byte[] AsciiHex(byte[] data)
    {
        var o = new List<byte>(data.Length / 2);
        int high = -1;
        foreach (var c in data)
        {
            if (c == '>') break;
            int d = PdfLexer.HexValue(c);
            if (d < 0) continue;
            if (high < 0) high = d;
            else { o.Add((byte)(high * 16 + d)); high = -1; }
        }
        if (high >= 0) o.Add((byte)(high * 16));
        return [.. o];
    }

    public static byte[] Ascii85(byte[] data)
    {
        var o = new List<byte>(data.Length);
        int start = data.AsSpan().StartsWith("<~"u8) ? 2 : 0;
        Span<int> group = stackalloc int[5];
        int count = 0;
        for (int i = start; i < data.Length; i++)
        {
            byte c = data[i];
            if (c == '~') break;
            if (PdfLexer.IsWhite(c)) continue;
            if (c == 'z' && count == 0) { o.AddRange([0, 0, 0, 0]); continue; }
            if (c < '!' || c > 'u') continue;
            group[count++] = c - '!';
            if (count == 5) { Emit(group, 4); count = 0; }
        }
        if (count > 1)
        {
            for (int k = count; k < 5; k++) group[k] = 84;
            Emit(group, count - 1);
        }
        return [.. o];

        void Emit(Span<int> g, int n)
        {
            long v = 0;
            for (int k = 0; k < 5; k++) v = v * 85 + g[k];
            for (int k = 0; k < n; k++) o.Add((byte)(v >> (24 - 8 * k)));
        }
    }

    public static byte[] RunLength(byte[] data, long max)
    {
        var o = new MemoryStream();
        for (int i = 0; i < data.Length;)
        {
            int len = data[i++];
            if (len == 128) break;
            if (len < 128)
            {
                int n = Math.Min(len + 1, data.Length - i);
                o.Write(data, i, n);
                i += n;
            }
            else if (i < data.Length)
            {
                for (int k = 0; k < 257 - len; k++) o.WriteByte(data[i]);
                i++;
            }
            if (o.Length > max) throw new ToolError(ErrorCode.LimitExceeded, $"a stream decodes past the {max:N0}-byte item limit.");
        }
        return o.ToArray();
    }
}
