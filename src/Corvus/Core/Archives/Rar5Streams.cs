using System.Text;

namespace Corvus.Core.Archives;

/// <summary>The NTFS stream service records (STM) of a RAR 5 archive, read from its block headers.</summary>
internal static class Rar5Streams
{
    private const int MaxBlocks = 100_000;
    private const int MaxHeader = 1 << 20;

    /// <summary>The stream records as file:stream names; empty for other formats, or at the first damaged block.</summary>
    public static List<string> Names(Stream s)
    {
        var names = new List<string>();
        Span<byte> sig = stackalloc byte[8];
        s.Position = 0;
        if (s.ReadAtLeast(sig, 8, throwOnEndOfStream: false) < 8 || !sig.SequenceEqual("Rar!\x1A\x07\x01\x00"u8)) return names;
        string file = "";
        for (int block = 0; block < MaxBlocks && s.Position + 4 < s.Length; block++)
        {
            s.Position += 4;
            if (Vint(s) is not { } size || size is 0 or > MaxHeader) break;
            var header = new byte[size];
            if (s.ReadAtLeast(header, header.Length, throwOnEndOfStream: false) < header.Length) break;
            int p = 0;
            if (Vint(header, ref p) is not { } type || Vint(header, ref p) is not { } flags) break;
            long extra = 0, data = 0;
            if ((flags & 1) != 0 && Vint(header, ref p) is { } e) extra = (long)Math.Min(e, int.MaxValue);
            if ((flags & 2) != 0 && Vint(header, ref p) is { } d) data = (long)Math.Min(d, long.MaxValue / 2);
            if (type is 2 or 3)
            {
                // File flags, unpacked size, attributes, then the optional time and checksum.
                if (Vint(header, ref p) is not { } fileFlags || Vint(header, ref p) is null || Vint(header, ref p) is null) break;
                if ((fileFlags & 2) != 0) p += 4;
                if ((fileFlags & 4) != 0) p += 4;
                if (Vint(header, ref p) is null || Vint(header, ref p) is null || Vint(header, ref p) is not { } nameLength) break;
                if (p < 0 || nameLength > (ulong)(header.Length - p)) break;
                var name = Encoding.UTF8.GetString(header, p, (int)nameLength);
                if (type == 2) file = name;
                else if (name == "STM" && StreamName(header, (int)Math.Max(0, header.Length - extra)) is { } stream) names.Add(file + stream);
            }
            if (type == 5) break;
            s.Position += data;
        }
        return names;
    }

    /// <summary>The service data record (type 7) of an extra area: the stream name.</summary>
    private static string? StreamName(byte[] header, int start)
    {
        for (int p = start; p < header.Length;)
        {
            if (Vint(header, ref p) is not { } size) return null;
            int record = p;
            if (Vint(header, ref p) is not { } type || size > (ulong)(header.Length - record)) return null;
            int end = record + (int)size;
            if (type == 7 && p <= end) return Encoding.UTF8.GetString(header, p, end - p);
            p = end;
        }
        return null;
    }

    private static ulong? Vint(byte[] b, ref int p)
    {
        ulong v = 0;
        for (int shift = 0; shift < 64 && p < b.Length; shift += 7)
        {
            byte x = b[p++];
            v |= (ulong)(x & 0x7F) << shift;
            if ((x & 0x80) == 0) return v;
        }
        return null;
    }

    private static ulong? Vint(Stream s)
    {
        ulong v = 0;
        for (int shift = 0; shift < 64; shift += 7)
        {
            int x = s.ReadByte();
            if (x < 0) return null;
            v |= (ulong)(x & 0x7F) << shift;
            if ((x & 0x80) == 0) return v;
        }
        return null;
    }
}
