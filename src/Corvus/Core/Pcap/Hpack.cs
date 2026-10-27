using System.Text;

namespace Corvus.Core.Pcap;

/// <summary>An HPACK decoder (RFC 7541) for one HTTP/2 direction; a malformed block ends its decode without an exception.</summary>
internal sealed class Hpack
{
    private const int MaxHeaders = 200, MaxString = 64 * 1024;

    private readonly LinkedList<(string Name, string Value)> _dynamic = new();
    private int _size, _max = 4096;

    /// <summary>The headers of the complete representations in <paramref name="b"/>; null when one is malformed, as the table state is then unknown.</summary>
    /// <remarks><paramref name="consumed"/> stops before a representation the fragment's end cuts.</remarks>
    public List<(string Name, string Value)>? Decode(ReadOnlySpan<byte> b, out int consumed)
    {
        var headers = new List<(string, string)>();
        consumed = 0;
        int at = 0;
        while (at < b.Length && headers.Count < MaxHeaders)
        {
            byte first = b[at];
            if ((first & 0x80) != 0)
            {
                if (!Integer(b, ref at, 7, out var index)) return headers;
                if (Entry(index) is not { } e) return null;
                headers.Add(e);
            }
            else if ((first & 0xE0) == 0x20)
            {
                if (!Integer(b, ref at, 5, out var size)) return headers;
                if (size > 1 << 20) return null;
                _max = (int)size;
                Evict(0);
            }
            else
            {
                bool incremental = (first & 0xC0) == 0x40;
                if (!Integer(b, ref at, incremental ? 6 : 4, out var index)) return headers;
                string? name = null;
                if (index != 0 && (name = Entry(index)?.Name) == null) return null;
                if (index == 0 && String(b, ref at, out name) is var n && n <= 0) return n == 0 ? headers : null;
                if (String(b, ref at, out var value) is var v && v <= 0) return v == 0 ? headers : null;
                headers.Add((name!, value!));
                if (incremental) Add(name!, value!);
            }
            consumed = at;
        }
        return headers;
    }

    private (string Name, string Value)? Entry(ulong index)
    {
        if (index == 0) return null;
        if (index <= (ulong)Static.Length) return Static[index - 1];
        ulong d = index - (ulong)Static.Length - 1;
        if (d >= (ulong)_dynamic.Count) return null;
        var node = _dynamic.First;
        for (ulong i = 0; i < d; i++) node = node!.Next;
        return node!.Value;
    }

    private void Add(string name, string value)
    {
        int size = name.Length + value.Length + 32;
        Evict(size);
        if (size > _max) return;
        _dynamic.AddFirst((name, value));
        _size += size;
    }

    private void Evict(int room)
    {
        while (_dynamic.Count > 0 && _size + room > _max)
        {
            var last = _dynamic.Last!.Value;
            _size -= last.Name.Length + last.Value.Length + 32;
            _dynamic.RemoveLast();
        }
    }

    internal static bool Integer(ReadOnlySpan<byte> b, ref int at, int prefix, out ulong value)
    {
        value = 0;
        if (at >= b.Length) return false;
        ulong max = (1UL << prefix) - 1;
        value = b[at++] & max;
        if (value < max) return true;
        for (int shift = 0; shift <= 56; shift += 7)
        {
            if (at >= b.Length) return false;
            byte next = b[at++];
            value += (ulong)(next & 0x7F) << shift;
            if ((next & 0x80) == 0) return true;
        }
        return false;
    }

    /// <summary>A string literal: 1 read, 0 cut by the end of <paramref name="b"/>, -1 malformed.</summary>
    private static int String(ReadOnlySpan<byte> b, ref int at, out string? s)
    {
        s = null;
        if (at >= b.Length) return 0;
        bool huffman = (b[at] & 0x80) != 0;
        if (!Integer(b, ref at, 7, out var length)) return 0;
        if (length > MaxString) return -1;
        if (length > (ulong)(b.Length - at)) return 0;
        var raw = b.Slice(at, (int)length);
        at += (int)length;
        s = huffman ? Huffman(raw) : Encoding.Latin1.GetString(raw);
        return s == null ? -1 : 1;
    }

    /// <summary>Decodes a Huffman-coded string; padding longer than 7 bits or the EOS symbol make it malformed.</summary>
    internal static string? Huffman(ReadOnlySpan<byte> b)
    {
        var sb = new StringBuilder(b.Length * 8 / 5);
        int node = 0, depth = 0;
        foreach (byte x in b)
            for (int bit = 7; bit >= 0; bit--)
            {
                node = Tree[node * 2 + ((x >> bit) & 1)];
                depth++;
                if (node == 0) return null;
                if (node < 0)
                {
                    int symbol = ~node;
                    if (symbol == 256) return null;
                    sb.Append((char)symbol);
                    node = 0;
                    depth = 0;
                }
            }
        return depth <= 7 ? sb.ToString() : null;
    }

    /// <summary>The decode tree: two children per node; a negative child is ~symbol, 0 is no code. Built after the tables below.</summary>
    private static int[] Tree => _tree ??= BuildTree();
    private static int[]? _tree;

    private static int[] BuildTree()
    {
        var tree = new List<int> { 0, 0 };
        for (int symbol = 0; symbol < Codes.Length; symbol++)
        {
            uint code = Codes[symbol];
            int length = Lengths[symbol], node = 0;
            for (int bit = length - 1; bit >= 0; bit--)
            {
                int slot = node * 2 + (int)((code >> bit) & 1);
                if (bit == 0) { tree[slot] = ~symbol; break; }
                if (tree[slot] <= 0)
                {
                    tree[slot] = tree.Count / 2;
                    tree.Add(0);
                    tree.Add(0);
                }
                node = tree[slot];
            }
        }
        return [.. tree];
    }

    // RFC 7541 Appendix B: the code of each symbol 0–256 (EOS), and its length in bits.
    private static readonly uint[] Codes =
    [
        0x1FF8, 0x7FFFD8, 0xFFFFFE2, 0xFFFFFE3, 0xFFFFFE4, 0xFFFFFE5, 0xFFFFFE6, 0xFFFFFE7, 0xFFFFFE8, 0xFFFFEA, 0x3FFFFFFC, 0xFFFFFE9,
        0xFFFFFEA, 0x3FFFFFFD, 0xFFFFFEB, 0xFFFFFEC, 0xFFFFFED, 0xFFFFFEE, 0xFFFFFEF, 0xFFFFFF0, 0xFFFFFF1, 0xFFFFFF2, 0x3FFFFFFE,
        0xFFFFFF3, 0xFFFFFF4, 0xFFFFFF5, 0xFFFFFF6, 0xFFFFFF7, 0xFFFFFF8, 0xFFFFFF9, 0xFFFFFFA, 0xFFFFFFB, 0x14, 0x3F8, 0x3F9, 0xFFA,
        0x1FF9, 0x15, 0xF8, 0x7FA, 0x3FA, 0x3FB, 0xF9, 0x7FB, 0xFA, 0x16, 0x17, 0x18, 0x0, 0x1, 0x2, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E,
        0x1F, 0x5C, 0xFB, 0x7FFC, 0x20, 0xFFB, 0x3FC, 0x1FFA, 0x21, 0x5D, 0x5E, 0x5F, 0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,
        0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F, 0x70, 0x71, 0x72, 0xFC, 0x73, 0xFD, 0x1FFB, 0x7FFF0, 0x1FFC, 0x3FFC, 0x22, 0x7FFD,
        0x3, 0x23, 0x4, 0x24, 0x5, 0x25, 0x26, 0x27, 0x6, 0x74, 0x75, 0x28, 0x29, 0x2A, 0x7, 0x2B, 0x76, 0x2C, 0x8, 0x9, 0x2D, 0x77, 0x78,
        0x79, 0x7A, 0x7B, 0x7FFE, 0x7FC, 0x3FFD, 0x1FFD, 0xFFFFFFC, 0xFFFE6, 0x3FFFD2, 0xFFFE7, 0xFFFE8, 0x3FFFD3, 0x3FFFD4, 0x3FFFD5,
        0x7FFFD9, 0x3FFFD6, 0x7FFFDA, 0x7FFFDB, 0x7FFFDC, 0x7FFFDD, 0x7FFFDE, 0xFFFFEB, 0x7FFFDF, 0xFFFFEC, 0xFFFFED, 0x3FFFD7, 0x7FFFE0,
        0xFFFFEE, 0x7FFFE1, 0x7FFFE2, 0x7FFFE3, 0x7FFFE4, 0x1FFFDC, 0x3FFFD8, 0x7FFFE5, 0x3FFFD9, 0x7FFFE6, 0x7FFFE7, 0xFFFFEF, 0x3FFFDA,
        0x1FFFDD, 0xFFFE9, 0x3FFFDB, 0x3FFFDC, 0x7FFFE8, 0x7FFFE9, 0x1FFFDE, 0x7FFFEA, 0x3FFFDD, 0x3FFFDE, 0xFFFFF0, 0x1FFFDF, 0x3FFFDF,
        0x7FFFEB, 0x7FFFEC, 0x1FFFE0, 0x1FFFE1, 0x3FFFE0, 0x1FFFE2, 0x7FFFED, 0x3FFFE1, 0x7FFFEE, 0x7FFFEF, 0xFFFEA, 0x3FFFE2, 0x3FFFE3,
        0x3FFFE4, 0x7FFFF0, 0x3FFFE5, 0x3FFFE6, 0x7FFFF1, 0x3FFFFE0, 0x3FFFFE1, 0xFFFEB, 0x7FFF1, 0x3FFFE7, 0x7FFFF2, 0x3FFFE8, 0x1FFFFEC,
        0x3FFFFE2, 0x3FFFFE3, 0x3FFFFE4, 0x7FFFFDE, 0x7FFFFDF, 0x3FFFFE5, 0xFFFFF1, 0x1FFFFED, 0x7FFF2, 0x1FFFE3, 0x3FFFFE6, 0x7FFFFE0,
        0x7FFFFE1, 0x3FFFFE7, 0x7FFFFE2, 0xFFFFF2, 0x1FFFE4, 0x1FFFE5, 0x3FFFFE8, 0x3FFFFE9, 0xFFFFFFD, 0x7FFFFE3, 0x7FFFFE4, 0x7FFFFE5,
        0xFFFEC, 0xFFFFF3, 0xFFFED, 0x1FFFE6, 0x3FFFE9, 0x1FFFE7, 0x1FFFE8, 0x7FFFF3, 0x3FFFEA, 0x3FFFEB, 0x1FFFFEE, 0x1FFFFEF, 0xFFFFF4,
        0xFFFFF5, 0x3FFFFEA, 0x7FFFF4, 0x3FFFFEB, 0x7FFFFE6, 0x3FFFFEC, 0x3FFFFED, 0x7FFFFE7, 0x7FFFFE8, 0x7FFFFE9, 0x7FFFFEA, 0x7FFFFEB,
        0xFFFFFFE, 0x7FFFFEC, 0x7FFFFED, 0x7FFFFEE, 0x7FFFFEF, 0x7FFFFF0, 0x3FFFFEE, 0x3FFFFFFF,
    ];

    private static readonly byte[] Lengths =
    [
        13, 23, 28, 28, 28, 28, 28, 28, 28, 24, 30, 28, 28, 30, 28, 28, 28, 28, 28, 28, 28, 28, 30, 28, 28, 28, 28, 28, 28, 28, 28, 28, 6,
        10, 10, 12, 13, 6, 8, 11, 10, 10, 8, 11, 8, 6, 6, 6, 5, 5, 5, 6, 6, 6, 6, 6, 6, 6, 7, 8, 15, 6, 12, 10, 13, 6, 7, 7, 7, 7, 7, 7,
        7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 8, 7, 8, 13, 19, 13, 14, 6, 15, 5, 6, 5, 6, 5, 6, 6, 6, 5, 7, 7, 6, 6, 6, 5, 6, 7,
        6, 5, 5, 6, 7, 7, 7, 7, 7, 15, 11, 14, 13, 28, 20, 22, 20, 20, 22, 22, 22, 23, 22, 23, 23, 23, 23, 23, 24, 23, 24, 24, 22, 23, 24,
        23, 23, 23, 23, 21, 22, 23, 22, 23, 23, 24, 22, 21, 20, 22, 22, 23, 23, 21, 23, 22, 22, 24, 21, 22, 23, 23, 21, 21, 22, 21, 23,
        22, 23, 23, 20, 22, 22, 22, 23, 22, 22, 23, 26, 26, 20, 19, 22, 23, 22, 25, 26, 26, 26, 27, 27, 26, 24, 25, 19, 21, 26, 27, 27,
        26, 27, 24, 21, 21, 26, 26, 28, 27, 27, 27, 20, 24, 20, 21, 22, 21, 21, 23, 22, 22, 25, 25, 24, 24, 26, 23, 26, 27, 26, 26, 27,
        27, 27, 27, 27, 28, 27, 27, 27, 27, 27, 26, 30,
    ];

    // RFC 7541 Appendix A.
    private static readonly (string Name, string Value)[] Static =
    [
        (":authority", ""), (":method", "GET"), (":method", "POST"), (":path", "/"), (":path", "/index.html"), (":scheme", "http"),
        (":scheme", "https"), (":status", "200"), (":status", "204"), (":status", "206"), (":status", "304"), (":status", "400"),
        (":status", "404"), (":status", "500"), ("accept-charset", ""), ("accept-encoding", "gzip, deflate"), ("accept-language", ""),
        ("accept-ranges", ""), ("accept", ""), ("access-control-allow-origin", ""), ("age", ""), ("allow", ""), ("authorization", ""),
        ("cache-control", ""), ("content-disposition", ""), ("content-encoding", ""), ("content-language", ""), ("content-length", ""),
        ("content-location", ""), ("content-range", ""), ("content-type", ""), ("cookie", ""), ("date", ""), ("etag", ""), ("expect", ""),
        ("expires", ""), ("from", ""), ("host", ""), ("if-match", ""), ("if-modified-since", ""), ("if-none-match", ""), ("if-range", ""),
        ("if-unmodified-since", ""), ("last-modified", ""), ("link", ""), ("location", ""), ("max-forwards", ""), ("proxy-authenticate", ""),
        ("proxy-authorization", ""), ("range", ""), ("referer", ""), ("refresh", ""), ("retry-after", ""), ("server", ""), ("set-cookie", ""),
        ("strict-transport-security", ""), ("transfer-encoding", ""), ("user-agent", ""), ("vary", ""), ("via", ""), ("www-authenticate", ""),
    ];
}
