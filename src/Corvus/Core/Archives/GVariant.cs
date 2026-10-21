using System.Buffers.Binary;
using System.Text;

namespace Corvus.Core.Archives;

/// <summary>
/// GVariant serialized data (the GLib format OSTree and Flatpak write), read by type string: tuples, arrays, dictionary
/// entries, variants, strings and fixed-size numbers, each a slice of the container's bytes. Framing offsets are bounds-checked.
/// </summary>
internal static class GVariant
{
    /// <summary>The complete types of a tuple or dictionary entry type, in order.</summary>
    public static List<string> Members(string type)
    {
        var list = new List<string>();
        for (int at = 1; at < type.Length - 1;)
        {
            int end = End(type, at);
            list.Add(type[at..end]);
            at = end;
        }
        return list;
    }

    /// <summary>The index after the complete type starting at <paramref name="at"/>.</summary>
    private static int End(string type, int at)
    {
        if (type[at] == 'a') return End(type, at + 1);
        if (type[at] is not ('(' or '{')) return at + 1;
        int depth = 0;
        for (int i = at; i < type.Length; i++)
        {
            if (type[i] is '(' or '{') depth++;
            else if (type[i] is ')' or '}' && --depth == 0) return i + 1;
        }
        throw new InvalidDataException($"unbalanced GVariant type {type}");
    }

    public static int Alignment(string type) => type[0] switch
    {
        'y' or 'b' or 's' or 'o' or 'g' => 1,
        'n' or 'q' => 2,
        'i' or 'u' or 'h' => 4,
        'x' or 't' or 'd' or 'v' => 8,
        'a' => Alignment(type[1..]),
        '(' or '{' => Members(type).Select(Alignment).DefaultIfEmpty(1).Max(),
        _ => throw new InvalidDataException($"unsupported GVariant type {type}"),
    };

    /// <summary>The size of a fixed-size type, or null for a variable-size one.</summary>
    public static int? FixedSize(string type)
    {
        switch (type[0])
        {
            case 'y' or 'b': return 1;
            case 'n' or 'q': return 2;
            case 'i' or 'u' or 'h': return 4;
            case 'x' or 't' or 'd': return 8;
            case '(' or '{':
                int size = 0;
                foreach (var m in Members(type))
                {
                    if (FixedSize(m) is not { } s) return null;
                    size = Align(size, Alignment(m)) + s;
                }
                return size == 0 ? 1 : Align(size, Alignment(type));
            default: return null;
        }
    }

    private static int Align(int n, int to) => (n + to - 1) / to * to;

    private static int OffsetSize(int length) => length == 0 ? 0 : length <= 0xFF ? 1 : length <= 0xFFFF ? 2 : 4;

    private static int Offset(ReadOnlySpan<byte> b, int at, int size)
    {
        if (at < 0 || at + size > b.Length) throw new InvalidDataException("a GVariant framing offset lies outside its container");
        long v = size switch { 1 => b[at], 2 => BinaryPrimitives.ReadUInt16LittleEndian(b[at..]), _ => BinaryPrimitives.ReadUInt32LittleEndian(b[at..]) };
        if (v > b.Length) throw new InvalidDataException("a GVariant framing offset points past its container");
        return (int)v;
    }

    /// <summary>The members of a tuple or dictionary entry of <paramref name="type"/>.</summary>
    public static List<ReadOnlyMemory<byte>> Tuple(string type, ReadOnlyMemory<byte> data)
    {
        var members = Members(type);
        var span = data.Span;
        int size = OffsetSize(data.Length), framed = 0, at = 0;
        var result = new List<ReadOnlyMemory<byte>>(members.Count);
        for (int i = 0; i < members.Count; i++)
        {
            at = Align(at, Alignment(members[i]));
            int end;
            if (FixedSize(members[i]) is { } fixedSize) end = at + fixedSize;
            else if (i == members.Count - 1) end = data.Length - framed * size;
            else end = Offset(span, data.Length - ++framed * size, size);
            if (at > end || end > data.Length) throw new InvalidDataException($"a member of a GVariant {type} lies outside it");
            result.Add(data[at..end]);
            at = end;
        }
        return result;
    }

    /// <summary>The elements of an array of <paramref name="element"/>.</summary>
    public static List<ReadOnlyMemory<byte>> Array(string element, ReadOnlyMemory<byte> data)
    {
        var result = new List<ReadOnlyMemory<byte>>();
        if (data.Length == 0) return result;
        if (FixedSize(element) is { } fixedSize)
        {
            for (int at = 0; at + fixedSize <= data.Length; at += fixedSize) result.Add(data.Slice(at, fixedSize));
            return result;
        }
        var span = data.Span;
        int size = OffsetSize(data.Length), table = Offset(span, data.Length - size, size), start = 0, alignment = Alignment(element);
        if (table > data.Length - size) throw new InvalidDataException("a GVariant array's offset table lies outside it");
        for (int at = table; at + size <= data.Length; at += size)
        {
            int end = Offset(span, at, size);
            if (start > end || end > table) throw new InvalidDataException("a GVariant array element lies outside it");
            result.Add(data[start..end]);
            start = Align(end, alignment);
        }
        return result;
    }

    /// <summary>A variant: its value's type and bytes.</summary>
    public static (string Type, ReadOnlyMemory<byte> Value) Variant(ReadOnlyMemory<byte> data)
    {
        int nul = data.Span.LastIndexOf((byte)0);
        if (nul < 0) throw new InvalidDataException("a GVariant variant has no type");
        return (Encoding.ASCII.GetString(data.Span[(nul + 1)..]), data[..nul]);
    }

    public static string String(ReadOnlyMemory<byte> data) =>
        data.Length == 0 ? "" : Encoding.UTF8.GetString(data.Span[..^1]);

    public static uint U32(ReadOnlyMemory<byte> data) => data.Length < 4 ? 0 : BinaryPrimitives.ReadUInt32LittleEndian(data.Span);

    public static ulong U64(ReadOnlyMemory<byte> data) => data.Length < 8 ? 0 : BinaryPrimitives.ReadUInt64LittleEndian(data.Span);

    /// <summary>An a{sv} dictionary: each key with its variant's type and value.</summary>
    public static Dictionary<string, (string Type, ReadOnlyMemory<byte> Value)> Dictionary(ReadOnlyMemory<byte> data)
    {
        var result = new Dictionary<string, (string, ReadOnlyMemory<byte>)>(StringComparer.Ordinal);
        foreach (var entry in Array("{sv}", data))
        {
            var kv = Tuple("{sv}", entry);
            result[String(kv[0])] = Variant(kv[1]);
        }
        return result;
    }
}
