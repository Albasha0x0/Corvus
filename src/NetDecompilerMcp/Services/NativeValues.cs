using System.Buffers.Binary;
using System.Globalization;
using System.Text;
using NetDecompilerMcp.Native;

namespace NetDecompilerMcp.Services;

/// <summary>
/// Values of C-typed items read from a native image's mapped bytes: integers (sign from the type's spelling), floats,
/// pointers with the name of their target, characters and strings, enums by enumerator, bit fields; other types as their
/// leading bytes. Shared by get_native_type read=true and read_bytes type=.
/// </summary>
public static class NativeValues
{
    /// <summary>Most array elements a value lists.</summary>
    public const int MaxElements = 16;
    /// <summary>Most characters a string value shows.</summary>
    public const int MaxChars = 256;

    /// <summary>How a type reads: kind (int, uint, float, bool, char, wchar, pointer, string, string16, other) and width.</summary>
    public readonly record struct Scalar(string Kind, int Size);

    private static readonly Dictionary<string, Scalar> Named = new(StringComparer.Ordinal)
    {
        ["u8"] = new("uint", 1), ["i8"] = new("int", 1), ["u16"] = new("uint", 2), ["i16"] = new("int", 2), ["u32"] = new("uint", 4), ["i32"] = new("int", 4),
        ["u64"] = new("uint", 8), ["i64"] = new("int", 8), ["f32"] = new("float", 4), ["f64"] = new("float", 8),
        ["byte"] = new("uint", 1), ["word"] = new("uint", 2), ["dword"] = new("uint", 4), ["qword"] = new("uint", 8),
        ["BYTE"] = new("uint", 1), ["WORD"] = new("uint", 2), ["DWORD"] = new("uint", 4), ["QWORD"] = new("uint", 8), ["UINT"] = new("uint", 4),
        ["ULONG"] = new("uint", 4), ["USHORT"] = new("uint", 2), ["UCHAR"] = new("uint", 1), ["ULONGLONG"] = new("uint", 8), ["LONG"] = new("int", 4),
        ["INT"] = new("int", 4), ["SHORT"] = new("int", 2), ["LONGLONG"] = new("int", 8), ["BOOL"] = new("int", 4), ["BOOLEAN"] = new("uint", 1),
        ["char"] = new("char", 1), ["signed char"] = new("int", 1), ["unsigned char"] = new("uint", 1), ["CHAR"] = new("char", 1),
        ["wchar_t"] = new("wchar", 2), ["char16_t"] = new("wchar", 2), ["WCHAR"] = new("wchar", 2), ["char8_t"] = new("char", 1),
        ["short"] = new("int", 2), ["unsigned short"] = new("uint", 2), ["int"] = new("int", 4), ["unsigned int"] = new("uint", 4), ["unsigned"] = new("uint", 4),
        ["long"] = new("int", 4), ["unsigned long"] = new("uint", 4), ["long long"] = new("int", 8), ["unsigned long long"] = new("uint", 8),
        ["__int8"] = new("int", 1), ["__int16"] = new("int", 2), ["__int32"] = new("int", 4), ["__int64"] = new("int", 8),
        ["unsigned __int8"] = new("uint", 1), ["unsigned __int16"] = new("uint", 2), ["unsigned __int32"] = new("uint", 4), ["unsigned __int64"] = new("uint", 8),
        ["_BYTE"] = new("uint", 1), ["_WORD"] = new("uint", 2), ["_DWORD"] = new("uint", 4), ["_QWORD"] = new("uint", 8),
        ["int8_t"] = new("int", 1), ["int16_t"] = new("int", 2), ["int32_t"] = new("int", 4), ["int64_t"] = new("int", 8),
        ["uint8_t"] = new("uint", 1), ["uint16_t"] = new("uint", 2), ["uint32_t"] = new("uint", 4), ["uint64_t"] = new("uint", 8),
        ["float"] = new("float", 4), ["double"] = new("float", 8), ["long double"] = new("float", 8), ["f4"] = new("float", 4), ["f8"] = new("float", 8),
        ["bool"] = new("bool", 1), ["_Bool"] = new("bool", 1),
        ["string"] = new("string", 1), ["string16"] = new("string16", 2),
    };

    /// <summary>
    /// How <paramref name="type"/> reads, or null for an aggregate or unknown name. Pointers (ptr, T *) take <paramref name="pointerSize"/>;
    /// size_t / intptr_t like types too.
    /// </summary>
    public static Scalar? Classify(string type, int pointerSize)
    {
        var t = Normalize(type);
        if (t == "ptr" || t.EndsWith('*') || t.Contains("*)", StringComparison.Ordinal)) return new("pointer", pointerSize);
        if (t is "size_t" or "uintptr_t" or "ULONG_PTR" or "SIZE_T" or "DWORD_PTR" or "UINT_PTR") return new("uint", pointerSize);
        if (t is "ssize_t" or "intptr_t" or "ptrdiff_t" or "LONG_PTR" or "INT_PTR") return new("int", pointerSize);
        return Named.TryGetValue(t, out var s) ? s : null;
    }

    /// <summary>Drops const / volatile and struct / enum keywords and folds white space.</summary>
    private static string Normalize(string type)
    {
        var words = type.Replace("*", " * ", StringComparison.Ordinal).Split(' ', StringSplitOptions.RemoveEmptyEntries)
            .Where(w => w is not ("const" or "volatile" or "struct" or "class" or "union" or "enum")).ToList();
        return string.Join(' ', words).Replace(" *", "*", StringComparison.Ordinal).Trim();
    }

    /// <summary>"T[n]" as (T, n), else null.</summary>
    public static (string Element, long Count)? ArrayOf(string type)
    {
        var t = type.Trim();
        if (!t.EndsWith(']')) return null;
        int open = t.LastIndexOf('[');
        return open > 0 && long.TryParse(t[(open + 1)..^1], NumberStyles.None, CultureInfo.InvariantCulture, out var n) && n > 0 ? (t[..open].Trim(), n) : null;
    }

    /// <summary>
    /// The value of <paramref name="size"/> bytes at <paramref name="rva"/> read as <paramref name="type"/>; null for
    /// unknown sizes. A bit field reads its bits from the storage unit; <paramref name="enumerators"/> name an enum's value;
    /// <paramref name="nameAt"/> names pointer targets.
    /// </summary>
    public static string? Read(INativeImage image, uint rva, long size, string type, Func<uint, string?>? nameAt = null,
        IReadOnlyList<NativeTypeEnumerator>? enumerators = null, int? bitOffset = null, int? bitSize = null)
    {
        if (size <= 0 || size > 1 << 20) return null;
        var bytes = new byte[size];
        if (image.Read(rva, bytes) < size) return "(not mapped)";
        int pointer = image.Is64Bit ? 8 : 4;
        if (bitSize is { } bits && size <= 8)
        {
            ulong unit = Unsigned(bytes, (int)size);
            ulong field = (unit >> (bitOffset ?? 0)) & (bits >= 64 ? ulong.MaxValue : (1UL << bits) - 1);
            return Number(field, false, bits);
        }
        if (enumerators is { Count: > 0 } && size <= 8) return Enum(Unsigned(bytes, (int)size), (int)size, enumerators);
        if (Classify(type, pointer) is { } scalar && scalar.Kind is not ("string" or "string16") && scalar.Size == size)
            return Format(image, bytes, scalar, nameAt);
        if (ArrayOf(type) is { } array && size % array.Count == 0)
        {
            int width = (int)(size / array.Count);
            var element = Classify(array.Element, pointer);
            if (element is { Kind: "char", Size: 1 } && width == 1) return Quote(Encoding.Latin1.GetString(bytes, 0, Terminated(bytes, 1)));
            if (element is { Kind: "wchar", Size: 2 } && width == 2) return Quote(Encoding.Unicode.GetString(bytes, 0, Terminated(bytes, 2) * 2));
            if (element is { } e && e.Size == width)
            {
                var items = Enumerable.Range(0, (int)Math.Min(array.Count, MaxElements)).Select(i => Format(image, bytes.AsSpan(i * width, width).ToArray(), e, nameAt, brief: true));
                return "{" + string.Join(", ", items) + (array.Count > MaxElements ? $", ... {array.Count - MaxElements} more" : "") + "}";
            }
        }
        return Bytes(bytes);
    }

    /// <summary>A string at <paramref name="rva"/> (C or UTF-16) up to its terminator, at most <see cref="MaxChars"/> characters.</summary>
    public static string? ReadString(INativeImage image, uint rva, bool wide)
    {
        int width = wide ? 2 : 1;
        var bytes = new byte[MaxChars * width];
        int read = image.Read(rva, bytes);
        if (read < width) return null;
        var span = bytes.AsSpan(0, read - read % width).ToArray();
        int chars = Terminated(span, width);
        var text = wide ? Encoding.Unicode.GetString(span, 0, chars * 2) : Encoding.UTF8.GetString(span, 0, chars);
        return Quote(text) + (chars * width >= span.Length ? " ..." : "");
    }

    /// <summary>Formats one scalar item of <paramref name="scalar"/>'s width; <paramref name="brief"/> leaves out the hex beside integers.</summary>
    public static string Format(INativeImage image, byte[] bytes, Scalar scalar, Func<uint, string?>? nameAt, bool brief = false)
    {
        switch (scalar.Kind)
        {
            case "float":
                return scalar.Size == 4 ? BinaryPrimitives.ReadSingleLittleEndian(bytes).ToString("R", CultureInfo.InvariantCulture)
                    : BinaryPrimitives.ReadDoubleLittleEndian(bytes).ToString("R", CultureInfo.InvariantCulture);
            case "bool":
                return bytes[0] switch { 0 => "false", 1 => "true", var b => $"true (0x{b:X2})" };
            case "char":
                return bytes[0] is >= 0x20 and < 0x7F ? $"'{(char)bytes[0]}' ({bytes[0]})" : Number(bytes[0], false, 8);
            case "wchar":
                var c = BinaryPrimitives.ReadUInt16LittleEndian(bytes);
                return c is >= 0x20 and < 0xD800 ? $"'{(char)c}' ({c})" : Number(c, false, 16);
            case "pointer":
                ulong p = Unsigned(bytes, scalar.Size);
                if (p == 0) return "null";
                var va = $"0x{p:X}";
                if (p < image.ImageBase || p - image.ImageBase >= image.SizeOfImage) return va;
                var target = (uint)(p - image.ImageBase);
                return nameAt?.Invoke(target) is { } name ? $"{va} ({name})" : va;
            default:
                return Number(Unsigned(bytes, scalar.Size), scalar.Kind == "int", scalar.Size * 8, brief);
        }
    }

    private static ulong Unsigned(byte[] bytes, int size)
    {
        ulong v = 0;
        for (int i = Math.Min(size, 8) - 1; i >= 0; i--) v = v << 8 | bytes[i];
        return v;
    }

    /// <summary>Decimal (sign-extended from <paramref name="bits"/> when signed) with hex beside values above 9.</summary>
    private static string Number(ulong raw, bool signed, int bits, bool brief = false)
    {
        if (signed && bits < 64 && (raw >> (bits - 1) & 1) == 1) raw |= ulong.MaxValue << bits;
        var dec = signed ? ((long)raw).ToString(CultureInfo.InvariantCulture) : raw.ToString(CultureInfo.InvariantCulture);
        ulong hex = bits >= 64 ? raw : raw & ((1UL << bits) - 1);
        return hex > 9 && !brief ? $"{dec} (0x{hex:X})" : dec;
    }

    /// <summary>An enumerator's name, a flags combination A | B, or the number.</summary>
    private static string Enum(ulong raw, int size, IReadOnlyList<NativeTypeEnumerator> enumerators)
    {
        ulong mask = size >= 8 ? ulong.MaxValue : (1UL << size * 8) - 1;
        var number = Number(raw & mask, false, size * 8);
        if (enumerators.FirstOrDefault(e => ((ulong)e.Value & mask) == (raw & mask)) is { } exact) return $"{exact.Name} ({number})";
        var flags = enumerators.Where(e => e.Value > 0 && ulong.IsPow2((ulong)e.Value) && (raw & (ulong)e.Value) == (ulong)e.Value).ToList();
        ulong covered = flags.Aggregate(0UL, (a, e) => a | (ulong)e.Value);
        return flags.Count > 0 && covered == (raw & mask) ? $"{string.Join(" | ", flags.Select(f => f.Name))} ({number})" : number;
    }

    private static int Terminated(byte[] bytes, int width)
    {
        for (int i = 0; i + width <= bytes.Length; i += width)
            if (width == 1 ? bytes[i] == 0 : bytes[i] == 0 && bytes[i + 1] == 0) return i / width;
        return bytes.Length / width;
    }

    private static string Quote(string s)
    {
        var sb = new StringBuilder("\"");
        foreach (var ch in s.Length > MaxChars ? s[..MaxChars] : s)
            sb.Append(ch switch { '"' => "\\\"", '\\' => "\\\\", '\n' => "\\n", '\r' => "\\r", '\t' => "\\t", < ' ' => $"\\x{(int)ch:X2}", _ => ch.ToString() });
        return sb.Append('"').ToString();
    }

    private static string Bytes(byte[] bytes) =>
        string.Join(' ', bytes.Take(MaxElements).Select(b => b.ToString("X2", CultureInfo.InvariantCulture))) + (bytes.Length > MaxElements ? " ..." : "");
}
