using System.Buffers.Binary;
using System.Globalization;
using System.Text;
using NetDecompilerMcp.Native;

namespace NetDecompilerMcp.Core.Mobile;

/// <summary>Chunk types of Android's compiled resource formats (ResourceTypes.h).</summary>
internal static class ResChunk
{
    public const ushort StringPool = 0x0001, Table = 0x0002, Xml = 0x0003;
    public const ushort XmlStartNamespace = 0x0100, XmlEndNamespace = 0x0101, XmlStartElement = 0x0102, XmlEndElement = 0x0103, XmlCData = 0x0104;
    public const ushort XmlResourceMap = 0x0180;
    public const ushort TablePackage = 0x0200, TableType = 0x0201, TableTypeSpec = 0x0202, TableLibrary = 0x0203;
    public const ushort TableOverlayable = 0x0204, TableOverlayablePolicy = 0x0205, TableStagedAlias = 0x0206;

    /// <summary>A chunk header at <paramref name="at"/> that fits in <paramref name="end"/>, or null with an issue.</summary>
    public static (ushort Type, int HeaderSize, int Size)? Header(ReadOnlySpan<byte> data, int at, int end, string area, List<ParseIssue> issues)
    {
        if (at < 0 || at + 8 > end)
        {
            issues.Add(new(area, "truncated chunk header", at));
            return null;
        }
        var type = BinaryPrimitives.ReadUInt16LittleEndian(data[at..]);
        int headerSize = BinaryPrimitives.ReadUInt16LittleEndian(data[(at + 2)..]);
        var size = BinaryPrimitives.ReadUInt32LittleEndian(data[(at + 4)..]);
        if (headerSize < 8 || size < (uint)headerSize || size > (uint)(end - at))
        {
            issues.Add(new(area, $"chunk 0x{type:x4} has header size {headerSize} and size {size}, outside the {end - at} bytes left", at));
            return null;
        }
        return (type, headerSize, (int)size);
    }

    /// <summary>The outermost chunk: a size past the end of a truncated file is clamped (with an issue) so the rest still reads.</summary>
    public static (ushort Type, int HeaderSize, int Size)? Outer(ReadOnlySpan<byte> data, string area, List<ParseIssue> issues)
    {
        if (data.Length < 8) { issues.Add(new(area, "truncated chunk header", 0)); return null; }
        ushort type = U16(data, 0);
        int headerSize = U16(data, 2);
        uint size = U32(data, 4);
        if (size > (uint)data.Length)
        {
            issues.Add(new(area, $"the file is truncated: {data.Length} of {size} bytes", data.Length));
            size = (uint)data.Length;
        }
        if (headerSize < 8 || (uint)headerSize > size)
        {
            issues.Add(new(area, $"chunk 0x{type:x4} has header size {headerSize} and size {size}", 0));
            return null;
        }
        return (type, headerSize, (int)size);
    }

    public static ushort U16(ReadOnlySpan<byte> d, int at) => at >= 0 && at + 2 <= d.Length ? BinaryPrimitives.ReadUInt16LittleEndian(d[at..]) : (ushort)0;
    public static uint U32(ReadOnlySpan<byte> d, int at) => at >= 0 && at + 4 <= d.Length ? BinaryPrimitives.ReadUInt32LittleEndian(d[at..]) : 0;
}

/// <summary>A resource string pool (UTF-8 or UTF-16). Style spans are not kept.</summary>
public sealed class ResStringPool
{
    public static readonly ResStringPool Empty = new([], false);

    private readonly string?[] _strings;

    private ResStringPool(string?[] strings, bool utf8)
    {
        _strings = strings;
        IsUtf8 = utf8;
    }

    public int Count => _strings.Length;
    public bool IsUtf8 { get; }

    /// <summary>The string at <paramref name="index"/>; null for 0xFFFFFFFF (no string), out of range, or undecodable.</summary>
    public string? Get(uint index) => index < (uint)_strings.Length ? _strings[index] : null;

    private const int UTF8Flag = 0x100;

    /// <summary>Reads the pool chunk at <paramref name="at"/> (header already validated to fit).</summary>
    internal static ResStringPool Read(ReadOnlySpan<byte> data, int at, int headerSize, int size, string area, List<ParseIssue> issues)
    {
        var chunk = data.Slice(at, size);
        uint count = ResChunk.U32(chunk, 8);
        uint flags = ResChunk.U32(chunk, 16);
        uint stringsStart = ResChunk.U32(chunk, 20);
        if (headerSize < 28 || count > (uint)(size - headerSize) / 4)
        {
            issues.Add(new(area, $"string pool claims {count} strings in {size} bytes", at));
            return Empty;
        }
        bool utf8 = (flags & UTF8Flag) != 0;
        var strings = new string?[count];
        int bad = 0;
        for (int i = 0; i < count; i++)
        {
            long offset = (long)stringsStart + ResChunk.U32(chunk, headerSize + i * 4);
            strings[i] = offset < size ? Decode(chunk[(int)offset..], utf8) : null;
            if (strings[i] == null) bad++;
        }
        if (bad > 0) issues.Add(new(area, $"{bad} of {count} strings could not be decoded", at));
        return new(strings, utf8);
    }

    private static string? Decode(ReadOnlySpan<byte> s, bool utf8)
    {
        if (utf8)
        {
            // UTF-16 length then UTF-8 length, each 1 or 2 bytes (high bit of the first byte set: 2 bytes).
            int p = 0;
            if (Length8(s, ref p) < 0) return null;
            int bytes = Length8(s, ref p);
            if (bytes < 0 || p + bytes > s.Length) return null;
            return Encoding.UTF8.GetString(s.Slice(p, bytes));
        }
        if (s.Length < 2) return null;
        int chars = BinaryPrimitives.ReadUInt16LittleEndian(s);
        int q = 2;
        if ((chars & 0x8000) != 0)
        {
            if (s.Length < 4) return null;
            chars = ((chars & 0x7FFF) << 16) | BinaryPrimitives.ReadUInt16LittleEndian(s[2..]);
            q = 4;
        }
        if ((long)q + chars * 2L > s.Length) return null;
        return Encoding.Unicode.GetString(s.Slice(q, chars * 2));
    }

    private static int Length8(ReadOnlySpan<byte> s, ref int p)
    {
        if (p >= s.Length) return -1;
        int len = s[p++];
        if ((len & 0x80) != 0)
        {
            if (p >= s.Length) return -1;
            len = ((len & 0x7F) << 8) | s[p++];
        }
        return len;
    }
}

/// <summary>A typed resource value (Res_value): the data type and its 32-bit payload.</summary>
public readonly record struct ResValue(byte DataType, uint Data)
{
    public const byte Null = 0x00, Reference = 0x01, Attribute = 0x02, String = 0x03, Float = 0x04, Dimension = 0x05, Fraction = 0x06;
    public const byte DynamicReference = 0x07, DynamicAttribute = 0x08;
    public const byte IntDec = 0x10, IntHex = 0x11, IntBoolean = 0x12, ColorArgb8 = 0x1c, ColorRgb8 = 0x1d, ColorArgb4 = 0x1e, ColorRgb4 = 0x1f;

    /// <summary>Reads the 8-byte Res_value at <paramref name="at"/>; null when it does not fit.</summary>
    internal static ResValue? Read(ReadOnlySpan<byte> d, int at) =>
        at >= 0 && at + 8 <= d.Length ? new ResValue(d[at + 3], BinaryPrimitives.ReadUInt32LittleEndian(d[(at + 4)..])) : null;

    public string TypeName => DataType switch
    {
        Null => "null", Reference => "reference", Attribute => "attribute", String => "string", Float => "float",
        Dimension => "dimension", Fraction => "fraction", DynamicReference => "dynamic_reference", DynamicAttribute => "dynamic_attribute",
        IntDec => "int", IntHex => "int_hex", IntBoolean => "bool",
        ColorArgb8 or ColorRgb8 or ColorArgb4 or ColorRgb4 => "color",
        _ => $"type_0x{DataType:x2}",
    };

    public bool IsReference => DataType is Reference or DynamicReference;

    /// <summary>The value as aapt prints it: strings from <paramref name="strings"/>, references through <paramref name="resolve"/>.</summary>
    public string Format(ResStringPool strings, Func<uint, string?>? resolve = null)
    {
        var inv = CultureInfo.InvariantCulture;
        return DataType switch
        {
            Null => Data == 1 ? "@empty" : "@null",
            Reference or DynamicReference => Data == 0 ? "@null" : resolve?.Invoke(Data) ?? $"@0x{Data:x8}",
            Attribute or DynamicAttribute => "?" + (resolve?.Invoke(Data)?.TrimStart('@') ?? $"0x{Data:x8}"),
            String => strings.Get(Data) ?? $"(string #{Data})",
            Float => BitConverter.Int32BitsToSingle((int)Data).ToString("R", inv),
            Dimension => Complex(Data).ToString("R", inv) + (Data & 0xF) switch { 0 => "px", 1 => "dp", 2 => "sp", 3 => "pt", 4 => "in", 5 => "mm", _ => $"(unit {Data & 0xF})" },
            Fraction => (Complex(Data) * 100).ToString("R", inv) + ((Data & 0xF) == 1 ? "%p" : "%"),
            IntDec => ((int)Data).ToString(inv),
            IntHex => $"0x{Data:x}",
            IntBoolean => Data != 0 ? "true" : "false",
            ColorRgb8 => $"#{Data & 0xFFFFFF:x6}",
            ColorArgb8 or ColorArgb4 or ColorRgb4 => $"#{Data:x8}",
            _ => $"(type 0x{DataType:x2})0x{Data:x8}",
        };
    }

    // Complex values: a signed 24-bit mantissa with a 2-bit radix choosing where the binary point sits.
    private static float Complex(uint data)
    {
        ReadOnlySpan<float> radix = [1f / (1 << 8), 1f / (1 << 15), 1f / (1 << 23), 1f / (1L << 31)];
        return (int)(data & 0xFFFFFF00) * radix[(int)((data >> 4) & 3)];
    }
}
