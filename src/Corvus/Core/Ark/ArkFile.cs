using System.Buffers.Binary;
using System.Text;

namespace Corvus.Core.Ark;

/// <summary>A field of an Ark bytecode class: name, access flags and its integer value, null when it has none.</summary>
internal sealed record ArkField(string Name, uint AccessFlags, long? Value);

/// <summary>
/// A method of an Ark bytecode class: its offset, class name, name, access flags, code offset (null for none), debug
/// information offset (null for none) and source language (null when the class's applies).
/// </summary>
internal sealed record ArkMethod(int Offset, string Class, string Name, uint AccessFlags, int? Code, int? DebugInfo, byte? Language)
{
    public string FullName => ArkFile.Qualified(Class, Name);
}

/// <summary>A class (record) of an Ark bytecode file: offset, name as ark_disasm prints it (descriptor without L and ;), access flags, source file (null for none), fields and methods.</summary>
internal sealed record ArkClass(int Offset, string Name, uint AccessFlags, string? SourceFile, IReadOnlyList<ArkField> Fields, IReadOnlyList<ArkMethod> Methods);

/// <summary>A try block of a method body: start and length in bytes, then each handler's catch type (null catches all) and handler offset.</summary>
internal sealed record ArkTry(int Start, int Length, IReadOnlyList<(string? Type, int Handler)> Catches);

/// <summary>A method body: virtual registers, arguments, the instruction bytes and its try blocks.</summary>
internal sealed record ArkCode(int Registers, int Arguments, byte[] Instructions, IReadOnlyList<ArkTry> Tries);

/// <summary>One literal of a literal array: its tag (as the dynamic literal tags name it) and value.</summary>
internal readonly record struct ArkLiteral(byte Tag, object? Value);

/// <summary>
/// Ark bytecode files (Panda binary format, <c>.abc</c>): header, classes with their fields and methods, method
/// bodies, the region indexes that resolve 16-bit ids, strings and literal arrays. Structure that runs past the file
/// or points into the header throws <see cref="InvalidDataException"/>.
/// </summary>
internal sealed class ArkFile
{
    private const int HeaderSize = 60;
    private readonly byte[] _data;
    private readonly (int Start, int End, int MethodCount, int MethodIndex, int ClassCount, int ClassIndex)[] _regions;
    private readonly int _foreignStart, _foreignEnd;

    /// <summary>The format version as four dotted numbers (12.0.6.0).</summary>
    public string Version { get; }
    public bool ChecksumMatches { get; }
    public IReadOnlyList<ArkClass> Classes { get; }
    public IReadOnlyList<string> Issues { get; }

    public static bool Looks(ReadOnlySpan<byte> data) => data.Length >= HeaderSize && data.StartsWith("PANDA\0\0\0"u8);

    public ArkFile(byte[] data)
    {
        if (!Looks(data)) throw new InvalidDataException("no PANDA header");
        _data = data;
        var issues = new List<string>();
        Version = string.Join('.', data[12..16]);
        long size = U32(16);
        if (size != data.Length) issues.Add($"the header declares {size:N0} bytes; the file holds {data.Length:N0}");
        var adler = Adler32(data.AsSpan(12, (int)Math.Min(size, data.Length) - 12));
        ChecksumMatches = adler == U32(8);
        if (!ChecksumMatches) issues.Add($"checksum 0x{U32(8):X8} differs from the content's 0x{adler:X8}");
        _foreignStart = (int)U32(20);
        _foreignEnd = (int)Math.Min(int.MaxValue, (long)_foreignStart + U32(24));
        int classes = Count(U32(28), 4, U32(32), "class index");
        int regions = Count(U32(52), 40, U32(56), "region index");
        _regions = new (int, int, int, int, int, int)[regions];
        for (int i = 0; i < regions; i++)
        {
            int at = (int)U32(56) + 40 * i;
            _regions[i] = ((int)U32(at), (int)U32(at + 4), Count(U32(at + 16), 4, U32(at + 20), "method region index"), (int)U32(at + 20),
                Count(U32(at + 8), 4, U32(at + 12), "class region index"), (int)U32(at + 12));
        }
        var list = new List<ArkClass>();
        for (int i = 0; i < classes; i++)
        {
            int offset = (int)U32((int)U32(32) + 4 * i);
            if (IsForeign(offset)) continue;
            try { list.Add(ReadClass(offset)); }
            catch (InvalidDataException ex) { issues.Add($"class at 0x{offset:X}: {ex.Message}"); }
        }
        Classes = list;
        Issues = issues;
    }

    public bool IsForeign(int offset) => offset >= _foreignStart && offset < _foreignEnd;

    /// <summary>The string at <paramref name="offset"/> (MUTF-8, surrogate pairs and the two-byte zero decoded).</summary>
    public string String(int offset)
    {
        Check(offset, 1);
        int p = offset;
        Uleb(ref p);
        int end = Array.IndexOf(_data, (byte)0, p);
        if (end < 0) throw new InvalidDataException($"the string at 0x{offset:X} has no terminator");
        return Mutf8(_data.AsSpan(p, end - p));
    }

    /// <summary>The offset a 16-bit method-region id names for an instruction of the method at <paramref name="method"/>.</summary>
    public int MethodRegionId(int method, int id)
    {
        foreach (var r in _regions)
            if (method >= r.Start && method < r.End)
            {
                if (id >= r.MethodCount) throw new InvalidDataException($"id {id} past the {r.MethodCount} entries of the region");
                return (int)U32(r.MethodIndex + 4 * id);
            }
        throw new InvalidDataException($"no index region holds 0x{method:X}");
    }

    /// <summary>The name of the method at <paramref name="offset"/> with its class: <c>class.name</c>; foreign methods too.</summary>
    public string MethodName(int offset)
    {
        Check(offset, 8);
        int classOffset = ClassAt(offset, BinaryPrimitives.ReadUInt16LittleEndian(_data.AsSpan(offset)));
        string name = String((int)U32(offset + 4));
        return classOffset > 0 ? Qualified(ClassName(classOffset), name) : name;
    }

    public ArkCode Code(int offset)
    {
        int p = offset;
        Check(p, 1);
        int registers = (int)Uleb(ref p), arguments = (int)Uleb(ref p), size = (int)Uleb(ref p), tries = (int)Uleb(ref p);
        Check(p, size);
        var instructions = _data[p..(p + size)];
        p += size;
        var blocks = new List<ArkTry>();
        for (int i = 0; i < tries; i++)
        {
            int start = (int)Uleb(ref p), length = (int)Uleb(ref p), count = (int)Uleb(ref p);
            var catches = new List<(string?, int)>();
            for (int c = 0; c < count; c++)
            {
                int type = (int)Uleb(ref p), handler = (int)Uleb(ref p);
                Uleb(ref p);
                catches.Add((type == 0 ? null : $"type {type - 1}", handler));
            }
            blocks.Add(new ArkTry(start, length, catches));
        }
        return new ArkCode(registers, arguments, instructions, blocks);
    }

    // Dynamic literal tags (libpandafile LiteralTag): name and value size in bytes; strings, methods and arrays are
    // 32-bit offsets.
    private static readonly Dictionary<byte, (string Name, int Size)> LiteralTags = new()
    {
        [0x00] = ("tagvalue", 1), [0x01] = ("u1", 1), [0x02] = ("i32", 4), [0x03] = ("f32", 4), [0x04] = ("f64", 8),
        [0x05] = ("string", 4), [0x06] = ("method", 4), [0x07] = ("generator_method", 4), [0x08] = ("accessor", 1),
        [0x09] = ("method_affiliate", 2), [0x0a] = ("u1[]", 4), [0x0b] = ("u8[]", 4), [0x0c] = ("i8[]", 4), [0x0d] = ("u16[]", 4),
        [0x0e] = ("i16[]", 4), [0x0f] = ("u32[]", 4), [0x10] = ("i32[]", 4), [0x11] = ("u64[]", 4), [0x12] = ("i64[]", 4),
        [0x13] = ("f32[]", 4), [0x14] = ("f64[]", 4), [0x15] = ("string[]", 4), [0x16] = ("async_generator_method", 4),
        [0x17] = ("literal_buffer_index", 4), [0x18] = ("literal_array", 4), [0x19] = ("builtin_type_index", 1),
        [0x1a] = ("getter", 4), [0x1b] = ("setter", 4), [0xff] = ("null_value", 1),
    };

    /// <summary>The name ark_disasm gives a literal tag; null for a tag not in the table.</summary>
    public static string? LiteralTagName(byte tag) => LiteralTags.TryGetValue(tag, out var t) ? t.Name : null;

    /// <summary>
    /// The literals of the tag and value array at <paramref name="offset"/> (the header counts tags and values both):
    /// strings resolved to text, methods to their names, numbers as read, other offsets as numbers.
    /// </summary>
    public List<ArkLiteral> Literals(int offset)
    {
        Check(offset, 4);
        long count = U32(offset);
        int p = offset + 4;
        var literals = new List<ArkLiteral>();
        for (long i = 0; i + 1 < count; i += 2)
        {
            Check(p, 1);
            byte tag = _data[p++];
            if (!LiteralTags.TryGetValue(tag, out var t)) throw new InvalidDataException($"literal tag 0x{tag:X2} at 0x{p - 1:X}");
            Check(p, t.Size);
            var v = _data.AsSpan(p, t.Size);
            object? value = (tag, t.Size) switch
            {
                (0x01, _) => v[0] != 0,
                (0x02, _) => BinaryPrimitives.ReadInt32LittleEndian(v),
                (0x03, _) => BinaryPrimitives.ReadSingleLittleEndian(v),
                (0x04, _) => BinaryPrimitives.ReadDoubleLittleEndian(v),
                (0x05, _) => String((int)BinaryPrimitives.ReadUInt32LittleEndian(v)),
                (0x06 or 0x07 or 0x16 or 0x1a or 0x1b, _) => MethodShortName((int)BinaryPrimitives.ReadUInt32LittleEndian(v)),
                (_, 1) => v[0],
                (_, 2) => BinaryPrimitives.ReadUInt16LittleEndian(v),
                _ => BinaryPrimitives.ReadUInt32LittleEndian(v),
            };
            p += t.Size;
            literals.Add(new ArkLiteral(tag, value));
        }
        return literals;
    }

    /// <summary>A method's own name, without its class.</summary>
    public string MethodShortName(int offset)
    {
        Check(offset, 8);
        return String((int)U32(offset + 4));
    }

    /// <summary>The argument count of the method at <paramref name="offset"/>, from its code; null when it has none or it is foreign.</summary>
    public int? ArgumentCount(int offset)
    {
        if (IsForeign(offset)) return null;
        Check(offset, 8);
        int p = offset + 8;
        Uleb(ref p);
        while (true)
        {
            Check(p, 1);
            byte tag = _data[p++];
            if (tag == 0) return null;
            if (tag == 0x01) { Check(p, 4); return Code((int)U32(p)).Arguments; }
            p += tag == 0x02 ? 1 : 4;
        }
    }

    private ArkClass ReadClass(int offset)
    {
        string display = Display(String(offset));
        int p = offset;
        SkipString(ref p);
        Check(p, 4);
        p += 4;
        uint flags = (uint)Uleb(ref p);
        int fields = (int)Uleb(ref p), methods = (int)Uleb(ref p);
        string? source = null;
        while (true)
        {
            Check(p, 1);
            byte tag = _data[p++];
            if (tag == 0) break;
            switch (tag)
            {
                case 0x01:
                    int n = (int)Uleb(ref p);
                    p += 2 * n;
                    break;
                case 0x02: p++; break;
                case 0x07: Check(p, 4); source = String((int)U32(p)); p += 4; break;
                case >= 0x03 and <= 0x06: p += 4; break;
                default: throw new InvalidDataException($"class tag 0x{tag:X2}");
            }
        }
        var fieldList = new List<ArkField>();
        for (int i = 0; i < fields; i++)
        {
            Check(p, 8);
            string fieldName = String((int)U32(p + 4));
            p += 8;
            uint fieldFlags = (uint)Uleb(ref p);
            long? value = null;
            while (true)
            {
                Check(p, 1);
                byte tag = _data[p++];
                if (tag == 0) break;
                switch (tag)
                {
                    case 0x01: value = Sleb(ref p); break;
                    case 0x02: Check(p, 4); value = U32(p); p += 4; break;
                    case >= 0x03 and <= 0x06: p += 4; break;
                    default: throw new InvalidDataException($"field tag 0x{tag:X2}");
                }
            }
            fieldList.Add(new ArkField(fieldName, fieldFlags, value));
        }
        var methodList = new List<ArkMethod>();
        for (int i = 0; i < methods; i++)
        {
            int at = p;
            Check(p, 8);
            string methodName = String((int)U32(p + 4));
            p += 8;
            uint methodFlags = (uint)Uleb(ref p);
            int? code = null, debug = null;
            byte? language = null;
            while (true)
            {
                Check(p, 1);
                byte tag = _data[p++];
                if (tag == 0) break;
                switch (tag)
                {
                    case 0x01: Check(p, 4); code = (int)U32(p); p += 4; break;
                    case 0x02: Check(p, 1); language = _data[p++]; break;
                    case 0x05: Check(p, 4); debug = (int)U32(p); p += 4; break;
                    case 0x03 or 0x04 or (>= 0x06 and <= 0x09): p += 4; break;
                    default: throw new InvalidDataException($"method tag 0x{tag:X2}");
                }
            }
            methodList.Add(new ArkMethod(at, display, methodName, methodFlags, code, debug, language));
        }
        return new ArkClass(offset, display, flags, source, fieldList, methodList);
    }

    private int ClassAt(int from, int index)
    {
        foreach (var r in _regions)
            if (from >= r.Start && from < r.End)
                return index < r.ClassCount ? (int)U32(r.ClassIndex + 4 * index) : 0;
        return 0;
    }

    private string ClassName(int offset) => offset >= HeaderSize && offset < _data.Length ? Display(String(offset)) : $"class 0x{offset:X}";

    /// <summary>A method name with its class as ark_disasm prints it: the record of an unmerged file (_GLOBAL) is left out.</summary>
    public static string Qualified(string cls, string name) => cls == "_GLOBAL" ? name : $"{cls}.{name}";

    /// <summary>A type descriptor as ark_disasm prints it: <c>Lcom/example/A;</c> becomes <c>com.example.A</c>; other text is kept.</summary>
    public static string Display(string descriptor) =>
        descriptor.Length > 2 && descriptor[0] == 'L' && descriptor[^1] == ';' ? descriptor[1..^1].Replace('/', '.') : descriptor;

    private int Count(uint count, int entry, uint at, string what)
    {
        if (count == 0) return 0;
        if (at < HeaderSize || (ulong)at + (ulong)count * (ulong)entry > (ulong)_data.Length) throw new InvalidDataException($"the {what} ({count:N0} entries at 0x{at:X}) runs past the file");
        return (int)count;
    }

    private void Check(int at, int length)
    {
        if (at < HeaderSize || length < 0 || (long)at + length > _data.Length) throw new InvalidDataException($"{length:N0} bytes at 0x{at:X} run past the file");
    }

    private uint U32(int at)
    {
        if (at < 0 || at + 4 > _data.Length) throw new InvalidDataException($"a field at 0x{at:X} runs past the file");
        return BinaryPrimitives.ReadUInt32LittleEndian(_data.AsSpan(at));
    }

    private void SkipString(ref int p)
    {
        Uleb(ref p);
        int end = Array.IndexOf(_data, (byte)0, p);
        if (end < 0) throw new InvalidDataException($"the string at 0x{p:X} has no terminator");
        p = end + 1;
    }

    private ulong Uleb(ref int p)
    {
        ulong value = 0;
        for (int shift = 0; ; shift += 7)
        {
            if (p >= _data.Length || shift > 63) throw new InvalidDataException($"a ULEB128 at 0x{p:X} runs past the file");
            byte b = _data[p++];
            value |= (ulong)(b & 0x7F) << shift;
            if (b < 0x80) return value;
        }
    }

    private long Sleb(ref int p)
    {
        long value = 0;
        int shift = 0;
        byte b;
        do
        {
            if (p >= _data.Length || shift > 63) throw new InvalidDataException($"an SLEB128 at 0x{p:X} runs past the file");
            b = _data[p++];
            value |= (long)(b & 0x7F) << shift;
            shift += 7;
        } while (b >= 0x80);
        return shift < 64 && (b & 0x40) != 0 ? value | -1L << shift : value;
    }

    private static uint Adler32(ReadOnlySpan<byte> data)
    {
        uint a = 1, b = 0;
        // 5552 bytes is the longest run whose sums cannot overflow before the modulo.
        while (!data.IsEmpty)
        {
            var chunk = data[..Math.Min(5552, data.Length)];
            foreach (byte x in chunk) { a += x; b += a; }
            a %= 65521;
            b %= 65521;
            data = data[chunk.Length..];
        }
        return b << 16 | a;
    }

    // MUTF-8: zero as C0 80, supplementary characters as two three-byte surrogates.
    private static string Mutf8(ReadOnlySpan<byte> s)
    {
        var sb = new StringBuilder(s.Length);
        for (int i = 0; i < s.Length;)
        {
            byte b = s[i];
            if (b < 0x80) { sb.Append((char)b); i++; }
            else if ((b & 0xE0) == 0xC0 && i + 1 < s.Length) { sb.Append((char)((b & 0x1F) << 6 | s[i + 1] & 0x3F)); i += 2; }
            else if ((b & 0xF0) == 0xE0 && i + 2 < s.Length) { sb.Append((char)((b & 0x0F) << 12 | (s[i + 1] & 0x3F) << 6 | s[i + 2] & 0x3F)); i += 3; }
            else { sb.Append('�'); i++; }
        }
        return sb.ToString();
    }
}
