using System.Buffers.Binary;
using System.Globalization;
using System.Text;
using Corvus.Native;

namespace Corvus.Core.Mobile;

public sealed record DexProto(string Shorty, string ReturnType, IReadOnlyList<string> Parameters)
{
    public string Descriptor => "(" + string.Concat(Parameters) + ")" + ReturnType;
}

public sealed record DexFieldRef(string Class, string Type, string Name)
{
    /// <summary>Lpkg/C;->name:Ltype;</summary>
    public string Descriptor => $"{Class}->{Name}:{Type}";
}

public sealed record DexMethodRef(string Class, string Name, DexProto Proto)
{
    /// <summary>Lpkg/C;->name(params)ret: exact, so overloads never collide.</summary>
    public string Descriptor => $"{Class}->{Name}{Proto.Descriptor}";
}

public sealed record DexEncodedField(int FieldIndex, uint Access, bool IsStatic);

public sealed record DexEncodedMethod(int MethodIndex, uint Access, uint CodeOffset, bool IsDirect);

public sealed record DexTry(int Start, int Count, IReadOnlyList<(string? Type, int Handler)> Handlers);

/// <summary>A method body: register counts, the code units, try blocks and the debug info offset.</summary>
public sealed record DexCode(int Registers, int Ins, int Outs, ushort[] Instructions, IReadOnlyList<DexTry> Tries, uint DebugInfoOffset);

public sealed record DexAnnotation(string Visibility, string Type, IReadOnlyList<(string Name, DexValue Value)> Elements);

/// <summary>An encoded_value: its kind (byte, int, string, type, field, method, enum, array, annotation, null, boolean, ...) and value.</summary>
public sealed record DexValue(string Kind, object? Value)
{
    public override string ToString() => Kind switch
    {
        "null" => "null",
        "string" => "\"" + DexFile.Escape((string)Value!) + "\"",
        "boolean" => (bool)Value! ? "true" : "false",
        "char" => $"'{DexFile.Escape(((char)Value!).ToString())}'",
        "array" => "{" + string.Join(", ", ((IReadOnlyList<DexValue>)Value!).Select(v => v.ToString())) + "}",
        "annotation" => ((DexAnnotation)Value!) is var a ? $"{a.Type}({string.Join(", ", a.Elements.Select(e => $"{e.Name}={e.Value}"))})" : "",
        "enum" => ".enum " + Value,
        "long" => Hex((long)Value!) + "L",
        "int" => Hex((int)Value!),
        "short" => Hex((short)Value!) + "s",
        "byte" => Hex((sbyte)Value!) + "t",
        "float" => DexFile.JavaNumber((float)Value!) + "f",
        "double" => DexFile.JavaNumber((double)Value!),
        _ => Value?.ToString() ?? "",
    };

    private static string Hex(long v) => v < 0 ? $"-0x{(ulong)-v:x}" : $"0x{v:x}";
}

public sealed record DexClass(int Index, string Descriptor, uint Access, string? SuperClass, IReadOnlyList<string> Interfaces, string? SourceFile,
    uint AnnotationsOffset, uint ClassDataOffset, uint StaticValuesOffset);

/// <summary>Annotations of a class, its fields, methods and parameters.</summary>
public sealed record DexClassAnnotations(IReadOnlyList<DexAnnotation> Class, IReadOnlyDictionary<int, IReadOnlyList<DexAnnotation>> Fields,
    IReadOnlyDictionary<int, IReadOnlyList<DexAnnotation>> Methods, IReadOnlyDictionary<int, IReadOnlyList<IReadOnlyList<DexAnnotation>>> Parameters);

/// <summary>
/// A DEX file (versions 035-041): pools, class definitions, class data, code items, annotations, encoded values and debug line
/// numbers. Reads a copy of the bytes, bounds-checks every offset and never throws after construction: what cannot be read is
/// reported in <see cref="Issues"/> and comes back empty.
/// </summary>
public sealed class DexFile
{
    public const int HeaderSize = 0x70;
    public string Name { get; }
    public int Version { get; }
    public long Size => _d.Length;
    public IReadOnlyList<ParseIssue> Issues => _issues;

    private readonly byte[] _d;
    private readonly List<ParseIssue> _issues = [];
    private readonly int _strings, _stringsAt, _types, _typesAt, _protos, _protosAt, _fields, _fieldsAt, _methods, _methodsAt, _classes, _classesAt;
    private readonly string?[] _stringCache;
    private readonly DexProto?[] _protoCache;

    public int StringCount => _strings;
    public int TypeCount => _types;
    public int FieldCount => _fields;
    public int MethodCount => _methods;
    public int ClassCount => _classes;

    private DexFile(byte[] data, string name)
    {
        _d = data;
        Name = name;
        Version = int.TryParse(Encoding.ASCII.GetString(data, 4, 3), NumberStyles.Integer, CultureInfo.InvariantCulture, out var v) ? v : 0;
        (int, int) Table(int sizeAt, int offAt, int itemSize, string what)
        {
            uint count = U32(sizeAt), at = U32(offAt);
            if (count == 0) return (0, 0);
            if (at > data.Length || count > (data.Length - at) / (uint)itemSize)
            {
                _issues.Add(new("dex", $"{what}: {count} items at 0x{at:x} do not fit the {data.Length}-byte file", offAt));
                return (0, 0);
            }
            return ((int)count, (int)at);
        }
        (_strings, _stringsAt) = Table(56, 60, 4, "string ids");
        (_types, _typesAt) = Table(64, 68, 4, "type ids");
        (_protos, _protosAt) = Table(72, 76, 12, "proto ids");
        (_fields, _fieldsAt) = Table(80, 84, 8, "field ids");
        (_methods, _methodsAt) = Table(88, 92, 8, "method ids");
        (_classes, _classesAt) = Table(96, 100, 32, "class defs");
        _stringCache = new string?[_strings];
        _protoCache = new DexProto?[_protos];
        if (U32(40) != 0x12345678) _issues.Add(new("dex", $"endian tag 0x{U32(40):x8} is not 0x12345678", 40));
        if (U32(32) != data.Length) _issues.Add(new("dex", $"header file size {U32(32)} differs from the {data.Length} bytes read", 32));
        if (Version >= 41 && U32(0x70) > U32(32)) _issues.Add(new("dex", "a DEX container with several files: only the first is read", 0x70));
    }

    /// <summary>True for "dex\n0NN\0".</summary>
    public static bool IsDex(ReadOnlySpan<byte> b) => b.Length >= HeaderSize && b[0] == 'd' && b[1] == 'e' && b[2] == 'x' && b[3] == '\n' && b[7] == 0;

    /// <summary>Reads a DEX file; not a DEX header is a typed error, anything else an issue.</summary>
    public static DexFile Read(byte[] data, string name)
    {
        if (!IsDex(data)) throw new ToolError(ErrorCode.MalformedInput, $"{name} is not a DEX file (no \"dex\\n0NN\" header).");
        return new DexFile(data, name);
    }

    private uint U32(long at) => at >= 0 && at + 4 <= _d.Length ? BinaryPrimitives.ReadUInt32LittleEndian(_d.AsSpan((int)at)) : 0;
    private ushort U16(long at) => at >= 0 && at + 2 <= _d.Length ? BinaryPrimitives.ReadUInt16LittleEndian(_d.AsSpan((int)at)) : (ushort)0;

    private uint Uleb(ref long at)
    {
        uint result = 0;
        for (int shift = 0; shift < 35 && at < _d.Length; shift += 7)
        {
            byte b = _d[at++];
            result |= (uint)(b & 0x7F) << shift;
            if ((b & 0x80) == 0) return result;
        }
        return result;
    }

    private int Sleb(ref long at)
    {
        int result = 0, shift = 0;
        byte b = 0;
        for (; shift < 35 && at < _d.Length; shift += 7)
        {
            b = _d[at++];
            result |= (b & 0x7F) << shift;
            if ((b & 0x80) == 0) { shift += 7; break; }
        }
        return shift < 32 && (b & 0x40) != 0 ? result | -(1 << shift) : result;
    }

    public string String(int index)
    {
        if ((uint)index >= (uint)_strings) return $"<string {index}>";
        if (_stringCache[index] is { } cached) return cached;
        long at = U32(_stringsAt + index * 4L);
        uint chars = Uleb(ref at);
        return _stringCache[index] = Mutf8(at, chars);
    }

    /// <summary>Modified UTF-8: NUL as C0 80 and supplementary characters as two 3-byte surrogates.</summary>
    private string Mutf8(long at, uint chars)
    {
        var sb = new StringBuilder((int)Math.Min(chars, 65_536));
        while (at < _d.Length && sb.Length < chars)
        {
            int b = _d[at++];
            if (b == 0) break;
            if (b < 0x80) sb.Append((char)b);
            else if ((b & 0xE0) == 0xC0 && at < _d.Length) sb.Append((char)((b & 0x1F) << 6 | _d[at++] & 0x3F));
            else if ((b & 0xF0) == 0xE0 && at + 1 < _d.Length) { sb.Append((char)((b & 0x0F) << 12 | (_d[at] & 0x3F) << 6 | _d[at + 1] & 0x3F)); at += 2; }
            else sb.Append((char)0xFFFD);
        }
        return sb.ToString();
    }

    public string Type(int index) => (uint)index < (uint)_types ? String((int)U32(_typesAt + index * 4L)) : $"<type {index}>";

    public DexProto Proto(int index)
    {
        if ((uint)index >= (uint)_protos) return new DexProto("V", "V", []);
        if (_protoCache[index] is { } cached) return cached;
        long at = _protosAt + index * 12L;
        return _protoCache[index] = new DexProto(String((int)U32(at)), Type((int)U32(at + 4)), TypeList(U32(at + 8)));
    }

    private List<string> TypeList(uint offset)
    {
        if (offset == 0 || offset + 4 > _d.Length) return [];
        uint size = U32(offset);
        if (size > (_d.Length - offset - 4) / 2) return [];
        var list = new List<string>((int)size);
        for (int i = 0; i < size; i++) list.Add(Type(U16(offset + 4 + i * 2L)));
        return list;
    }

    public DexFieldRef Field(int index)
    {
        long at = _fieldsAt + index * 8L;
        return (uint)index < (uint)_fields ? new(Type(U16(at)), Type(U16(at + 2)), String((int)U32(at + 4))) : new("<field>", "V", $"<field {index}>");
    }

    public DexMethodRef Method(int index)
    {
        long at = _methodsAt + index * 8L;
        return (uint)index < (uint)_methods ? new(Type(U16(at)), String((int)U32(at + 4)), Proto(U16(at + 2))) : new("<method>", $"<method {index}>", new("V", "V", []));
    }

    private List<DexClass>? _classList;

    public IReadOnlyList<DexClass> Classes => _classList ??= ReadClasses();

    private List<DexClass> ReadClasses()
    {
        var list = new List<DexClass>(_classes);
        for (int i = 0; i < _classes; i++)
        {
            long at = _classesAt + i * 32L;
            uint super = U32(at + 8), source = U32(at + 16);
            list.Add(new DexClass(i, Type((int)U32(at)), U32(at + 4), super == 0xFFFFFFFF ? null : Type((int)super), TypeList(U32(at + 12)),
                source == 0xFFFFFFFF ? null : String((int)source), U32(at + 20), U32(at + 24), U32(at + 28)));
        }
        return list;
    }

    /// <summary>The fields and methods a class defines (static, instance, direct, virtual), in file order.</summary>
    public (List<DexEncodedField> Fields, List<DexEncodedMethod> Methods) ClassData(DexClass c)
    {
        var fields = new List<DexEncodedField>();
        var methods = new List<DexEncodedMethod>();
        if (c.ClassDataOffset == 0 || c.ClassDataOffset >= _d.Length) return (fields, methods);
        long at = c.ClassDataOffset;
        uint sf = Uleb(ref at), inf = Uleb(ref at), dm = Uleb(ref at), vm = Uleb(ref at);
        if ((long)sf + inf + dm + vm > _d.Length - at) { _issues.Add(new("dex", $"{c.Descriptor}: class data counts do not fit the file", c.ClassDataOffset)); return (fields, methods); }
        int index = 0;
        for (int i = 0; i < sf + inf; i++)
        {
            if (i == sf) index = 0;
            index += (int)Uleb(ref at);
            fields.Add(new(index, Uleb(ref at), i < sf));
        }
        index = 0;
        for (int i = 0; i < dm + vm; i++)
        {
            if (i == dm) index = 0;
            index += (int)Uleb(ref at);
            uint access = Uleb(ref at);
            methods.Add(new(index, access, Uleb(ref at), i < dm));
        }
        return (fields, methods);
    }

    /// <summary>The code item at <paramref name="offset"/>, or null when there is none or it does not fit.</summary>
    public DexCode? Code(uint offset)
    {
        if (offset == 0 || offset + 16 > _d.Length) return null;
        int registers = U16(offset), ins = U16(offset + 2), outs = U16(offset + 4), triesSize = U16(offset + 6);
        uint debug = U32(offset + 8), units = U32(offset + 12);
        long insns = offset + 16;
        if (units > (_d.Length - insns) / 2) { _issues.Add(new("dex", $"code item at 0x{offset:x}: {units} code units do not fit the file", offset)); return null; }
        var code = new ushort[units];
        for (int i = 0; i < units; i++) code[i] = U16(insns + i * 2L);
        var tries = new List<DexTry>();
        long triesAt = insns + units * 2L + (units % 2 == 1 && triesSize > 0 ? 2 : 0);
        long handlersAt = triesAt + triesSize * 8L;
        for (int t = 0; t < triesSize && handlersAt <= _d.Length; t++)
        {
            long ta = triesAt + t * 8L;
            long h = handlersAt + U16(ta + 6);
            int size = Sleb(ref h);
            var handlers = new List<(string?, int)>();
            for (int k = 0; k < Math.Min(Math.Abs(size), 4096); k++)
            {
                var type = Type((int)Uleb(ref h));
                handlers.Add((type, (int)Uleb(ref h)));
            }
            if (size <= 0) handlers.Add((null, (int)Uleb(ref h)));
            tries.Add(new DexTry((int)U32(ta), U16(ta + 4), handlers));
        }
        return new DexCode(registers, ins, outs, code, tries, debug);
    }

    /// <summary>Source line per code offset from the debug info (line starts only), and the parameter names it lists.</summary>
    public (List<(int Offset, int Line)> Lines, List<string?> ParameterNames) Debug(uint offset)
    {
        var lines = new List<(int, int)>();
        var names = new List<string?>();
        if (offset == 0 || offset >= _d.Length) return (lines, names);
        long at = offset;
        int line = (int)Uleb(ref at);
        uint count = Uleb(ref at);
        for (int i = 0; i < count && i < 256; i++) names.Add(Uleb(ref at) is var n and > 0 ? String((int)n - 1) : null);
        int address = 0;
        for (int steps = 0; at < _d.Length && steps < 1_000_000; steps++)
        {
            byte op = _d[at++];
            switch (op)
            {
                case 0x00: return (lines, names);
                case 0x01: address += (int)Uleb(ref at); break;
                case 0x02: line += Sleb(ref at); break;
                case 0x03: Uleb(ref at); Uleb(ref at); Uleb(ref at); break;
                case 0x04: Uleb(ref at); Uleb(ref at); Uleb(ref at); Uleb(ref at); break;
                case 0x05 or 0x06: Uleb(ref at); break;
                case 0x07 or 0x08: break;
                case 0x09: Uleb(ref at); break;
                default:
                    int adjusted = op - 0x0A;
                    line += -4 + adjusted % 15;
                    address += adjusted / 15;
                    lines.Add((address, line));
                    break;
            }
        }
        return (lines, names);
    }

    public DexClassAnnotations Annotations(DexClass c)
    {
        var empty = new DexClassAnnotations([], new Dictionary<int, IReadOnlyList<DexAnnotation>>(), new Dictionary<int, IReadOnlyList<DexAnnotation>>(),
            new Dictionary<int, IReadOnlyList<IReadOnlyList<DexAnnotation>>>());
        uint at = c.AnnotationsOffset;
        if (at == 0 || at + 16 > _d.Length) return empty;
        uint fieldsSize = U32(at + 4), methodsSize = U32(at + 8), paramsSize = U32(at + 12);
        if ((long)fieldsSize + methodsSize + paramsSize > (_d.Length - at - 16) / 8) return empty;
        var fields = new Dictionary<int, IReadOnlyList<DexAnnotation>>();
        var methods = new Dictionary<int, IReadOnlyList<DexAnnotation>>();
        var parameters = new Dictionary<int, IReadOnlyList<IReadOnlyList<DexAnnotation>>>();
        long p = at + 16;
        for (int i = 0; i < fieldsSize; i++, p += 8) fields[(int)U32(p)] = AnnotationSet(U32(p + 4));
        for (int i = 0; i < methodsSize; i++, p += 8) methods[(int)U32(p)] = AnnotationSet(U32(p + 4));
        for (int i = 0; i < paramsSize; i++, p += 8)
        {
            uint list = U32(p + 4);
            uint size = list != 0 && list + 4 <= _d.Length ? Math.Min(U32(list), 256) : 0;
            parameters[(int)U32(p)] = Enumerable.Range(0, (int)size).Select(k => AnnotationSet(U32(list + 4 + k * 4L))).ToList();
        }
        return new DexClassAnnotations(AnnotationSet(U32(at)), fields, methods, parameters);
    }

    private List<DexAnnotation> AnnotationSet(uint offset)
    {
        var list = new List<DexAnnotation>();
        if (offset == 0 || offset + 4 > _d.Length) return list;
        uint size = U32(offset);
        for (int i = 0; i < size && i < 1024 && offset + 4 + i * 4L + 4 <= _d.Length; i++)
        {
            long at = U32(offset + 4 + i * 4L);
            if (at >= _d.Length) continue;
            var visibility = _d[at++] switch { 0 => "build", 1 => "runtime", 2 => "system", var v => $"visibility{v}" };
            var a = EncodedAnnotation(ref at, 0);
            list.Add(a with { Visibility = visibility });
        }
        return list;
    }

    private DexAnnotation EncodedAnnotation(ref long at, int depth)
    {
        var type = Type((int)Uleb(ref at));
        uint size = Uleb(ref at);
        var elements = new List<(string, DexValue)>();
        for (int i = 0; i < size && i < 4096 && at < _d.Length; i++)
        {
            var name = String((int)Uleb(ref at));
            elements.Add((name, Value(ref at, depth + 1)));
        }
        return new DexAnnotation("", type, elements);
    }

    /// <summary>The encoded_array_item of a class's static field initial values, in static field order.</summary>
    public List<DexValue> StaticValues(DexClass c)
    {
        if (c.StaticValuesOffset == 0 || c.StaticValuesOffset >= _d.Length) return [];
        long at = c.StaticValuesOffset;
        uint size = Uleb(ref at);
        var list = new List<DexValue>();
        for (int i = 0; i < size && i < 65_536 && at < _d.Length; i++) list.Add(Value(ref at, 0));
        return list;
    }

    private DexValue Value(ref long at, int depth)
    {
        if (at >= _d.Length || depth > 32) return new("null", null);
        byte header = _d[at++];
        int arg = header >> 5, type = header & 0x1F;
        switch (type)
        {
            case 0x00: return new("byte", (sbyte)Raw(ref at, arg, true));
            case 0x02: return new("short", (short)Raw(ref at, arg, true));
            case 0x03: return new("char", (char)Raw(ref at, arg, false));
            case 0x04: return new("int", (int)Raw(ref at, arg, true));
            case 0x06: return new("long", (long)Raw(ref at, arg, true));
            case 0x10: return new("float", BitConverter.Int32BitsToSingle((int)((Raw(ref at, arg, false) << (56 - 8 * arg)) >> 32)));
            case 0x11: return new("double", BitConverter.Int64BitsToDouble((long)(Raw(ref at, arg, false) << (56 - 8 * arg))));
            case 0x15: return new("method_type", Proto((int)Raw(ref at, arg, false)).Descriptor);
            case 0x16: return new("method_handle", $"method_handle {Raw(ref at, arg, false)}");
            case 0x17: return new("string", String((int)Raw(ref at, arg, false)));
            case 0x18: return new("type", Type((int)Raw(ref at, arg, false)));
            case 0x19: return new("field", Field((int)Raw(ref at, arg, false)).Descriptor);
            case 0x1a: return new("method", Method((int)Raw(ref at, arg, false)).Descriptor);
            case 0x1b: return new("enum", Field((int)Raw(ref at, arg, false)).Descriptor);
            case 0x1c:
            {
                uint size = Uleb(ref at);
                var items = new List<DexValue>();
                for (int i = 0; i < size && i < 65_536 && at < _d.Length; i++) items.Add(Value(ref at, depth + 1));
                return new("array", items);
            }
            case 0x1d: return new("annotation", EncodedAnnotation(ref at, depth + 1));
            case 0x1e: return new("null", null);
            case 0x1f: return new("boolean", arg != 0);
            default:
                _issues.Add(new("dex", $"unknown encoded value type 0x{type:x2}", at - 1));
                at = _d.Length; // the rest of this value cannot be sized
                return new("null", null);
        }
    }

    /// <summary>arg + 1 little-endian bytes, sign-extended when <paramref name="signed"/>.</summary>
    private ulong Raw(ref long at, int arg, bool signed)
    {
        int n = arg + 1;
        ulong v = 0;
        for (int k = 0; k < n && at < _d.Length; k++) v |= (ulong)_d[at++] << (8 * k);
        if (signed && n < 8) v = (ulong)((long)(v << (64 - 8 * n)) >> (64 - 8 * n));
        return v;
    }

    /// <summary>A float or double as Java's toString writes it: 1.0, 0.001, 1.0E7, NaN, -Infinity.</summary>
    public static string JavaNumber(double v)
    {
        if (double.IsNaN(v)) return "NaN";
        if (double.IsInfinity(v)) return v > 0 ? "Infinity" : "-Infinity";
        var a = Math.Abs(v);
        if (a == 0 || (a >= 1e-3 && a < 1e7))
        {
            var s = v.ToString("R", CultureInfo.InvariantCulture);
            return s.Contains('.', StringComparison.Ordinal) || s.Contains('E', StringComparison.Ordinal) ? s : s + ".0";
        }
        // Shortest round-trip digits as d.ddddE-n, with at least one fraction digit.
        var (digits, exp) = Shortest(a);
        return (v < 0 ? "-" : "") + digits[0] + "." + (digits.Length > 1 ? digits[1..] : "0") + "E" + exp.ToString(CultureInfo.InvariantCulture);
    }

    /// <summary>The shortest round-trip significant digits of a positive number and the exponent of its first digit.</summary>
    public static (string Digits, int Exponent) Shortest(double a)
    {
        var s = a.ToString("R", CultureInfo.InvariantCulture);
        int exp = 0, e = s.IndexOfAny(['E', 'e']);
        if (e >= 0) { exp = int.Parse(s[(e + 1)..], CultureInfo.InvariantCulture); s = s[..e]; }
        int dot = s.IndexOf('.', StringComparison.Ordinal);
        int intDigits = dot >= 0 ? dot : s.Length;
        var all = dot >= 0 ? s.Remove(dot, 1) : s;
        int lead = 0;
        while (lead < all.Length - 1 && all[lead] == '0') lead++;
        var digits = all[lead..].TrimEnd('0');
        return (digits.Length == 0 ? "0" : digits, exp + intDigits - lead - 1);
    }

    public static string JavaNumber(float v) =>
        float.IsNaN(v) || float.IsInfinity(v) ? JavaNumber((double)v) : JavaNumber(double.Parse(v.ToString("R", CultureInfo.InvariantCulture), CultureInfo.InvariantCulture));

    /// <summary>Smali string escaping.</summary>
    public static string Escape(string s)
    {
        var sb = new StringBuilder(s.Length);
        foreach (var c in s)
            sb.Append(c switch
            {
                '"' => "\\\"", '\\' => "\\\\", '\'' => "\\'", '\n' => "\\n", '\r' => "\\r", '\t' => "\\t",
                < ' ' or > '~' => @"\u" + ((int)c).ToString("x4", CultureInfo.InvariantCulture),
                _ => c.ToString(),
            });
        return sb.ToString();
    }

    /// <summary>"Lcom/a/B$C;" as "com.a.B$C"; arrays and primitives as Java writes them.</summary>
    public static string JavaName(string descriptor)
    {
        int dims = 0;
        while (dims < descriptor.Length && descriptor[dims] == '[') dims++;
        var element = descriptor[dims..];
        var name = element switch
        {
            "V" => "void", "Z" => "boolean", "B" => "byte", "S" => "short", "C" => "char", "I" => "int", "J" => "long", "F" => "float", "D" => "double",
            _ when element.StartsWith('L') && element.EndsWith(';') => element[1..^1].Replace('/', '.'),
            _ => element,
        };
        return name + string.Concat(Enumerable.Repeat("[]", dims));
    }

    /// <summary>Java access modifiers for a class (0), field (1) or method (2).</summary>
    public static string Access(uint flags, int kind)
    {
        var names = new List<string>();
        (uint, string)[] all =
        [
            (0x1, "public"), (0x2, "private"), (0x4, "protected"), (0x8, "static"), (0x10, "final"), (0x20, kind == 2 ? "synchronized" : ""),
            (0x40, kind == 1 ? "volatile" : kind == 2 ? "bridge" : ""), (0x80, kind == 1 ? "transient" : kind == 2 ? "varargs" : ""),
            (0x100, kind == 2 ? "native" : ""), (0x200, kind == 0 ? "interface" : ""), (0x400, "abstract"), (0x800, kind == 2 ? "strictfp" : ""),
            (0x1000, "synthetic"), (0x2000, kind == 0 ? "annotation" : ""), (0x4000, kind != 2 ? "enum" : ""), (0x10000, kind == 2 ? "constructor" : ""),
            (0x20000, kind == 2 ? "declared-synchronized" : ""),
        ];
        foreach (var (bit, name) in all)
            if ((flags & bit) != 0 && name.Length > 0) names.Add(name);
        return string.Join(' ', names);
    }
}
