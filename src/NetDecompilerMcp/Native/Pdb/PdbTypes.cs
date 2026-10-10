using System.Buffers.Binary;
using System.Text;

namespace NetDecompilerMcp.Native.Pdb;

/// <summary>
/// C declarations of a PDB's types for an engine without a PDB loader of its own: structs, classes and unions (data
/// members, base subobjects and the vftable pointer at the offsets the PDB records, bit fields, gaps padded), enums,
/// the S_UDT type names that differ from their tag (typedefs), and a prototype per procedure with an address.
/// Declared under <c>#pragma pack(push, 1)</c> with explicit padding, so every offset and size is the PDB's.
/// <see cref="Records"/>: type records read from the TPI stream; <see cref="Skipped"/>: members and records left out,
/// by reason (unsupported_leaf, overlapping_member, member_type_unwritable, ...).
/// </summary>
public sealed record PdbTypeDeclarations(
    string Declarations,
    IReadOnlyList<(uint Rva, string Declaration)> Prototypes,
    int Structs,
    int Unions,
    int Enums,
    int Typedefs,
    int Records,
    IReadOnlyDictionary<string, int> Skipped,
    IReadOnlyList<string> Notes);

/// <summary>Reads the TPI (types) and IPI (ids) streams of a PDB and writes them as C declarations.</summary>
public sealed class PdbTypes
{
    private const int TpiStream = 2, IpiStream = 4;
    /// <summary>Most bytes of type records read per stream; most aggregates and prototypes written.</summary>
    public const int MaxStreamBytes = 1 << 30, MaxAggregates = 60_000, MaxPrototypes = 300_000;
    private const int MaxDepth = 48;

    private readonly Stream _tpi, _ipi;
    private readonly int _pointerSize;
    private readonly Dictionary<string, int> _skipped = [];
    private readonly List<string> _notes = [];

    /// <summary>A type stream: its records' bytes and where each record starts (index - first).</summary>
    private sealed class Stream(byte[] bytes, uint first, int[] offsets)
    {
        public readonly byte[] Bytes = bytes;
        public readonly uint First = first;
        public readonly int[] Offsets = offsets;

        public bool TryGet(uint index, out ushort kind, out ReadOnlySpan<byte> data)
        {
            kind = 0;
            data = default;
            if (index < First || index - First >= (uint)Offsets.Length) return false;
            int at = Offsets[index - First];
            int len = BinaryPrimitives.ReadUInt16LittleEndian(Bytes.AsSpan(at));
            kind = BinaryPrimitives.ReadUInt16LittleEndian(Bytes.AsSpan(at + 2));
            data = Bytes.AsSpan(at + 4, len - 2);
            return true;
        }
    }

    private PdbTypes(Stream tpi, Stream ipi, int pointerSize)
    {
        _tpi = tpi;
        _ipi = ipi;
        _pointerSize = pointerSize;
    }

    /// <summary>
    /// The declarations for <paramref name="pdb"/> (read again from its file for the type streams); the image's
    /// pointer size decides simple pointer types. Malformed records are skipped and counted, never thrown.
    /// </summary>
    public static PdbTypeDeclarations Build(PdbFile pdb, int pointerSize, CancellationToken ct = default)
    {
        using var msf = MsfFile.Open(pdb.Path);
        var notes = new List<string>();
        var tpi = ReadStream(msf, TpiStream, "TPI", notes, ct);
        var ipi = ReadStream(msf, IpiStream, "IPI", notes, ct);
        var types = new PdbTypes(tpi, ipi, pointerSize);
        types._notes.AddRange(notes);
        return types.Write(pdb, ct);
    }

    private static Stream ReadStream(MsfFile msf, int index, string label, List<string> notes, CancellationToken ct)
    {
        var empty = new Stream([], 0x1000, []);
        long size = msf.StreamSize(index);
        if (size < 56)
        {
            if (index == TpiStream) notes.Add($"the {label} stream is missing or shorter than its header: no types");
            return empty;
        }
        if (size > MaxStreamBytes)
        {
            notes.Add($"the {label} stream has {size:N0} bytes; types past {MaxStreamBytes:N0} are not read");
            size = MaxStreamBytes;
        }
        var bytes = new byte[size];
        int got = msf.Read(index, 0, bytes);
        var h = bytes.AsSpan(0, got);
        uint headerSize = BinaryPrimitives.ReadUInt32LittleEndian(h[4..]);
        uint first = BinaryPrimitives.ReadUInt32LittleEndian(h[8..]);
        uint last = BinaryPrimitives.ReadUInt32LittleEndian(h[12..]);
        if (headerSize < 56 || headerSize > got || first < 0x1000 || last < first || last - first > 50_000_000)
        {
            notes.Add($"the {label} stream header is not valid (header {headerSize} bytes, indices 0x{first:X}-0x{last:X}): its types are not read");
            return empty;
        }
        var offsets = new List<int>((int)(last - first));
        int at = (int)headerSize;
        while (at + 4 <= got && offsets.Count < last - first)
        {
            if ((offsets.Count & 0xFFFF) == 0) ct.ThrowIfCancellationRequested();
            int len = BinaryPrimitives.ReadUInt16LittleEndian(h[at..]);
            if (len < 2 || at + 2 + len > got)
            {
                notes.Add($"the {label} record 0x{first + offsets.Count:X} at 0x{at:X} (length {len}) runs past the stream; later records are not read");
                break;
            }
            offsets.Add(at);
            at += 2 + len;
        }
        return new Stream(bytes, first, [.. offsets]);
    }

    private void Skip(string reason) => _skipped[reason] = _skipped.GetValueOrDefault(reason) + 1;

    // ---- leaf decoding ----

    private const ushort LF_MODIFIER = 0x1001, LF_POINTER = 0x1002, LF_PROCEDURE = 0x1008, LF_MFUNCTION = 0x1009, LF_ARGLIST = 0x1201,
        LF_FIELDLIST = 0x1203, LF_BITFIELD = 0x1205, LF_ARRAY = 0x1503, LF_CLASS = 0x1504, LF_STRUCTURE = 0x1505, LF_UNION = 0x1506,
        LF_ENUM = 0x1507, LF_INTERFACE = 0x1519, LF_CLASS2 = 0x1608, LF_STRUCTURE2 = 0x1609, LF_UNION2 = 0x160A, LF_INTERFACE2 = 0x160B,
        LF_FUNC_ID = 0x1601, LF_MFUNC_ID = 0x1602;

    /// <summary>A numeric leaf at <paramref name="at"/>; advances past it. False when it is not a plain integer.</summary>
    private static bool Numeric(ReadOnlySpan<byte> d, ref int at, out long value)
    {
        value = 0;
        if (at + 2 > d.Length) return false;
        ushort v = BinaryPrimitives.ReadUInt16LittleEndian(d[at..]);
        at += 2;
        if (v < 0x8000) { value = v; return true; }
        int size = v switch { 0x8000 => 1, 0x8001 or 0x8002 => 2, 0x8003 or 0x8004 => 4, 0x8009 or 0x800A => 8, _ => 0 };
        if (size == 0 || at + size > d.Length) return false;
        var s = d.Slice(at, size);
        value = v switch
        {
            0x8000 => (sbyte)s[0],
            0x8001 => BinaryPrimitives.ReadInt16LittleEndian(s),
            0x8002 => BinaryPrimitives.ReadUInt16LittleEndian(s),
            0x8003 => BinaryPrimitives.ReadInt32LittleEndian(s),
            0x8004 => BinaryPrimitives.ReadUInt32LittleEndian(s),
            _ => BinaryPrimitives.ReadInt64LittleEndian(s),
        };
        at += size;
        return true;
    }

    private static string Str(ReadOnlySpan<byte> d, ref int at)
    {
        if (at >= d.Length) return "";
        var rest = d[at..];
        int len = rest.IndexOf((byte)0);
        if (len < 0) len = rest.Length;
        at += len + 1;
        return Encoding.UTF8.GetString(rest[..Math.Min(len, PdbLimits.MaxNameLength)]);
    }

    private static uint U32(ReadOnlySpan<byte> d, int at) => at + 4 <= d.Length ? BinaryPrimitives.ReadUInt32LittleEndian(d[at..]) : 0;
    private static ushort U16(ReadOnlySpan<byte> d, int at) => at + 2 <= d.Length ? BinaryPrimitives.ReadUInt16LittleEndian(d[at..]) : (ushort)0;

    /// <summary>A struct, class, union or enum record.</summary>
    private sealed record Aggregate(uint Index, ushort Kind, string Name, string? UniqueName, bool Forward, uint FieldList, long Size, uint Underlying)
    {
        public bool IsUnion => Kind is LF_UNION or LF_UNION2;
        public bool IsEnum => Kind == LF_ENUM;
    }

    private Aggregate? ReadAggregate(uint index)
    {
        if (!_tpi.TryGet(index, out var kind, out var d)) return null;
        int at;
        ushort property;
        uint field, underlying = 0;
        long size = 0;
        switch (kind)
        {
            case LF_CLASS or LF_STRUCTURE or LF_INTERFACE:
                if (d.Length < 18) return null;
                property = U16(d, 2);
                field = U32(d, 4);
                at = 16;
                if (!Numeric(d, ref at, out size)) return null;
                break;
            case LF_CLASS2 or LF_STRUCTURE2 or LF_INTERFACE2:
                // property (32-bit), field list, derived, vshape, member count, then the size
                if (d.Length < 20) return null;
                property = (ushort)U32(d, 0);
                field = U32(d, 4);
                at = 18;
                if (!Numeric(d, ref at, out size)) return null;
                break;
            case LF_UNION:
                if (d.Length < 10) return null;
                property = U16(d, 2);
                field = U32(d, 4);
                at = 8;
                if (!Numeric(d, ref at, out size)) return null;
                break;
            case LF_UNION2:
                if (d.Length < 12) return null;
                property = (ushort)U32(d, 0);
                field = U32(d, 4);
                at = 10;
                if (!Numeric(d, ref at, out size)) return null;
                break;
            case LF_ENUM:
                if (d.Length < 12) return null;
                property = U16(d, 2);
                underlying = U32(d, 4);
                field = U32(d, 8);
                at = 12;
                break;
            default:
                return null;
        }
        string name = Str(d, ref at);
        string? unique = (property & 0x200) != 0 ? Str(d, ref at) : null;
        return new Aggregate(index, kind, name, unique, (property & 0x80) != 0, field, size, underlying);
    }

    // ---- simple types ----

    private static string? SimpleName(uint kind) => kind switch
    {
        0x03 => "void",
        0x08 => "int", // HRESULT
        0x10 or 0x70 => "char",
        0x20 or 0x69 or 0x7C => "unsigned char",
        0x68 => "signed char",
        0x71 => "wchar_t",
        0x7A or 0x11 or 0x72 => kind == 0x7A ? "unsigned short" : "short",
        0x7B => "unsigned int",
        0x21 or 0x73 => "unsigned short",
        0x12 => "long",
        0x22 => "unsigned long",
        0x74 => "int",
        0x75 => "unsigned int",
        0x13 or 0x76 => "__int64",
        0x23 or 0x77 => "unsigned __int64",
        0x14 or 0x78 => "__int128",
        0x24 or 0x79 => "unsigned __int128",
        0x30 => "bool",
        0x31 => "unsigned short",
        0x32 => "unsigned int",
        0x33 => "unsigned __int64",
        0x40 => "float",
        0x41 => "double",
        0x42 => "long double",
        0x46 => "unsigned short", // 16-bit float
        _ => null,
    };

    private static int SimpleSize(uint kind) => kind switch
    {
        0x03 => 0,
        0x10 or 0x20 or 0x68 or 0x69 or 0x70 or 0x7C or 0x30 => 1,
        0x11 or 0x21 or 0x71 or 0x72 or 0x73 or 0x7A or 0x31 or 0x46 => 2,
        0x08 or 0x12 or 0x22 or 0x74 or 0x75 or 0x7B or 0x32 or 0x40 => 4,
        0x13 or 0x23 or 0x76 or 0x77 or 0x33 or 0x41 => 8,
        0x42 => 10,
        0x14 or 0x24 or 0x78 or 0x79 => 16,
        _ => -1,
    };

    // ---- names ----

    private readonly Dictionary<uint, string> _identOf = [];
    private readonly HashSet<string> _idents = new(StringComparer.Ordinal);
    private readonly Dictionary<string, uint> _definitionByName = new(StringComparer.Ordinal);
    private readonly Dictionary<uint, uint> _resolved = [];

    private static string Identifier(string name)
    {
        var sb = new StringBuilder(name.Length);
        foreach (char c in name)
        {
            bool ok = char.IsAsciiLetterOrDigit(c) || c == '_';
            if (ok) sb.Append(c);
            else if (sb.Length > 0 && sb[^1] != '_') sb.Append('_');
        }
        var s = sb.ToString().TrimEnd('_');
        if (s.Length == 0) return "anon";
        if (char.IsAsciiDigit(s[0])) s = "_" + s;
        return Keywords.Contains(s) ? s + "_" : s;
    }

    /// <summary>C and C++ keywords and the engine's type words: not usable as names in a declaration.</summary>
    private static readonly HashSet<string> Keywords = new(StringComparer.Ordinal)
    {
        "alignas", "alignof", "and", "and_eq", "asm", "auto", "bitand", "bitor", "bool", "break", "case", "catch", "char", "char8_t", "char16_t",
        "char32_t", "class", "compl", "concept", "const", "consteval", "constexpr", "constinit", "const_cast", "continue", "co_await", "co_return",
        "co_yield", "decltype", "default", "delete", "do", "double", "dynamic_cast", "else", "enum", "explicit", "export", "extern", "false", "float",
        "for", "friend", "goto", "if", "inline", "int", "long", "mutable", "namespace", "new", "noexcept", "not", "not_eq", "nullptr", "operator",
        "or", "or_eq", "private", "protected", "public", "register", "reinterpret_cast", "requires", "restrict", "return", "short", "signed",
        "sizeof", "static", "static_assert", "static_cast", "struct", "switch", "template", "this", "thread_local", "throw", "true", "try",
        "typedef", "typeid", "typename", "union", "unsigned", "using", "virtual", "void", "volatile", "wchar_t", "while", "xor", "xor_eq",
        "_Bool", "_Complex", "_Imaginary", "_Alignas", "_Alignof", "_Atomic", "_Generic", "_Noreturn", "_Static_assert", "_Thread_local",
        "__int8", "__int16", "__int32", "__int64", "__int128", "__cdecl", "__stdcall", "__fastcall", "__thiscall", "__vectorcall", "__usercall",
        "__userpurge", "__pascal", "__ptr32", "__ptr64", "__unaligned", "__restrict", "__declspec", "__hidden", "__return_ptr", "__struct_ptr",
        "__array_ptr", "__spoils", "__shifted", "__near", "__far", "__huge", "__based", "__sptr", "__uptr", "__w64", "__int3264", "__export",
        "__import", "_BYTE", "_WORD", "_DWORD", "_QWORD", "_OWORD", "_TBYTE", "_UNKNOWN", "_BOOL1", "_BOOL2", "_BOOL4", "_BOOL8",
    };

    private static bool Unnamed(string name) =>
        name.Length == 0 || name.Contains("<unnamed-", StringComparison.Ordinal) || name.Contains("<anonymous-", StringComparison.Ordinal) ||
        name.StartsWith("__unnamed", StringComparison.Ordinal);

    /// <summary>The definition a (possibly forward) aggregate record stands for; the record itself when it is one; null when none is in the PDB.</summary>
    private Aggregate? Definition(uint index)
    {
        if (_resolved.TryGetValue(index, out var def)) return def == 0 ? null : ReadAggregate(def);
        var a = ReadAggregate(index);
        uint result = 0;
        if (a != null)
        {
            if (!a.Forward) result = index;
            else if (_definitionByName.TryGetValue(Key(a), out var d)) result = d;
        }
        _resolved[index] = result;
        return result == 0 ? null : ReadAggregate(result);
    }

    private static string Key(Aggregate a) => (a.IsEnum ? "e:" : a.IsUnion ? "u:" : "s:") + (a.UniqueName ?? a.Name);

    private string IdentOf(Aggregate a)
    {
        if (_identOf.TryGetValue(a.Index, out var id)) return id;
        var basis = Unnamed(a.Name) ? $"anon_{a.Index:X}" : Identifier(a.Name);
        id = basis;
        for (int i = 2; !_idents.Add(id); i++) id = $"{basis}_{i}";
        _identOf[a.Index] = id;
        return id;
    }

    // ---- sizes and declarators ----

    private long SizeOf(uint index, int depth = 0)
    {
        if (depth > MaxDepth) return -1;
        if (index < 0x1000)
        {
            uint mode = (index >> 8) & 0xF;
            if (mode != 0) return mode is 4 or 5 ? 4 : mode == 6 ? 8 : mode is 1 or 2 ? 2 : _pointerSize;
            return SimpleSize(index & 0xFF);
        }
        if (!_tpi.TryGet(index, out var kind, out var d)) return -1;
        switch (kind)
        {
            case LF_MODIFIER: return SizeOf(U32(d, 0), depth + 1);
            case LF_POINTER:
                uint bytes = (U32(d, 4) >> 13) & 0x3F;
                return bytes > 0 ? bytes : _pointerSize;
            case LF_BITFIELD: return SizeOf(U32(d, 0), depth + 1);
            case LF_ARRAY:
                int at = 8;
                return d.Length >= 10 && Numeric(d, ref at, out var size) ? size : -1;
            case LF_ENUM:
                return Definition(index) is { } e ? SizeOf(e.Underlying, depth + 1) : -1;
            case LF_CLASS or LF_STRUCTURE or LF_INTERFACE or LF_UNION or LF_CLASS2 or LF_STRUCTURE2 or LF_INTERFACE2 or LF_UNION2:
                return Definition(index)?.Size ?? -1;
            default: return -1;
        }
    }

    private static string Join(string type, string declarator) => declarator.Length == 0 ? type : type.EndsWith('*') ? type + declarator : $"{type} {declarator}";

    private static string CallingConvention(byte cc) => cc switch
    {
        0x04 => "__fastcall",
        0x07 => "__stdcall",
        0x0B => "__thiscall",
        0x18 => "__vectorcall",
        _ => "__cdecl",
    };

    /// <summary>
    /// <paramref name="declarator"/> declared with type <paramref name="index"/> ("int *x", "struct S (*p)[4]"); null
    /// when the type cannot be written (unsupported leaf, a struct without a definition used by value).
    /// <paramref name="thisName"/> names a member function's this parameter (prototypes only).
    /// </summary>
    private string? Declare(uint index, string declarator, int depth = 0, string? thisName = null)
    {
        if (depth > MaxDepth) return null;
        if (index < 0x1000)
        {
            uint mode = (index >> 8) & 0xF;
            var name = SimpleName(index & 0xFF);
            if (name == null) return index == 0 ? null : mode != 0 ? Join("void", "*" + declarator) : null;
            return mode != 0 ? Join(name, "*" + declarator) : Join(name, declarator);
        }
        if (!_tpi.TryGet(index, out var kind, out var d)) return null;
        switch (kind)
        {
            case LF_MODIFIER:
            {
                uint target = U32(d, 0);
                ushort attr = U16(d, 4);
                bool pointerTarget = target >= 0x1000 ? _tpi.TryGet(target, out var tk, out _) && tk == LF_POINTER : ((target >> 8) & 0xF) != 0;
                var inner = Declare(target, declarator, depth + 1);
                return inner == null || pointerTarget || (attr & 3) == 0 ? inner : ((attr & 1) != 0 ? "const " : "") + ((attr & 2) != 0 ? "volatile " : "") + inner;
            }
            case LF_POINTER:
            {
                uint attr = U32(d, 4);
                uint mode = (attr >> 5) & 7;
                if (mode is 2 or 3)
                {
                    // pointer to member: an integer of its size
                    long size = (attr >> 13) & 0x3F;
                    return size switch { 4 => Join("unsigned int", declarator), 8 => Join("unsigned __int64", declarator), _ => Join("unsigned char", $"{declarator}[{Math.Max(1, size)}]") };
                }
                return Declare(U32(d, 0), "*" + declarator, depth + 1) ?? Join("void", "*" + declarator);
            }
            case LF_ARRAY:
            {
                uint element = U32(d, 0);
                int at = 8;
                if (d.Length < 10 || !Numeric(d, ref at, out var bytes)) return null;
                long es = SizeOf(element, depth + 1);
                if (es <= 0) return null;
                var inner = declarator.StartsWith('*') ? $"({declarator})" : declarator;
                return Declare(element, $"{inner}[{bytes / es}]", depth + 1);
            }
            case LF_CLASS or LF_STRUCTURE or LF_INTERFACE or LF_UNION or LF_CLASS2 or LF_STRUCTURE2 or LF_INTERFACE2 or LF_UNION2:
            {
                var a = Definition(index) ?? ReadAggregate(index);
                if (a == null) return null;
                if (Definition(index) == null)
                {
                    // only a forward declaration: pointers to it work, values do not
                    if (!declarator.StartsWith('*')) return null;
                    return Join("void", declarator);
                }
                Use(a);
                return Join((a.IsUnion ? "union " : "struct ") + IdentOf(a), declarator);
            }
            case LF_ENUM:
            {
                var a = Definition(index);
                if (a == null) return SizeOf(index) is var s and > 0 ? Join(IntOfSize(s), declarator) : Join("int", declarator);
                Use(a);
                return Join("enum " + IdentOf(a), declarator);
            }
            case LF_PROCEDURE or LF_MFUNCTION:
            {
                bool member = kind == LF_MFUNCTION;
                uint ret = U32(d, 0);
                uint thisType = member ? U32(d, 8) : 0;
                byte cc = member ? (d.Length > 12 ? d[12] : (byte)0) : (d.Length > 4 ? d[4] : (byte)0);
                uint argList = member ? U32(d, 16) : U32(d, 8);
                var args = new List<string>();
                if (member && thisType != 0)
                    args.Add(Declare(thisType, thisName ?? "", depth + 1) ?? Join("void", "*" + (thisName ?? "")));
                if (_tpi.TryGet(argList, out var ak, out var ad) && ak == LF_ARGLIST)
                {
                    uint count = U32(ad, 0);
                    for (int i = 0; i < count && 4 + 4 * i + 4 <= ad.Length; i++)
                    {
                        uint t = U32(ad, 4 + 4 * i);
                        if (t == 0) { args.Add("..."); continue; }
                        args.Add(Declare(t, "", depth + 1) ?? (SizeOf(t) is var s and > 0 ? IntOfSize(s) : "int"));
                    }
                }
                if (args.Count == 0) args.Add("void");
                // C has no "f(...)": an empty list leaves the arguments unspecified
                else if (args is ["..."]) args.Clear();
                var inner = declarator.StartsWith('*') ? $"({CallingConvention(cc)} {declarator})" : $"{CallingConvention(cc)} {declarator}".TrimEnd();
                return Declare(ret, $"{inner}({string.Join(", ", args)})", depth + 1) ?? Join("int", $"{inner}({string.Join(", ", args)})");
            }
            default:
                return null;
        }
    }

    private static string IntOfSize(long size) => size switch { 1 => "unsigned char", 2 => "unsigned short", 8 => "unsigned __int64", _ => "unsigned int" };

    // ---- aggregates ----

    private readonly HashSet<uint> _used = [];
    private readonly Queue<uint> _pending = new();

    private void Use(Aggregate a)
    {
        if (_used.Add(a.Index)) _pending.Enqueue(a.Index);
    }

    private sealed record Member(long Offset, string Name, uint Type, int BitLength = -1, int BitPosition = 0, bool Base = false);

    /// <summary>The data members, base subobjects and vftable pointer of a field list (continuations followed).</summary>
    private List<Member> Members(Aggregate a, out List<(string Name, long Value)> enumerators)
    {
        var members = new List<Member>();
        enumerators = [];
        var seen = new HashSet<uint>();
        bool vfptr = false;
        for (uint list = a.FieldList; list != 0 && seen.Add(list);)
        {
            if (!_tpi.TryGet(list, out var kind, out var d) || kind != LF_FIELDLIST) { Skip("bad_field_list"); break; }
            uint next = 0;
            int at = 0;
            while (at + 2 <= d.Length)
            {
                if (d[at] >= 0xF0) { at += d[at] & 0x0F; continue; } // padding to 4
                ushort leaf = U16(d, at);
                at += 2;
                switch (leaf)
                {
                    case 0x150D: // LF_MEMBER: attr, type, offset, name
                    {
                        uint type = U32(d, at + 2);
                        at += 6;
                        if (!Numeric(d, ref at, out var offset)) goto bad;
                        string name = Str(d, ref at);
                        if (_tpi.TryGet(type, out var tk, out var td) && tk == LF_BITFIELD && td.Length >= 6)
                            members.Add(new Member(offset, name, U32(td, 0), td[4], td[5]));
                        else members.Add(new Member(offset, name, type));
                        break;
                    }
                    case 0x1502: // LF_ENUMERATE: attr, value, name
                    {
                        at += 2;
                        if (!Numeric(d, ref at, out var value)) goto bad;
                        enumerators.Add((Str(d, ref at), value));
                        break;
                    }
                    case 0x1400: // LF_BCLASS: attr, type, offset
                    {
                        uint type = U32(d, at + 2);
                        at += 6;
                        if (!Numeric(d, ref at, out var offset)) goto bad;
                        members.Add(new Member(offset, $"baseclass_{offset:X}", type, Base: true));
                        break;
                    }
                    case 0x1401 or 0x1402: // LF_VBCLASS / LF_IVBCLASS: attr, base, vbptr type, vbptr offset, vbtable index
                    {
                        at += 10;
                        if (!Numeric(d, ref at, out _) || !Numeric(d, ref at, out _)) goto bad;
                        Skip("virtual_base");
                        break;
                    }
                    case 0x1409: // LF_VFUNCTAB: pad, type
                        at += 6;
                        vfptr = true;
                        break;
                    case 0x150E: // LF_STMEMBER: attr, type, name
                        at += 6;
                        Str(d, ref at);
                        break;
                    case 0x150F: // LF_METHOD: count, method list, name
                        at += 6;
                        Str(d, ref at);
                        break;
                    case 0x1511: // LF_ONEMETHOD: attr, type, [vbaseoff when introducing virtual], name
                    {
                        ushort attr = U16(d, at);
                        at += 6;
                        if (((attr >> 2) & 7) is 4 or 6) at += 4;
                        Str(d, ref at);
                        break;
                    }
                    case 0x1510 or 0x1512: // LF_NESTTYPE / LF_NESTTYPEEX: pad or attr, type, name
                        at += 6;
                        Str(d, ref at);
                        break;
                    case 0x140B or 0x150C: // LF_FRIENDCLS: pad, type / LF_FRIENDFCN: pad, type, name
                        at += 6;
                        if (leaf == 0x150C) Str(d, ref at);
                        break;
                    case 0x1404: // LF_INDEX: pad, continuation field list
                        next = U32(d, at + 2);
                        at += 6;
                        break;
                    case 0x140C: // LF_VFUNCOFF: pad, type, offset
                        at += 10;
                        break;
                    default:
                        Skip("unsupported_leaf");
                        goto done;
                }
                continue;
            bad:
                Skip("malformed_member");
                goto done;
            }
        done:
            list = next;
        }
        // the class introduces a vftable pointer: at offset 0 unless a base subobject there holds one
        if (vfptr && !members.Any(m => m.Base && m.Offset == 0))
            members.Insert(0, new Member(0, "__vftable", _pointerSize == 4 ? 0x0403u : 0x0603u)); // T_32PVOID / T_64PVOID
        return members;
    }

    /// <summary>The body of a struct or union, its by-value dependencies collected into <paramref name="needs"/>.</summary>
    private string? Body(Aggregate a, HashSet<uint> needs)
    {
        var members = Members(a, out _);
        var sb = new StringBuilder();
        var names = new HashSet<string>(StringComparer.Ordinal);
        string Unique(string name)
        {
            var basis = Unnamed(name) || name.Length == 0 ? "field" : Identifier(name);
            var n = basis;
            for (int i = 2; !names.Add(n); i++) n = $"{basis}_{i}";
            return n;
        }
        void Need(uint type)
        {
            // the aggregate a member holds by value (through modifiers and arrays)
            for (int depth = 0; depth < MaxDepth && type >= 0x1000 && _tpi.TryGet(type, out var k, out var d); depth++)
            {
                if (k == LF_MODIFIER) type = U32(d, 0);
                else if (k == LF_ARRAY) type = U32(d, 0);
                else
                {
                    if (Definition(type) is { IsEnum: false } def) needs.Add(def.Index);
                    return;
                }
            }
        }
        string Plain(Member m, string name)
        {
            var decl = Declare(m.Type, name);
            if (decl != null) { Need(m.Type); return decl; }
            Skip("member_type_unwritable");
            long size = SizeOf(m.Type);
            return size > 0 ? $"unsigned char {name}[{size}]" : $"unsigned char {name}[1]";
        }

        if (a.IsUnion)
        {
            long largest = 0;
            foreach (var m in members.Where(m => m.Offset == 0))
            {
                if (m.BitLength >= 0)
                {
                    sb.Append("  ").Append(Declare(m.Type, "") ?? "unsigned int").Append(' ').Append(Unique(m.Name)).Append(" : ").Append(m.BitLength).Append(";\n");
                    largest = Math.Max(largest, SizeOf(m.Type));
                    continue;
                }
                sb.Append("  ").Append(Plain(m, Unique(m.Name))).Append(";\n");
                largest = Math.Max(largest, SizeOf(m.Type));
            }
            if (members.Any(m => m.Offset != 0)) Skip("overlapping_member");
            if (a.Size > largest) sb.Append($"  unsigned char __size[{a.Size}];\n");
            return sb.Length == 0 ? null : sb.ToString();
        }

        long end = 0;
        int pad = 0;
        var ordered = members.Select((m, i) => (m, i)).OrderBy(x => x.m.Offset).ThenBy(x => x.i).Select(x => x.m).ToList();
        for (int i = 0; i < ordered.Count; i++)
        {
            var m = ordered[i];
            if (m.Offset < end || m.Offset < 0) { Skip("overlapping_member"); continue; }
            if (m.Offset > end) sb.Append($"  unsigned char __pad{pad++}[{m.Offset - end}];\n");
            if (m.BitLength >= 0)
            {
                // the bit fields sharing this storage unit, in bit order, unused bits as unnamed fields
                long unitSize = SizeOf(m.Type);
                if (unitSize <= 0) { Skip("member_type_unwritable"); continue; }
                var unitType = Declare(m.Type, "") ?? IntOfSize(unitSize);
                int bit = 0;
                var group = ordered.Skip(i).TakeWhile(x => x.Offset == m.Offset && x.BitLength >= 0 && x.Type == m.Type).OrderBy(x => x.BitPosition).ToList();
                foreach (var f in group)
                {
                    if (f.BitPosition < bit) { Skip("overlapping_member"); continue; }
                    if (f.BitPosition > bit) sb.Append($"  {unitType} : {f.BitPosition - bit};\n");
                    sb.Append($"  {unitType} {Unique(f.Name)} : {f.BitLength};\n");
                    bit = f.BitPosition + f.BitLength;
                }
                if (bit < unitSize * 8) sb.Append($"  {unitType} : {unitSize * 8 - bit};\n");
                i += group.Count - 1;
                end = m.Offset + unitSize;
                continue;
            }
            long size = SizeOf(m.Type);
            if (size < 0) { Skip("member_type_unwritable"); continue; }
            // a zero-length array is only valid as the last member
            if (size == 0 && m.Offset < a.Size) { Skip("zero_size_member"); continue; }
            sb.Append("  ").Append(Plain(m, Unique(m.Name))).Append(";\n");
            end = m.Offset + size;
        }
        if (a.Size > end) sb.Append($"  unsigned char __pad{pad}[{a.Size - end}];\n");
        return sb.Length == 0 ? null : sb.ToString();
    }

    private string EnumBody(Aggregate a, HashSet<string> enumerators)
    {
        Members(a, out var values);
        var sb = new StringBuilder();
        var id = IdentOf(a);
        foreach (var (name, value) in values)
        {
            // enumerator names are global in C: a clash takes the enum's name as prefix
            var n = Identifier(name);
            if (!enumerators.Add(n)) { n = $"{id}__{n}"; if (!enumerators.Add(n)) continue; }
            sb.Append($"  {n} = {value},\n");
        }
        return sb.ToString();
    }

    // ---- the whole PDB ----

    private PdbTypeDeclarations Write(PdbFile pdb, CancellationToken ct)
    {
        // definitions by name, for forward references
        for (uint i = 0; i < _tpi.Offsets.Length; i++)
        {
            if ((i & 0xFFFF) == 0) ct.ThrowIfCancellationRequested();
            if (ReadAggregate(_tpi.First + i) is { Forward: false } a)
                _definitionByName.TryAdd(Key(a), a.Index);
        }

        // prototypes of the procedures with addresses
        var prototypes = new List<(uint, string)>();
        var done = new HashSet<uint>();
        foreach (var s in pdb.Symbols)
        {
            if (s.Kind is not (PdbSymbolKind.GlobalProc or PdbSymbolKind.LocalProc) || s.Rva is not { } rva || s.TypeIndex == 0 || !done.Add(rva)) continue;
            if (prototypes.Count >= MaxPrototypes) { _notes.Add($"prototypes beyond {MaxPrototypes:N0} are not written"); break; }
            uint type = s.TypeIndex;
            // the _ID procedure kinds carry an IPI index (the linker normally rewrites them to TPI indices)
            if (!(_tpi.TryGet(type, out var tk0, out _) && tk0 is LF_PROCEDURE or LF_MFUNCTION) && _ipi.TryGet(type, out var ik, out var id) && ik is LF_FUNC_ID or LF_MFUNC_ID)
                type = U32(id, 4);
            if (!_tpi.TryGet(type, out var k, out _) || k is not (LF_PROCEDURE or LF_MFUNCTION)) { Skip("prototype_not_a_function_type"); continue; }
            var decl = Declare(type, "f", thisName: "this");
            if (decl == null) { Skip("prototype_unwritable"); continue; }
            prototypes.Add((rva, decl + ";"));
        }

        // S_UDT names: tags are emitted as used, names differing from their tag become typedefs
        var typedefs = new List<string>();
        foreach (var t in pdb.Typedefs)
        {
            if (typedefs.Count >= MaxAggregates) break;
            if (t.TypeIndex >= 0x1000 && Definition(t.TypeIndex) is { } a && !Unnamed(a.Name) && Identifier(t.Name) == Identifier(a.Name))
            {
                if (_used.Count < MaxAggregates) Use(a);
                continue;
            }
            var name = Identifier(t.Name);
            if (!_idents.Add(name)) continue;
            var decl = Declare(t.TypeIndex, name);
            if (decl == null) { _idents.Remove(name); Skip("typedef_unwritable"); continue; }
            typedefs.Add($"typedef {decl};");
        }

        // bodies of every aggregate used (a body can use more)
        var bodies = new Dictionary<uint, (string Text, HashSet<uint> Needs)>();
        var enums = new List<string>();
        var enumerators = new HashSet<string>(StringComparer.Ordinal);
        int structs = 0, unions = 0;
        while (_pending.Count > 0)
        {
            ct.ThrowIfCancellationRequested();
            var a = ReadAggregate(_pending.Dequeue())!;
            if (bodies.Count + enums.Count >= MaxAggregates) { _notes.Add($"types beyond {MaxAggregates:N0} are declared without members"); break; }
            if (a.IsEnum)
            {
                var underlying = Declare(a.Underlying, "") ?? "int";
                enums.Add($"enum {IdentOf(a)} : {underlying}\n{{\n{EnumBody(a, enumerators)}}};");
                continue;
            }
            var needs = new HashSet<uint>();
            var body = Body(a, needs);
            if (body == null) continue;
            bodies[a.Index] = (body, needs);
            if (a.IsUnion) unions++;
            else structs++;
        }

        // forward declarations, enums, then bodies with what they hold by value first
        var sb = new StringBuilder("#pragma pack(push, 1)\n");
        foreach (var index in _used)
            if (ReadAggregate(index) is { IsEnum: false } a) sb.Append(a.IsUnion ? "union " : "struct ").Append(IdentOf(a)).Append(";\n");
        foreach (var e in enums) sb.Append(e).Append('\n');
        var emitted = new HashSet<uint>();
        var visiting = new HashSet<uint>();
        void Emit(uint index, int depth)
        {
            if (emitted.Contains(index) || !bodies.TryGetValue(index, out var b) || !visiting.Add(index)) return;
            // nesting by value deeper than this is not real code: the rest of the chain follows in table order
            if (depth < 256)
                foreach (var n in b.Needs) Emit(n, depth + 1);
            visiting.Remove(index);
            emitted.Add(index);
            var a = ReadAggregate(index)!;
            sb.Append(a.IsUnion ? "union " : "struct ").Append(IdentOf(a)).Append("\n{\n").Append(b.Text).Append("};\n");
        }
        foreach (var index in bodies.Keys) Emit(index, 0);
        foreach (var t in typedefs) sb.Append(t).Append('\n');
        sb.Append("#pragma pack(pop)\n");
        return new PdbTypeDeclarations(sb.ToString(), prototypes, structs, unions, enums.Count, typedefs.Count, _tpi.Offsets.Length,
            new Dictionary<string, int>(_skipped), _notes);
    }
}
