using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Runtime.CompilerServices;
using System.Text;

namespace NetDecompilerMcp.Native.Pdb;

public enum PdbTypeKind { Simple, Pointer, Modifier, Array, Struct, Class, Interface, Union, Enum, Procedure, MemberFunction, Bitfield, Other }

public enum PdbMemberKind { Data, Base, VirtualBase, Vfptr, Static }

/// <summary>
/// A member of a struct, class or union. <see cref="Offset"/> in bytes, -1 for static members and virtual bases (reached
/// through the vbtable); a bit field when <see cref="BitLength"/> &gt;= 0, <see cref="Type"/> then the storage unit's type.
/// </summary>
public sealed record PdbTypeMember(PdbMemberKind Kind, long Offset, string Name, uint Type, int BitLength = -1, int BitPosition = 0);

public sealed record PdbEnumerator(string Name, long Value);

/// <summary>A procedure or member function type; <see cref="Class"/> and <see cref="This"/> are 0 for a procedure or a static member.</summary>
public sealed record PdbFunctionType(uint Return, IReadOnlyList<uint> Parameters, bool Variadic, string Convention, uint Class, uint This);

/// <summary>
/// One type record. <see cref="Element"/>: the pointee, modified type, array element, enum's underlying type or bit field's
/// storage type; <see cref="Count"/>: array elements; <see cref="Size"/> -1 when unknown. <see cref="Name"/> is the PDB's
/// name for aggregates and enums, the C spelling for the others.
/// </summary>
public sealed record PdbTypeNode(
    uint Index,
    PdbTypeKind Kind,
    string Name,
    string? UniqueName,
    long Size,
    bool Forward,
    uint Element,
    long Count,
    bool Const,
    bool Volatile,
    bool Reference,
    IReadOnlyList<PdbTypeMember> Members,
    IReadOnlyList<PdbEnumerator> Enumerators,
    PdbFunctionType? Function,
    int BitLength = -1,
    int BitPosition = 0)
{
    public bool IsAggregate => Kind is PdbTypeKind.Struct or PdbTypeKind.Class or PdbTypeKind.Interface or PdbTypeKind.Union;
}

/// <summary>
/// The TPI (types) and IPI (ids) streams of a PDB as immutable nodes: aggregates with members, bases and bit fields,
/// enums, pointers, arrays, modifiers and function types; forward references resolve to their definition by
/// (unique) name. Malformed records are skipped, never thrown. Safe for concurrent readers.
/// </summary>
public sealed class PdbTypeModel
{
    private const int TpiStream = 2, IpiStream = 4;
    /// <summary>Most bytes of type records read per stream.</summary>
    public const int MaxStreamBytes = 1 << 30;
    internal const int MaxDepth = 48;

    internal const ushort LF_MODIFIER = 0x1001, LF_POINTER = 0x1002, LF_PROCEDURE = 0x1008, LF_MFUNCTION = 0x1009, LF_ARGLIST = 0x1201,
        LF_FIELDLIST = 0x1203, LF_BITFIELD = 0x1205, LF_ARRAY = 0x1503, LF_CLASS = 0x1504, LF_STRUCTURE = 0x1505, LF_UNION = 0x1506,
        LF_ENUM = 0x1507, LF_INTERFACE = 0x1519, LF_CLASS2 = 0x1608, LF_STRUCTURE2 = 0x1609, LF_UNION2 = 0x160A, LF_INTERFACE2 = 0x160B,
        LF_FUNC_ID = 0x1601, LF_MFUNC_ID = 0x1602;

    /// <summary>A type stream: its records' bytes and where each record starts (index - first).</summary>
    internal sealed class Stream(byte[] bytes, uint first, int[] offsets)
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

    internal readonly Stream Tpi, Ipi;
    public int PointerSize { get; }
    /// <summary>Why types were not read or read only in part.</summary>
    public IReadOnlyList<string> Notes { get; }
    /// <summary>Type records read from the TPI stream.</summary>
    public int Records => Tpi.Offsets.Length;
    public uint FirstIndex => Tpi.First;

    private readonly Dictionary<string, uint> _definitionByName = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<uint, uint> _resolved = new();
    private readonly Lazy<Dictionary<string, List<uint>>> _byName;

    private PdbTypeModel(Stream tpi, Stream ipi, int pointerSize, List<string> notes, CancellationToken ct)
    {
        Tpi = tpi;
        Ipi = ipi;
        PointerSize = pointerSize;
        Notes = notes;
        // definitions by name, for forward references
        for (uint i = 0; i < Tpi.Offsets.Length; i++)
        {
            if ((i & 0xFFFF) == 0) ct.ThrowIfCancellationRequested();
            if (ReadAggregate(Tpi.First + i) is { Forward: false } a)
                _definitionByName.TryAdd(Key(a), a.Index);
        }
        _byName = new(BuildNameIndex);
    }

    /// <summary>The types of <paramref name="pdb"/>, read again from its file; <paramref name="pointerSize"/> sizes simple pointer types.</summary>
    public static PdbTypeModel Read(PdbFile pdb, int pointerSize, CancellationToken ct = default)
    {
        var notes = new List<string>();
        Stream tpi, ipi;
        if (pdb.Path.Length == 0)
        {
            notes.Add("the PDB was read from memory: its type streams are not available");
            tpi = ipi = new Stream([], 0x1000, []);
        }
        else
        {
            using var msf = MsfFile.Open(pdb.Path);
            tpi = ReadStream(msf, TpiStream, "TPI", notes, ct);
            ipi = ReadStream(msf, IpiStream, "IPI", notes, ct);
        }
        return new PdbTypeModel(tpi, ipi, pointerSize, notes, ct);
    }

    private sealed class Cache
    {
        public readonly Lazy<PdbTypeModel>?[] Models = new Lazy<PdbTypeModel>?[2];
    }

    private static readonly ConditionalWeakTable<PdbFile, Cache> Models = new();

    /// <summary><see cref="Read"/>, kept for the lifetime of <paramref name="pdb"/>.</summary>
    public static PdbTypeModel Of(PdbFile pdb, int pointerSize)
    {
        var cache = Models.GetValue(pdb, _ => new Cache());
        int slot = pointerSize == 4 ? 0 : 1;
        Lazy<PdbTypeModel> lazy;
        lock (cache) lazy = cache.Models[slot] ??= new Lazy<PdbTypeModel>(() => Read(pdb, pointerSize));
        return lazy.Value;
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

    internal bool TryGet(uint index, out ushort kind, out ReadOnlySpan<byte> data) => Tpi.TryGet(index, out kind, out data);

    /// <summary>A numeric leaf at <paramref name="at"/>; advances past it. False when it is not a plain integer.</summary>
    internal static bool Numeric(ReadOnlySpan<byte> d, ref int at, out long value)
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

    internal static string Str(ReadOnlySpan<byte> d, ref int at)
    {
        if (at >= d.Length) return "";
        var rest = d[at..];
        int len = rest.IndexOf((byte)0);
        if (len < 0) len = rest.Length;
        at += len + 1;
        return Encoding.UTF8.GetString(rest[..Math.Min(len, PdbLimits.MaxNameLength)]);
    }

    internal static uint U32(ReadOnlySpan<byte> d, int at) => at + 4 <= d.Length ? BinaryPrimitives.ReadUInt32LittleEndian(d[at..]) : 0;
    internal static ushort U16(ReadOnlySpan<byte> d, int at) => at + 2 <= d.Length ? BinaryPrimitives.ReadUInt16LittleEndian(d[at..]) : (ushort)0;

    /// <summary>A struct, class, union or enum record.</summary>
    internal sealed record Aggregate(uint Index, ushort Kind, string Name, string? UniqueName, bool Forward, uint FieldList, long Size, uint Underlying)
    {
        public bool IsUnion => Kind is LF_UNION or LF_UNION2;
        public bool IsEnum => Kind == LF_ENUM;
    }

    internal Aggregate? ReadAggregate(uint index)
    {
        if (!Tpi.TryGet(index, out var kind, out var d)) return null;
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

    internal static string? SimpleName(uint kind) => kind switch
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

    internal static int SimpleSize(uint kind) => kind switch
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

    internal static bool Unnamed(string name) =>
        name.Length == 0 || name.Contains("<unnamed-", StringComparison.Ordinal) || name.Contains("<anonymous-", StringComparison.Ordinal) ||
        name.StartsWith("__unnamed", StringComparison.Ordinal);

    internal static string Key(Aggregate a) => (a.IsEnum ? "e:" : a.IsUnion ? "u:" : "s:") + (a.UniqueName ?? a.Name);

    /// <summary>The definition a (possibly forward) aggregate record stands for; the record itself when it is one; null when none is in the PDB.</summary>
    internal Aggregate? Definition(uint index)
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

    /// <summary>The definition of an aggregate or enum record (itself when it is one), 0 when the PDB has only forward references.</summary>
    public uint DefinitionOf(uint index) => Definition(index)?.Index ?? 0;

    /// <summary>Size in bytes; -1 when unknown.</summary>
    public long SizeOf(uint index, int depth = 0)
    {
        if (depth > MaxDepth) return -1;
        if (index < 0x1000)
        {
            uint mode = (index >> 8) & 0xF;
            if (mode != 0) return mode is 4 or 5 ? 4 : mode == 6 ? 8 : mode is 1 or 2 ? 2 : PointerSize;
            return SimpleSize(index & 0xFF);
        }
        if (!Tpi.TryGet(index, out var kind, out var d)) return -1;
        switch (kind)
        {
            case LF_MODIFIER: return SizeOf(U32(d, 0), depth + 1);
            case LF_POINTER:
                uint bytes = (U32(d, 4) >> 13) & 0x3F;
                return bytes > 0 ? bytes : PointerSize;
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

    /// <summary>
    /// The members of an aggregate's field list (continuations followed): data members, bases, virtual bases, static
    /// members and the vftable pointer the class introduces; enumerators for an enum. <paramref name="skipped"/> gets a
    /// reason per member or list not read.
    /// </summary>
    internal List<PdbTypeMember> Members(Aggregate a, out List<PdbEnumerator> enumerators, List<string>? skipped = null)
    {
        var members = new List<PdbTypeMember>();
        enumerators = [];
        var seen = new HashSet<uint>();
        bool vfptr = false;
        for (uint list = a.FieldList; list != 0 && seen.Add(list);)
        {
            if (!Tpi.TryGet(list, out var kind, out var d) || kind != LF_FIELDLIST) { skipped?.Add("bad_field_list"); break; }
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
                        if (Tpi.TryGet(type, out var tk, out var td) && tk == LF_BITFIELD && td.Length >= 6)
                            members.Add(new PdbTypeMember(PdbMemberKind.Data, offset, name, U32(td, 0), td[4], td[5]));
                        else members.Add(new PdbTypeMember(PdbMemberKind.Data, offset, name, type));
                        break;
                    }
                    case 0x1502: // LF_ENUMERATE: attr, value, name
                    {
                        at += 2;
                        if (!Numeric(d, ref at, out var value)) goto bad;
                        enumerators.Add(new PdbEnumerator(Str(d, ref at), value));
                        break;
                    }
                    case 0x1400: // LF_BCLASS: attr, type, offset
                    {
                        uint type = U32(d, at + 2);
                        at += 6;
                        if (!Numeric(d, ref at, out var offset)) goto bad;
                        members.Add(new PdbTypeMember(PdbMemberKind.Base, offset, $"baseclass_{offset:X}", type));
                        break;
                    }
                    case 0x1401 or 0x1402: // LF_VBCLASS / LF_IVBCLASS: attr, base, vbptr type, vbptr offset, vbtable index
                    {
                        uint type = U32(d, at + 2);
                        at += 10;
                        if (!Numeric(d, ref at, out _) || !Numeric(d, ref at, out _)) goto bad;
                        skipped?.Add("virtual_base");
                        // an indirect virtual base belongs to a base class
                        if (leaf == 0x1401) members.Add(new PdbTypeMember(PdbMemberKind.VirtualBase, -1, "", type));
                        break;
                    }
                    case 0x1409: // LF_VFUNCTAB: pad, type
                        at += 6;
                        vfptr = true;
                        break;
                    case 0x150E: // LF_STMEMBER: attr, type, name
                    {
                        uint type = U32(d, at + 2);
                        at += 6;
                        members.Add(new PdbTypeMember(PdbMemberKind.Static, -1, Str(d, ref at), type));
                        break;
                    }
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
                        skipped?.Add("unsupported_leaf");
                        goto done;
                }
                continue;
            bad:
                skipped?.Add("malformed_member");
                goto done;
            }
        done:
            list = next;
        }
        // the class introduces a vftable pointer: at offset 0 unless a base subobject there holds one
        if (vfptr && !members.Any(m => m.Kind == PdbMemberKind.Base && m.Offset == 0))
            members.Insert(0, new PdbTypeMember(PdbMemberKind.Vfptr, 0, "__vftable", PointerSize == 4 ? 0x0403u : 0x0603u)); // T_32PVOID / T_64PVOID
        return members;
    }

    /// <summary>The procedure type of a function symbol's type index (an IPI function id resolved to its TPI type), or 0.</summary>
    public uint FunctionTypeOf(uint typeIndex)
    {
        uint type = typeIndex;
        // the _ID procedure kinds carry an IPI index (the linker normally rewrites them to TPI indices)
        if (!(Tpi.TryGet(type, out var tk0, out _) && tk0 is LF_PROCEDURE or LF_MFUNCTION) && Ipi.TryGet(type, out var ik, out var id) && ik is LF_FUNC_ID or LF_MFUNC_ID)
            type = U32(id, 4);
        return Tpi.TryGet(type, out var k, out _) && k is LF_PROCEDURE or LF_MFUNCTION ? type : 0;
    }

    internal static string CallingConvention(byte cc) => cc switch
    {
        0x04 => "__fastcall",
        0x07 => "__stdcall",
        0x0B => "__thiscall",
        0x18 => "__vectorcall",
        _ => "__cdecl",
    };

    /// <summary>The record at <paramref name="index"/> (simple types below 0x1000 included); null when there is none.</summary>
    public PdbTypeNode? Node(uint index)
    {
        if (index < 0x1000)
        {
            uint mode = (index >> 8) & 0xF;
            if (mode == 0 && SimpleName(index) == null) return null;
            return Plain(index, mode != 0 ? PdbTypeKind.Pointer : PdbTypeKind.Simple, Spell(index), SizeOf(index), mode != 0 ? index & 0xFF : 0);
        }
        if (!Tpi.TryGet(index, out var kind, out var d)) return null;
        switch (kind)
        {
            case LF_MODIFIER:
            {
                ushort attr = U16(d, 4);
                return Plain(index, PdbTypeKind.Modifier, Spell(index), SizeOf(index), U32(d, 0)) with { Const = (attr & 1) != 0, Volatile = (attr & 2) != 0 };
            }
            case LF_POINTER:
            {
                uint mode = (U32(d, 4) >> 5) & 7;
                return Plain(index, PdbTypeKind.Pointer, Spell(index), SizeOf(index), U32(d, 0)) with { Reference = mode is 1 or 4 };
            }
            case LF_ARRAY:
            {
                uint element = U32(d, 0);
                long size = SizeOf(index), es = SizeOf(element);
                return Plain(index, PdbTypeKind.Array, Spell(index), size, element) with { Count = es > 0 && size >= 0 ? size / es : -1 };
            }
            case LF_BITFIELD:
                return Plain(index, PdbTypeKind.Bitfield, Spell(index), SizeOf(index), U32(d, 0)) with
                {
                    BitLength = d.Length > 4 ? d[4] : -1, BitPosition = d.Length > 5 ? d[5] : 0,
                };
            case LF_PROCEDURE or LF_MFUNCTION:
            {
                bool member = kind == LF_MFUNCTION;
                byte cc = member ? (d.Length > 12 ? d[12] : (byte)0) : (d.Length > 4 ? d[4] : (byte)0);
                uint argList = member ? U32(d, 16) : U32(d, 8);
                var parameters = new List<uint>();
                bool variadic = false;
                if (Tpi.TryGet(argList, out var ak, out var ad) && ak == LF_ARGLIST)
                {
                    uint count = U32(ad, 0);
                    for (int i = 0; i < count && 4 + 4 * i + 4 <= ad.Length; i++)
                    {
                        uint t = U32(ad, 4 + 4 * i);
                        if (t == 0) variadic = true;
                        else parameters.Add(t);
                    }
                }
                var function = new PdbFunctionType(U32(d, 0), parameters, variadic, CallingConvention(cc), member ? U32(d, 4) : 0, member ? U32(d, 8) : 0);
                return Plain(index, member ? PdbTypeKind.MemberFunction : PdbTypeKind.Procedure, Spell(index), -1, 0) with { Function = function };
            }
            default:
                if (ReadAggregate(index) is not { } a) return Plain(index, PdbTypeKind.Other, $"<leaf 0x{kind:X4}>", -1, 0);
                var members = Members(a, out var enumerators);
                var k = a.IsEnum ? PdbTypeKind.Enum : a.IsUnion ? PdbTypeKind.Union
                    : a.Kind is LF_CLASS or LF_CLASS2 ? PdbTypeKind.Class : a.Kind is LF_INTERFACE or LF_INTERFACE2 ? PdbTypeKind.Interface : PdbTypeKind.Struct;
                return new PdbTypeNode(index, k, a.Name, a.UniqueName, a.IsEnum || a.Forward ? SizeOf(index) : a.Size, a.Forward,
                    a.Underlying, -1, false, false, false, a.IsEnum ? [] : members, enumerators, null);
        }
    }

    private static PdbTypeNode Plain(uint index, PdbTypeKind kind, string name, long size, uint element) =>
        new(index, kind, name, null, size, false, element, -1, false, false, false, [], [], null);

    /// <summary>The C spelling of a type: "int", "Packet *", "char[16]", "int (__cdecl *)(const Packet *)".</summary>
    public string Spell(uint index) => Spell(index, "", 0) ?? $"<type 0x{index:X}>";

    private static string Join(string type, string declarator) =>
        declarator.Length == 0 ? type : type.EndsWith('*') || declarator[0] is '[' or '(' ? type + (declarator[0] is '[' ? "" : " ") + declarator : $"{type} {declarator}";

    private string? Spell(uint index, string declarator, int depth)
    {
        if (depth > MaxDepth) return null;
        if (index < 0x1000)
        {
            uint mode = (index >> 8) & 0xF;
            var name = SimpleName(index & 0xFF) ?? (index == 0 ? null : "void");
            if (name == null) return null;
            return mode != 0 ? Join(name, "*" + declarator) : Join(name, declarator);
        }
        if (!Tpi.TryGet(index, out var kind, out var d)) return null;
        switch (kind)
        {
            case LF_MODIFIER:
            {
                uint target = U32(d, 0);
                ushort attr = U16(d, 4);
                var cv = ((attr & 1) != 0 ? "const " : "") + ((attr & 2) != 0 ? "volatile " : "");
                bool pointerTarget = target >= 0x1000 ? Tpi.TryGet(target, out var tk, out _) && tk == LF_POINTER : ((target >> 8) & 0xF) != 0;
                if (pointerTarget) return Spell(target, (cv + declarator).TrimEnd(), depth + 1);
                return Spell(target, declarator, depth + 1) is { } inner ? cv + inner : null;
            }
            case LF_POINTER:
            {
                uint attr = U32(d, 4);
                uint mode = (attr >> 5) & 7;
                var sigil = mode switch { 1 => "&", 4 => "&&", 2 or 3 => $"{Spell(U32(d, 8), "", depth + 1) ?? "?"}::*", _ => "*" };
                return Spell(U32(d, 0), sigil + declarator, depth + 1) ?? Join("void", sigil + declarator);
            }
            case LF_ARRAY:
            {
                uint element = U32(d, 0);
                int at = 8;
                if (d.Length < 10 || !Numeric(d, ref at, out var bytes)) return null;
                long es = SizeOf(element, depth + 1);
                var inner = declarator.Length > 0 && declarator[0] is '*' or '&' ? $"({declarator})" : declarator;
                return Spell(element, $"{inner}[{(es > 0 ? (bytes / es).ToString(System.Globalization.CultureInfo.InvariantCulture) : "")}]", depth + 1);
            }
            case LF_BITFIELD:
                return Spell(U32(d, 0), declarator, depth + 1);
            case LF_PROCEDURE or LF_MFUNCTION:
            {
                bool member = kind == LF_MFUNCTION;
                byte cc = member ? (d.Length > 12 ? d[12] : (byte)0) : (d.Length > 4 ? d[4] : (byte)0);
                uint argList = member ? U32(d, 16) : U32(d, 8);
                var args = new List<string>();
                if (Tpi.TryGet(argList, out var ak, out var ad) && ak == LF_ARGLIST)
                {
                    uint count = U32(ad, 0);
                    for (int i = 0; i < count && 4 + 4 * i + 4 <= ad.Length; i++)
                    {
                        uint t = U32(ad, 4 + 4 * i);
                        args.Add(t == 0 ? "..." : Spell(t, "", depth + 1) ?? "?");
                    }
                }
                if (args.Count == 0) args.Add("void");
                var inner = declarator.Length > 0 && declarator[0] is '*' or '&' ? $"({CallingConvention(cc)} {declarator})" : $"{CallingConvention(cc)} {declarator}".TrimEnd();
                return Spell(U32(d, 0), $"{inner}({string.Join(", ", args)})", depth + 1) ?? Join("void", $"{inner}({string.Join(", ", args)})");
            }
            default:
                return ReadAggregate(index) is { } a ? Join(a.Name.Length > 0 ? a.Name : "<unnamed>", declarator) : null;
        }
    }

    /// <summary>Aggregate and enum definitions by name (forward-only types by their forward record), one per unique name.</summary>
    public IReadOnlyList<uint> Named(string name) => _byName.Value.TryGetValue(name, out var list) ? list : [];

    /// <summary>Every name <see cref="Named"/> knows.</summary>
    public IEnumerable<string> Names => _byName.Value.Keys;

    private Dictionary<string, List<uint>> BuildNameIndex()
    {
        var byName = new Dictionary<string, List<uint>>(StringComparer.Ordinal);
        var keys = new HashSet<string>(StringComparer.Ordinal);
        for (uint i = 0; i < Tpi.Offsets.Length; i++)
        {
            if (ReadAggregate(Tpi.First + i) is not { } a || Unnamed(a.Name)) continue;
            // a forward reference stands for its definition, which is listed on its own
            if (a.Forward && _definitionByName.ContainsKey(Key(a))) continue;
            if (!keys.Add(Key(a))) continue;
            (byName.TryGetValue(a.Name, out var list) ? list : byName[a.Name] = []).Add(a.Index);
        }
        return byName;
    }
}
