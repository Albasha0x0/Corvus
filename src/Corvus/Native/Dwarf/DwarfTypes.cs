using System.Text;
using Corvus.Native.Pdb;

namespace Corvus.Native.Dwarf;

/// <summary>
/// Writes DWARF types as CodeView type records (the PDB's TPI form), so <see cref="PdbTypeModel"/> and everything built
/// on it (get_native_type, list_native_types, typed globals and prototypes, the engines' declarations) read DWARF the
/// way they read a PDB. Structs, classes and unions (members at their DWARF offsets, bit fields, bases, static members),
/// enums, typedefs (kept as type names), pointers, references, arrays, const/volatile and function types. Types repeated
/// across units are written once: named aggregates and enums by kind, qualified name and size; derived types by their
/// shape. Base types map to the CodeView simple type of their encoding and size.
/// </summary>
internal sealed class DwarfTypes
{
    public const uint FirstIndex = 0x1000;
    /// <summary>Most bytes of type records written.</summary>
    public const long MaxBytes = 512L << 20;
    private const int MaxDepth = 64;
    private const int MaxRecordData = 0xFF00;
    private const int MaxName = 2000;
    private const ushort LfModifier = 0x1001, LfPointer = 0x1002, LfProcedure = 0x1008, LfArglist = 0x1201, LfFieldlist = 0x1203, LfBitfield = 0x1205,
        LfIndex = 0x1404, LfBclass = 0x1400, LfEnumerate = 0x1502, LfArray = 0x1503, LfClass = 0x1504, LfStructure = 0x1505, LfUnion = 0x1506,
        LfEnum = 0x1507, LfMember = 0x150D, LfStmember = 0x150E;
    private const uint Void = 0x03;

    private readonly DwarfReader _reader;
    private readonly int _pointerSize;
    private readonly List<byte[]> _records = [];
    private readonly List<long> _sizes = [];
    private readonly Dictionary<string, uint> _byShape = new(StringComparer.Ordinal);
    private readonly Dictionary<long, uint> _unitMemo = [];
    private readonly Dictionary<long, uint> _crossMemo = [];
    private readonly HashSet<string> _typedefNames = new(StringComparer.Ordinal);
    private DwarfUnit? _unit;
    private long _bytes;
    private int _depth;
    private (long Offset, string Name)? _nameFor;

    /// <summary>The name of an aggregate or enum entry: its own, a typedef's for an unnamed one, else null (unnamed).</summary>
    private string? NameOf(DwarfUnit u, DwarfDie d) =>
        !string.IsNullOrEmpty(d.Name) ? Qualify(u, d, d.Name, _reader) : _nameFor is { } n && n.Offset == d.Offset ? n.Name : null;

    public List<PdbTypedef> Typedefs { get; } = [];
    public Dictionary<string, int> Skipped { get; } = [];
    public bool Full { get; private set; }

    public DwarfTypes(DwarfReader reader, int pointerSize)
    {
        _reader = reader;
        _pointerSize = pointerSize;
    }

    public int Count => _records.Count;

    /// <summary>Starts a unit: its entry offsets are remembered until the next unit.</summary>
    public void Begin(DwarfUnit unit)
    {
        _unit = unit;
        _unitMemo.Clear();
    }

    private void Skip(string why) => Skipped[why] = Skipped.GetValueOrDefault(why) + 1;

    /// <summary>The records as one TPI stream body and each record's offset.</summary>
    public (byte[] Bytes, int[] Offsets) Build()
    {
        var bytes = new byte[_records.Sum(r => (long)r.Length)];
        var offsets = new int[_records.Count];
        int at = 0;
        for (int i = 0; i < _records.Count; i++)
        {
            offsets[i] = at;
            _records[i].CopyTo(bytes, at);
            at += _records[i].Length;
        }
        return (bytes, offsets);
    }

    // ---- record writing ----

    private sealed class Writer
    {
        public readonly List<byte> B = [];
        public void U8(int v) => B.Add((byte)v);
        public void U16(int v) { B.Add((byte)v); B.Add((byte)(v >> 8)); }
        public void U32(uint v) { U16((int)(v & 0xFFFF)); U16((int)(v >> 16)); }
        public void Numeric(long v)
        {
            if (v is >= 0 and < 0x8000) U16((int)v);
            else if (v is >= int.MinValue and <= int.MaxValue) { U16(0x8003); U32((uint)(int)v); }
            else { U16(0x8009); U32((uint)v); U32((uint)(v >> 32)); }
        }
        public void Name(string s)
        {
            var bytes = Encoding.UTF8.GetBytes(s.Length > MaxName ? s[..MaxName] : s);
            B.AddRange(bytes);
            B.Add(0);
        }
    }

    private static byte[] Record(ushort kind, Writer w)
    {
        var r = new byte[4 + w.B.Count];
        int len = 2 + w.B.Count;
        r[0] = (byte)len; r[1] = (byte)(len >> 8);
        r[2] = (byte)kind; r[3] = (byte)(kind >> 8);
        w.B.CopyTo(r, 4);
        return r;
    }

    private uint Add(byte[] record, long size)
    {
        if (_bytes + record.Length > MaxBytes)
        {
            Full = true;
            return Void;
        }
        _bytes += record.Length;
        _records.Add(record);
        _sizes.Add(size);
        return FirstIndex + (uint)(_records.Count - 1);
    }

    private uint Shaped(string key, ushort kind, Writer w, long size)
    {
        if (_byShape.TryGetValue(key, out var existing)) return existing;
        var index = Add(Record(kind, w), size);
        if (index != Void) _byShape[key] = index;
        return index;
    }

    /// <summary>Size in bytes of a type index; -1 when unknown.</summary>
    public long SizeOf(uint index)
    {
        if (index < FirstIndex)
        {
            if (((index >> 8) & 0xF) != 0) return _pointerSize;
            return SimpleSize(index & 0xFF);
        }
        int i = (int)(index - FirstIndex);
        return i < _sizes.Count ? _sizes[i] : -1;
    }

    private static long SimpleSize(uint kind) => kind switch
    {
        0x03 => 0,
        0x10 or 0x20 or 0x68 or 0x69 or 0x70 or 0x7C or 0x30 => 1,
        0x11 or 0x21 or 0x71 or 0x72 or 0x73 or 0x7A or 0x31 => 2,
        0x12 or 0x22 or 0x74 or 0x75 or 0x7B or 0x32 or 0x40 => 4,
        0x13 or 0x23 or 0x76 or 0x77 or 0x33 or 0x41 => 8,
        0x42 => 10,
        0x14 or 0x24 or 0x78 or 0x79 or 0x43 => 16,
        _ => -1,
    };

    // ---- conversion ----

    /// <summary>The type index of the type entry at <paramref name="offset"/> (void when -1 or unreadable).</summary>
    public uint TypeOf(DwarfUnit unit, long offset)
    {
        if (offset < 0) return Void;
        if (_unitMemo.TryGetValue(offset, out var known) || _crossMemo.TryGetValue(offset, out known)) return known;
        if (Full) return Void;
        if (_reader.Entry(offset, unit) is not { } e) { Skip("unresolved_reference"); return Void; }
        if (_depth >= MaxDepth) { Skip("too_deep"); return Void; }
        _depth++;
        try
        {
            var memo = ReferenceEquals(e.Unit, _unit) ? _unitMemo : _crossMemo;
            var index = Convert(e.Unit, e.Die, memo);
            memo[offset] = index;
            return index;
        }
        finally { _depth--; }
    }

    private uint Convert(DwarfUnit u, DwarfDie d, Dictionary<long, uint> memo)
    {
        switch (d.Tag)
        {
            case Dw.TagBaseType: return Simple(d);
            case Dw.TagUnspecifiedType: return SimplePointer(Void);
            case Dw.TagTypedef or Dw.TagTemplateAlias:
            {
                // C's "typedef struct { ... } Name": the unnamed type takes the typedef's name
                if (d.Name is { Length: > 0 } && _reader.Entry(d.Type, u) is { } e)
                {
                    // a declaration by signature stands for its definition in a type unit
                    var t = e.Die.SignatureTarget >= 0 && _reader.Entry(e.Die.SignatureTarget, e.Unit) is { } s ? s.Die : e.Die;
                    if (t is { Name: null, Declaration: false, Tag: Dw.TagStructureType or Dw.TagClassType or Dw.TagUnionType or Dw.TagEnumerationType })
                        _nameFor = (t.Offset, Qualify(u, d, d.Name, _reader));
                }
                uint target;
                try { target = TypeOf(u, d.Type); }
                finally { _nameFor = null; }
                if (d.Name is { Length: > 0 } && IsDeclarationScope(u, d))
                {
                    var name = Qualify(u, d, d.Name, _reader);
                    if (_typedefNames.Add(name)) Typedefs.Add(new PdbTypedef(name, target));
                }
                return target;
            }
            case Dw.TagConstType or Dw.TagVolatileType: return Modifier(TypeOf(u, d.Type), d.Tag == Dw.TagConstType ? 1 : 2);
            case Dw.TagRestrictType or Dw.TagAtomicType or Dw.TagImmutableType: return TypeOf(u, d.Type);
            case Dw.TagPointerType: return Pointer(TypeOf(u, d.Type), 0, d.ByteSize);
            case Dw.TagReferenceType: return Pointer(TypeOf(u, d.Type), 1, d.ByteSize);
            case Dw.TagRvalueReferenceType: return Pointer(TypeOf(u, d.Type), 4, d.ByteSize);
            case Dw.TagPtrToMemberType:
            {
                // Itanium: a data member pointer is one word, a member function pointer two
                bool function = _reader.Entry(d.Type, u) is { Die.Tag: Dw.TagSubroutineType };
                return Array(0x20, function ? 2L * _pointerSize : _pointerSize);
            }
            case Dw.TagArrayType: return ArrayOf(u, d);
            case Dw.TagStructureType or Dw.TagClassType or Dw.TagUnionType: return Aggregate(u, d, memo);
            case Dw.TagEnumerationType: return Enum(u, d, memo);
            case Dw.TagSubroutineType: return Procedure(u, d, d.Type);
            default:
                Skip($"tag_0x{d.Tag:X}");
                return Void;
        }
    }

    private uint Simple(DwarfDie d)
    {
        long size = d.ByteSize;
        string name = d.Name ?? "";
        switch (d.Encoding)
        {
            case Dw.AteBoolean: return size == 1 ? 0x30u : size == 2 ? 0x31u : size == 4 ? 0x32u : 0x33u;
            case Dw.AteFloat: return size switch { 4 => 0x40u, 8 => 0x41u, 10 or 12 => 0x42u, 16 => 0x43u, _ => Array(0x20, size) };
            case Dw.AteSignedChar or Dw.AteUnsignedChar or Dw.AteSigned or Dw.AteUnsigned or Dw.AteUtf:
            {
                bool unsigned = d.Encoding is Dw.AteUnsigned or Dw.AteUnsignedChar or Dw.AteUtf;
                if (name == "wchar_t" && size == 2) return 0x71;
                return size switch
                {
                    1 => name == "char" ? 0x70u : name == "signed char" ? 0x68u : unsigned ? 0x20u : 0x10u,
                    2 => unsigned ? 0x21u : 0x11u,
                    4 => name is "long" or "long int" ? 0x12u : name is "unsigned long" or "long unsigned int" ? 0x22u : unsigned ? 0x75u : 0x74u,
                    8 => unsigned ? 0x77u : 0x76u,
                    16 => unsigned ? 0x79u : 0x78u,
                    _ => Array(0x20, Math.Max(0, size)),
                };
            }
            default:
                Skip("base_type_encoding");
                return size > 0 ? Array(0x20, size) : Void;
        }
    }

    private uint SimplePointer(uint target) => (_pointerSize == 8 ? 0x600u : 0x400u) | target;

    private uint Pointer(uint target, int mode, long size)
    {
        if (size <= 0) size = _pointerSize;
        if (mode == 0 && size == _pointerSize && target < 0x100) return SimplePointer(target);
        var w = new Writer();
        w.U32(target);
        uint kind = size == 8 ? 0x0Cu : 0x0Au;
        w.U32(kind | (uint)mode << 5 | (uint)size << 13);
        return Shaped($"p{target}:{mode}:{size}", LfPointer, w, size);
    }

    private uint Modifier(uint target, int attr)
    {
        var w = new Writer();
        w.U32(target);
        w.U16(attr);
        return Shaped($"m{target}:{attr}", LfModifier, w, SizeOf(target));
    }

    private uint Array(uint element, long bytes)
    {
        var w = new Writer();
        w.U32(element);
        w.U32(_pointerSize == 8 ? 0x23u : 0x22u);
        w.Numeric(bytes);
        w.Name("");
        return Shaped($"r{element}:{bytes}", LfArray, w, bytes);
    }

    private uint ArrayOf(DwarfUnit u, DwarfDie d)
    {
        uint element = TypeOf(u, d.Type);
        var counts = new List<long>();
        int index = u.IndexOf(d);
        foreach (var c in u.Children(index))
        {
            if (c.Tag != Dw.TagSubrangeType) continue;
            long n = c.Count >= 0 ? c.Count : c.UpperBound != long.MinValue ? c.UpperBound - c.LowerBound + 1 : 0;
            counts.Add(Math.Max(0, n));
        }
        if (counts.Count == 0) return Array(element, d.ByteSize > 0 ? d.ByteSize : 0);
        uint inner = element;
        for (int i = counts.Count - 1; i >= 0; i--)
        {
            long es = SizeOf(inner);
            inner = Array(inner, es > 0 ? counts[i] * es : 0);
        }
        return inner;
    }

    /// <summary>
    /// The prototype of a function entry: return type and parameter types (the parameters of its own children, else its
    /// declaration's); <paramref name="names"/> receives the parameter names.
    /// </summary>
    public uint Procedure(DwarfUnit u, DwarfDie d, long returnType, List<string?>? names = null)
    {
        var args = new List<uint>();
        bool variadic = false;
        var (pu, pd) = (u, d);
        // a definition without parameter entries takes them from its declaration or abstract origin
        for (int hop = 0; hop < 4; hop++)
        {
            int idx = pu.IndexOf(pd);
            if (pu.Children(idx).Any(c => c.Tag is Dw.TagFormalParameter or Dw.TagUnspecifiedParameters)) break;
            long next = pd.AbstractOrigin >= 0 ? pd.AbstractOrigin : pd.Specification;
            if (next < 0 || _reader.Entry(next, pu) is not { } e) break;
            (pu, pd) = e;
        }
        foreach (var c in pu.Children(pu.IndexOf(pd)))
        {
            if (c.Tag == Dw.TagUnspecifiedParameters) variadic = true;
            if (c.Tag != Dw.TagFormalParameter) continue;
            long type = c.Type;
            string? name = c.Name;
            if (c.AbstractOrigin >= 0 && (type < 0 || name == null) && _reader.Entry(c.AbstractOrigin, pu) is { } o)
            {
                if (type < 0) type = o.Die.Type;
                name ??= o.Die.Name;
            }
            args.Add(TypeOf(pu, type));
            names?.Add(name);
        }
        if (variadic) args.Add(0);
        var aw = new Writer();
        aw.U32((uint)args.Count);
        foreach (var a in args) aw.U32(a);
        uint list = Shaped("a" + string.Join(",", args), LfArglist, aw, -1);
        uint ret = TypeOf(u, returnType);
        var w = new Writer();
        w.U32(ret);
        w.U8(0);
        w.U8(0);
        w.U16(args.Count);
        w.U32(list);
        return Shaped($"f{ret}:{list}", LfProcedure, w, -1);
    }

    /// <summary>Whether a type's name is visible at file, namespace or class scope (not local to a function).</summary>
    private static bool IsDeclarationScope(DwarfUnit u, DwarfDie d)
    {
        for (var p = u.ParentOf(d); p != null; p = u.ParentOf(p))
        {
            if (Dw.IsUnit(p.Tag)) return true;
            if (!Dw.IsScope(p.Tag)) return false;
        }
        return true;
    }

    /// <summary>
    /// "ns::Outer::name": the enclosing namespaces and types of <paramref name="d"/> (in its unit), then <paramref name="name"/>.
    /// A type declared by signature (its definition in a type unit) is named by its definition.
    /// </summary>
    public static string Qualify(DwarfUnit u, DwarfDie d, string name, DwarfReader? reader = null)
    {
        StringBuilder? prefix = null;
        for (var p = u.ParentOf(d); p != null && !Dw.IsUnit(p.Tag); p = u.ParentOf(p))
        {
            if (!Dw.IsScope(p.Tag)) continue;
            var part = p.Name ?? (p.SignatureTarget >= 0 ? reader?.Entry(p.SignatureTarget, u)?.Die.Name : null)
                ?? (p.Tag == Dw.TagNamespace ? "(anonymous namespace)" : "<unnamed>");
            prefix = prefix == null ? new StringBuilder(part) : prefix.Insert(0, part + "::");
        }
        return prefix == null ? name : prefix.Append("::").Append(name).ToString();
    }

    private uint Aggregate(DwarfUnit u, DwarfDie d, Dictionary<long, uint> memo)
    {
        if (d.SignatureTarget >= 0) return TypeOf(u, d.SignatureTarget);
        bool union = d.Tag == Dw.TagUnionType;
        ushort kind = union ? LfUnion : d.Tag == Dw.TagClassType ? LfClass : LfStructure;
        var own = NameOf(u, d);
        bool unnamed = own == null;
        string name = own ?? "<unnamed-tag>";
        string? unique = unnamed ? $"dwarf@{d.Offset:x}" : null;
        string tag = union ? "u" : "s";
        if (d.Declaration)
        {
            var fw = new Writer();
            fw.U16(0);
            fw.U16(0x80 | (unique != null ? 0x200 : 0));
            fw.U32(0);
            if (!union) { fw.U32(0); fw.U32(0); }
            fw.Numeric(0);
            fw.Name(name);
            if (unique != null) fw.Name(unique);
            return Shaped($"fwd:{tag}:{unique ?? name}", kind, fw, -1);
        }
        long size = Math.Max(0, d.ByteSize);
        string key = $"{tag}:{unique ?? name}:{size}";
        if (_byShape.TryGetValue(key, out var existing)) return existing;
        // reserve the index first: members may point back at the type
        uint self = Add([], size);
        if (self == Void) return Void;
        _byShape[key] = self;
        memo[d.Offset] = self;

        var members = new List<byte[]>();
        int index = u.IndexOf(d);
        foreach (var c in u.Children(index))
        {
            switch (c.Tag)
            {
                case Dw.TagMember when c.Declaration || (c.External && c.MemberLocation < 0 && c.DataBitOffset < 0 && !union):
                case Dw.TagVariable:
                {
                    var w = new Writer();
                    w.U16(LfStmember);
                    w.U16(3);
                    w.U32(TypeOf(u, c.Type));
                    w.Name(c.Name ?? "");
                    members.Add([.. w.B]);
                    break;
                }
                case Dw.TagMember:
                {
                    uint type = TypeOf(u, c.Type);
                    long offset = union ? 0 : Math.Max(0, c.MemberLocation);
                    if (c.BitSize > 0) (type, offset) = Bitfield(c, type, union);
                    var w = new Writer();
                    w.U16(LfMember);
                    w.U16(3);
                    w.U32(type);
                    w.Numeric(offset);
                    w.Name(c.Name ?? "");
                    members.Add([.. w.B]);
                    break;
                }
                case Dw.TagInheritance:
                {
                    if (c.Virtuality != 0) { Skip("virtual_base"); break; }
                    var w = new Writer();
                    w.U16(LfBclass);
                    w.U16(3);
                    w.U32(TypeOf(u, c.Type));
                    w.Numeric(Math.Max(0, c.MemberLocation));
                    members.Add([.. w.B]);
                    break;
                }
            }
        }
        uint fields = FieldList(members);
        var sw = new Writer();
        sw.U16(Math.Min(members.Count, 0xFFFF));
        sw.U16(unique != null ? 0x200 : 0);
        sw.U32(fields);
        if (!union) { sw.U32(0); sw.U32(0); }
        sw.Numeric(size);
        sw.Name(name);
        if (unique != null) sw.Name(unique);
        _records[(int)(self - FirstIndex)] = Record(kind, sw);
        _bytes += _records[(int)(self - FirstIndex)].Length;
        return self;
    }

    /// <summary>A bit field member: its storage unit's byte offset and an LF_BITFIELD of the bits within it.</summary>
    private (uint Type, long Offset) Bitfield(DwarfDie c, uint type, bool union)
    {
        long storage = c.ByteSize > 0 ? c.ByteSize : SizeOf(type);
        if (storage <= 0) storage = 4;
        // positions are counted from the storage unit's least significant bit, as CodeView counts them
        long byteOffset, position;
        if (c.DataBitOffset >= 0)
        {
            // DWARF 4+: bits from the start of the struct in memory order (from the first byte's MSB on big-endian targets)
            long bits = c.DataBitOffset;
            byteOffset = bits / (storage * 8) * storage;
            position = bits - byteOffset * 8;
            if (_reader.BigEndian) position = storage * 8 - position - c.BitSize;
        }
        else
        {
            // DWARF 2/3: bit_offset counts from the storage unit's most significant bit, on either byte order
            byteOffset = union ? 0 : Math.Max(0, c.MemberLocation);
            position = storage * 8 - Math.Max(0, c.BitOffset) - c.BitSize;
        }
        if (position < 0 || c.BitSize > 64) Skip("bit_field_position");
        var w = new Writer();
        w.U32(type);
        w.U8((int)Math.Min(c.BitSize, 255));
        w.U8((int)Math.Clamp(position, 0, 255));
        return (Shaped($"b{type}:{c.BitSize}:{position}", LfBitfield, w, storage), byteOffset);
    }

    /// <summary>One or more field list records (continued with LF_INDEX when one would be too long); 0 when there are no members.</summary>
    private uint FieldList(List<byte[]> members)
    {
        if (members.Count == 0) return 0;
        var chunks = new List<List<byte[]>> { new() };
        int bytes = 0;
        foreach (var m in members)
        {
            if (bytes + m.Length > MaxRecordData - 8 && chunks[^1].Count > 0) { chunks.Add([]); bytes = 0; }
            chunks[^1].Add(m);
            bytes += m.Length;
        }
        // written last chunk first, so each can name the next
        uint next = 0;
        for (int i = chunks.Count - 1; i >= 0; i--)
        {
            var w = new Writer();
            foreach (var m in chunks[i]) w.B.AddRange(m);
            if (next != 0)
            {
                w.U16(LfIndex);
                w.U16(0);
                w.U32(next);
            }
            next = Add(Record(LfFieldlist, w), -1);
        }
        return next;
    }

    private uint Enum(DwarfUnit u, DwarfDie d, Dictionary<long, uint> memo)
    {
        if (d.SignatureTarget >= 0) return TypeOf(u, d.SignatureTarget);
        var own = NameOf(u, d);
        bool unnamed = own == null;
        string name = own ?? "<unnamed-enum>";
        string? unique = unnamed ? $"dwarf@{d.Offset:x}" : null;
        long size = d.ByteSize > 0 ? d.ByteSize : 4;
        int index = u.IndexOf(d);
        var values = u.Children(index).Where(c => c.Tag == Dw.TagEnumerator).ToList();
        uint underlying = d.Type >= 0 ? TypeOf(u, d.Type) : 0;
        bool signedUnder = underlying is 0x10 or 0x68 or 0x70 or 0x11 or 0x72 or 0x12 or 0x74 or 0x76 or 0x78 or 0x13;
        if (underlying == 0)
        {
            signedUnder = values.Any(v => v.ConstSize == 255 && v.ConstValue < 0) || d.Encoding == 0 && values.All(v => v.ConstSize == 255);
            underlying = size switch { 1 => signedUnder ? 0x68u : 0x20u, 2 => signedUnder ? 0x11u : 0x21u, 8 => signedUnder ? 0x76u : 0x77u, _ => signedUnder ? 0x74u : 0x75u };
        }
        string key = d.Declaration ? $"fwd:e:{unique ?? name}" : $"e:{unique ?? name}:{size}";
        if (_byShape.TryGetValue(key, out var existing)) return existing;
        uint fields = 0;
        if (!d.Declaration)
        {
            var members = new List<byte[]>();
            foreach (var v in values)
            {
                long value = v.ConstValue;
                if (v.ConstSize is > 0 and < 8 && signedUnder)
                {
                    int shift = 64 - v.ConstSize * 8;
                    value = value << shift >> shift;
                }
                var w = new Writer();
                w.U16(LfEnumerate);
                w.U16(3);
                w.Numeric(value);
                w.Name(v.Name ?? "");
                members.Add([.. w.B]);
            }
            fields = FieldList(members);
        }
        var ew = new Writer();
        ew.U16(Math.Min(values.Count, 0xFFFF));
        ew.U16((d.Declaration ? 0x80 : 0) | (unique != null ? 0x200 : 0));
        ew.U32(underlying);
        ew.U32(fields);
        ew.Name(name);
        if (unique != null) ew.Name(unique);
        var index2 = Shaped(key, LfEnum, ew, size);
        memo[d.Offset] = index2;
        return index2;
    }
}
