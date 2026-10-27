using System.Text;

namespace Corvus.Core.WebAssembly;

/// <summary>A value type: numbers, v128, reference shorthands by byte, other reference types packed by <see cref="WasmRef"/>.</summary>
public enum WasmType
{
    I32 = 0x7F, I64 = 0x7E, F32 = 0x7D, F64 = 0x7C, V128 = 0x7B, FuncRef = 0x70, ExternRef = 0x6F, ExnRef = 0x69,
    AnyRef = 0x6E, EqRef = 0x6D, I31Ref = 0x6C, StructRef = 0x6B, ArrayRef = 0x6A, NullRef = 0x71, NullExternRef = 0x72, NullFuncRef = 0x73, NullExnRef = 0x74,
}

/// <summary>GC reference types: shorthand byte for nullable abstract ones, else packed (bit 28 set, 27 nullable, 24 abstract).</summary>
public static class WasmRef
{
    private const int Marker = 1 << 28, Null = 1 << 27, Abstract = 1 << 24;

    /// <summary>The heap type bytes: func, extern, any, eq, i31, struct, array, exn, none, noextern, nofunc, noexn.</summary>
    public static bool IsAbstractHeap(int b) => b is >= 0x69 and <= 0x74;

    /// <summary>(ref null? heap): heap a type index, or an abstract heap type's byte given as -(0x80 - byte) (its s33 value).</summary>
    public static WasmType Make(bool nullable, long heap)
    {
        if (heap < 0)
        {
            int b = (int)(heap + 0x80);
            return nullable ? (WasmType)b : (WasmType)(Marker | Abstract | b);
        }
        return (WasmType)(Marker | (nullable ? Null : 0) | (int)heap);
    }

    public static bool IsRef(WasmType t) => (int)t is >= 0x69 and <= 0x74 || ((int)t & Marker) != 0;

    public static bool Nullable(WasmType t) => (int)t is >= 0x69 and <= 0x74 || ((int)t & (Marker | Null)) == (Marker | Null);

    /// <summary>The heap type: (true, byte) for an abstract one, (false, index) for a defined type.</summary>
    public static (bool Abstract, int Value) Heap(WasmType t) =>
        (int)t is >= 0x69 and <= 0x74 ? (true, (int)t) : ((int)t & Abstract) != 0 ? (true, (int)t & 0xFF) : (false, (int)t & 0xFFFFFF);

    public static WasmType WithNull(WasmType t, bool nullable)
    {
        var (isAbstract, value) = Heap(t);
        return Make(nullable, isAbstract ? value - 0x80 : value);
    }

    public static string HeapName(int b) => b switch
    {
        0x70 => "func", 0x6F => "extern", 0x6E => "any", 0x6D => "eq", 0x6C => "i31", 0x6B => "struct", 0x6A => "array", 0x69 => "exn",
        0x71 => "none", 0x72 => "noextern", 0x73 => "nofunc", 0x74 => "noexn", _ => $"heap_0x{b:x2}",
    };
}

public enum WasmExternal : byte { Func, Table, Memory, Global, Tag }

public sealed record WasmFuncType(WasmType[] Params, WasmType[] Results);

public enum WasmComposite : byte { Func, Struct, Array }

/// <summary>A struct field or array element: its value type, or a packed i8 / i16 (Packed 8 or 16, Type i32), and whether it is mutable.</summary>
public readonly record struct WasmField(WasmType Type, byte Packed, bool Mutable)
{
    /// <summary>The type a read gives: a packed field reads as i32.</summary>
    public WasmType Unpacked => Packed != 0 ? WasmType.I32 : Type;
}

/// <summary>A GC defined type (func, struct or array) with finality, supertypes and recursion group.</summary>
public sealed record WasmTypeDef(WasmComposite Kind, WasmFuncType? Func, WasmField[] Fields, bool Final, uint[] Supers, int Group, int GroupSize)
{
    /// <summary>A plain function type: final, no supertypes, alone in its group (the MVP form 0x60).</summary>
    public bool Plain => Kind == WasmComposite.Func && Final && Supers.Length == 0 && GroupSize == 1;
}

public readonly record struct WasmLimits(ulong Min, ulong? Max, bool Shared, bool Is64);

public sealed record WasmTableType(WasmType Element, WasmLimits Limits);

public readonly record struct WasmGlobalType(WasmType Type, bool Mutable);

/// <summary>A constant expression's bytes, from its first instruction up to and including its end.</summary>
public readonly record struct WasmExpr(int Start, int End);

/// <summary>An import; <see cref="Offset"/> is its entry's file offset in the import section.</summary>
public sealed record WasmImport(string Module, string Name, WasmExternal Kind, uint TypeIndex, WasmTableType? Table, WasmLimits? Memory, WasmGlobalType? Global)
{
    public int Offset { get; init; }
}

public sealed record WasmExport(string Name, WasmExternal Kind, uint Index)
{
    public int Offset { get; init; }
}

/// <summary>A defined global; <see cref="Offset"/> is its entry's file offset in the global section.</summary>
public sealed record WasmGlobal(WasmGlobalType Type, WasmExpr Init)
{
    public int Offset { get; init; }
}

public sealed record WasmTable(WasmTableType Type, WasmExpr? Init);

public enum WasmSegmentMode : byte { Active, Passive, Declarative }

/// <summary>An element segment: its encoding flags, mode, table, offset, element type, and either function indexes or expressions.</summary>
public sealed record WasmElement(uint Flags, WasmSegmentMode Mode, uint Table, WasmExpr? Offset, WasmType Type, uint[]? Functions, WasmExpr[]? Exprs)
{
    /// <summary>The segment entry's file offset in the element section.</summary>
    public int Position { get; init; }
}

/// <summary>A data segment: mode, memory, offset, and the bytes' range in the file.</summary>
public sealed record WasmData(WasmSegmentMode Mode, uint Memory, WasmExpr? Offset, int Start, int Length);

/// <summary>A function body: its range in the file (after the size), the local declarations, and where its instructions start.</summary>
public sealed record WasmBody(int Start, int End, int CodeStart, (uint Count, WasmType Type)[] Locals)
{
    public ulong LocalCount => Locals.Aggregate(0UL, (n, l) => n + l.Count);
}

/// <summary>Names of the name section by kind (0 module ... 11 tag) and of locals per function.</summary>
public sealed class WasmNames
{
    public string? Module { get; internal set; }
    public Dictionary<uint, string> Functions { get; } = [];
    public Dictionary<uint, Dictionary<uint, string>> Locals { get; } = [];
    public Dictionary<uint, string> Types { get; } = [];
    public Dictionary<uint, string> Tables { get; } = [];
    public Dictionary<uint, string> Memories { get; } = [];
    public Dictionary<uint, string> Globals { get; } = [];
    public Dictionary<uint, string> Elements { get; } = [];
    public Dictionary<uint, string> Data { get; } = [];
    public Dictionary<uint, string> Tags { get; } = [];
}

/// <summary>A WebAssembly module read completely, bodies decoded on demand; a structural problem stops with an issue, never throws.</summary>
/// <remarks>What came before a problem is kept; offsets are file offsets.</remarks>
public sealed class WasmBinary
{
    public byte[] Bytes { get; }
    public uint Version { get; private set; }
    /// <summary>The function type of each type index; a struct or array type holds an empty one (see <see cref="TypeDefs"/>).</summary>
    public List<WasmFuncType> Types { get; } = [];
    /// <summary>Every defined type with its kind, fields, supertypes and recursion group, by type index.</summary>
    public List<WasmTypeDef> TypeDefs { get; } = [];
    /// <summary>The module uses the GC proposal (struct / array / sub / rec types or reference types beyond funcref, externref and exnref).</summary>
    public bool Gc { get; private set; }
    public List<WasmImport> Imports { get; } = [];
    /// <summary>Type index of each defined function.</summary>
    public List<uint> Functions { get; } = [];
    public List<WasmTable> Tables { get; } = [];
    public List<WasmLimits> Memories { get; } = [];
    public List<uint> Tags { get; } = [];
    public List<WasmGlobal> Globals { get; } = [];
    public List<WasmExport> Exports { get; } = [];
    public uint? Start { get; private set; }
    public List<WasmElement> Elements { get; } = [];
    public uint? DataCount { get; private set; }
    public List<WasmBody> Bodies { get; } = [];
    public List<WasmData> Data { get; } = [];
    public List<(string Name, int Start, int End)> Customs { get; } = [];
    /// <summary>Known sections in file order: id, content start and end.</summary>
    public List<(byte Id, int Start, int End)> Sections { get; } = [];
    public WasmNames Names { get; } = new();
    public List<string> Issues { get; } = [];
    /// <summary>A section the reader does not model (GC types, an unknown id); the module cannot be printed or validated whole.</summary>
    public string? Unsupported { get; private set; }

    public int ImportedFunctions { get; private set; }
    public int ImportedTables { get; private set; }
    public int ImportedMemories { get; private set; }
    public int ImportedGlobals { get; private set; }
    public int ImportedTags { get; private set; }

    public int FunctionCount => ImportedFunctions + Functions.Count;
    public int TableCount => ImportedTables + Tables.Count;
    public int MemoryCount => ImportedMemories + Memories.Count;
    public int GlobalCount => ImportedGlobals + Globals.Count;
    public int TagCount => ImportedTags + Tags.Count;

    private const int MaxCount = 10_000_000;

    private WasmBinary(byte[] bytes) => Bytes = bytes;

    public static bool Looks(ReadOnlySpan<byte> b) => b.Length >= 8 && b[..4].SequenceEqual("\0asm"u8);

    public static WasmBinary Read(byte[] bytes, CancellationToken ct = default)
    {
        var m = new WasmBinary(bytes);
        if (!Looks(bytes)) { m.Issues.Add("no \\0asm magic"); return m; }
        m.Version = BitConverter.ToUInt32(bytes, 4);
        if (m.Version != 1) { m.Issues.Add($"version {m.Version} is not 1"); m.Unsupported = $"binary version {m.Version}"; return m; }
        int p = 8;
        byte last = 0;
        while (p < bytes.Length)
        {
            ct.ThrowIfCancellationRequested();
            int start = p;
            byte id = bytes[p++];
            var r = new WasmReader(bytes, p, bytes.Length);
            if (!r.TryU32(out uint size) || size > bytes.Length - r.Pos) { m.Issues.Add($"section {id} at 0x{start:X} runs past the end"); break; }
            int body = r.Pos, end = body + (int)size;
            if (id != 0)
            {
                int order = Order(id);
                if (order < 0) { m.Issues.Add($"unknown section id {id} at 0x{start:X}"); m.Unsupported ??= $"section id {id}"; break; }
                if (order <= Order(last)) m.Issues.Add($"section {Name(id)} at 0x{start:X} is out of order or repeated");
                last = id;
                m.Sections.Add((id, body, end));
            }
            try
            {
                var s = new WasmReader(bytes, body, end);
                m.Section(id, ref s, ct);
                if (id != 0 && s.Pos != end) m.Issues.Add($"section {Name(id)} at 0x{start:X}: {end - s.Pos} bytes left over");
            }
            catch (WasmFormatException ex)
            {
                m.Issues.Add($"section {Name(id)} at 0x{start:X}: {ex.Message}");
                // Later sections would be read against a wrong count.
                if (id is 1 or 2 or 3 or 10) break;
            }
            p = end;
        }
        if (m.Functions.Count != m.Bodies.Count && m.Issues.Count == 0)
            m.Issues.Add($"function and code section counts differ ({m.Functions.Count} and {m.Bodies.Count})");
        return m;
    }

    /// <summary>The order of known sections; data count (12) sits before code (10), tags (13) between memory and global.</summary>
    private static int Order(byte id) => id switch
    {
        0 => 0, 1 => 1, 2 => 2, 3 => 3, 4 => 4, 5 => 5, 13 => 6, 6 => 7, 7 => 8, 8 => 9, 9 => 10, 12 => 11, 10 => 12, 11 => 13,
        _ => -1,
    };

    public static string Name(byte id) => id switch
    {
        0 => "custom", 1 => "type", 2 => "import", 3 => "function", 4 => "table", 5 => "memory", 6 => "global", 7 => "export", 8 => "start",
        9 => "element", 10 => "code", 11 => "data", 12 => "datacount", 13 => "tag", _ => $"id {id}",
    };

    private void Section(byte id, ref WasmReader r, CancellationToken ct)
    {
        switch (id)
        {
            case 0:
                {
                    var name = r.Name();
                    Customs.Add((name, r.Pos, r.End));
                    if (name == "name")
                    {
                        try { NameSection(r); }
                        catch (WasmFormatException ex) { Issues.Add($"name section: {ex.Message}"); }
                    }
                    r.Pos = r.End;
                    break;
                }
            case 1:
                for (uint i = 0, n = Count(ref r); i < n; i++)
                {
                    if (r.Peek() == 0x4E)
                    {
                        r.Byte();
                        Gc = true;
                        uint size = Count(ref r);
                        int group = Types.Count;
                        for (uint k = 0; k < size; k++) SubType(ref r, group, (int)size);
                    }
                    else SubType(ref r, Types.Count, 1);
                }
                break;
            case 2:
                for (uint i = 0, n = Count(ref r); i < n; i++)
                {
                    int at = r.Pos;
                    var module = r.Name();
                    var field = r.Name();
                    byte kind = r.Byte();
                    WasmImport import;
                    switch (kind)
                    {
                        case 0: import = new WasmImport(module, field, WasmExternal.Func, r.U32(), null, null, null); ImportedFunctions++; break;
                        case 1: import = new WasmImport(module, field, WasmExternal.Table, 0, TableType(ref r), null, null); ImportedTables++; break;
                        case 2: import = new WasmImport(module, field, WasmExternal.Memory, 0, null, Limits(ref r, memory: true), null); ImportedMemories++; break;
                        case 3: import = new WasmImport(module, field, WasmExternal.Global, 0, null, null, GlobalType(ref r)); ImportedGlobals++; break;
                        case 4:
                            if (r.Byte() != 0) throw new WasmFormatException("tag attribute is not 0");
                            import = new WasmImport(module, field, WasmExternal.Tag, r.U32(), null, null, null);
                            ImportedTags++;
                            break;
                        default: throw new WasmFormatException($"import {i} has kind {kind}");
                    }
                    Imports.Add(import with { Offset = at });
                }
                break;
            case 3:
                for (uint i = 0, n = Count(ref r); i < n; i++) Functions.Add(r.U32());
                break;
            case 4:
                for (uint i = 0, n = Count(ref r); i < n; i++)
                {
                    if (r.Peek() == 0x40)
                    {
                        r.Byte();
                        if (r.Byte() != 0) throw new WasmFormatException("table with an initializer: reserved byte is not 0");
                        var type = TableType(ref r);
                        Tables.Add(new WasmTable(type, ConstExpr(ref r)));
                    }
                    else Tables.Add(new WasmTable(TableType(ref r), null));
                }
                break;
            case 5:
                for (uint i = 0, n = Count(ref r); i < n; i++) Memories.Add(Limits(ref r, memory: true));
                break;
            case 13:
                for (uint i = 0, n = Count(ref r); i < n; i++)
                {
                    if (r.Byte() != 0) throw new WasmFormatException("tag attribute is not 0");
                    Tags.Add(r.U32());
                }
                break;
            case 6:
                for (uint i = 0, n = Count(ref r); i < n; i++)
                {
                    int at = r.Pos;
                    var type = GlobalType(ref r);
                    Globals.Add(new WasmGlobal(type, ConstExpr(ref r)) { Offset = at });
                }
                break;
            case 7:
                for (uint i = 0, n = Count(ref r); i < n; i++)
                {
                    int at = r.Pos;
                    var name = r.Name();
                    byte kind = r.Byte();
                    if (kind > 4) throw new WasmFormatException($"export {i} has kind {kind}");
                    Exports.Add(new WasmExport(name, (WasmExternal)kind, r.U32()) { Offset = at });
                }
                break;
            case 8: Start = r.U32(); break;
            case 9:
                for (uint i = 0, n = Count(ref r); i < n; i++) { int at = r.Pos; Elements.Add(Element(ref r) with { Position = at }); }
                break;
            case 12: DataCount = r.U32(); break;
            case 10:
                for (uint i = 0, n = Count(ref r); i < n; i++)
                {
                    if ((i & 0xFFF) == 0) ct.ThrowIfCancellationRequested();
                    uint size = r.U32();
                    if (size > r.End - r.Pos) throw new WasmFormatException($"function body {i} runs past the section");
                    int start = r.Pos, end = start + (int)size;
                    var b = new WasmReader(Bytes, start, end);
                    uint groups = b.U32();
                    if (groups > MaxCount) throw new WasmFormatException($"function body {i}: {groups} local groups");
                    var locals = new (uint, WasmType)[groups];
                    for (uint g = 0; g < groups; g++) locals[g] = (b.U32(), ValType(ref b));
                    Bodies.Add(new WasmBody(start, end, b.Pos, locals));
                    r.Pos = end;
                }
                break;
            case 11:
                for (uint i = 0, n = Count(ref r); i < n; i++)
                {
                    uint flags = r.U32();
                    WasmData data = flags switch
                    {
                        0 => Segment(ref r, WasmSegmentMode.Active, 0, ConstExpr(ref r)),
                        1 => Segment(ref r, WasmSegmentMode.Passive, 0, null),
                        2 => Segment(ref r, WasmSegmentMode.Active, r.U32(), ConstExpr(ref r)),
                        _ => throw new WasmFormatException($"data segment {i} has flags {flags}"),
                    };
                    Data.Add(data);
                }
                break;
        }
    }

    private static WasmData Segment(ref WasmReader r, WasmSegmentMode mode, uint memory, WasmExpr? offset)
    {
        uint length = r.U32();
        if (length > r.End - r.Pos) throw new WasmFormatException("data segment runs past the section");
        var d = new WasmData(mode, memory, offset, r.Pos, (int)length);
        r.Pos += (int)length;
        return d;
    }

    private WasmElement Element(ref WasmReader r)
    {
        uint flags = r.U32();
        if (flags > 7) throw new WasmFormatException($"element segment flags {flags}");
        bool passiveOrDeclarative = (flags & 1) != 0, explicitTable = (flags & 2) != 0, exprs = (flags & 4) != 0;
        var mode = !passiveOrDeclarative ? WasmSegmentMode.Active : explicitTable ? WasmSegmentMode.Declarative : WasmSegmentMode.Passive;
        uint table = 0;
        WasmExpr? offset = null;
        if (mode == WasmSegmentMode.Active)
        {
            if (explicitTable) table = r.U32();
            offset = ConstExpr(ref r);
        }
        var type = WasmType.FuncRef;
        if (passiveOrDeclarative || explicitTable)
        {
            if (exprs) type = ValType(ref r);
            else if (r.Byte() != 0) throw new WasmFormatException("element kind is not funcref");
        }
        uint n = Count(ref r);
        if (exprs)
        {
            var list = new WasmExpr[n];
            for (uint i = 0; i < n; i++) list[i] = ConstExpr(ref r);
            return new WasmElement(flags, mode, table, offset, type, null, list);
        }
        var funcs = new uint[n];
        for (uint i = 0; i < n; i++) funcs[i] = r.U32();
        return new WasmElement(flags, mode, table, offset, type, funcs, null);
    }

    /// <summary>A constant expression: instructions up to the end that closes it (nested blocks are not allowed).</summary>
    private static WasmExpr ConstExpr(ref WasmReader r)
    {
        int start = r.Pos;
        var code = new WasmCode(r.Bytes, r.Pos, r.End);
        while (true)
        {
            if (!code.Next(out var ins)) throw new WasmFormatException(code.Error ?? "constant expression runs past the section");
            if (ins.Op == 0x0B) { r.Pos = code.Pos; return new WasmExpr(start, code.Pos); }
        }
    }

    private uint Count(ref WasmReader r)
    {
        uint n = r.U32();
        if (n > MaxCount || n > r.End - r.Pos) throw new WasmFormatException($"count {n} exceeds the section");
        return n;
    }

    /// <summary>One subtype: [sub [final] supertypes] then a func (0x60), struct (0x5F) or array (0x5E) composite type.</summary>
    private void SubType(ref WasmReader r, int group, int groupSize)
    {
        byte b = r.Byte();
        bool final = true;
        uint[] supers = [];
        if (b is 0x50 or 0x4F)
        {
            Gc = true;
            final = b == 0x4F;
            supers = new uint[Count(ref r)];
            for (int s = 0; s < supers.Length; s++) supers[s] = r.U32();
            b = r.Byte();
        }
        switch (b)
        {
            case 0x60:
                {
                    var func = new WasmFuncType(ValTypes(ref r), ValTypes(ref r));
                    Types.Add(func);
                    TypeDefs.Add(new WasmTypeDef(WasmComposite.Func, func, [], final, supers, group, groupSize));
                    break;
                }
            case 0x5F:
                {
                    Gc = true;
                    var fields = new WasmField[Count(ref r)];
                    for (int f = 0; f < fields.Length; f++) fields[f] = FieldType(ref r);
                    Types.Add(new WasmFuncType([], []));
                    TypeDefs.Add(new WasmTypeDef(WasmComposite.Struct, null, fields, final, supers, group, groupSize));
                    break;
                }
            case 0x5E:
                Gc = true;
                Types.Add(new WasmFuncType([], []));
                TypeDefs.Add(new WasmTypeDef(WasmComposite.Array, null, [FieldType(ref r)], final, supers, group, groupSize));
                break;
            default:
                throw new WasmFormatException($"type {Types.Count} has form 0x{b:X2}");
        }
    }

    private WasmField FieldType(ref WasmReader r)
    {
        byte packed = r.Peek() switch { 0x78 => 8, 0x77 => 16, _ => 0 };
        var type = packed != 0 ? WasmType.I32 : ValType(ref r);
        if (packed != 0) r.Byte();
        byte mut = r.Byte();
        if (mut > 1) throw new WasmFormatException($"field mutability {mut}");
        return new WasmField(type, packed, mut == 1);
    }

    private WasmType[] ValTypes(ref WasmReader r)
    {
        uint n = Count(ref r);
        var types = new WasmType[n];
        for (uint i = 0; i < n; i++) types[i] = ValType(ref r);
        return types;
    }

    internal WasmType ValType(ref WasmReader r)
    {
        var t = ReadValType(ref r);
        if (WasmRef.IsRef(t) && t is not (WasmType.FuncRef or WasmType.ExternRef or WasmType.ExnRef)) Gc = true;
        return t;
    }

    /// <summary>A value type: one byte, or 0x63 (ref null) / 0x64 (ref) followed by a heap type (s33: an abstract byte or a type index).</summary>
    internal static WasmType ReadValType(ref WasmReader r)
    {
        byte b = r.Byte();
        if (IsValType(b)) return (WasmType)b;
        if (b is 0x63 or 0x64)
        {
            long heap = r.S33();
            if (heap < 0 && !WasmRef.IsAbstractHeap((int)(heap + 0x80))) throw new WasmFormatException($"heap type {heap}");
            if (heap >= 1 << 24) throw new WasmFormatException($"heap type {heap} is out of range");
            return WasmRef.Make(b == 0x63, heap);
        }
        throw new WasmFormatException($"value type 0x{b:X2}");
    }

    /// <summary>A one-byte value type: a number, v128, or a nullable abstract reference shorthand.</summary>
    internal static bool IsValType(byte b) => b is 0x7F or 0x7E or 0x7D or 0x7C or 0x7B || WasmRef.IsAbstractHeap(b);

    private WasmTableType TableType(ref WasmReader r)
    {
        var type = ValType(ref r);
        if (!WasmRef.IsRef(type)) throw new WasmFormatException($"table element type {TypeName(type)}");
        return new WasmTableType(type, Limits(ref r, memory: false));
    }

    private WasmGlobalType GlobalType(ref WasmReader r)
    {
        var type = ValType(ref r);
        byte mut = r.Byte();
        if (mut > 1) throw new WasmFormatException($"global mutability {mut}");
        return new WasmGlobalType(type, mut == 1);
    }

    /// <summary>The single result of a block type that names a value type, else null (empty, or a type index).</summary>
    public static WasmType? BlockResult(long blockType) => blockType switch
    {
        -0x40 or >= 0 => null,
        <= WasmCode.TypedBlock => (WasmType)(int)(WasmCode.TypedBlock - blockType),
        _ => (WasmType)(int)(blockType & 0x7F),
    };

    /// <summary>The function type at a type index, or null when the index is out of range or names a struct or array.</summary>
    public WasmFuncType? FuncTypeAt(long index) =>
        index >= 0 && index < Types.Count && (index >= TypeDefs.Count || TypeDefs[(int)index].Kind == WasmComposite.Func) ? Types[(int)index] : null;

    private static WasmLimits Limits(ref WasmReader r, bool memory)
    {
        byte flags = r.Byte();
        if (flags > (memory ? 7 : 5)) throw new WasmFormatException($"limits flags 0x{flags:X2}");
        bool is64 = (flags & 4) != 0, shared = (flags & 2) != 0;
        ulong min = is64 ? r.U64() : r.U32();
        ulong? max = (flags & 1) != 0 ? is64 ? r.U64() : r.U32() : null;
        return new WasmLimits(min, max, shared, is64);
    }

    private void NameSection(WasmReader r)
    {
        byte previous = 0;
        bool first = true;
        while (r.Pos < r.End)
        {
            byte sub = r.Byte();
            uint size = r.U32();
            if (size > r.End - r.Pos) throw new WasmFormatException("subsection runs past the section");
            if (!first && sub <= previous) throw new WasmFormatException($"subsection {sub} out of order");
            first = false;
            previous = sub;
            var s = new WasmReader(r.Bytes, r.Pos, r.Pos + (int)size);
            r.Pos += (int)size;
            switch (sub)
            {
                case 0: Names.Module = s.Name(); break;
                case 1: Map(ref s, Names.Functions); break;
                case 2:
                    for (uint i = 0, n = s.U32(); i < n && s.Pos < s.End; i++)
                    {
                        uint func = s.U32();
                        var locals = new Dictionary<uint, string>();
                        Map(ref s, locals);
                        Names.Locals[func] = locals;
                    }
                    break;
                case 4: Map(ref s, Names.Types); break;
                case 5: Map(ref s, Names.Tables); break;
                case 6: Map(ref s, Names.Memories); break;
                case 7: Map(ref s, Names.Globals); break;
                case 8: Map(ref s, Names.Elements); break;
                case 9: Map(ref s, Names.Data); break;
                case 11: Map(ref s, Names.Tags); break;
            }
        }
    }

    private static void Map(ref WasmReader r, Dictionary<uint, string> into)
    {
        uint n = r.U32();
        for (uint i = 0; i < n && r.Pos < r.End; i++)
        {
            uint index = r.U32();
            into[index] = r.Name();
        }
    }

    // Lookups.

    /// <summary>The type of function <paramref name="index"/> (imports first), or null when out of range.</summary>
    public WasmFuncType? FunctionType(uint index)
    {
        uint type;
        if (index < ImportedFunctions) type = ImportAt(WasmExternal.Func, index)!.TypeIndex;
        else if (index - ImportedFunctions < Functions.Count) type = Functions[(int)(index - ImportedFunctions)];
        else return null;
        return FuncTypeAt(type);
    }

    public uint? FunctionTypeIndex(uint index) =>
        index < ImportedFunctions ? ImportAt(WasmExternal.Func, index)!.TypeIndex
        : index - ImportedFunctions < Functions.Count ? Functions[(int)(index - ImportedFunctions)] : null;

    private Dictionary<WasmExternal, List<WasmImport>>? _importsByKind;

    /// <summary>The <paramref name="index"/>-th import of a kind.</summary>
    public WasmImport? ImportAt(WasmExternal kind, uint index)
    {
        _importsByKind ??= Imports.GroupBy(i => i.Kind).ToDictionary(g => g.Key, g => g.ToList());
        return _importsByKind.TryGetValue(kind, out var list) && index < list.Count ? list[(int)index] : null;
    }

    public WasmGlobalType? GlobalTypeOf(uint index) =>
        index < ImportedGlobals ? ImportAt(WasmExternal.Global, index)!.Global
        : index - ImportedGlobals < Globals.Count ? Globals[(int)(index - ImportedGlobals)].Type : null;

    public WasmTableType? TableTypeOf(uint index) =>
        index < ImportedTables ? ImportAt(WasmExternal.Table, index)!.Table
        : index - ImportedTables < Tables.Count ? Tables[(int)(index - ImportedTables)].Type : null;

    public WasmLimits? MemoryOf(uint index) =>
        index < ImportedMemories ? ImportAt(WasmExternal.Memory, index)!.Memory
        : index - ImportedMemories < Memories.Count ? Memories[(int)(index - ImportedMemories)] : null;

    public uint? TagTypeIndex(uint index) =>
        index < ImportedTags ? ImportAt(WasmExternal.Tag, index)!.TypeIndex
        : index - ImportedTags < Tags.Count ? Tags[(int)(index - ImportedTags)] : null;

    /// <summary>The body of function <paramref name="index"/>, or null for an import or a missing body.</summary>
    public WasmBody? BodyOf(uint index) => index >= ImportedFunctions && index - ImportedFunctions < Bodies.Count ? Bodies[(int)(index - ImportedFunctions)] : null;

    /// <summary>The text format of a value type; a defined heap type by its index (<paramref name="typeName"/> may name it).</summary>
    public static string TypeName(WasmType t, Func<int, string>? typeName = null) => t switch
    {
        WasmType.I32 => "i32", WasmType.I64 => "i64", WasmType.F32 => "f32", WasmType.F64 => "f64", WasmType.V128 => "v128",
        _ when (int)t is >= 0x69 and <= 0x74 => (int)t switch
        {
            0x71 => "nullref", 0x72 => "nullexternref", 0x73 => "nullfuncref", 0x74 => "nullexnref", var b => WasmRef.HeapName(b) + "ref",
        },
        _ when WasmRef.IsRef(t) => $"(ref {(WasmRef.Nullable(t) ? "null " : "")}{HeapText(WasmRef.Heap(t), typeName)})",
        _ => $"type_0x{(int)t:x2}",
    };

    public static string HeapText((bool Abstract, int Value) heap, Func<int, string>? typeName = null) =>
        heap.Abstract ? WasmRef.HeapName(heap.Value) : typeName?.Invoke(heap.Value) ?? heap.Value.ToString(System.Globalization.CultureInfo.InvariantCulture);

    /// <summary>A heap type immediate (s33) as text: an abstract name or a type index.</summary>
    public static string HeapText(long heap, Func<int, string>? typeName = null) =>
        heap < 0 ? WasmRef.HeapName((int)(heap + 0x80)) : HeapText((false, (int)heap), typeName);

    /// <summary>A UTF-8 string of the module (names), decoded with replacement characters for invalid sequences.</summary>
    internal static string Utf8(ReadOnlySpan<byte> b) => Encoding.UTF8.GetString(b);
}

/// <summary>Malformed bytes; the reader turns it into an issue.</summary>
public sealed class WasmFormatException(string message) : Exception(message);

/// <summary>A bounds-checked cursor over a byte range: LEB128 integers, bytes and names.</summary>
internal struct WasmReader(byte[] bytes, int pos, int end)
{
    public readonly byte[] Bytes = bytes;
    public int Pos = pos;
    public readonly int End = end;

    public byte Peek() => Pos < End ? Bytes[Pos] : throw new WasmFormatException("unexpected end");
    public byte Byte() => Pos < End ? Bytes[Pos++] : throw new WasmFormatException("unexpected end");

    public uint U32() => TryU32(out var v) ? v : throw new WasmFormatException("bad LEB128 u32");

    public bool TryU32(out uint value)
    {
        value = 0;
        for (int shift = 0; shift < 35; shift += 7)
        {
            if (Pos >= End) return false;
            byte b = Bytes[Pos++];
            if (shift == 28 && (b & 0x70) != 0) return false;
            value |= (uint)(b & 0x7F) << shift;
            if ((b & 0x80) == 0) return true;
        }
        return false;
    }

    public ulong U64()
    {
        ulong value = 0;
        for (int shift = 0; shift < 70; shift += 7)
        {
            byte b = Byte();
            if (shift == 63 && (b & 0x7E) != 0) throw new WasmFormatException("bad LEB128 u64");
            value |= (ulong)(b & 0x7F) << shift;
            if ((b & 0x80) == 0) return value;
        }
        throw new WasmFormatException("bad LEB128 u64");
    }

    public int S32()
    {
        int result = 0, shift = 0;
        byte b;
        do
        {
            if (shift >= 35) throw new WasmFormatException("bad LEB128 s32");
            b = Byte();
            // The last byte's unused bits sign-extend bit 31.
            if (shift == 28 && ((b & 0x80) != 0 || (b & 0x78) is not (0 or 0x78))) throw new WasmFormatException("bad LEB128 s32");
            result |= (b & 0x7F) << shift;
            shift += 7;
        } while ((b & 0x80) != 0);
        if (shift < 32 && (b & 0x40) != 0) result |= -1 << shift;
        return result;
    }

    public long S64()
    {
        long result = 0;
        int shift = 0;
        byte b;
        do
        {
            if (shift >= 70) throw new WasmFormatException("bad LEB128 s64");
            b = Byte();
            if (shift == 63 && b != 0 && b != 0x7F) throw new WasmFormatException("bad LEB128 s64");
            result |= (long)(b & 0x7F) << shift;
            shift += 7;
        } while ((b & 0x80) != 0);
        if (shift < 64 && (b & 0x40) != 0) result |= -1L << shift;
        return result;
    }

    /// <summary>A signed 33-bit block type: a negative value type code, or a type index.</summary>
    public long S33()
    {
        long result = 0;
        int shift = 0;
        byte b;
        do
        {
            if (shift >= 35) throw new WasmFormatException("bad block type");
            b = Byte();
            result |= (long)(b & 0x7F) << shift;
            shift += 7;
        } while ((b & 0x80) != 0);
        if (shift < 64 && (b & 0x40) != 0) result |= -1L << shift;
        return result;
    }

    public string Name()
    {
        uint length = U32();
        if (length > End - Pos) throw new WasmFormatException("name runs past the section");
        var s = WasmBinary.Utf8(Bytes.AsSpan(Pos, (int)length));
        Pos += (int)length;
        return s;
    }
}
