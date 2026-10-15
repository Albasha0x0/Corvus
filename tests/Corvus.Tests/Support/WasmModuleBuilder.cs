using System.Text;
using Corvus.Core.WebAssembly;

namespace Corvus.Tests;

/// <summary>Instruction bytes: opcodes, LEB128 immediates, constants.</summary>
internal sealed class WasmAsm
{
    private readonly List<byte> _b = [];

    public byte[] Bytes => [.. _b];

    public WasmAsm Op(params byte[] bytes) { _b.AddRange(bytes); return this; }

    /// <summary>A prefixed opcode (0xFC, 0xFD, 0xFE) with its LEB128 sub-opcode.</summary>
    public WasmAsm Prefixed(byte prefix, uint sub) { _b.Add(prefix); return U(sub); }

    public WasmAsm U(ulong v) { _b.AddRange(Leb(v)); return this; }
    public WasmAsm S(long v) { _b.AddRange(Sleb(v)); return this; }
    public WasmAsm I32(int v) { _b.Add(0x41); return S(v); }
    public WasmAsm I64(long v) { _b.Add(0x42); return S(v); }
    public WasmAsm F32Bits(uint bits) { _b.Add(0x43); _b.AddRange(BitConverter.GetBytes(bits)); return this; }
    public WasmAsm F64Bits(ulong bits) { _b.Add(0x44); _b.AddRange(BitConverter.GetBytes(bits)); return this; }
    public WasmAsm F32(float v) => F32Bits(BitConverter.SingleToUInt32Bits(v));
    public WasmAsm F64(double v) => F64Bits(BitConverter.DoubleToUInt64Bits(v));
    public WasmAsm Raw(byte[] bytes) { _b.AddRange(bytes); return this; }
    public WasmAsm End() => Op(0x0B);

    /// <summary>A constant of each type a signature letter names (i, l, f, d, v).</summary>
    public WasmAsm Const(char type) => type switch
    {
        'i' => I32(1),
        'l' => I64(1),
        'f' => F32(1),
        'd' => F64(1),
        'v' => Prefixed(0xFD, 12).Raw(new byte[16]),
        _ => throw new ArgumentException($"no constant for '{type}'"),
    };

    public static byte[] Leb(ulong v)
    {
        var o = new List<byte>();
        do
        {
            byte b = (byte)(v & 0x7F);
            v >>= 7;
            if (v != 0) b |= 0x80;
            o.Add(b);
        } while (v != 0);
        return [.. o];
    }

    public static byte[] Sleb(long v)
    {
        var o = new List<byte>();
        while (true)
        {
            byte b = (byte)(v & 0x7F);
            v >>= 7;
            bool done = v == 0 && (b & 0x40) == 0 || v == -1 && (b & 0x40) != 0;
            if (!done) b |= 0x80;
            o.Add(b);
            if (done) return [.. o];
        }
    }
}

/// <summary>Writes a module section by section; every method takes ready entries, so invalid modules are as easy as valid ones.</summary>
internal sealed class WasmModuleBuilder
{
    private readonly List<byte[]> _types = [], _imports = [], _tables = [], _memories = [], _tags = [], _globals = [], _exports = [], _elements = [], _codes = [], _data = [];
    private readonly List<uint> _funcs = [];
    private readonly List<(string Name, byte[] Body)> _customs = [];
    private uint? _start, _dataCount;
    private int _importedFuncs;

    public static byte[] Name(string s) { var b = Encoding.UTF8.GetBytes(s); return [.. WasmAsm.Leb((ulong)b.Length), .. b]; }
    private static byte[] Vec(IEnumerable<byte[]> items) { var list = items.ToList(); return [.. WasmAsm.Leb((ulong)list.Count), .. list.SelectMany(x => x)]; }
    private static byte[] Types(WasmType[] t) => [.. WasmAsm.Leb((ulong)t.Length), .. t.Select(x => (byte)x)];

    public uint Type(WasmType[] parameters, WasmType[] results) { _types.Add([0x60, .. Types(parameters), .. Types(results)]); return (uint)_types.Count - 1; }

    public uint ImportFunc(string module, string name, uint type) { _imports.Add([.. Name(module), .. Name(name), 0, .. WasmAsm.Leb(type)]); return (uint)_importedFuncs++; }
    public void ImportTable(string module, string name, WasmType element, uint min, uint? max = null) => _imports.Add([.. Name(module), .. Name(name), 1, (byte)element, .. Limits(min, max)]);
    public void ImportMemory(string module, string name, uint min, uint? max = null, bool shared = false) => _imports.Add([.. Name(module), .. Name(name), 2, .. Limits(min, max, shared)]);
    public void ImportGlobal(string module, string name, WasmType type, bool mutable) => _imports.Add([.. Name(module), .. Name(name), 3, (byte)type, (byte)(mutable ? 1 : 0)]);
    public void ImportTag(string module, string name, uint type) => _imports.Add([.. Name(module), .. Name(name), 4, 0, .. WasmAsm.Leb(type)]);

    public static byte[] Limits(ulong min, ulong? max, bool shared = false, bool is64 = false) =>
        [(byte)((max != null ? 1 : 0) | (shared ? 2 : 0) | (is64 ? 4 : 0)), .. WasmAsm.Leb(min), .. max is { } m ? WasmAsm.Leb(m) : []];

    /// <summary>A function of <paramref name="type"/>: locals as (count, type) groups, the body without its final end.</summary>
    public uint Func(uint type, byte[] body, params (uint Count, WasmType Type)[] locals)
    {
        _funcs.Add(type);
        byte[] code = [.. Vec(locals.Select(l => (byte[])[.. WasmAsm.Leb(l.Count), (byte)l.Type])), .. body, 0x0B];
        _codes.Add([.. WasmAsm.Leb((ulong)code.Length), .. code]);
        return (uint)(_importedFuncs + _funcs.Count - 1);
    }

    /// <summary>A function section entry and code entry given as raw bytes (for bodies that are deliberately malformed).</summary>
    public void RawFunc(uint type, byte[] code) { _funcs.Add(type); _codes.Add([.. WasmAsm.Leb((ulong)code.Length), .. code]); }

    public void Table(WasmType element, uint min, uint? max = null) => _tables.Add([(byte)element, .. Limits(min, max)]);
    public void Memory(ulong min, ulong? max = null, bool shared = false, bool is64 = false) => _memories.Add(Limits(min, max, shared, is64));
    public void Tag(uint type) => _tags.Add([0, .. WasmAsm.Leb(type)]);
    public void Global(WasmType type, bool mutable, byte[] init) => _globals.Add([(byte)type, (byte)(mutable ? 1 : 0), .. init, 0x0B]);
    public void Export(string name, WasmExternal kind, uint index) => _exports.Add([.. Name(name), (byte)kind, .. WasmAsm.Leb(index)]);
    public void Start(uint function) => _start = function;
    public void DataCount(uint count) => _dataCount = count;

    /// <summary>An element segment's bytes after its flags.</summary>
    public void ElementRaw(uint flags, byte[] rest) => _elements.Add([.. WasmAsm.Leb(flags), .. rest]);

    /// <summary>The common form: active in table 0 at an i32 offset, function indexes.</summary>
    public void Element(int offset, params uint[] functions) =>
        ElementRaw(0, [.. new WasmAsm().I32(offset).End().Bytes, .. Vec(functions.Select(f => WasmAsm.Leb(f)))]);

    public static byte[] FunctionList(params uint[] functions) => Vec(functions.Select(f => WasmAsm.Leb(f)));
    public static byte[] ExprList(params byte[][] exprs) => Vec(exprs.Select(e => (byte[])[.. e, 0x0B]));

    public void Data(int offset, byte[] bytes) => _data.Add([0, .. new WasmAsm().I32(offset).End().Bytes, .. WasmAsm.Leb((ulong)bytes.Length), .. bytes]);
    public void PassiveData(byte[] bytes) => _data.Add([1, .. WasmAsm.Leb((ulong)bytes.Length), .. bytes]);
    public void DataIn(uint memory, int offset, byte[] bytes) => _data.Add([2, .. WasmAsm.Leb(memory), .. new WasmAsm().I32(offset).End().Bytes, .. WasmAsm.Leb((ulong)bytes.Length), .. bytes]);

    public void Custom(string name, byte[] body) => _customs.Add((name, body));

    /// <summary>A name section: module name, then maps by subsection id (1 functions, 4 types, 7 globals...), and local names.</summary>
    public void Names(string? module, Dictionary<int, Dictionary<uint, string>> maps, Dictionary<uint, Dictionary<uint, string>>? locals = null)
    {
        var body = new List<byte>();
        void Sub(int id, byte[] content) { body.Add((byte)id); body.AddRange(WasmAsm.Leb((ulong)content.Length)); body.AddRange(content); }
        static byte[] Map(Dictionary<uint, string> m) => Vec(m.OrderBy(x => x.Key).Select(x => (byte[])[.. WasmAsm.Leb(x.Key), .. Name(x.Value)]));
        if (module != null) Sub(0, Name(module));
        foreach (var (id, map) in maps.Where(m => m.Key < 2)) Sub(id, Map(map));
        if (locals != null) Sub(2, Vec(locals.OrderBy(x => x.Key).Select(x => (byte[])[.. WasmAsm.Leb(x.Key), .. Map(x.Value)])));
        foreach (var (id, map) in maps.Where(m => m.Key > 2).OrderBy(m => m.Key)) Sub(id, Map(map));
        _customs.Add(("name", [.. body]));
    }

    public byte[] Build()
    {
        var o = new List<byte>([0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00]);
        void Section(byte id, byte[] content) { o.Add(id); o.AddRange(WasmAsm.Leb((ulong)content.Length)); o.AddRange(content); }
        if (_types.Count > 0) Section(1, Vec(_types));
        if (_imports.Count > 0) Section(2, Vec(_imports));
        if (_funcs.Count > 0) Section(3, Vec(_funcs.Select(f => WasmAsm.Leb(f))));
        if (_tables.Count > 0) Section(4, Vec(_tables));
        if (_memories.Count > 0) Section(5, Vec(_memories));
        if (_tags.Count > 0) Section(13, Vec(_tags));
        if (_globals.Count > 0) Section(6, Vec(_globals));
        if (_exports.Count > 0) Section(7, Vec(_exports));
        if (_start is { } s) Section(8, WasmAsm.Leb(s));
        if (_elements.Count > 0) Section(9, Vec(_elements));
        if (_dataCount is { } dc) Section(12, WasmAsm.Leb(dc));
        if (_codes.Count > 0) Section(10, Vec(_codes));
        if (_data.Count > 0) Section(11, Vec(_data));
        foreach (var (name, body) in _customs) Section(0, [.. Name(name), .. body]);
        return [.. o];
    }
}
