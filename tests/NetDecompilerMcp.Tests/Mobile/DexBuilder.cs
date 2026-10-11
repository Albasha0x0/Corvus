using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace NetDecompilerMcp.Tests;

/// <summary>Pool indexes an instruction is encoded with, assigned once every pool is sorted.</summary>
internal interface IDexPools
{
    int String(string s);
    int Type(string descriptor);
    int Field(string id);
    int Method(string id);
    int Proto(string descriptor);
}

/// <summary>One instruction to encode: its code units, given the final pool indexes.</summary>
internal sealed record DexInsn(Func<IDexPools, ushort[]> Encode, string[] Strings, string[] Types, string[] Fields, string[] Methods);

/// <summary>Instruction encoders by format (Dalvik bytecode spec). Branch offsets are relative code units, as in the encoding.</summary>
internal static class Asm
{
    private static DexInsn Plain(params ushort[] units) => new(_ => units, [], [], [], []);
    private static ushort U(int op, int hi) => (ushort)(op | hi << 8);

    public static DexInsn Raw(params ushort[] units) => Plain(units);
    public static DexInsn Nop() => Plain(0);
    public static DexInsn ReturnVoid() => Plain(0x0e);
    public static DexInsn Return(int op, int reg) => Plain(U(op, reg));
    public static DexInsn Op11x(int op, int a) => Plain(U(op, a));
    public static DexInsn Op12x(int op, int a, int b) => Plain(U(op, a | b << 4));
    public static DexInsn Op23x(int op, int a, int b, int c) => Plain(U(op, a), (ushort)(b | c << 8));
    public static DexInsn Const4(int reg, int value) => Plain(U(0x12, reg | (value & 0xF) << 4));
    public static DexInsn Const16(int reg, short value) => Plain(U(0x13, reg), (ushort)value);
    public static DexInsn Const(int reg, int value) => Plain(U(0x14, reg), (ushort)value, (ushort)(value >> 16));
    public static DexInsn ConstHigh16(int reg, int value) => Plain(U(0x15, reg), (ushort)((uint)value >> 16));
    public static DexInsn ConstWide(int reg, long value) => Plain(U(0x18, reg), (ushort)value, (ushort)(value >> 16), (ushort)(value >> 32), (ushort)(value >> 48));
    public static DexInsn ConstString(int reg, string s) => new(p => [U(0x1a, reg), (ushort)p.String(s)], [s], [], [], []);
    public static DexInsn ConstClass(int reg, string type) => new(p => [U(0x1c, reg), (ushort)p.Type(type)], [], [type], [], []);
    public static DexInsn NewInstance(int reg, string type) => new(p => [U(0x22, reg), (ushort)p.Type(type)], [], [type], [], []);
    public static DexInsn CheckCast(int reg, string type) => new(p => [U(0x1f, reg), (ushort)p.Type(type)], [], [type], [], []);
    public static DexInsn Goto(int offset) => Plain(U(0x28, offset & 0xFF));
    public static DexInsn IfEqz(int reg, short offset) => Plain(U(0x38, reg), (ushort)offset);
    public static DexInsn IfEq(int a, int b, short offset) => Plain(U(0x32, a | b << 4), (ushort)offset);
    public static DexInsn AddIntLit8(int a, int b, sbyte lit) => Plain(U(0xd8, a), (ushort)(b | (byte)lit << 8));
    public static DexInsn PackedSwitch(int reg, int payloadOffset) => Plain(U(0x2b, reg), (ushort)payloadOffset, (ushort)(payloadOffset >> 16));
    public static DexInsn FillArrayData(int reg, int payloadOffset) => Plain(U(0x26, reg), (ushort)payloadOffset, (ushort)(payloadOffset >> 16));

    /// <summary>iget / iput (0x52-0x5f): vA, vB (object), field.</summary>
    public static DexInsn Instance(int op, int a, int b, string field) => new(p => [U(op, a | b << 4), (ushort)p.Field(field)], [], [], [field], []);
    /// <summary>sget / sput (0x60-0x6d): vAA, field.</summary>
    public static DexInsn Static(int op, int a, string field) => new(p => [U(op, a), (ushort)p.Field(field)], [], [], [field], []);

    /// <summary>invoke-kind (0x6e-0x72) with up to five registers.</summary>
    public static DexInsn Invoke(int op, string method, params int[] regs)
    {
        int[] r = [.. regs, 0, 0, 0, 0, 0];
        return new(p => [U(op, regs.Length << 4 | r[4]), (ushort)p.Method(method), (ushort)(r[0] | r[1] << 4 | r[2] << 8 | r[3] << 12)], [], [], [], [method]);
    }

    /// <summary>invoke-kind/range (0x74-0x78): count registers from first.</summary>
    public static DexInsn InvokeRange(int op, string method, int first, int count) =>
        new(p => [U(op, count), (ushort)p.Method(method), (ushort)first], [], [], [], [method]);

    public static DexInsn PackedSwitchPayload(int first, params int[] targets)
    {
        var units = new List<ushort> { 0x0100, (ushort)targets.Length, (ushort)first, (ushort)(first >> 16) };
        foreach (var t in targets) { units.Add((ushort)t); units.Add((ushort)(t >> 16)); }
        return Plain([.. units]);
    }

    public static DexInsn ArrayPayload(int width, params long[] values)
    {
        var bytes = new List<byte>();
        foreach (var v in values) for (int k = 0; k < width; k++) bytes.Add((byte)(v >> (8 * k)));
        if (bytes.Count % 2 == 1) bytes.Add(0);
        var units = new List<ushort> { 0x0300, (ushort)width, (ushort)values.Length, (ushort)(values.Length >> 16) };
        for (int i = 0; i < bytes.Count; i += 2) units.Add((ushort)(bytes[i] | bytes[i + 1] << 8));
        return Plain([.. units]);
    }
}

/// <summary>
/// Writes a DEX file (version 035) with the pools sorted as the spec requires, class data, code items with try blocks and line
/// numbers, class annotations, static values and a map list; checksum and signature are computed.
/// </summary>
internal sealed class DexBuilder
{
    public sealed record Try(int Start, int Count, (string? Type, int Handler)[] Handlers);

    public sealed class MethodDef(string name, string returnType, string[] parameters, uint access)
    {
        public string Name { get; } = name;
        public string Return { get; } = returnType;
        public string[] Parameters { get; } = parameters;
        public uint Access { get; } = access;
        public int Registers { get; set; } = 4;
        public List<DexInsn>? Code { get; set; }
        public List<Try> Tries { get; } = [];
        public List<(int Offset, int Line)> Lines { get; } = [];
        public string?[]? ParameterNames { get; set; }
    }

    public sealed class ClassDef(string descriptor, uint access, string? super, string? source)
    {
        public string Descriptor { get; } = descriptor;
        public uint Access { get; } = access;
        public string? Super { get; } = super;
        public string? Source { get; } = source;
        public List<string> Interfaces { get; } = [];
        public List<(string Name, string Type, uint Access, int? Value)> Fields { get; } = [];
        public List<MethodDef> Methods { get; } = [];
        /// <summary>Class annotations: (type, visibility, elements of strings / ints / string arrays).</summary>
        public List<(string Type, byte Visibility, (string Name, object Value)[] Elements)> Annotations { get; } = [];

        public MethodDef Method(string name, string returnType, string[] parameters, uint access, params DexInsn[] code)
        {
            var m = new MethodDef(name, returnType, parameters, access) { Code = code.Length > 0 || (access & 0x500) == 0 ? [.. code] : null };
            Methods.Add(m);
            return m;
        }

        public ClassDef Field(string name, string type, uint access = 1, int? value = null) { Fields.Add((name, type, access, value)); return this; }
    }

    private readonly List<ClassDef> _classes = [];

    public ClassDef Class(string descriptor, uint access = 1, string? super = "Ljava/lang/Object;", string? source = null)
    {
        var c = new ClassDef(descriptor, access, super, source);
        _classes.Add(c);
        return c;
    }

    private static string Shorty(string t) => t.StartsWith('L') || t.StartsWith('[') ? "L" : t;
    private static string ProtoKey(string ret, string[] ps) => "(" + string.Concat(ps) + ")" + ret;
    private static (string Class, string Name, string Tail) Split(string id)
    {
        int arrow = id.IndexOf("->", StringComparison.Ordinal);
        var rest = id[(arrow + 2)..];
        int cut = rest.IndexOfAny(['(', ':']);
        return (id[..arrow], rest[..cut], rest[cut..]);
    }

    private static string[] ParseParameters(string proto)
    {
        var inner = proto[1..proto.IndexOf(')')];
        var list = new List<string>();
        for (int i = 0; i < inner.Length;)
        {
            int s = i;
            while (inner[i] == '[') i++;
            i = inner[i] == 'L' ? inner.IndexOf(';', i) + 1 : i + 1;
            list.Add(inner[s..i]);
        }
        return [.. list];
    }

    private sealed class Pools : IDexPools
    {
        public List<string> Strings = [], Types = [], Protos = [], Fields = [], Methods = [];
        public Dictionary<string, int> S = [], T = [], P = [], F = [], M = [];
        public int String(string s) => S[s];
        public int Type(string d) => T[d];
        public int Field(string id) => F[id];
        public int Method(string id) => M[id];
        public int Proto(string d) => P[d];
    }

    public byte[] Build()
    {
        var strings = new HashSet<string>(StringComparer.Ordinal);
        var types = new HashSet<string>(StringComparer.Ordinal);
        var protos = new HashSet<string>(StringComparer.Ordinal);
        var fields = new HashSet<string>(StringComparer.Ordinal);
        var methods = new HashSet<string>(StringComparer.Ordinal);
        void AddType(string t) { types.Add(t); strings.Add(t); }
        void AddProto(string p) { protos.Add(p); var ret = p[(p.IndexOf(')') + 1)..]; AddType(ret); foreach (var x in ParseParameters(p)) AddType(x); strings.Add(Shorty(ret) + string.Concat(ParseParameters(p).Select(Shorty))); }
        void AddField(string id) { fields.Add(id); var (c, n, r) = Split(id); AddType(c); strings.Add(n); AddType(r[1..]); }
        void AddMethod(string id) { methods.Add(id); var (c, n, r) = Split(id); AddType(c); strings.Add(n); AddProto(r); }
        foreach (var c in _classes)
        {
            AddType(c.Descriptor);
            if (c.Super != null) AddType(c.Super);
            if (c.Source != null) strings.Add(c.Source);
            c.Interfaces.ForEach(AddType);
            foreach (var f in c.Fields) AddField($"{c.Descriptor}->{f.Name}:{f.Type}");
            foreach (var m in c.Methods)
            {
                AddMethod($"{c.Descriptor}->{m.Name}{ProtoKey(m.Return, m.Parameters)}");
                foreach (var i in m.Code ?? [])
                {
                    foreach (var s in i.Strings) strings.Add(s);
                    i.Types.ToList().ForEach(AddType);
                    i.Fields.ToList().ForEach(AddField);
                    i.Methods.ToList().ForEach(AddMethod);
                }
                foreach (var t in m.Tries.SelectMany(t => t.Handlers).Select(h => h.Type).OfType<string>()) AddType(t);
                foreach (var n in m.ParameterNames ?? []) if (n != null) strings.Add(n);
            }
            foreach (var a in c.Annotations)
            {
                AddType(a.Type);
                foreach (var (name, value) in a.Elements)
                {
                    strings.Add(name);
                    if (value is string s) strings.Add(s);
                    if (value is string[] arr) foreach (var x in arr) strings.Add(x);
                }
            }
        }
        var p = new Pools();
        p.Strings = [.. strings.Order(StringComparer.Ordinal)];
        for (int i = 0; i < p.Strings.Count; i++) p.S[p.Strings[i]] = i;
        p.Types = [.. types.OrderBy(t => p.S[t])];
        for (int i = 0; i < p.Types.Count; i++) p.T[p.Types[i]] = i;
        p.Protos = [.. protos.OrderBy(x => p.T[x[(x.IndexOf(')') + 1)..]]).ThenBy(x => string.Join(",", ParseParameters(x).Select(t => p.T[t].ToString("D5"))), StringComparer.Ordinal)];
        for (int i = 0; i < p.Protos.Count; i++) p.P[p.Protos[i]] = i;
        p.Fields = [.. fields.OrderBy(f => p.T[Split(f).Class]).ThenBy(f => p.S[Split(f).Name]).ThenBy(f => p.T[Split(f).Tail[1..]])];
        for (int i = 0; i < p.Fields.Count; i++) p.F[p.Fields[i]] = i;
        p.Methods = [.. methods.OrderBy(m => p.T[Split(m).Class]).ThenBy(m => p.S[Split(m).Name]).ThenBy(m => p.P[Split(m).Tail])];
        for (int i = 0; i < p.Methods.Count; i++) p.M[p.Methods[i]] = i;
        var classes = _classes.OrderBy(c => p.T[c.Descriptor]).ToList();

        var w = new MemoryStream();
        void U8(byte v) => w.WriteByte(v);
        void U16(ushort v) => w.Write(BitConverter.GetBytes(v));
        void U32(uint v) => w.Write(BitConverter.GetBytes(v));
        void Uleb(uint v) { do { byte b = (byte)(v & 0x7F); v >>= 7; U8((byte)(b | (v != 0 ? 0x80 : 0))); } while (v != 0); }
        void Sleb(int v) { while (true) { byte b = (byte)(v & 0x7F); v >>= 7; bool done = (v == 0 && (b & 0x40) == 0) || (v == -1 && (b & 0x40) != 0); U8((byte)(b | (done ? 0 : 0x80))); if (done) break; } }
        void Align4() { while (w.Length % 4 != 0) U8(0); }
        void PatchU32(long at, uint v) { var pos = w.Position; w.Position = at; U32(v); w.Position = pos; }

        w.Write(new byte[0x70]);
        long stringIds = w.Length; w.Write(new byte[p.Strings.Count * 4]);
        long typeIds = w.Length; foreach (var t in p.Types) U32((uint)p.S[t]);
        long protoIds = w.Length; w.Write(new byte[p.Protos.Count * 12]);
        long fieldIds = w.Length;
        foreach (var f in p.Fields) { var (c, n, r) = Split(f); U16((ushort)p.T[c]); U16((ushort)p.T[r[1..]]); U32((uint)p.S[n]); }
        long methodIds = w.Length;
        foreach (var m in p.Methods) { var (c, n, r) = Split(m); U16((ushort)p.T[c]); U16((ushort)p.P[r]); U32((uint)p.S[n]); }
        long classDefs = w.Length; w.Write(new byte[classes.Count * 32]);
        long data = w.Length;
        var map = new List<(ushort Type, int Count, long Offset)> { (0x0000, 1, 0) };
        if (p.Strings.Count > 0) map.Add((0x0001, p.Strings.Count, stringIds));
        if (p.Types.Count > 0) map.Add((0x0002, p.Types.Count, typeIds));
        if (p.Protos.Count > 0) map.Add((0x0003, p.Protos.Count, protoIds));
        if (p.Fields.Count > 0) map.Add((0x0004, p.Fields.Count, fieldIds));
        if (p.Methods.Count > 0) map.Add((0x0005, p.Methods.Count, methodIds));
        if (classes.Count > 0) map.Add((0x0006, classes.Count, classDefs));

        // Type lists (proto parameters, interfaces), 4-aligned.
        var typeLists = new Dictionary<string, long>(StringComparer.Ordinal);
        long TypeList(IReadOnlyList<string> list)
        {
            if (list.Count == 0) return 0;
            var key = string.Join(",", list);
            if (typeLists.TryGetValue(key, out var at)) return at;
            Align4();
            at = w.Length;
            U32((uint)list.Count);
            foreach (var t in list) U16((ushort)p.T[t]);
            return typeLists[key] = at;
        }
        long typeListsStart = -1;
        for (int i = 0; i < p.Protos.Count; i++)
        {
            var ps = ParseParameters(p.Protos[i]);
            long before = w.Length;
            long at = TypeList(ps);
            if (typeListsStart < 0 && at != 0) typeListsStart = at;
            var ret = p.Protos[i][(p.Protos[i].IndexOf(')') + 1)..];
            PatchU32(protoIds + i * 12, (uint)p.S[Shorty(ret) + string.Concat(ps.Select(Shorty))]);
            PatchU32(protoIds + i * 12 + 4, (uint)p.T[ret]);
            PatchU32(protoIds + i * 12 + 8, (uint)at);
        }
        var interfaceLists = classes.Select(c => { long at = TypeList(c.Interfaces); if (typeListsStart < 0 && at != 0) typeListsStart = at; return at; }).ToList();
        if (typeLists.Count > 0) map.Add((0x1001, typeLists.Count, typeListsStart));

        // Code items with debug info, then class data.
        var codeOffsets = new Dictionary<MethodDef, long>();
        int codeCount = 0;
        long codeStart = 0, debugStart = 0;
        int debugCount = 0;
        var debugOffsets = new Dictionary<MethodDef, long>();
        foreach (var m in classes.SelectMany(c => c.Methods).Where(m => m.Lines.Count > 0 || m.ParameterNames != null))
        {
            if (debugCount++ == 0) debugStart = w.Length;
            debugOffsets[m] = w.Length;
            int line = m.Lines.Count > 0 ? m.Lines[0].Line : 1;
            Uleb((uint)line);
            var names = m.ParameterNames ?? new string?[m.Parameters.Length];
            Uleb((uint)names.Length);
            foreach (var n in names) Uleb(n == null ? 0u : (uint)p.S[n] + 1);
            int address = 0, current = line;
            foreach (var (offset, l) in m.Lines)
            {
                int dl = l - current, da = offset - address;
                if (dl < -4 || dl > 10) { U8(0x02); Sleb(dl); dl = 0; }
                int special = 0x0A + (dl + 4) + 15 * da;
                if (special > 0xFF) { U8(0x01); Uleb((uint)da); da = 0; special = 0x0A + (dl + 4); }
                U8((byte)special);
                address = offset;
                current = l;
            }
            U8(0x00);
        }
        if (debugCount > 0) map.Add((0x2003, debugCount, debugStart));
        foreach (var m in classes.SelectMany(c => c.Methods).Where(m => m.Code != null))
        {
            Align4();
            if (codeCount++ == 0) codeStart = w.Length;
            codeOffsets[m] = w.Length;
            var units = m.Code!.SelectMany(i => i.Encode(p)).ToArray();
            int ins = m.Parameters.Sum(t => t is "J" or "D" ? 2 : 1) + ((m.Access & 0x8) == 0 ? 1 : 0);
            U16((ushort)m.Registers); U16((ushort)ins); U16(5); U16((ushort)m.Tries.Count);
            U32(debugOffsets.TryGetValue(m, out var dbg) ? (uint)dbg : 0); U32((uint)units.Length);
            foreach (var u in units) U16(u);
            if (m.Tries.Count > 0)
            {
                if (units.Length % 2 == 1) U16(0);
                var handlers = new MemoryStream();
                var handlerOffsets = new List<int>();
                var hw = w;
                w = handlers;
                Uleb((uint)m.Tries.Count);
                foreach (var t in m.Tries)
                {
                    handlerOffsets.Add((int)w.Length);
                    var typed = t.Handlers.Where(h => h.Type != null).ToList();
                    bool all = t.Handlers.Any(h => h.Type == null);
                    Sleb(all ? -typed.Count : typed.Count);
                    foreach (var h in typed) { Uleb((uint)p.T[h.Type!]); Uleb((uint)h.Handler); }
                    if (all) Uleb((uint)t.Handlers.First(h => h.Type == null).Handler);
                }
                w = hw;
                for (int i = 0; i < m.Tries.Count; i++) { U32((uint)m.Tries[i].Start); U16((ushort)m.Tries[i].Count); U16((ushort)handlerOffsets[i]); }
                w.Write(handlers.ToArray());
            }
        }
        if (codeCount > 0) map.Add((0x2001, codeCount, codeStart));

        // Class annotations: annotation items, sets, directories.
        var directories = new Dictionary<ClassDef, long>();
        long annotationStart = 0, setStart = 0, dirStart = 0;
        int annotationCount = 0, setCount = 0;
        var itemOffsets = new Dictionary<ClassDef, List<long>>();
        foreach (var c in classes.Where(c => c.Annotations.Count > 0))
        {
            var list = new List<long>();
            foreach (var a in c.Annotations.OrderBy(a => p.T[a.Type]))
            {
                if (annotationCount++ == 0) annotationStart = w.Length;
                list.Add(w.Length);
                U8(a.Visibility);
                Uleb((uint)p.T[a.Type]);
                Uleb((uint)a.Elements.Length);
                foreach (var (name, value) in a.Elements.OrderBy(e => p.S[e.Name]))
                {
                    Uleb((uint)p.S[name]);
                    switch (value)
                    {
                        case int i: U8(0x04 | 3 << 5); U32((uint)i); break;
                        case string s: U8(0x17 | 3 << 5); U32((uint)p.S[s]); break;
                        case string[] arr: U8(0x1c); Uleb((uint)arr.Length); foreach (var s in arr) { U8(0x17 | 3 << 5); U32((uint)p.S[s]); } break;
                    }
                }
            }
            itemOffsets[c] = list;
        }
        if (annotationCount > 0) map.Add((0x2004, annotationCount, annotationStart));
        var sets = new Dictionary<ClassDef, long>();
        foreach (var (c, list) in itemOffsets)
        {
            Align4();
            if (setCount++ == 0) setStart = w.Length;
            sets[c] = w.Length;
            U32((uint)list.Count);
            foreach (var at in list) U32((uint)at);
        }
        if (setCount > 0) map.Add((0x1003, setCount, setStart));
        foreach (var (c, set) in sets)
        {
            Align4();
            if (directories.Count == 0) dirStart = w.Length;
            directories[c] = w.Length;
            U32((uint)set); U32(0); U32(0); U32(0);
        }
        if (directories.Count > 0) map.Add((0x2006, directories.Count, dirStart));

        // Static values.
        var staticValues = new Dictionary<ClassDef, long>();
        long staticStart = 0;
        foreach (var c in classes)
        {
            var statics = c.Fields.Where(f => (f.Access & 0x8) != 0).OrderBy(f => p.F[$"{c.Descriptor}->{f.Name}:{f.Type}"]).ToList();
            if (!statics.Any(f => f.Value != null)) continue;
            if (staticValues.Count == 0) staticStart = w.Length;
            staticValues[c] = w.Length;
            Uleb((uint)statics.Count);
            foreach (var f in statics) { U8(0x04 | 3 << 5); U32((uint)(f.Value ?? 0)); }
        }
        if (staticValues.Count > 0) map.Add((0x2005, staticValues.Count, staticStart));

        // Class data.
        var classData = new Dictionary<ClassDef, long>();
        long classDataStart = 0;
        foreach (var c in classes)
        {
            if (c.Fields.Count == 0 && c.Methods.Count == 0) continue;
            if (classData.Count == 0) classDataStart = w.Length;
            classData[c] = w.Length;
            var sf = c.Fields.Where(f => (f.Access & 0x8) != 0).Select(f => (Id: p.F[$"{c.Descriptor}->{f.Name}:{f.Type}"], f.Access)).OrderBy(f => f.Id).ToList();
            var inf = c.Fields.Where(f => (f.Access & 0x8) == 0).Select(f => (Id: p.F[$"{c.Descriptor}->{f.Name}:{f.Type}"], f.Access)).OrderBy(f => f.Id).ToList();
            bool Direct(MethodDef m) => (m.Access & 0xA) != 0 || m.Name is "<init>" or "<clinit>";
            var dm = c.Methods.Where(Direct).Select(m => (Id: p.M[$"{c.Descriptor}->{m.Name}{ProtoKey(m.Return, m.Parameters)}"], M: m)).OrderBy(m => m.Id).ToList();
            var vm = c.Methods.Where(m => !Direct(m)).Select(m => (Id: p.M[$"{c.Descriptor}->{m.Name}{ProtoKey(m.Return, m.Parameters)}"], M: m)).OrderBy(m => m.Id).ToList();
            Uleb((uint)sf.Count); Uleb((uint)inf.Count); Uleb((uint)dm.Count); Uleb((uint)vm.Count);
            foreach (var group in new[] { sf, inf }) { int prev = 0; foreach (var f in group) { Uleb((uint)(f.Id - prev)); Uleb(f.Access); prev = f.Id; } }
            foreach (var group in new[] { dm, vm })
            {
                int prev = 0;
                foreach (var (id, m) in group)
                {
                    Uleb((uint)(id - prev)); Uleb(m.Access | (m.Name is "<init>" or "<clinit>" ? 0x10000u : 0)); Uleb(codeOffsets.TryGetValue(m, out var co) ? (uint)co : 0);
                    prev = id;
                }
            }
        }
        if (classData.Count > 0) map.Add((0x2000, classData.Count, classDataStart));

        // String data.
        long stringData = w.Length;
        for (int i = 0; i < p.Strings.Count; i++)
        {
            PatchU32(stringIds + i * 4, (uint)w.Length);
            Uleb((uint)p.Strings[i].Length);
            w.Write(Mutf8(p.Strings[i]));
            U8(0);
        }
        if (p.Strings.Count > 0) map.Add((0x2002, p.Strings.Count, stringData));

        for (int i = 0; i < classes.Count; i++)
        {
            var c = classes[i];
            long at = classDefs + i * 32;
            PatchU32(at, (uint)p.T[c.Descriptor]);
            PatchU32(at + 4, c.Access);
            PatchU32(at + 8, c.Super == null ? 0xFFFFFFFF : (uint)p.T[c.Super]);
            PatchU32(at + 12, (uint)interfaceLists[i]);
            PatchU32(at + 16, c.Source == null ? 0xFFFFFFFF : (uint)p.S[c.Source]);
            PatchU32(at + 20, directories.TryGetValue(c, out var d) ? (uint)d : 0);
            PatchU32(at + 24, classData.TryGetValue(c, out var cd) ? (uint)cd : 0);
            PatchU32(at + 28, staticValues.TryGetValue(c, out var sv) ? (uint)sv : 0);
        }

        Align4();
        long mapAt = w.Length;
        map.Add((0x1000, 1, mapAt));
        map.Sort((a, b) => a.Offset.CompareTo(b.Offset));
        U32((uint)map.Count);
        foreach (var (type, count, offset) in map) { U16(type); U16(0); U32((uint)count); U32((uint)offset); }

        var bytes = w.ToArray();
        "dex\n035\0"u8.CopyTo(bytes);
        void H(int at, long v) => BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(at), (uint)v);
        H(32, bytes.Length); H(36, 0x70); H(40, 0x12345678); H(52, mapAt);
        H(56, p.Strings.Count); H(60, p.Strings.Count > 0 ? stringIds : 0);
        H(64, p.Types.Count); H(68, p.Types.Count > 0 ? typeIds : 0);
        H(72, p.Protos.Count); H(76, p.Protos.Count > 0 ? protoIds : 0);
        H(80, p.Fields.Count); H(84, p.Fields.Count > 0 ? fieldIds : 0);
        H(88, p.Methods.Count); H(92, p.Methods.Count > 0 ? methodIds : 0);
        H(96, classes.Count); H(100, classes.Count > 0 ? classDefs : 0);
        H(104, bytes.Length - data); H(108, data);
        SHA1.HashData(bytes.AsSpan(32)).CopyTo(bytes, 12);
        uint a1 = 1, b1 = 0;
        foreach (var x in bytes.AsSpan(12)) { a1 = (a1 + x) % 65521; b1 = (b1 + a1) % 65521; }
        H(8, b1 << 16 | a1);
        return bytes;
    }

    private static byte[] Mutf8(string s)
    {
        var o = new List<byte>();
        foreach (char c in s)
        {
            if (c != 0 && c < 0x80) o.Add((byte)c);
            else if (c < 0x800) { o.Add((byte)(0xC0 | c >> 6)); o.Add((byte)(0x80 | c & 0x3F)); }
            else { o.Add((byte)(0xE0 | c >> 12)); o.Add((byte)(0x80 | (c >> 6) & 0x3F)); o.Add((byte)(0x80 | c & 0x3F)); }
        }
        return [.. o];
    }
}
