namespace Corvus.Core.WebAssembly;

/// <summary>A WebAssembly component's world in WIT syntax from its top-level imports and exports; nested components are counted.</summary>
public sealed class WasmWorld
{
    private const int MaxDepth = 32, MaxItems = 100_000;

    /// <summary>A named type of an interface: its name and definition ("record { a: u32 }", "resource", "type list&lt;u8&gt;").</summary>
    public sealed record TypeDef(string Name, string Definition);

    /// <summary>A function: its name as the binary has it ("[method]stream.read") and signature ("func(self: borrow&lt;stream&gt;) -> u64").</summary>
    public sealed record Function(string Name, string Signature);

    /// <summary>A top-level import or export: interface, func, type, instance, component, module or value, with what its type declares.</summary>
    public sealed record Item(string Direction, string Name, string Kind, IReadOnlyList<TypeDef> Types, IReadOnlyList<Function> Functions, string? Signature, string? Note);

    public List<Item> Imports { get; } = [];
    public List<Item> Exports { get; } = [];
    /// <summary>Entries per section kind ("core module", "type", "canon lift" ...).</summary>
    public SortedDictionary<string, int> Sections { get; } = new(StringComparer.Ordinal);
    /// <summary>String encodings named by canonical options.</summary>
    public SortedSet<string> StringEncodings { get; } = new(StringComparer.Ordinal);
    public List<string> Issues { get; } = [];

    // Component-level types, as the binary format defines them.
    private abstract class T;
    private sealed class Prim(string name) : T { public readonly string Name = name; }
    private sealed class Def(string kind) : T
    {
        public readonly string Kind = kind;
        public readonly List<(string Name, T? Type)> Fields = [];
        public readonly List<T?> Items = [];
        public uint Length;
    }
    private sealed class Res(string? name) : T { public readonly string? Name = name; }
    private sealed class Named(string name, T target) : T { public readonly string Name = name; public readonly T Target = target; }
    private sealed class Func(List<(string Name, T? Type)> ps, T? result, bool async, bool hasResult) : T
    {
        public readonly List<(string Name, T? Type)> Params = ps;
        public readonly T? Result = result;
        public readonly bool Async = async, HasResult = hasResult;
    }
    private sealed class Inst : T { public readonly List<(string Name, string Sort, T? Type)> Exports = []; }
    private sealed class Comp : T { public readonly List<(string Name, string Sort, T? Type)> Imports = [], Exports = []; }
    private sealed class Opaque(string what) : T { public readonly string What = what; }
    // The (sub resource) bound: each declaration with it makes a fresh resource.
    private sealed class SubResource : T { public static readonly SubResource Bound = new(); }

    private sealed class Scope(Scope? parent)
    {
        public readonly Scope? Parent = parent;
        public readonly List<T?> Types = [], Funcs = [], Instances = [], Components = [];
    }

    private static readonly Dictionary<byte, string> Prims = new()
    {
        [0x7f] = "bool", [0x7e] = "s8", [0x7d] = "u8", [0x7c] = "s16", [0x7b] = "u16", [0x7a] = "s32", [0x79] = "u32", [0x78] = "s64",
        [0x77] = "u64", [0x76] = "f32", [0x75] = "f64", [0x74] = "char", [0x73] = "string", [0x64] = "error-context",
    };

    private static readonly string[] SectionNames =
        ["custom", "core module", "core instance", "core type", "component", "instance", "alias", "type", "canon", "start", "import", "export", "value"];

    private int _items;
    private readonly CancellationToken _ct;
    private readonly int _depth;
    // The declarations as types, for a nested component's type: imports by name, exports in order.
    private readonly Dictionary<string, T?> _imported = new(StringComparer.Ordinal);
    private readonly List<(string Name, string Sort, T? Type)> _exported = [];

    private WasmWorld(CancellationToken ct, int depth)
    {
        _ct = ct;
        _depth = depth;
    }

    /// <summary>Reads the top level of the component in <paramref name="bytes"/>; null when it is not a component. A section that cannot be read ends the walk and is named in <see cref="Issues"/>.</summary>
    public static WasmWorld? Read(byte[] bytes, CancellationToken ct = default)
    {
        if (!WasmComponent.Looks(bytes)) return null;
        var w = new WasmWorld(ct, 0);
        w.Walk(bytes, 8, bytes.Length, new Scope(null));
        return w;
    }

    /// <summary>Reads the sections in [<paramref name="p"/>, <paramref name="end"/>); false when one could not be read.</summary>
    private bool Walk(byte[] bytes, int p, int end, Scope scope)
    {
        while (p < end)
        {
            int start = p;
            byte id = bytes[p++];
            var head = new WasmReader(bytes, p, end);
            if (!head.TryU32(out uint size) || size > end - head.Pos) { Issues.Add($"section {id} at 0x{start:X} runs past the end"); return false; }
            var r = new WasmReader(bytes, head.Pos, head.Pos + (int)size);
            p = head.Pos + (int)size;
            try { Section(id, ref r, scope); }
            catch (WasmFormatException ex)
            {
                Issues.Add($"the {(id < SectionNames.Length ? SectionNames[id] : $"id {id}")} section at 0x{start:X} is not read ({ex.Message}); later sections are not decoded");
                return false;
            }
        }
        return true;
    }

    // A nested component's type: its imports and exports as declared, or null when it cannot be read.
    private Comp? Nested(ref WasmReader r, Scope s)
    {
        int at = r.Pos, size = r.End - r.Pos;
        if (_depth >= MaxDepth || !WasmComponent.Looks(r.Bytes.AsSpan(at, size))) return null;
        var child = new WasmWorld(_ct, _depth + 1);
        if (!child.Walk(r.Bytes, at + 8, at + size, new Scope(s))) return null;
        var c = new Comp();
        c.Imports.AddRange(child._imported.Select(i => (i.Key, "import", i.Value)));
        c.Exports.AddRange(child._exported);
        return c;
    }

    private void Count(string section, int n = 1) => Sections[section] = Sections.GetValueOrDefault(section) + n;

    private void Budget()
    {
        _ct.ThrowIfCancellationRequested();
        if (++_items > MaxItems) throw new WasmFormatException($"over {MaxItems:N0} definitions");
    }

    private void Section(byte id, ref WasmReader r, Scope s)
    {
        switch (id)
        {
            case 0: Count("custom"); break;
            case 1: Count("core module"); break;
            case 2: Count("core instance", (int)r.U32()); break;
            case 3: Count("core type", (int)r.U32()); break;
            case 4: Count("component"); s.Components.Add(Nested(ref r, s)); break;
            case 5:
                for (uint n = r.U32(), i = 0; i < n; i++) { Budget(); s.Instances.Add(Instance(ref r, s)); Count("instance"); }
                break;
            case 6:
                for (uint n = r.U32(), i = 0; i < n; i++) { Budget(); Alias(ref r, s); Count("alias"); }
                break;
            case 7:
                for (uint n = r.U32(), i = 0; i < n; i++) { Budget(); s.Types.Add(DefType(ref r, s, 0)); Count("type"); }
                break;
            case 8:
                for (uint n = r.U32(), i = 0; i < n; i++) { Budget(); Canon(ref r, s); }
                break;
            case 9: Count("start"); break;
            case 10:
                for (uint n = r.U32(), i = 0; i < n; i++)
                {
                    Budget();
                    var name = ExternName(ref r);
                    var (sort, type) = ExternType(ref r, s);
                    var declared = Declare(s, name, sort, type);
                    _imported[name] = declared;
                    if (_depth == 0) Imports.Add(ItemOf("import", name, sort, declared));
                    Count("import");
                }
                break;
            case 11:
                for (uint n = r.U32(), i = 0; i < n; i++)
                {
                    Budget();
                    var name = ExternName(ref r);
                    var (sort, index) = SortIdx(ref r);
                    T? source = Lookup(s, sort, index);
                    (string Sort, T? Type)? ascribed = r.Byte() == 1 ? ExternType(ref r, s) : null;
                    var type = ascribed?.Type ?? source;
                    // A type export without an ascribed bound names the type it exports.
                    var declared = sort == "type" && ascribed == null && type != null ? Add(s, sort, new Named(name, type)) : Declare(s, name, sort, type);
                    _exported.Add((name, sort, declared));
                    if (_depth == 0) Exports.Add(ItemOf("export", name, sort, declared));
                    Count("export");
                }
                break;
            case 12: Count("value", (int)r.U32()); break;
            default: throw new WasmFormatException($"unknown section id {id}");
        }
    }

    private static T? Add(Scope s, string sort, T? t)
    {
        switch (sort)
        {
            case "type": s.Types.Add(t); break;
            case "func": s.Funcs.Add(t); break;
            case "instance": s.Instances.Add(t); break;
        }
        return t;
    }

    private static T? Lookup(Scope s, string sort, uint i)
    {
        var list = sort switch { "type" => s.Types, "func" => s.Funcs, "instance" => s.Instances, _ => null };
        return list != null && i < list.Count ? list[(int)i] : null;
    }

    private static T? TypeAt(Scope s, uint i) => i < s.Types.Count ? s.Types[(int)i] : throw new WasmFormatException($"type index {i} is out of range ({s.Types.Count})");

    // An import or export declaration: a type bound of (sub resource) makes a fresh resource, (eq i) names type i.
    private static T? Declare(Scope s, string name, string sort, T? type)
    {
        if (sort == "type") return Add(s, sort, type is SubResource ? new Res(name) : type is null ? null : new Named(name, type));
        return Add(s, sort, type);
    }

    private static (string Sort, T? Type) ExternType(ref WasmReader r, Scope s)
    {
        byte k = r.Byte();
        switch (k)
        {
            case 0x00:
                if (r.Byte() != 0x11) throw new WasmFormatException("a core extern type other than a module");
                r.U32();
                return ("module", new Opaque("core module"));
            case 0x01: return ("func", TypeAt(s, r.U32()));
            case 0x02:
                if (r.Byte() == 0x00) r.U32(); else ValType(ref r, s);
                return ("value", new Opaque("value"));
            case 0x03: return ("type", r.Byte() == 0x00 ? TypeAt(s, r.U32()) : SubResource.Bound);
            case 0x04: return ("component", TypeAt(s, r.U32()));
            case 0x05: return ("instance", TypeAt(s, r.U32()));
            default: throw new WasmFormatException($"extern type 0x{k:X2}");
        }
    }

    private static string ExternName(ref WasmReader r)
    {
        byte form = r.Byte();
        if (form > 2) throw new WasmFormatException($"name form 0x{form:X2}");
        var name = r.Name();
        if (form == 2)
            for (uint n = r.U32(), i = 0; i < n; i++)
            {
                byte a = r.Byte();
                if (a > 2) throw new WasmFormatException($"name attribute 0x{a:X2}");
                r.Name();
            }
        return name;
    }

    private static string SortName(ref WasmReader r)
    {
        byte b = r.Byte();
        switch (b)
        {
            case 0x00: r.Byte(); return "core";
            case 0x01: return "func";
            case 0x02: return "value";
            case 0x03: return "type";
            case 0x04: return "component";
            case 0x05: return "instance";
            default: throw new WasmFormatException($"sort 0x{b:X2}");
        }
    }

    private static (string Sort, uint Index) SortIdx(ref WasmReader r) => (SortName(ref r), r.U32());

    private static T? Instance(ref WasmReader r, Scope s)
    {
        byte k = r.Byte();
        if (k == 0x00)
        {
            uint c = r.U32();
            var map = new Dictionary<T, T>(ReferenceEqualityComparer.Instance);
            var component = c < s.Components.Count ? s.Components[(int)c] as Comp : null;
            for (uint n = r.U32(), i = 0; i < n; i++)
            {
                var name = r.Name();
                var (sort, index) = SortIdx(ref r);
                if (component?.Imports.FirstOrDefault(x => x.Name == name).Type is { } from && Lookup(s, sort, index) is { } to) map[from] = to;
            }
            if (component == null) return null;
            // The instance exports what the component does, with the arguments in place of its imports.
            var instance = new Inst();
            var memo = new Dictionary<T, T>(ReferenceEqualityComparer.Instance);
            instance.Exports.AddRange(component.Exports.Select(e => (e.Name, e.Sort, e.Type == null ? null : Substitute(e.Type, map, memo, 0))));
            return instance;
        }
        if (k != 0x01) throw new WasmFormatException($"instance expression 0x{k:X2}");
        var inst = new Inst();
        for (uint n = r.U32(), i = 0; i < n; i++)
        {
            var name = ExternName(ref r);
            var (sort, index) = SortIdx(ref r);
            inst.Exports.Add((name, sort, Lookup(s, sort, index)));
        }
        return inst;
    }

    private static T Substitute(T t, Dictionary<T, T> map, Dictionary<T, T> memo, int depth)
    {
        if (map.TryGetValue(t, out var to)) return to;
        if (memo.TryGetValue(t, out var done)) return done;
        if (depth > MaxDepth) return t;
        T? Sub(T? x) => x == null ? null : Substitute(x, map, memo, depth + 1);
        T result;
        switch (t)
        {
            case Named n: result = Sub(n.Target) is var nt && ReferenceEquals(nt, n.Target) ? n : new Named(n.Name, nt!); break;
            case Def d:
                var copy = new Def(d.Kind) { Length = d.Length };
                copy.Fields.AddRange(d.Fields.Select(f => (f.Name, Sub(f.Type))));
                copy.Items.AddRange(d.Items.Select(Sub));
                result = copy;
                break;
            case Func f: result = new Func([.. f.Params.Select(p => (p.Name, Sub(p.Type)))], Sub(f.Result), f.Async, f.HasResult); break;
            case Inst i:
                var inst = new Inst();
                inst.Exports.AddRange(i.Exports.Select(e => (e.Name, e.Sort, Sub(e.Type))));
                result = inst;
                break;
            default: result = t; break;
        }
        memo[t] = result;
        return result;
    }

    private void Alias(ref WasmReader r, Scope s)
    {
        var sort = SortName(ref r);
        byte target = r.Byte();
        T? t = null;
        switch (target)
        {
            case 0x00:
                uint inst = r.U32();
                var name = r.Name();
                if (inst < s.Instances.Count && s.Instances[(int)inst] is Inst it)
                    t = it.Exports.FirstOrDefault(e => e.Name == name).Type;
                break;
            case 0x01: r.U32(); r.Name(); break;
            case 0x02:
                uint ct = r.U32(), idx = r.U32();
                var outer = s;
                for (uint i = 0; i < ct && outer != null; i++) outer = outer.Parent;
                if (outer != null && sort == "type") t = TypeAt(outer, idx);
                break;
            default: throw new WasmFormatException($"alias target 0x{target:X2}");
        }
        if (sort != "core") Add(s, sort, t);
    }

    private void Canon(ref WasmReader r, Scope s)
    {
        byte op = r.Byte();
        switch (op)
        {
            case 0x00:
                r.Byte(); r.U32(); Opts(ref r);
                s.Funcs.Add(TypeAt(s, r.U32()));
                Count("canon lift");
                return;
            case 0x01: r.Byte(); r.U32(); Opts(ref r); Count("canon lower"); return;
            case 0x02 or 0x03 or 0x04: r.U32(); Count("canon resource"); return;
            case 0x09: ResultList(ref r, s); Opts(ref r); break;
            case 0x0a or 0x0b: r.Byte(); r.U32(); break;
            case 0x06: r.Byte(); break;
            case 0x0e or 0x13 or 0x14 or 0x15 or 0x1a or 0x1b or 0x2e or 0x2f: r.U32(); break;
            case 0x0f or 0x10 or 0x16 or 0x17: r.U32(); Opts(ref r); break;
            case 0x11 or 0x12 or 0x18 or 0x19: r.U32(); r.Byte(); break;
            case 0x1c or 0x1d: Opts(ref r); break;
            case 0x20 or 0x21: r.Byte(); r.U32(); break;
            case 0x0c or 0x29 or 0x2a or 0x2b or 0x2c or 0x2d: r.Byte(); break;
            case 0x27: r.U32(); r.U32(); break;
            case 0x40: r.Byte(); r.U32(); break;
            case 0x41: r.Byte(); r.U32(); r.U32(); break;
            case 0x42: r.Byte(); break;
            case 0x05 or 0x0d or 0x1e or 0x1f or 0x22 or 0x23 or 0x24 or 0x25 or 0x26 or 0x28: break;
            default: throw new WasmFormatException($"canonical definition 0x{op:X2}");
        }
        Count("canon builtin");
    }

    private void Opts(ref WasmReader r)
    {
        for (uint n = r.U32(), i = 0; i < n; i++)
        {
            byte o = r.Byte();
            switch (o)
            {
                case 0x00: StringEncodings.Add("utf8"); break;
                case 0x01: StringEncodings.Add("utf16"); break;
                case 0x02: StringEncodings.Add("latin1+utf16"); break;
                case 0x03 or 0x04 or 0x05 or 0x07: r.U32(); break;
                case 0x06: break;
                default: throw new WasmFormatException($"canonical option 0x{o:X2}");
            }
        }
    }

    private T? DefType(ref WasmReader r, Scope s, int depth)
    {
        if (depth > MaxDepth) throw new WasmFormatException($"types nested deeper than {MaxDepth} levels");
        byte b = r.Peek();
        switch (b)
        {
            case 0x40 or 0x43:
            {
                r.Byte();
                var ps = new List<(string, T?)>();
                for (uint n = r.U32(), i = 0; i < n; i++) ps.Add((r.Name(), ValType(ref r, s)));
                var (has, result) = ResultList(ref r, s);
                return new Func(ps, result, b == 0x43, has);
            }
            case 0x41:
            {
                r.Byte();
                var c = new Comp();
                var inner = new Scope(s);
                for (uint n = r.U32(), i = 0; i < n; i++)
                {
                    Budget();
                    if (r.Peek() == 0x03)
                    {
                        r.Byte();
                        var name = ExternName(ref r);
                        var (sort, type) = ExternType(ref r, inner);
                        c.Imports.Add((name, sort, Declare(inner, name, sort, type)));
                    }
                    else InstanceDecl(ref r, inner, c.Exports, depth + 1);
                }
                return c;
            }
            case 0x42:
            {
                r.Byte();
                var it = new Inst();
                var inner = new Scope(s);
                for (uint n = r.U32(), i = 0; i < n; i++) { Budget(); InstanceDecl(ref r, inner, it.Exports, depth + 1); }
                return it;
            }
            case 0x3f:
                r.Byte();
                r.Byte();
                if (r.Byte() == 0x01) r.U32();
                return new Res(null);
            default:
                return DefValType(ref r, s);
        }
    }

    private void InstanceDecl(ref WasmReader r, Scope s, List<(string, string, T?)> exports, int depth)
    {
        byte k = r.Byte();
        switch (k)
        {
            case 0x00: CoreType(ref r); break;
            case 0x01: s.Types.Add(DefType(ref r, s, depth)); break;
            case 0x02: Alias(ref r, s); break;
            case 0x04:
                var name = ExternName(ref r);
                var (sort, type) = ExternType(ref r, s);
                exports.Add((name, sort, Declare(s, name, sort, type)));
                break;
            default: throw new WasmFormatException($"declaration 0x{k:X2}");
        }
    }

    private (bool Has, T? Type) ResultList(ref WasmReader r, Scope s)
    {
        byte k = r.Byte();
        if (k == 0x00) return (true, ValType(ref r, s));
        if (k == 0x01 && r.Byte() == 0x00) return (false, null);
        throw new WasmFormatException("a result list other than one type or none");
    }

    private T? DefValType(ref WasmReader r, Scope s)
    {
        byte b = r.Byte();
        if (Prims.TryGetValue(b, out var prim)) return new Prim(prim);
        Def d;
        switch (b)
        {
            case 0x72:
                d = new Def("record");
                for (uint n = r.U32(), i = 0; i < n; i++) d.Fields.Add((r.Name(), ValType(ref r, s)));
                return d;
            case 0x71:
                d = new Def("variant");
                for (uint n = r.U32(), i = 0; i < n; i++)
                {
                    var label = r.Name();
                    d.Fields.Add((label, r.Byte() == 0x01 ? ValType(ref r, s) : null));
                    if (r.Byte() != 0x00) throw new WasmFormatException("a variant case with a refinement");
                }
                return d;
            case 0x70: d = new Def("list"); d.Items.Add(ValType(ref r, s)); return d;
            case 0x67: d = new Def("list"); d.Items.Add(ValType(ref r, s)); d.Length = r.U32(); return d;
            case 0x6f:
                d = new Def("tuple");
                for (uint n = r.U32(), i = 0; i < n; i++) d.Items.Add(ValType(ref r, s));
                return d;
            case 0x6e or 0x6d:
                d = new Def(b == 0x6e ? "flags" : "enum");
                for (uint n = r.U32(), i = 0; i < n; i++) d.Fields.Add((r.Name(), null));
                return d;
            case 0x6b: d = new Def("option"); d.Items.Add(ValType(ref r, s)); return d;
            case 0x6a:
                d = new Def("result");
                d.Items.Add(r.Byte() == 0x01 ? ValType(ref r, s) : null);
                d.Items.Add(r.Byte() == 0x01 ? ValType(ref r, s) : null);
                return d;
            case 0x69 or 0x68: d = new Def(b == 0x69 ? "own" : "borrow"); d.Items.Add(TypeAt(s, r.U32())); return d;
            case 0x66 or 0x65: d = new Def(b == 0x66 ? "stream" : "future"); d.Items.Add(r.Byte() == 0x01 ? ValType(ref r, s) : null); return d;
            case 0x63: d = new Def("map"); d.Items.Add(ValType(ref r, s)); d.Items.Add(ValType(ref r, s)); return d;
            default: throw new WasmFormatException($"type 0x{b:X2}");
        }
    }

    // A value type is a primitive's (negative) s33 code or a type index.
    private static T? ValType(ref WasmReader r, Scope s)
    {
        long v = r.S33();
        if (v >= 0) return TypeAt(s, (uint)v);
        return Prims.TryGetValue((byte)(v & 0x7F), out var prim) ? new Prim(prim) : throw new WasmFormatException($"value type {v}");
    }

    // A core type inside a component type: a module type, read only to keep the position.
    private static void CoreType(ref WasmReader r)
    {
        if (r.Byte() != 0x50) throw new WasmFormatException("a core type other than a module type");
        for (uint n = r.U32(), i = 0; i < n; i++)
        {
            byte k = r.Byte();
            switch (k)
            {
                case 0x00: r.Name(); r.Name(); CoreExtern(ref r); break;
                case 0x01:
                    if (r.Byte() != 0x60) throw new WasmFormatException("a core type other than a function type");
                    for (int part = 0; part < 2; part++)
                        for (uint m = r.U32(), j = 0; j < m; j++) CoreValType(ref r);
                    break;
                case 0x02: r.Byte(); r.Byte(); r.U32(); r.U32(); break;
                case 0x03: r.Name(); CoreExtern(ref r); break;
                default: throw new WasmFormatException($"module declaration 0x{k:X2}");
            }
        }
    }

    private static void CoreExtern(ref WasmReader r)
    {
        byte k = r.Byte();
        switch (k)
        {
            case 0x00: r.U32(); break;
            case 0x01: CoreValType(ref r); Limits(ref r); break;
            case 0x02: Limits(ref r); break;
            case 0x03: CoreValType(ref r); r.Byte(); break;
            case 0x04: r.Byte(); r.U32(); break;
            default: throw new WasmFormatException($"core extern type 0x{k:X2}");
        }
    }

    private static void CoreValType(ref WasmReader r)
    {
        byte b = r.Byte();
        if (b is 0x63 or 0x64) r.S33();
    }

    private static void Limits(ref WasmReader r)
    {
        uint flags = r.U32();
        if ((flags & 4) != 0) { r.U64(); if ((flags & 1) != 0) r.U64(); }
        else { r.U32(); if ((flags & 1) != 0) r.U32(); }
    }

    private static Item ItemOf(string direction, string name, string sort, T? type)
    {
        switch (sort)
        {
            case "instance" when type is Inst inst:
            {
                var types = new List<TypeDef>();
                var funcs = new List<Function>();
                foreach (var (n, s, t) in inst.Exports)
                {
                    if (s == "type" && t != null) types.Add(new TypeDef(n, Definition(t)));
                    else if (s == "func" && t is Func f) funcs.Add(new Function(n, Signature(f)));
                }
                var other = inst.Exports.Where(e => e.Sort is not ("type" or "func")).Select(e => $"{e.Name} ({e.Sort})").ToList();
                return new Item(direction, name, "interface", types, funcs, null, other.Count > 0 ? "also exports " + string.Join(", ", other) : null);
            }
            case "func" when type is Func f: return new Item(direction, name, "func", [], [], Signature(f), null);
            case "type" when type != null: return new Item(direction, name, "type", [], [], Definition(type), null);
            default:
                return new Item(direction, name, sort, [], [], null, type == null ? "type unknown: the definition it comes from is not decoded" : null);
        }
    }

    private static string Signature(Func f) =>
        (f.Async ? "async func(" : "func(") + string.Join(", ", f.Params.Select(p => $"{p.Name}: {Ref(p.Type)}")) + ")" + (f.HasResult ? " -> " + Ref(f.Result) : "");

    /// <summary>A named type's definition: the record, variant, enum or flags body, "resource", or "type" and what it stands for.</summary>
    private static string Definition(T t) => t switch
    {
        Res or Named { Target: Res { Name: null } } => "resource",
        Named { Target: Def { Kind: "record" or "variant" or "enum" or "flags" } d } => Body(d),
        Named n => "type " + Ref(n.Target),
        Def { Kind: "record" or "variant" or "enum" or "flags" } d => Body(d),
        _ => "type " + Ref(t),
    };

    private static string Body(Def d) => d.Kind switch
    {
        "record" => $"record {{ {string.Join(", ", d.Fields.Select(f => $"{f.Name}: {Ref(f.Type)}"))} }}",
        "variant" => $"variant {{ {string.Join(", ", d.Fields.Select(f => f.Type == null ? f.Name : $"{f.Name}({Ref(f.Type)})"))} }}",
        _ => $"{d.Kind} {{ {string.Join(", ", d.Fields.Select(f => f.Name))} }}",
    };

    private static string Ref(T? t) => t switch
    {
        null => "unknown",
        Prim p => p.Name,
        Named n => n.Name,
        Res r => r.Name ?? "resource",
        Func f => Signature(f),
        Def d => d.Kind switch
        {
            "list" => d.Length > 0 ? $"list<{Ref(d.Items[0])}, {d.Length}>" : $"list<{Ref(d.Items[0])}>",
            "tuple" => $"tuple<{string.Join(", ", d.Items.Select(Ref))}>",
            "option" => $"option<{Ref(d.Items[0])}>",
            "result" => (d.Items[0], d.Items[1]) switch
            {
                (null, null) => "result",
                (var ok, null) => $"result<{Ref(ok)}>",
                (var ok, var err) => $"result<{(ok == null ? "_" : Ref(ok))}, {Ref(err)}>",
            },
            "own" => Ref(d.Items[0]),
            "borrow" => $"borrow<{Ref(d.Items[0])}>",
            "stream" or "future" => d.Items[0] == null ? d.Kind : $"{d.Kind}<{Ref(d.Items[0])}>",
            "map" => $"map<{Ref(d.Items[0])}, {Ref(d.Items[1])}>",
            _ => Body(d),
        },
        Opaque o => o.What,
        _ => "unknown",
    };
}
