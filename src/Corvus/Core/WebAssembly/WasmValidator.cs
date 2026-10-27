using System.Globalization;

namespace Corvus.Core.WebAssembly;

/// <summary>A validation verdict: valid, invalid with its errors (each with the function and offset), or unknown when the module holds what is not modelled.</summary>
public sealed record WasmValidation(string Verdict, IReadOnlyList<string> Errors)
{
    public bool Valid => Verdict == "valid";
}

/// <summary>WebAssembly validation by the specification's algorithm, with wasm-validate's features plus threads, and GC when used.</summary>
public sealed class WasmValidator
{
    private const int MaxErrors = 50;
    private const WasmType Unknown = 0;

    private readonly WasmBinary _m;
    private readonly List<string> _errors = [];
    private readonly HashSet<uint> _declared = [];

    // Canonical id of each type index: equal ids are the same type (iso-recursive).
    private readonly int[] _canon;

    private WasmValidator(WasmBinary m)
    {
        _m = m;
        _canon = Canonical(m);
    }

    public static WasmValidation Validate(WasmBinary m, CancellationToken ct = default)
    {
        if (m.Unsupported != null) return new WasmValidation("unknown", [$"not validated: {m.Unsupported} is not modelled"]);
        if (m.Issues.Count > 0) return new WasmValidation("invalid", [.. m.Issues.Take(MaxErrors).Select(i => "malformed: " + i)]);
        var v = new WasmValidator(m);
        v.Module(ct);
        return new WasmValidation(v._errors.Count == 0 ? "valid" : "invalid", v._errors);
    }

    private void Error(string text)
    {
        if (_errors.Count < MaxErrors) _errors.Add(text);
    }

    // Module.

    private void Module(CancellationToken ct)
    {
        TypeSection();
        foreach (var i in _m.Imports)
            switch (i.Kind)
            {
                case WasmExternal.Func: if (_m.FuncTypeAt(i.TypeIndex) == null) Error($"import {i.Module}.{i.Name}: type {i.TypeIndex} {(i.TypeIndex >= _m.Types.Count ? "does not exist" : "is not a function type")}"); break;
                case WasmExternal.Global when !ValidType(i.Global!.Value.Type): Error($"import {i.Module}.{i.Name}: {Name(i.Global!.Value.Type)} names a type that does not exist"); break;
                case WasmExternal.Table: TableLimits(i.Table!.Limits, $"import {i.Module}.{i.Name}"); break;
                case WasmExternal.Memory: MemoryLimits(i.Memory!.Value, $"import {i.Module}.{i.Name}"); break;
                case WasmExternal.Tag: TagType(i.TypeIndex, $"import {i.Module}.{i.Name}"); break;
            }
        for (int f = 0; f < _m.Functions.Count; f++)
            if (_m.FuncTypeAt(_m.Functions[f]) == null) Error($"function {_m.ImportedFunctions + f}: type {_m.Functions[f]} {(_m.Functions[f] >= _m.Types.Count ? "does not exist" : "is not a function type")}");
        if (_m.Functions.Count != _m.Bodies.Count) Error($"{_m.Functions.Count} functions declared, {_m.Bodies.Count} bodies");
        for (int t = 0; t < _m.Tables.Count; t++)
        {
            var table = _m.Tables[t];
            TableLimits(table.Type.Limits, "table");
            if (!ValidType(table.Type.Element)) Error($"table {_m.ImportedTables + t}: element type {Name(table.Type.Element)} names a type that does not exist");
            if (table.Init is { } init) ConstExpr(init, table.Type.Element, $"table {_m.ImportedTables + t} initializer", null);
            else if (!Defaultable(table.Type.Element)) Error($"table {_m.ImportedTables + t}: a {Name(table.Type.Element)} table needs an initializer");
        }
        foreach (var l in _m.Memories) MemoryLimits(l, "memory");
        foreach (var t in _m.Tags) TagType(t, "tag");

        // Function references a body may take: in elements, exports and global initializers.
        foreach (var e in _m.Exports) if (e.Kind == WasmExternal.Func) _declared.Add(e.Index);
        foreach (var e in _m.Elements)
        {
            foreach (var f in e.Functions ?? []) _declared.Add(f);
            foreach (var x in e.Exprs ?? []) RefFuncs(x);
        }
        foreach (var g in _m.Globals) RefFuncs(g.Init);

        for (int g = 0; g < _m.Globals.Count; g++)
            ConstExpr(_m.Globals[g].Init, _m.Globals[g].Type.Type, $"global {_m.ImportedGlobals + g}", (uint)(_m.ImportedGlobals + g));
        var names = new HashSet<string>(StringComparer.Ordinal);
        foreach (var e in _m.Exports)
        {
            if (!names.Add(e.Name)) Error($"export \"{e.Name}\" is duplicated");
            int count = e.Kind switch
            {
                WasmExternal.Func => _m.FunctionCount, WasmExternal.Table => _m.TableCount, WasmExternal.Memory => _m.MemoryCount,
                WasmExternal.Global => _m.GlobalCount, _ => _m.TagCount,
            };
            if (e.Index >= count) Error($"export \"{e.Name}\": {e.Kind.ToString().ToLowerInvariant()} {e.Index} does not exist");
        }
        if (_m.Start is { } start)
        {
            if (_m.FunctionType(start) is not { } st) Error($"start function {start} does not exist");
            else if (st.Params.Length != 0 || st.Results.Length != 0) Error($"start function {start} must take and return nothing");
        }
        for (int i = 0; i < _m.Elements.Count; i++) Element(_m.Elements[i], i);
        if (_m.DataCount is { } dc && dc != _m.Data.Count) Error($"data count {dc} differs from the {_m.Data.Count} data segments");
        for (int i = 0; i < _m.Data.Count; i++)
        {
            var d = _m.Data[i];
            if (d.Mode != WasmSegmentMode.Active) continue;
            if (_m.MemoryOf(d.Memory) is not { } mem) { Error($"data segment {i}: memory {d.Memory} does not exist"); continue; }
            ConstExpr(d.Offset!.Value, mem.Is64 ? WasmType.I64 : WasmType.I32, $"data segment {i} offset", null);
        }
        for (int f = 0; f < _m.Bodies.Count && _errors.Count < MaxErrors; f++)
        {
            if ((f & 0xFF) == 0) ct.ThrowIfCancellationRequested();
            new Function(this, (uint)(_m.ImportedFunctions + f)).Check();
        }
    }

    // Types (GC).

    /// <summary>Canonical type ids: equal for types at the same position in structurally equal recursion groups.</summary>
    private static int[] Canonical(WasmBinary m)
    {
        var canon = new int[m.TypeDefs.Count];
        var groups = new Dictionary<string, int>(StringComparer.Ordinal);
        for (int g = 0; g < m.TypeDefs.Count;)
        {
            var first = m.TypeDefs[g];
            int start = first.Group, size = Math.Max(1, first.GroupSize);
            var key = new System.Text.StringBuilder();
            string Id(long index) => index >= start && index < start + size ? "r" + (index - start) : index < start && index < canon.Length ? "c" + canon[index] : "x" + index;
            string Ref(WasmType t)
            {
                if (!WasmRef.IsRef(t)) return ((int)t).ToString(CultureInfo.InvariantCulture);
                var (isAbstract, value) = WasmRef.Heap(t);
                return (WasmRef.Nullable(t) ? "n" : "") + (isAbstract ? "a" + value : Id(value));
            }
            for (int k = 0; k < size && start + k < m.TypeDefs.Count; k++)
            {
                var d = m.TypeDefs[start + k];
                key.Append('[').Append((int)d.Kind).Append(d.Final ? 'f' : 'o');
                foreach (var s in d.Supers) key.Append('s').Append(Id(s));
                if (d.Func is { } f) key.Append('(').AppendJoin(',', f.Params.Select(Ref)).Append(")(").AppendJoin(',', f.Results.Select(Ref)).Append(')');
                foreach (var field in d.Fields) key.Append('{').Append(Ref(field.Type)).Append(field.Packed).Append(field.Mutable ? 'm' : 'c').Append('}');
                key.Append(']');
            }
            if (!groups.TryGetValue(key.ToString(), out int baseId)) groups[key.ToString()] = baseId = start;
            for (int k = 0; k < size && start + k < canon.Length; k++) canon[start + k] = baseId + k;
            g = start + size;
        }
        return canon;
    }

    /// <summary>Recursion groups, supertypes (earlier, not final, of the same kind and structurally matching) and the value types types use.</summary>
    private void TypeSection()
    {
        for (int i = 0; i < _m.TypeDefs.Count; i++)
        {
            var d = _m.TypeDefs[i];
            int groupEnd = d.Group + Math.Max(1, d.GroupSize);
            var used = d.Func is { } f ? f.Params.Concat(f.Results) : d.Fields.Select(x => x.Type);
            foreach (var t in used)
                if (WasmRef.IsRef(t) && WasmRef.Heap(t) is (false, var value) && (value >= groupEnd || value >= _m.TypeDefs.Count))
                    Error($"type {i}: {Name(t)} names a type after its recursion group");
            if (d.Supers.Length > 1) Error($"type {i}: {d.Supers.Length} supertypes, at most one is allowed");
            foreach (var s in d.Supers)
            {
                if (s >= i) { Error($"type {i}: supertype {s} is not an earlier type"); continue; }
                var sup = _m.TypeDefs[(int)s];
                if (sup.Final) Error($"type {i}: supertype {s} is final");
                else if (!Matches(d, sup)) Error($"type {i} does not match its supertype {s}");
            }
        }
    }

    /// <summary>A type's composite type matches its supertype's: function parameters contra- and results covariant, struct fields a prefix, array elements, each field by its mutability.</summary>
    private bool Matches(WasmTypeDef sub, WasmTypeDef sup)
    {
        if (sub.Kind != sup.Kind) return false;
        if (sub.Kind == WasmComposite.Func)
        {
            var (a, b) = (sub.Func!, sup.Func!);
            return a.Params.Length == b.Params.Length && a.Results.Length == b.Results.Length
                   && a.Params.Zip(b.Params).All(p => Sub(p.Second, p.First)) && a.Results.Zip(b.Results).All(r => Sub(r.First, r.Second));
        }
        if (sub.Fields.Length < sup.Fields.Length) return false;
        for (int k = 0; k < sup.Fields.Length; k++)
            if (!FieldSub(sub.Fields[k], sup.Fields[k])) return false;
        return true;
    }

    /// <summary>A field or element of a subtype: the same packing and mutability, covariant when immutable, equal when mutable.</summary>
    private bool FieldSub(WasmField x, WasmField y) =>
        x.Mutable == y.Mutable && x.Packed == y.Packed && Sub(x.Type, y.Type) && (!x.Mutable || Sub(y.Type, x.Type));

    /// <summary>A type whose references name existing types.</summary>
    internal bool ValidType(WasmType t) => !WasmRef.IsRef(t) || WasmRef.Heap(t) is var (isAbstract, value) && (isAbstract || value < _m.TypeDefs.Count);

    /// <summary>A local, field or table element that can start without a value: numbers, v128 and nullable references.</summary>
    private static bool Defaultable(WasmType t) => !WasmRef.IsRef(t) || WasmRef.Nullable(t);

    /// <summary>Subtyping: equal types, or references with a compatible nullability and heap types. Unknown (unreachable code) matches everything.</summary>
    internal bool Sub(WasmType a, WasmType b)
    {
        if (a == b || a == Unknown || b == Unknown) return true;
        if (!WasmRef.IsRef(a) || !WasmRef.IsRef(b)) return false;
        if (WasmRef.Nullable(a) && !WasmRef.Nullable(b)) return false;
        return HeapSub(WasmRef.Heap(a), WasmRef.Heap(b));
    }

    private bool HeapSub((bool Abstract, int Value) a, (bool Abstract, int Value) b)
    {
        if (a.Abstract && b.Abstract)
            return a.Value == b.Value || (a.Value, b.Value) switch
            {
                // None is below the any hierarchy.
                (0x71, 0x6E or 0x6D or 0x6C or 0x6B or 0x6A) => true,
                // i31, struct, array <: eq <: any.
                (0x6C or 0x6B or 0x6A, 0x6D or 0x6E) => true,
                (0x6D, 0x6E) => true,
                // The bottom types nofunc, noextern and noexn.
                (0x73, 0x70) or (0x72, 0x6F) or (0x74, 0x69) => true,
                _ => false,
            };
        if (a.Abstract)
        {
            if (b.Value >= _m.TypeDefs.Count) return false;
            var kind = _m.TypeDefs[b.Value].Kind;
            return a.Value == 0x71 && kind != WasmComposite.Func || a.Value == 0x73 && kind == WasmComposite.Func;
        }
        if (a.Value >= _m.TypeDefs.Count) return false;
        if (b.Abstract)
            return _m.TypeDefs[a.Value].Kind switch
            {
                WasmComposite.Func => b.Value == 0x70,
                WasmComposite.Struct => b.Value is 0x6B or 0x6D or 0x6E,
                _ => b.Value is 0x6A or 0x6D or 0x6E,
            };
        if (b.Value >= _m.TypeDefs.Count) return false;
        // Up the declared supertype chain, compared by canonical id.
        for (int t = a.Value, guard = 0; guard < 10_000; guard++)
        {
            if (_canon[t] == _canon[b.Value]) return true;
            var supers = _m.TypeDefs[t].Supers;
            if (supers.Length == 0 || supers[0] >= t) return false;
            t = (int)supers[0];
        }
        return false;
    }

    /// <summary>The top of a heap type's hierarchy: any, func, extern or exn, by its byte.</summary>
    private int Top((bool Abstract, int Value) h)
    {
        if (!h.Abstract) return h.Value < _m.TypeDefs.Count && _m.TypeDefs[h.Value].Kind == WasmComposite.Func ? 0x70 : 0x6E;
        return h.Value switch { 0x70 or 0x73 => 0x70, 0x6F or 0x72 => 0x6F, 0x69 or 0x74 => 0x69, _ => 0x6E };
    }

    private void TableLimits(WasmLimits l, string what)
    {
        if (l.Max is { } max && max < l.Min) Error($"{what}: minimum {l.Min} is above the maximum {max}");
        if (l.Shared) Error($"{what}: tables cannot be shared");
    }

    private void MemoryLimits(WasmLimits l, string what)
    {
        ulong pages = l.Is64 ? 1UL << 48 : 65536;
        if (l.Min > pages) Error($"{what}: minimum {l.Min} pages is above {pages}");
        if (l.Max is { } max)
        {
            if (max > pages) Error($"{what}: maximum {max} pages is above {pages}");
            if (max < l.Min) Error($"{what}: minimum {l.Min} is above the maximum {max}");
        }
        else if (l.Shared) Error($"{what}: a shared memory needs a maximum");
    }

    private void TagType(uint type, string what)
    {
        if (_m.FuncTypeAt(type) is not { } t) Error($"{what}: type {type} {(type >= _m.Types.Count ? "does not exist" : "is not a function type")}");
        else if (t.Results.Length != 0) Error($"{what}: a tag type returns nothing");
    }

    private void RefFuncs(WasmExpr e)
    {
        var code = new WasmCode(_m.Bytes, e.Start, e.End);
        while (code.Next(out var ins)) if (ins.Op == 0xD2) _declared.Add(ins.A);
    }

    private void Element(WasmElement e, int index)
    {
        string what = $"element segment {index}";
        if (e.Mode == WasmSegmentMode.Active)
        {
            if (_m.TableTypeOf(e.Table) is not { } table) Error($"{what}: table {e.Table} does not exist");
            else
            {
                if (!Sub(e.Type, table.Element)) Error($"{what}: {Name(e.Type)} elements in a {Name(table.Element)} table");
                ConstExpr(e.Offset!.Value, table.Limits.Is64 ? WasmType.I64 : WasmType.I32, $"{what} offset", null);
            }
        }
        if (!WasmRef.IsRef(e.Type)) Error($"{what}: element type {Name(e.Type)} is not a reference");
        else if (!ValidType(e.Type)) Error($"{what}: element type {Name(e.Type)} names a type that does not exist");
        foreach (var f in e.Functions ?? []) if (f >= _m.FunctionCount) Error($"{what}: function {f} does not exist");
        foreach (var x in e.Exprs ?? []) ConstExpr(x, e.Type, what, null);
    }

    /// <summary>A constant expression of one value of <paramref name="type"/>: constants, ref.null / ref.func, imported immutable globals, and integer add / sub / mul.</summary>
    private void ConstExpr(WasmExpr e, WasmType type, string what, uint? self)
    {
        var stack = new List<WasmType>();
        var code = new WasmCode(_m.Bytes, e.Start, e.End);
        while (code.Next(out var ins))
        {
            switch (ins.Op)
            {
                case 0x0B:
                    if (stack.Count != 1 || !Sub(stack[0], type))
                        Error($"{what}: the expression gives [{string.Join(", ", stack.Select(t => Name(t)))}], not [{Name(type)}]");
                    return;
                case 0x41: stack.Add(WasmType.I32); break;
                case 0x42: stack.Add(WasmType.I64); break;
                case 0x43: stack.Add(WasmType.F32); break;
                case 0x44: stack.Add(WasmType.F64); break;
                case WasmOps.Fd | 12: stack.Add(WasmType.V128); break;
                case 0xD0: stack.Add(HeapType(ins.Value) ?? Unknown); break;
                case 0xD2:
                    if (ins.A >= _m.FunctionCount) Error($"{what}: function {ins.A} does not exist");
                    stack.Add(FuncRefOf(ins.A));
                    break;
                case WasmOps.Fb | 0 or WasmOps.Fb | 1 or WasmOps.Fb | 6 or WasmOps.Fb | 7 or WasmOps.Fb | 8 or WasmOps.Fb | 28 or WasmOps.Fb | 26 or WasmOps.Fb | 27 when _m.Gc:
                    {
                        // The GC constant instructions: allocation, i31 and the extern / any conversions.
                        var (pops, push) = ConstGc(ins);
                        if (pops == null) { Error($"{what}: {ins.Info.Name} names a type that does not exist"); return; }
                        for (int k = pops.Length - 1; k >= 0; k--)
                        {
                            if (stack.Count == 0 || !Sub(stack[^1], pops[k])) { Error($"{what}: {ins.Info.Name} needs [{string.Join(", ", pops.Select(Name))}]"); return; }
                            stack.RemoveAt(stack.Count - 1);
                        }
                        stack.Add(push);
                        break;
                    }
                case 0x23:
                    if (_m.Gc ? self != null && ins.A >= self : ins.A >= _m.ImportedGlobals && (self == null || ins.A >= self))
                        Error($"{what}: global.get {ins.A} is not an earlier global");
                    if (_m.GlobalTypeOf(ins.A) is not { } g) { Error($"{what}: global {ins.A} does not exist"); stack.Add(Unknown); }
                    else
                    {
                        if (g.Mutable) Error($"{what}: global.get of the mutable global {ins.A}");
                        stack.Add(g.Type);
                    }
                    break;
                case 0x6A or 0x6B or 0x6C or 0x7C or 0x7D or 0x7E:
                    {
                        var t = ins.Op < 0x7C ? WasmType.I32 : WasmType.I64;
                        if (stack.Count < 2 || stack[^1] != t || stack[^2] != t) Error($"{what}: {ins.Info.Name} needs two {Name(t)}");
                        if (stack.Count >= 2) stack.RemoveAt(stack.Count - 1);
                        if (stack.Count >= 1) stack[^1] = t;
                        break;
                    }
                default: Error($"{what}: {ins.Info.Name} is not constant"); return;
            }
        }
        Error($"{what}: {code.Error ?? "the expression has no end"}");
    }

    /// <summary>ref.null's type: func, extern and exn always; the other abstract heap types and defined types in a GC module.</summary>
    internal WasmType? HeapType(long v) => v switch
    {
        -0x10 => WasmType.FuncRef, -0x11 => WasmType.ExternRef, -0x17 => WasmType.ExnRef,
        < 0 when _m.Gc && WasmRef.IsAbstractHeap((int)(v + 0x80)) => WasmRef.Make(true, v),
        >= 0 when _m.Gc && v < _m.TypeDefs.Count => WasmRef.Make(true, v),
        _ => null,
    };

    /// <summary>ref.func's type: (ref $t) of the function's type in a GC module, funcref otherwise.</summary>
    internal WasmType FuncRefOf(uint function) =>
        _m.Gc && _m.FunctionTypeIndex(function) is { } t ? WasmRef.Make(false, t) : WasmType.FuncRef;

    /// <summary>The operand types and result of a constant GC instruction; null operands when its type is not of the right kind.</summary>
    private (WasmType[]? Pops, WasmType Push) ConstGc(in WasmInstr ins)
    {
        var self = WasmRef.Make(false, ins.A);
        switch (ins.Op & 0xFFFF)
        {
            case 0: return Def(ins.A, WasmComposite.Struct) is { } s ? ([.. s.Fields.Select(f => f.Unpacked)], self) : (null, Unknown);
            case 1: return Def(ins.A, WasmComposite.Struct) is { } d && d.Fields.All(f => Defaultable(f.Type)) ? ([], self) : (null, Unknown);
            case 6: return Def(ins.A, WasmComposite.Array) is { } a ? ([a.Fields[0].Unpacked, WasmType.I32], self) : (null, Unknown);
            case 7: return Def(ins.A, WasmComposite.Array) is { } ad && Defaultable(ad.Fields[0].Type) ? ([WasmType.I32], self) : (null, Unknown);
            case 8: return Def(ins.A, WasmComposite.Array) is { } af ? ([.. Enumerable.Repeat(af.Fields[0].Unpacked, (int)Math.Min(ins.B, 10_000))], self) : (null, Unknown);
            case 28: return ([WasmType.I32], WasmRef.Make(false, 0x6C - 0x80));
            case 26: return ([WasmType.ExternRef], WasmType.AnyRef);
            default: return ([WasmType.AnyRef], WasmType.ExternRef);
        }
    }

    private WasmTypeDef? Def(uint type, WasmComposite kind) =>
        type < _m.TypeDefs.Count && _m.TypeDefs[(int)type].Kind == kind ? _m.TypeDefs[(int)type] : null;

    private static string Name(WasmType t) => t == Unknown ? "any" : WasmBinary.TypeName(t);

    private static bool IsRef(WasmType t) => WasmRef.IsRef(t);

    private static WasmType Letter(char c, bool is64) => c switch
    {
        'i' => WasmType.I32, 'l' => WasmType.I64, 'f' => WasmType.F32, 'd' => WasmType.F64, 'v' => WasmType.V128,
        'a' => is64 ? WasmType.I64 : WasmType.I32, _ => Unknown,
    };

    // Functions.

    private sealed class Frame
    {
        public int Op;
        public WasmType[] Params = [], Results = [];
        public int InitHeight;
        public int Height;
        public bool Unreachable, HasElse;
    }

    /// <summary>Type checking of one body.</summary>
    private sealed class Function(WasmValidator v, uint index)
    {
        private readonly WasmBinary _m = v._m;
        private readonly List<WasmType> _vals = [];
        private readonly List<Frame> _ctrls = [];
        private WasmType[] _locals = [];
        private bool[] _init = [];
        private readonly List<int> _inits = [];
        private WasmType[] _results = [];
        private int _at;

        private void Error(string text) => v.Error($"function {index} at 0x{_at:X}: {text}");

        public void Check()
        {
            var type = _m.FunctionType(index);
            var body = _m.BodyOf(index)!;
            if (type == null) return;
            _results = type.Results;
            ulong count = (ulong)type.Params.Length + body.LocalCount;
            if (count > 50_000) { _at = body.Start; Error($"{count:N0} locals"); return; }
            var locals = new List<WasmType>(type.Params);
            foreach (var (n, t) in body.Locals) for (uint i = 0; i < n; i++) locals.Add(t);
            _locals = [.. locals];
            _init = [.. _locals.Select((t, i) => i < type.Params.Length || Defaultable(t))];
            _ctrls.Add(new Frame { Op = -1, Results = _results });
            var code = new WasmCode(_m.Bytes, body.CodeStart, body.End);
            while (code.Next(out var ins))
            {
                _at = ins.Offset;
                if (_ctrls.Count == 0) { Error("instructions after the function's end"); return; }
                if (!Instruction(ins)) return;
            }
            if (code.Error != null) { _at = code.Pos; Error(code.Error); return; }
            if (_ctrls.Count != 0) { _at = body.End; Error("the body does not end with end"); }
        }

        // The operand stack.

        private void Push(WasmType t) => _vals.Add(t);

        private WasmType Pop()
        {
            var frame = _ctrls[^1];
            if (_vals.Count == frame.Height)
            {
                if (frame.Unreachable) return Unknown;
                Error("the operand stack is empty");
                return Unknown;
            }
            var t = _vals[^1];
            _vals.RemoveAt(_vals.Count - 1);
            return t;
        }

        private WasmType Pop(WasmType expected)
        {
            var actual = Pop();
            if (!v.Sub(actual, expected)) Error($"type mismatch: expected {Name(expected)}, got {Name(actual)}");
            return actual == Unknown ? expected : actual;
        }

        private void PopAll(WasmType[] types)
        {
            for (int i = types.Length - 1; i >= 0; i--) Pop(types[i]);
        }

        private void PushAll(WasmType[] types) { foreach (var t in types) Push(t); }

        private void PushCtrl(int op, WasmType[] ps, WasmType[] rs)
        {
            _ctrls.Add(new Frame { Op = op, Params = ps, Results = rs, Height = _vals.Count, InitHeight = _inits.Count });
            PushAll(ps);
        }

        private Frame PopCtrl()
        {
            var frame = _ctrls[^1];
            PopAll(frame.Results);
            if (_vals.Count != frame.Height) Error($"{_vals.Count - frame.Height} values left on the stack at the end of a block");
            // Locals set inside the block are unset again after it.
            for (int i = frame.InitHeight; i < _inits.Count; i++) _init[_inits[i]] = false;
            _inits.RemoveRange(frame.InitHeight, _inits.Count - frame.InitHeight);
            _ctrls.RemoveAt(_ctrls.Count - 1);
            return frame;
        }

        private WasmType[] LabelTypes(Frame f) => f.Op == 0x03 ? f.Params : f.Results;

        private void SetUnreachable()
        {
            var frame = _ctrls[^1];
            _vals.RemoveRange(frame.Height, _vals.Count - frame.Height);
            frame.Unreachable = true;
        }

        private Frame? Label(uint depth)
        {
            if (depth >= _ctrls.Count) { Error($"label {depth} does not exist"); return null; }
            return _ctrls[_ctrls.Count - 1 - (int)depth];
        }

        private (WasmType[] Params, WasmType[] Results)? BlockType(long bt)
        {
            if (bt == -0x40) return ([], []);
            if (WasmBinary.BlockResult(bt) is { } result)
            {
                if (!WasmBinary.IsValType((byte)(bt & 0x7F)) && bt > WasmCode.TypedBlock) { Error($"block type 0x{bt & 0x7F:X2}"); return null; }
                if (!v.ValidType(result)) { Error($"block type {Name(result)} names a type that does not exist"); return null; }
                return ([], [result]);
            }
            if (_m.FuncTypeAt(bt) is not { } t) { Error($"block type {bt} is not a function type"); return null; }
            return (t.Params, t.Results);
        }

        private WasmFuncType? FuncType(uint type)
        {
            if (_m.FuncTypeAt(type) is not { } t) { Error($"type {type} is not a function type"); return null; }
            return t;
        }

        private void Call(WasmFuncType t)
        {
            PopAll(t.Params);
            PushAll(t.Results);
        }

        private bool Tail(WasmFuncType t)
        {
            if (t.Results.Length != _results.Length || t.Results.Where((r, i) => !v.Sub(r, _results[i])).Any()) Error("a tail call's results differ from the function's");
            PopAll(t.Params);
            SetUnreachable();
            return true;
        }

        private WasmLimits? Memory(uint memory)
        {
            var m = _m.MemoryOf(memory);
            if (m == null) Error($"memory {memory} does not exist");
            return m;
        }

        private WasmTableType? Table(uint table)
        {
            var t = _m.TableTypeOf(table);
            if (t == null) Error($"table {table} does not exist");
            return t;
        }

        private static int Lanes(string name) => name.StartsWith("i8x16", StringComparison.Ordinal) || name.StartsWith("v128.load8", StringComparison.Ordinal) || name.StartsWith("v128.store8", StringComparison.Ordinal) ? 16
            : name.StartsWith("i16x8", StringComparison.Ordinal) || name.Contains("16_lane", StringComparison.Ordinal) ? 8
            : name.StartsWith("i64x2", StringComparison.Ordinal) || name.StartsWith("f64x2", StringComparison.Ordinal) || name.Contains("64_lane", StringComparison.Ordinal) ? 2 : 4;

        private bool Instruction(in WasmInstr ins)
        {
            var info = ins.Info;
            switch (ins.Op)
            {
                case 0x00: SetUnreachable(); return true;
                case 0x02 or 0x03 or 0x06:
                    {
                        if (BlockType(ins.BlockType) is not { } bt) return false;
                        PopAll(bt.Params);
                        PushCtrl(ins.Op, bt.Params, bt.Results);
                        return true;
                    }
                case 0x04:
                    {
                        if (BlockType(ins.BlockType) is not { } bt) return false;
                        Pop(WasmType.I32);
                        PopAll(bt.Params);
                        PushCtrl(0x04, bt.Params, bt.Results);
                        return true;
                    }
                case 0x05:
                    {
                        var frame = _ctrls[^1];
                        if (frame.Op != 0x04 || frame.HasElse) { Error("else outside an if"); return false; }
                        PopCtrl();
                        PushCtrl(0x04, frame.Params, frame.Results);
                        _ctrls[^1].HasElse = true;
                        return true;
                    }
                case 0x0B:
                    {
                        var frame = PopCtrl();
                        if (frame.Op == 0x04 && !frame.HasElse && !frame.Params.SequenceEqual(frame.Results)) Error("an if without else must give back its parameters");
                        PushAll(frame.Results);
                        if (_ctrls.Count == 0) _vals.Clear();
                        return true;
                    }
                case 0x07 or 0x19: // catch, catch_all
                    {
                        var frame = _ctrls[^1];
                        if (frame.Op is not (0x06 or 0x07)) { Error($"{info.Name} outside a try"); return false; }
                        PopCtrl();
                        WasmType[] ps = [];
                        if (ins.Op == 0x07)
                        {
                            if (_m.TagTypeIndex(ins.A) is not { } tt || _m.FuncTypeAt(tt) is not { } tagType) { Error($"tag {ins.A} does not exist"); return false; }
                            ps = tagType.Params;
                        }
                        PushCtrl(ins.Op == 0x07 ? 0x07 : 0x19, frame.Params, frame.Results);
                        _vals.RemoveRange(_ctrls[^1].Height, _vals.Count - _ctrls[^1].Height);
                        PushAll(ps);
                        return true;
                    }
                case 0x18: // delegate
                    {
                        var frame = _ctrls[^1];
                        if (frame.Op != 0x06) { Error("delegate outside a try"); return false; }
                        if (ins.A >= _ctrls.Count - 1) Error($"label {ins.A} does not exist");
                        PopCtrl();
                        PushAll(frame.Results);
                        return true;
                    }
                case 0x08:
                    {
                        if (_m.TagTypeIndex(ins.A) is not { } tt || _m.FuncTypeAt(tt) is not { } tagType) { Error($"tag {ins.A} does not exist"); return false; }
                        PopAll(tagType.Params);
                        SetUnreachable();
                        return true;
                    }
                case 0x09:
                    if (Label(ins.A) is { } catchFrame && catchFrame.Op is not (0x07 or 0x19)) Error("rethrow does not name a catch");
                    SetUnreachable();
                    return true;
                case 0x0A: Pop(WasmType.ExnRef); SetUnreachable(); return true;
                case 0x0C:
                    if (Label(ins.A) is { } br) PopAll(LabelTypes(br));
                    SetUnreachable();
                    return true;
                case 0x0D:
                    {
                        Pop(WasmType.I32);
                        if (Label(ins.A) is not { } l) return true;
                        var types = LabelTypes(l);
                        PopAll(types);
                        PushAll(types);
                        return true;
                    }
                case 0x0E:
                    {
                        Pop(WasmType.I32);
                        var targets = WasmCode.Targets(_m.Bytes, ins);
                        if (Label(targets[^1]) is not { } def) return true;
                        int arity = LabelTypes(def).Length;
                        foreach (var t in targets)
                        {
                            if (Label(t) is not { } l) continue;
                            var types = LabelTypes(l);
                            if (types.Length != arity) { Error("br_table targets differ in arity"); continue; }
                            var saved = new List<WasmType>(_vals);
                            bool unreachable = _ctrls[^1].Unreachable;
                            PopAll(types);
                            _vals.Clear();
                            _vals.AddRange(saved);
                            _ctrls[^1].Unreachable = unreachable;
                        }
                        PopAll(LabelTypes(def));
                        SetUnreachable();
                        return true;
                    }
                case 0x0F: PopAll(_results); SetUnreachable(); return true;
                case 0x10:
                    if (_m.FunctionType(ins.A) is not { } ct) { Error($"function {ins.A} does not exist"); return false; }
                    Call(ct);
                    return true;
                case 0x12:
                    if (_m.FunctionType(ins.A) is not { } rt) { Error($"function {ins.A} does not exist"); return false; }
                    return Tail(rt);
                case 0x11 or 0x13:
                    {
                        if (Table(ins.B) is not { } table) return false;
                        if (!v.Sub(table.Element, WasmType.FuncRef)) Error($"call_indirect through a {Name(table.Element)} table");
                        if (FuncType(ins.A) is not { } t) return false;
                        Pop(table.Limits.Is64 ? WasmType.I64 : WasmType.I32);
                        if (ins.Op == 0x13) return Tail(t);
                        Call(t);
                        return true;
                    }
                case 0x14 or 0x15 or 0xD3 or 0xD4 or 0xD5 or 0xD6 when !_m.Gc:
                    Error($"{info.Name} needs typed function references, which are not enabled");
                    return false;
                case 0x14 or 0x15 or 0xD3 or 0xD4 or 0xD5 or 0xD6:
                    return TypedRefs(ins);
                case 0x1A: Pop(); return true;
                case 0x1B:
                    {
                        Pop(WasmType.I32);
                        var a = Pop();
                        var b = Pop();
                        if (IsRef(a) || IsRef(b)) Error("select without a type cannot pick references");
                        if (a != b && a != Unknown && b != Unknown) Error($"select operands differ: {Name(b)} and {Name(a)}");
                        Push(a == Unknown ? b : a);
                        return true;
                    }
                case 0x1C:
                    {
                        if (ins.Count != 1) { Error("select takes one type"); return false; }
                        var tr = new WasmReader(_m.Bytes, ins.ImmStart, ins.Offset + ins.Length);
                        var t = WasmBinary.ReadValType(ref tr);
                        if (!v.ValidType(t)) { Error($"select type {Name(t)} names a type that does not exist"); return false; }
                        Pop(WasmType.I32);
                        Pop(t);
                        Pop(t);
                        Push(t);
                        return true;
                    }
                case 0x1F:
                    {
                        if (BlockType(ins.BlockType) is not { } bt) return false;
                        var r = new WasmReader(_m.Bytes, ins.ImmStart, ins.Offset + ins.Length);
                        for (int i = 0; i < ins.Count; i++)
                        {
                            byte kind = r.Byte();
                            WasmType[] values = [];
                            if (kind < 2)
                            {
                                uint tag = r.U32();
                                if (_m.TagTypeIndex(tag) is not { } tt || _m.FuncTypeAt(tt) is not { } tagType) { Error($"tag {tag} does not exist"); return false; }
                                values = tagType.Params;
                            }
                            if (kind is 1 or 3) values = [.. values, WasmType.ExnRef];
                            if (Label(r.U32()) is { } l && (LabelTypes(l) is var lt && (lt.Length != values.Length || values.Where((x, k) => !v.Sub(x, lt[k])).Any())))
                                Error("a catch's values differ from its label's");
                        }
                        PopAll(bt.Params);
                        PushCtrl(0x02, bt.Params, bt.Results);
                        return true;
                    }
                case 0x20 or 0x21 or 0x22:
                    {
                        if (ins.A >= _locals.Length) { Error($"local {ins.A} does not exist"); return false; }
                        var t = _locals[ins.A];
                        if (ins.Op == 0x20)
                        {
                            if (!_init[ins.A]) Error($"local {ins.A} ({Name(t)}) is read before it is set");
                            Push(t);
                            return true;
                        }
                        Pop(t);
                        if (ins.Op == 0x22) Push(t);
                        if (!_init[ins.A]) { _init[ins.A] = true; _inits.Add((int)ins.A); }
                        return true;
                    }
                case 0x23 or 0x24:
                    {
                        if (_m.GlobalTypeOf(ins.A) is not { } g) { Error($"global {ins.A} does not exist"); return false; }
                        if (ins.Op == 0x23) Push(g.Type);
                        else
                        {
                            if (!g.Mutable) Error($"global.set of the immutable global {ins.A}");
                            Pop(g.Type);
                        }
                        return true;
                    }
                case 0x25 or 0x26:
                    {
                        if (Table(ins.A) is not { } t) return false;
                        if (ins.Op == 0x26) Pop(t.Element);
                        Pop((t.Limits.Is64 ? WasmType.I64 : WasmType.I32));
                        if (ins.Op == 0x25) Push(t.Element);
                        return true;
                    }
                case 0xD0:
                    if (v.HeapType(ins.Value) is not { } ht) { Error(_m.Gc ? $"ref.null of heap type {ins.Value}, which does not exist" : "ref.null of a heap type that is not func, extern or exn"); return false; }
                    Push(ht);
                    return true;
                case 0xD1:
                    {
                        var r = Pop();
                        if (r != Unknown && !IsRef(r)) Error($"ref.is_null of {Name(r)}");
                        Push(WasmType.I32);
                        return true;
                    }
                case 0xD2:
                    if (ins.A >= _m.FunctionCount) { Error($"function {ins.A} does not exist"); return false; }
                    if (!v._declared.Contains(ins.A)) Error($"ref.func {ins.A} is not declared in an element segment, an export or a global");
                    Push(v.FuncRefOf(ins.A));
                    return true;
                case WasmOps.Fc | 8:
                    {
                        if (Memory(ins.Memory) is not { } mem) return false;
                        DataIndex(ins.A);
                        PopAll([WasmType.I32, WasmType.I32]);
                        Pop((mem.Is64 ? WasmType.I64 : WasmType.I32));
                        return true;
                    }
                case WasmOps.Fc | 9: DataIndex(ins.A); return true;
                case WasmOps.Fc | 10:
                    {
                        if (Memory(ins.A) is not { } dst || Memory(ins.B) is not { } src) return false;
                        WasmType d = dst.Is64 ? WasmType.I64 : WasmType.I32, s = src.Is64 ? WasmType.I64 : WasmType.I32;
                        Pop(dst.Is64 && src.Is64 ? WasmType.I64 : WasmType.I32);
                        Pop(s);
                        Pop(d);
                        return true;
                    }
                case WasmOps.Fc | 11:
                    {
                        if (Memory(ins.Memory) is not { } mem) return false;
                        var a = (mem.Is64 ? WasmType.I64 : WasmType.I32);
                        Pop(a);
                        Pop(WasmType.I32);
                        Pop(a);
                        return true;
                    }
                case WasmOps.Fc | 12:
                    {
                        if (Table(ins.B) is not { } t) return false;
                        if (ins.A >= _m.Elements.Count) { Error($"element segment {ins.A} does not exist"); return false; }
                        if (!v.Sub(_m.Elements[(int)ins.A].Type, t.Element)) Error("table.init element types differ");
                        PopAll([WasmType.I32, WasmType.I32]);
                        Pop((t.Limits.Is64 ? WasmType.I64 : WasmType.I32));
                        return true;
                    }
                case WasmOps.Fc | 13:
                    if (ins.A >= _m.Elements.Count) Error($"element segment {ins.A} does not exist");
                    return true;
                case WasmOps.Fc | 14:
                    {
                        if (Table(ins.A) is not { } dst || Table(ins.B) is not { } src) return false;
                        if (!v.Sub(src.Element, dst.Element)) Error("table.copy element types differ");
                        PopAll([WasmType.I32, WasmType.I32, WasmType.I32]);
                        return true;
                    }
                case WasmOps.Fc | 15:
                    {
                        if (Table(ins.A) is not { } t) return false;
                        Pop((t.Limits.Is64 ? WasmType.I64 : WasmType.I32));
                        Pop(t.Element);
                        Push((t.Limits.Is64 ? WasmType.I64 : WasmType.I32));
                        return true;
                    }
                case WasmOps.Fc | 16:
                    if (Table(ins.A) is not { } size) return false;
                    Push((size.Limits.Is64 ? WasmType.I64 : WasmType.I32));
                    return true;
                case WasmOps.Fc | 17:
                    {
                        if (Table(ins.A) is not { } t) return false;
                        var a = (t.Limits.Is64 ? WasmType.I64 : WasmType.I32);
                        Pop(a);
                        Pop(t.Element);
                        Pop(a);
                        return true;
                    }
            }
            if (ins.Op >> 16 == 0xFB) return _m.Gc ? Gc(ins) : Fail($"{info.Name} needs GC, which the module's types do not use");
            bool is64 = false;
            if (info.Imm is WasmImm.MemArg or WasmImm.MemArgLane or WasmImm.Memory)
            {
                if (Memory(ins.Memory) is not { } mem) return false;
                is64 = mem.Is64;
                if (info.IsMemoryAccess)
                {
                    bool atomic = ins.Op >> 16 == 0xFE;
                    if (atomic ? ins.Align != info.Align : ins.Align > info.Align)
                        Error($"{info.Name}: alignment 2^{ins.Align} {(atomic ? "is not" : "exceeds")} the natural 2^{info.Align}");
                    if (!is64 && ins.MemOffset > uint.MaxValue) Error($"{info.Name}: offset {ins.MemOffset} exceeds 32 bits");
                }
            }
            if (info.Imm is WasmImm.Lane or WasmImm.MemArgLane && ins.Lane >= Lanes(info.Name)) Error($"{info.Name}: lane {ins.Lane} is out of range");
            if (info.Imm == WasmImm.Shuffle)
                for (int i = 0; i < 16; i++) if (_m.Bytes[ins.ImmStart + i] >= 32) Error($"i8x16.shuffle: lane {_m.Bytes[ins.ImmStart + i]} is out of range");
            if (info.Signature == "*") { Error($"{info.Name} is not checked"); return false; }
            int colon = info.Signature.IndexOf(':');
            for (int i = colon - 1; i >= 0; i--) Pop(Letter(info.Signature[i], is64));
            for (int i = colon + 1; i < info.Signature.Length; i++) Push(Letter(info.Signature[i], is64));
            return true;
        }

        private bool Fail(string message)
        {
            Error(message);
            return false;
        }

        private WasmType PopRef()
        {
            var r = Pop();
            if (r != Unknown && !IsRef(r)) Error($"expected a reference, got {Name(r)}");
            return r;
        }

        private static WasmType NonNull(WasmType r) => r == Unknown ? Unknown : WasmRef.WithNull(r, false);

        private bool ValidHeap(long heap) => heap < 0 ? WasmRef.IsAbstractHeap((int)(heap + 0x80)) : heap < _m.TypeDefs.Count;

        /// <summary>call_ref, return_call_ref, ref.eq, ref.as_non_null, br_on_null and br_on_non_null.</summary>
        private bool TypedRefs(in WasmInstr ins)
        {
            switch (ins.Op)
            {
                case 0x14 or 0x15:
                    {
                        if (FuncType(ins.A) is not { } t) return false;
                        Pop(WasmRef.Make(true, ins.A));
                        if (ins.Op == 0x15) return Tail(t);
                        Call(t);
                        return true;
                    }
                case 0xD3:
                    Pop(WasmType.EqRef);
                    Pop(WasmType.EqRef);
                    Push(WasmType.I32);
                    return true;
                case 0xD4:
                    Push(NonNull(PopRef()));
                    return true;
                case 0xD5:
                    {
                        var r = PopRef();
                        if (Label(ins.A) is { } l)
                        {
                            var types = LabelTypes(l);
                            PopAll(types);
                            PushAll(types);
                        }
                        Push(NonNull(r));
                        return true;
                    }
                default: // br_on_non_null
                    {
                        if (Label(ins.A) is not { } l) return false;
                        var types = LabelTypes(l);
                        if (types.Length == 0 || !IsRef(types[^1]) && types[^1] != Unknown) return Fail("br_on_non_null needs a label that takes a reference last");
                        var r = PopRef();
                        if (!v.Sub(NonNull(r), types[^1])) Error($"br_on_non_null: {Name(NonNull(r))} does not match the label's {Name(types[^1])}");
                        PopAll(types[..^1]);
                        PushAll(types[..^1]);
                        return true;
                    }
            }
        }

        /// <summary>The struct, array, cast and i31 instructions.</summary>
        private bool Gc(in WasmInstr ins)
        {
            int sub = ins.Op & 0xFFFF;
            var self = WasmRef.Make(false, ins.A);
            var selfNull = WasmRef.Make(true, ins.A);
            switch (sub)
            {
                case <= 5:
                    {
                        if (v.Def(ins.A, WasmComposite.Struct) is not { } d) return Fail($"{ins.Info.Name}: type {ins.A} is not a struct type");
                        if (sub == 0) { PopAll([.. d.Fields.Select(f => f.Unpacked)]); Push(self); return true; }
                        if (sub == 1)
                        {
                            if (d.Fields.Any(f => !Defaultable(f.Type))) Error($"struct.new_default: type {ins.A} has a field without a default");
                            Push(self);
                            return true;
                        }
                        if (ins.B >= d.Fields.Length) return Fail($"{ins.Info.Name}: type {ins.A} has no field {ins.B}");
                        var field = d.Fields[ins.B];
                        if (sub == 5)
                        {
                            if (!field.Mutable) Error($"struct.set: field {ins.B} of type {ins.A} is immutable");
                            Pop(field.Unpacked);
                            Pop(selfNull);
                            return true;
                        }
                        PackedRead(ins.Info.Name, sub == 2, field);
                        Pop(selfNull);
                        Push(field.Unpacked);
                        return true;
                    }
                case <= 19:
                    {
                        if (sub == 15) { Pop(WasmType.ArrayRef); Push(WasmType.I32); return true; }
                        if (v.Def(ins.A, WasmComposite.Array) is not { } d) return Fail($"{ins.Info.Name}: type {ins.A} is not an array type");
                        var e = d.Fields[0];
                        switch (sub)
                        {
                            case 6: Pop(WasmType.I32); Pop(e.Unpacked); Push(self); return true;
                            case 7:
                                if (!Defaultable(e.Type)) Error($"array.new_default: the elements of type {ins.A} have no default");
                                Pop(WasmType.I32);
                                Push(self);
                                return true;
                            case 8:
                                for (uint k = 0; k < Math.Min(ins.B, 100_000u); k++) Pop(e.Unpacked);
                                Push(self);
                                return true;
                            case 9 or 18:
                                if (IsRef(e.Type)) Error($"{ins.Info.Name}: the elements of type {ins.A} are references");
                                DataIndex(ins.B);
                                if (sub == 18) Mutable(ins.Info.Name, ins.A, e);
                                PopAll(sub == 9 ? [WasmType.I32, WasmType.I32] : [selfNull, WasmType.I32, WasmType.I32, WasmType.I32]);
                                if (sub == 9) Push(self);
                                return true;
                            case 10 or 19:
                                if (ins.B >= _m.Elements.Count) return Fail($"{ins.Info.Name}: element segment {ins.B} does not exist");
                                if (!v.Sub(_m.Elements[(int)ins.B].Type, e.Type)) Error($"{ins.Info.Name}: element segment {ins.B} holds {Name(_m.Elements[(int)ins.B].Type)}, not {Name(e.Type)}");
                                if (sub == 19) Mutable(ins.Info.Name, ins.A, e);
                                PopAll(sub == 10 ? [WasmType.I32, WasmType.I32] : [selfNull, WasmType.I32, WasmType.I32, WasmType.I32]);
                                if (sub == 10) Push(self);
                                return true;
                            case 11 or 12 or 13:
                                PackedRead(ins.Info.Name, sub == 11, e);
                                Pop(WasmType.I32);
                                Pop(selfNull);
                                Push(e.Unpacked);
                                return true;
                            case 14:
                                Mutable("array.set", ins.A, e);
                                Pop(e.Unpacked);
                                Pop(WasmType.I32);
                                Pop(selfNull);
                                return true;
                            case 16:
                                Mutable("array.fill", ins.A, e);
                                Pop(WasmType.I32);
                                Pop(e.Unpacked);
                                Pop(WasmType.I32);
                                Pop(selfNull);
                                return true;
                            default: // array.copy
                                {
                                    if (v.Def(ins.B, WasmComposite.Array) is not { } source) return Fail($"array.copy: type {ins.B} is not an array type");
                                    Mutable("array.copy", ins.A, e);
                                    var s = source.Fields[0];
                                    if (s.Packed != e.Packed || !v.Sub(s.Type, e.Type)) Error($"array.copy: the elements of type {ins.B} do not fit type {ins.A}");
                                    PopAll([selfNull, WasmType.I32, WasmRef.Make(true, ins.B), WasmType.I32, WasmType.I32]);
                                    return true;
                                }
                        }
                    }
                case <= 23:
                    {
                        if (!ValidHeap(ins.Value)) return Fail($"{ins.Info.Name}: heap type {ins.Value} does not exist");
                        var target = WasmRef.Make(sub is 21 or 23, ins.Value);
                        var r = PopRef();
                        if (r != Unknown && v.Top(WasmRef.Heap(r)) != v.Top(WasmRef.Heap(target)))
                            Error($"{ins.Info.Name}: {Name(r)} and {Name(target)} are in different hierarchies");
                        Push(sub <= 21 ? WasmType.I32 : target);
                        return true;
                    }
                case 24 or 25:
                    {
                        if (!ValidHeap(ins.Value) || !ValidHeap(ins.BlockType)) return Fail($"{ins.Info.Name}: a heap type does not exist");
                        var from = WasmRef.Make((ins.Lane & 1) != 0, ins.Value);
                        var to = WasmRef.Make((ins.Lane & 2) != 0, ins.BlockType);
                        if (!v.Sub(to, from)) Error($"{ins.Info.Name}: {Name(to)} is not a subtype of {Name(from)}");
                        if (Label(ins.A) is not { } l) return false;
                        var types = LabelTypes(l);
                        if (types.Length == 0 || !IsRef(types[^1]) && types[^1] != Unknown) return Fail($"{ins.Info.Name} needs a label that takes a reference last");
                        // The operand without the cast's type: non-null when the cast takes null.
                        var rest = WasmRef.WithNull(from, WasmRef.Nullable(from) && !WasmRef.Nullable(to));
                        var (branch, fall) = sub == 24 ? (to, rest) : (rest, to);
                        if (!v.Sub(branch, types[^1])) Error($"{ins.Info.Name}: {Name(branch)} does not match the label's {Name(types[^1])}");
                        Pop(from);
                        PopAll(types[..^1]);
                        PushAll(types[..^1]);
                        Push(fall);
                        return true;
                    }
                case 26 or 27:
                    {
                        var r = Pop(sub == 26 ? WasmType.ExternRef : WasmType.AnyRef);
                        bool nullable = r == Unknown || WasmRef.Nullable(r);
                        Push(WasmRef.Make(nullable, sub == 26 ? 0x6E - 0x80 : 0x6F - 0x80));
                        return true;
                    }
                case 28: Pop(WasmType.I32); Push(WasmRef.Make(false, 0x6C - 0x80)); return true;
                case 29 or 30: Pop(WasmType.I31Ref); Push(WasmType.I32); return true;
            }
            return Fail($"{ins.Info.Name} is not checked");
        }

        private void PackedRead(string name, bool plain, WasmField f)
        {
            if (plain && f.Packed != 0) Error($"{name}: a packed field is read with _s or _u");
            else if (!plain && f.Packed == 0) Error($"{name}: the field is not packed");
        }

        private void Mutable(string name, uint type, WasmField f)
        {
            if (!f.Mutable) Error($"{name}: the elements of type {type} are immutable");
        }

        private static bool Defaultable(WasmType t) => WasmValidator.Defaultable(t);

        private void DataIndex(uint data)
        {
            if (_m.DataCount == null) Error("memory.init and data.drop need a data count section");
            else if (data >= _m.DataCount) Error($"data segment {data} does not exist");
        }
    }

    internal static string Describe(WasmValidation v) =>
        v.Verdict + (v.Errors.Count > 0 ? ": " + string.Join("; ", v.Errors.Take(3)) + (v.Errors.Count > 3 ? $" (+{(v.Errors.Count - 3).ToString(CultureInfo.InvariantCulture)})" : "") : "");
}
