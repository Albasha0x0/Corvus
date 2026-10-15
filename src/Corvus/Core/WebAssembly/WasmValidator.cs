using System.Globalization;

namespace Corvus.Core.WebAssembly;

/// <summary>A validation verdict: valid, invalid with its errors (each with the function and offset), or unknown when the module holds what is not modelled.</summary>
public sealed record WasmValidation(string Verdict, IReadOnlyList<string> Errors)
{
    public bool Valid => Verdict == "valid";
}

/// <summary>
/// WebAssembly validation as the specification's algorithm: section rules (indexes, limits, constant expressions, unique
/// exports, declared function references, data count) and per-function type checking over an operand and a control stack
/// with the polymorphic stack after unreachable code. Features as wasm-validate enables them, plus threads.
/// </summary>
public sealed class WasmValidator
{
    private const int MaxErrors = 50;
    private const byte Unknown = 0;

    private readonly WasmBinary _m;
    private readonly List<string> _errors = [];
    private readonly HashSet<uint> _declared = [];

    private WasmValidator(WasmBinary m) => _m = m;

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

    // ---- module ----

    private void Module(CancellationToken ct)
    {
        foreach (var i in _m.Imports)
            switch (i.Kind)
            {
                case WasmExternal.Func: if (i.TypeIndex >= _m.Types.Count) Error($"import {i.Module}.{i.Name}: type {i.TypeIndex} does not exist"); break;
                case WasmExternal.Table: TableLimits(i.Table!.Limits, $"import {i.Module}.{i.Name}"); break;
                case WasmExternal.Memory: MemoryLimits(i.Memory!.Value, $"import {i.Module}.{i.Name}"); break;
                case WasmExternal.Tag: TagType(i.TypeIndex, $"import {i.Module}.{i.Name}"); break;
            }
        for (int f = 0; f < _m.Functions.Count; f++)
            if (_m.Functions[f] >= _m.Types.Count) Error($"function {_m.ImportedFunctions + f}: type {_m.Functions[f]} does not exist");
        if (_m.Functions.Count != _m.Bodies.Count) Error($"{_m.Functions.Count} functions declared, {_m.Bodies.Count} bodies");
        foreach (var t in _m.Tables) TableLimits(t.Type.Limits, "table");
        foreach (var l in _m.Memories) MemoryLimits(l, "memory");
        foreach (var t in _m.Tags) TagType(t, "tag");

        // function references a body may take: in elements, exports and global initializers
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
        if (type >= _m.Types.Count) Error($"{what}: type {type} does not exist");
        else if (_m.Types[(int)type].Results.Length != 0) Error($"{what}: a tag type returns nothing");
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
                if (table.Element != e.Type) Error($"{what}: {WasmBinary.TypeName(e.Type)} elements in a {WasmBinary.TypeName(table.Element)} table");
                ConstExpr(e.Offset!.Value, table.Limits.Is64 ? WasmType.I64 : WasmType.I32, $"{what} offset", null);
            }
        }
        if (e.Type is not (WasmType.FuncRef or WasmType.ExternRef or WasmType.ExnRef)) Error($"{what}: element type {WasmBinary.TypeName(e.Type)} is not a reference");
        foreach (var f in e.Functions ?? []) if (f >= _m.FunctionCount) Error($"{what}: function {f} does not exist");
        foreach (var x in e.Exprs ?? []) ConstExpr(x, e.Type, what, null);
    }

    /// <summary>A constant expression of one value of <paramref name="type"/>: constants, ref.null / ref.func, imported immutable globals, and integer add / sub / mul.</summary>
    private void ConstExpr(WasmExpr e, WasmType type, string what, uint? self)
    {
        var stack = new List<byte>();
        var code = new WasmCode(_m.Bytes, e.Start, e.End);
        while (code.Next(out var ins))
        {
            switch (ins.Op)
            {
                case 0x0B:
                    if (stack.Count != 1 || stack[0] != (byte)type)
                        Error($"{what}: the expression gives [{string.Join(", ", stack.Select(t => Name(t)))}], not [{WasmBinary.TypeName(type)}]");
                    return;
                case 0x41: stack.Add((byte)WasmType.I32); break;
                case 0x42: stack.Add((byte)WasmType.I64); break;
                case 0x43: stack.Add((byte)WasmType.F32); break;
                case 0x44: stack.Add((byte)WasmType.F64); break;
                case WasmOps.Fd | 12: stack.Add((byte)WasmType.V128); break;
                case 0xD0: stack.Add(HeapType(ins.Value) ?? Unknown); break;
                case 0xD2:
                    if (ins.A >= _m.FunctionCount) Error($"{what}: function {ins.A} does not exist");
                    stack.Add((byte)WasmType.FuncRef);
                    break;
                case 0x23:
                    if (ins.A >= _m.ImportedGlobals && (self == null || ins.A >= self)) Error($"{what}: global.get {ins.A} is not an earlier global");
                    if (_m.GlobalTypeOf(ins.A) is not { } g) { Error($"{what}: global {ins.A} does not exist"); stack.Add(Unknown); }
                    else
                    {
                        if (g.Mutable) Error($"{what}: global.get of the mutable global {ins.A}");
                        stack.Add((byte)g.Type);
                    }
                    break;
                case 0x6A or 0x6B or 0x6C or 0x7C or 0x7D or 0x7E:
                    {
                        byte t = (byte)(ins.Op < 0x7C ? WasmType.I32 : WasmType.I64);
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

    private static byte? HeapType(long v) => v switch { -0x10 => (byte)WasmType.FuncRef, -0x11 => (byte)WasmType.ExternRef, -0x17 => (byte)WasmType.ExnRef, _ => null };

    private static string Name(byte t) => t == Unknown ? "any" : WasmBinary.TypeName((WasmType)t);

    private static bool IsRef(byte t) => t is (byte)WasmType.FuncRef or (byte)WasmType.ExternRef or (byte)WasmType.ExnRef;

    private static byte Letter(char c, bool is64) => c switch
    {
        'i' => (byte)WasmType.I32, 'l' => (byte)WasmType.I64, 'f' => (byte)WasmType.F32, 'd' => (byte)WasmType.F64, 'v' => (byte)WasmType.V128,
        'a' => (byte)(is64 ? WasmType.I64 : WasmType.I32), _ => Unknown,
    };

    // ---- functions ----

    private sealed class Frame
    {
        public int Op;
        public byte[] Params = [], Results = [];
        public int Height;
        public bool Unreachable, HasElse;
    }

    /// <summary>Type checking of one body.</summary>
    private sealed class Function(WasmValidator v, uint index)
    {
        private readonly WasmBinary _m = v._m;
        private readonly List<byte> _vals = [];
        private readonly List<Frame> _ctrls = [];
        private byte[] _locals = [];
        private byte[] _results = [];
        private int _at;

        private void Error(string text) => v.Error($"function {index} at 0x{_at:X}: {text}");

        public void Check()
        {
            var type = _m.FunctionType(index);
            var body = _m.BodyOf(index)!;
            if (type == null) return;
            _results = [.. type.Results.Select(t => (byte)t)];
            ulong count = (ulong)type.Params.Length + body.LocalCount;
            if (count > 50_000) { _at = body.Start; Error($"{count:N0} locals"); return; }
            var locals = new List<byte>(type.Params.Select(t => (byte)t));
            foreach (var (n, t) in body.Locals) for (uint i = 0; i < n; i++) locals.Add((byte)t);
            _locals = [.. locals];
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

        // ---- the operand stack ----

        private void Push(byte t) => _vals.Add(t);

        private byte Pop()
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

        private byte Pop(byte expected)
        {
            var actual = Pop();
            if (actual != expected && actual != Unknown && expected != Unknown) Error($"type mismatch: expected {Name(expected)}, got {Name(actual)}");
            return actual == Unknown ? expected : actual;
        }

        private void PopAll(byte[] types)
        {
            for (int i = types.Length - 1; i >= 0; i--) Pop(types[i]);
        }

        private void PushAll(byte[] types) { foreach (var t in types) Push(t); }

        private void PushCtrl(int op, byte[] ps, byte[] rs)
        {
            _ctrls.Add(new Frame { Op = op, Params = ps, Results = rs, Height = _vals.Count });
            PushAll(ps);
        }

        private Frame PopCtrl()
        {
            var frame = _ctrls[^1];
            PopAll(frame.Results);
            if (_vals.Count != frame.Height) Error($"{_vals.Count - frame.Height} values left on the stack at the end of a block");
            _ctrls.RemoveAt(_ctrls.Count - 1);
            return frame;
        }

        private byte[] LabelTypes(Frame f) => f.Op == 0x03 ? f.Params : f.Results;

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

        private (byte[] Params, byte[] Results)? BlockType(long bt)
        {
            if (bt == -0x40) return ([], []);
            if (bt < 0)
            {
                byte b = (byte)(bt & 0x7F);
                if (!WasmBinary.IsValType(b)) { Error($"block type 0x{b:X2}"); return null; }
                return ([], [b]);
            }
            if (bt >= _m.Types.Count) { Error($"block type {bt} does not exist"); return null; }
            var t = _m.Types[(int)bt];
            return ([.. t.Params.Select(x => (byte)x)], [.. t.Results.Select(x => (byte)x)]);
        }

        private byte[]? FuncType(uint type)
        {
            if (type >= _m.Types.Count) { Error($"type {type} does not exist"); return null; }
            return [.. _m.Types[(int)type].Params.Select(x => (byte)x)];
        }

        private void Call(WasmFuncType t)
        {
            PopAll([.. t.Params.Select(x => (byte)x)]);
            PushAll([.. t.Results.Select(x => (byte)x)]);
        }

        private bool Tail(WasmFuncType t)
        {
            if (!t.Results.Select(x => (byte)x).SequenceEqual(_results)) Error("a tail call's results differ from the function's");
            PopAll([.. t.Params.Select(x => (byte)x)]);
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
                        Pop((byte)WasmType.I32);
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
                        byte[] ps = [];
                        if (ins.Op == 0x07)
                        {
                            if (_m.TagTypeIndex(ins.A) is not { } tt || tt >= _m.Types.Count) { Error($"tag {ins.A} does not exist"); return false; }
                            ps = [.. _m.Types[(int)tt].Params.Select(x => (byte)x)];
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
                        if (_m.TagTypeIndex(ins.A) is not { } tt || tt >= _m.Types.Count) { Error($"tag {ins.A} does not exist"); return false; }
                        PopAll([.. _m.Types[(int)tt].Params.Select(x => (byte)x)]);
                        SetUnreachable();
                        return true;
                    }
                case 0x09:
                    if (Label(ins.A) is { } catchFrame && catchFrame.Op is not (0x07 or 0x19)) Error("rethrow does not name a catch");
                    SetUnreachable();
                    return true;
                case 0x0A: Pop((byte)WasmType.ExnRef); SetUnreachable(); return true;
                case 0x0C:
                    if (Label(ins.A) is { } br) PopAll(LabelTypes(br));
                    SetUnreachable();
                    return true;
                case 0x0D:
                    {
                        Pop((byte)WasmType.I32);
                        if (Label(ins.A) is not { } l) return true;
                        var types = LabelTypes(l);
                        PopAll(types);
                        PushAll(types);
                        return true;
                    }
                case 0x0E:
                    {
                        Pop((byte)WasmType.I32);
                        var targets = WasmCode.Targets(_m.Bytes, ins);
                        if (Label(targets[^1]) is not { } def) return true;
                        int arity = LabelTypes(def).Length;
                        foreach (var t in targets)
                        {
                            if (Label(t) is not { } l) continue;
                            var types = LabelTypes(l);
                            if (types.Length != arity) { Error("br_table targets differ in arity"); continue; }
                            var saved = new List<byte>(_vals);
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
                        if (table.Element != WasmType.FuncRef) Error($"call_indirect through a {WasmBinary.TypeName(table.Element)} table");
                        if (FuncType(ins.A) == null) return false;
                        Pop((byte)(table.Limits.Is64 ? WasmType.I64 : WasmType.I32));
                        var t = _m.Types[(int)ins.A];
                        if (ins.Op == 0x13) return Tail(t);
                        Call(t);
                        return true;
                    }
                case 0x14 or 0x15 or 0xD3 or 0xD4 or 0xD5 or 0xD6:
                    Error($"{info.Name} needs typed function references, which are not enabled");
                    return false;
                case 0x1A: Pop(); return true;
                case 0x1B:
                    {
                        Pop((byte)WasmType.I32);
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
                        byte t = _m.Bytes[ins.ImmStart];
                        Pop((byte)WasmType.I32);
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
                            byte[] values = [];
                            if (kind < 2)
                            {
                                uint tag = r.U32();
                                if (_m.TagTypeIndex(tag) is not { } tt || tt >= _m.Types.Count) { Error($"tag {tag} does not exist"); return false; }
                                values = [.. _m.Types[(int)tt].Params.Select(x => (byte)x)];
                            }
                            if (kind is 1 or 3) values = [.. values, (byte)WasmType.ExnRef];
                            if (Label(r.U32()) is { } l && !LabelTypes(l).SequenceEqual(values)) Error("a catch's values differ from its label's");
                        }
                        PopAll(bt.Params);
                        PushCtrl(0x02, bt.Params, bt.Results);
                        return true;
                    }
                case 0x20 or 0x21 or 0x22:
                    {
                        if (ins.A >= _locals.Length) { Error($"local {ins.A} does not exist"); return false; }
                        var t = _locals[ins.A];
                        if (ins.Op == 0x20) Push(t);
                        else if (ins.Op == 0x21) Pop(t);
                        else { Pop(t); Push(t); }
                        return true;
                    }
                case 0x23 or 0x24:
                    {
                        if (_m.GlobalTypeOf(ins.A) is not { } g) { Error($"global {ins.A} does not exist"); return false; }
                        if (ins.Op == 0x23) Push((byte)g.Type);
                        else
                        {
                            if (!g.Mutable) Error($"global.set of the immutable global {ins.A}");
                            Pop((byte)g.Type);
                        }
                        return true;
                    }
                case 0x25 or 0x26:
                    {
                        if (Table(ins.A) is not { } t) return false;
                        if (ins.Op == 0x26) Pop((byte)t.Element);
                        Pop((byte)(t.Limits.Is64 ? WasmType.I64 : WasmType.I32));
                        if (ins.Op == 0x25) Push((byte)t.Element);
                        return true;
                    }
                case 0xD0:
                    if (HeapType(ins.Value) is not { } ht) { Error("ref.null of a heap type that is not func, extern or exn"); return false; }
                    Push(ht);
                    return true;
                case 0xD1:
                    {
                        var r = Pop();
                        if (r != Unknown && !IsRef(r)) Error($"ref.is_null of {Name(r)}");
                        Push((byte)WasmType.I32);
                        return true;
                    }
                case 0xD2:
                    if (ins.A >= _m.FunctionCount) { Error($"function {ins.A} does not exist"); return false; }
                    if (!v._declared.Contains(ins.A)) Error($"ref.func {ins.A} is not declared in an element segment, an export or a global");
                    Push((byte)WasmType.FuncRef);
                    return true;
                case WasmOps.Fc | 8:
                    {
                        if (Memory(ins.Memory) is not { } mem) return false;
                        DataIndex(ins.A);
                        PopAll([(byte)WasmType.I32, (byte)WasmType.I32]);
                        Pop((byte)(mem.Is64 ? WasmType.I64 : WasmType.I32));
                        return true;
                    }
                case WasmOps.Fc | 9: DataIndex(ins.A); return true;
                case WasmOps.Fc | 10:
                    {
                        if (Memory(ins.A) is not { } dst || Memory(ins.B) is not { } src) return false;
                        byte d = (byte)(dst.Is64 ? WasmType.I64 : WasmType.I32), s = (byte)(src.Is64 ? WasmType.I64 : WasmType.I32);
                        Pop(dst.Is64 && src.Is64 ? (byte)WasmType.I64 : (byte)WasmType.I32);
                        Pop(s);
                        Pop(d);
                        return true;
                    }
                case WasmOps.Fc | 11:
                    {
                        if (Memory(ins.Memory) is not { } mem) return false;
                        byte a = (byte)(mem.Is64 ? WasmType.I64 : WasmType.I32);
                        Pop(a);
                        Pop((byte)WasmType.I32);
                        Pop(a);
                        return true;
                    }
                case WasmOps.Fc | 12:
                    {
                        if (Table(ins.B) is not { } t) return false;
                        if (ins.A >= _m.Elements.Count) { Error($"element segment {ins.A} does not exist"); return false; }
                        if (_m.Elements[(int)ins.A].Type != t.Element) Error("table.init element types differ");
                        PopAll([(byte)WasmType.I32, (byte)WasmType.I32]);
                        Pop((byte)(t.Limits.Is64 ? WasmType.I64 : WasmType.I32));
                        return true;
                    }
                case WasmOps.Fc | 13:
                    if (ins.A >= _m.Elements.Count) Error($"element segment {ins.A} does not exist");
                    return true;
                case WasmOps.Fc | 14:
                    {
                        if (Table(ins.A) is not { } dst || Table(ins.B) is not { } src) return false;
                        if (dst.Element != src.Element) Error("table.copy element types differ");
                        PopAll([(byte)WasmType.I32, (byte)WasmType.I32, (byte)WasmType.I32]);
                        return true;
                    }
                case WasmOps.Fc | 15:
                    {
                        if (Table(ins.A) is not { } t) return false;
                        Pop((byte)(t.Limits.Is64 ? WasmType.I64 : WasmType.I32));
                        Pop((byte)t.Element);
                        Push((byte)(t.Limits.Is64 ? WasmType.I64 : WasmType.I32));
                        return true;
                    }
                case WasmOps.Fc | 16:
                    if (Table(ins.A) is not { } size) return false;
                    Push((byte)(size.Limits.Is64 ? WasmType.I64 : WasmType.I32));
                    return true;
                case WasmOps.Fc | 17:
                    {
                        if (Table(ins.A) is not { } t) return false;
                        byte a = (byte)(t.Limits.Is64 ? WasmType.I64 : WasmType.I32);
                        Pop(a);
                        Pop((byte)t.Element);
                        Pop(a);
                        return true;
                    }
            }
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

        private void DataIndex(uint data)
        {
            if (_m.DataCount == null) Error("memory.init and data.drop need a data count section");
            else if (data >= _m.DataCount) Error($"data segment {data} does not exist");
        }
    }

    internal static string Describe(WasmValidation v) =>
        v.Verdict + (v.Errors.Count > 0 ? ": " + string.Join("; ", v.Errors.Take(3)) + (v.Errors.Count > 3 ? $" (+{(v.Errors.Count - 3).ToString(CultureInfo.InvariantCulture)})" : "") : "");
}
