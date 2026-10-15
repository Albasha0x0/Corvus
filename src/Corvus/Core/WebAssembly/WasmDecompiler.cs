using System.Globalization;
using System.Text;

namespace Corvus.Core.WebAssembly;

/// <summary>
/// A readable view of one WebAssembly function: the operand stack folded into expressions, structured control flow as
/// labeled blocks and loops (JavaScript-style "break label" / "continue label"), memory accesses as typed pointer
/// dereferences, calls by name, constants inside data segments annotated with their string. Evaluation order is kept:
/// before anything with an effect, pending values that read memory, globals or calls are bound to temporaries.
/// </summary>
public sealed class WasmDecompiler
{
    private readonly WasmBinary _m;
    private readonly Func<uint, string> _functionName;
    private readonly WasmMemoryMap? _memory;
    private readonly StringBuilder _o = new();
    private readonly List<Ex> _stack = [];
    private readonly List<Frame> _frames = [];
    private readonly HashSet<int> _targeted = [];
    private string[] _locals = [];
    private WasmType[] _localTypes = [];
    private WasmType[] _results = [];
    private int _indent = 1, _temps, _blocks, _dead;

    /// <summary>An expression: its text, precedence (16 a primary, 3 a conditional), whether it reads state or has effects, and its type.</summary>
    private sealed record Ex(string Text, int Prec, bool Impure, WasmType Type, HashSet<uint>? Reads = null);

    private sealed class Frame
    {
        public int Id, Op;
        public WasmType[] Params = [], Results = [];
        public string[] ResultVars = [];
        public List<Ex> Args = [];
        public int Height;
    }

    private WasmDecompiler(WasmBinary m, Func<uint, string> functionName, WasmMemoryMap? memory)
    {
        _m = m;
        _functionName = functionName;
        _memory = memory;
    }

    /// <summary>The function's lifted text, or null for an import or a missing body.</summary>
    public static string? Function(WasmBinary m, uint index, Func<uint, string> functionName, WasmMemoryMap? memory = null)
    {
        if (m.BodyOf(index) is not { } body || m.FunctionType(index) is not { } type) return null;
        var d = new WasmDecompiler(m, functionName, memory);
        return d.Write(index, body, type);
    }

    private string Write(uint index, WasmBody body, WasmFuncType type)
    {
        var names = _m.Names.Locals.GetValueOrDefault(index);
        var types = new List<WasmType>(type.Params);
        foreach (var (count, t) in body.Locals)
            for (uint i = 0; i < count && types.Count < 100_000; i++) types.Add(t);
        _localTypes = [.. types];
        _locals = [.. types.Select((_, i) => names != null && names.TryGetValue((uint)i, out var n) && Identifier(n) is { Length: > 0 } id ? id
            : (i < type.Params.Length ? "p" : "l") + i.ToString(CultureInfo.InvariantCulture))];
        _results = type.Results;
        string ret = type.Results.Length switch { 0 => "void", 1 => TypeName(type.Results[0]), _ => "(" + string.Join(", ", type.Results.Select(TypeName)) + ")" };
        string head = $"{ret} {Identifier(_functionName(index))}({string.Join(", ", type.Params.Select((t, i) => $"{TypeName(t)} {_locals[i]}"))}) {{";
        var lines = new StringBuilder();
        lines.AppendLine(head);
        foreach (var g in Enumerable.Range(type.Params.Length, types.Count - type.Params.Length).GroupBy(i => types[i]))
            lines.Append("  ").Append(TypeName(g.Key)).Append(' ').AppendJoin(", ", g.Select(i => _locals[i])).AppendLine(";");
        Prescan(body);
        _frames.Add(new Frame { Id = 0, Op = -1, Results = type.Results });
        var code = new WasmCode(_m.Bytes, body.CodeStart, body.End);
        while (code.Next(out var ins))
        {
            if (_frames.Count == 0) break;
            Instruction(ins);
        }
        if (code.Error != null) Line($"// {code.Error}");
        lines.Append(_o);
        lines.AppendLine("}");
        return lines.ToString();
    }

    /// <summary>Which blocks a branch names, so only those get a label.</summary>
    private void Prescan(WasmBody body)
    {
        var ids = new List<int> { 0 };
        int next = 0;
        var code = new WasmCode(_m.Bytes, body.CodeStart, body.End);
        while (code.Next(out var ins))
        {
            switch (ins.Op)
            {
                case 0x02 or 0x03 or 0x04 or 0x06 or 0x1F: ids.Add(++next); break;
                case 0x0B: if (ids.Count > 0) ids.RemoveAt(ids.Count - 1); break;
                case 0x0C or 0x0D or 0xD4 or 0xD6: Mark(ins.A); break;
                case 0x0E: foreach (var t in WasmCode.Targets(_m.Bytes, ins)) Mark(t); break;
            }
        }
        void Mark(uint depth) { if (depth < ids.Count) _targeted.Add(ids[ids.Count - 1 - (int)depth]); }
    }

    // ---- output ----

    private void Line(string text) => _o.Append(' ', _indent * 2).AppendLine(text);

    private string Temp(WasmType t, string text)
    {
        var name = "t" + (++_temps).ToString(CultureInfo.InvariantCulture);
        Line($"{TypeName(t)} {name} = {text};");
        return name;
    }

    // ---- the stack ----

    private void Push(Ex e) => _stack.Add(e);

    private Ex Pop(WasmType hint = WasmType.I32)
    {
        int floor = _frames.Count > 0 ? _frames[^1].Height : 0;
        if (_stack.Count <= floor) return new Ex("?", 16, false, hint);
        var e = _stack[^1];
        _stack.RemoveAt(_stack.Count - 1);
        return e;
    }

    private List<Ex> Pop(int n)
    {
        var list = new List<Ex>(n);
        for (int i = 0; i < n; i++) list.Insert(0, Pop());
        return list;
    }

    /// <summary>
    /// Binds pending values to temporaries, oldest first: those that read state or have effects, those reading
    /// <paramref name="local"/>, or with <paramref name="all"/> every value that is not a constant or temporary (at block boundaries).
    /// </summary>
    private void Spill(uint? local = null, bool all = false)
    {
        for (int i = 0; i < _stack.Count; i++)
        {
            var e = _stack[i];
            bool settled = e.Prec >= 15 && e.Reads == null && !e.Impure && !e.Text.Contains('(');
            if (settled) continue;
            if (all || e.Impure || local is { } l && e.Reads?.Contains(l) == true)
                _stack[i] = new Ex(Temp(e.Type, e.Text), 16, false, e.Type);
        }
    }

    private static string Paren(Ex e, int prec) => e.Prec < prec ? "(" + e.Text + ")" : e.Text;

    private static HashSet<uint>? Union(params Ex[] es)
    {
        HashSet<uint>? set = null;
        foreach (var e in es)
            if (e.Reads != null) (set ??= []).UnionWith(e.Reads);
        return set;
    }

    // ---- instructions ----

    private void Instruction(in WasmInstr ins)
    {
        if (_dead > 0)
        {
            switch (ins.Op)
            {
                case 0x02 or 0x03 or 0x04 or 0x06 or 0x1F: _dead++; return;
                case 0x0B: if (--_dead > 0) return; _dead = 0; break;
                case 0x05 or 0x07 or 0x19: if (_dead > 1) return; _dead = 0; break;
                default: return;
            }
        }
        var info = ins.Info;
        switch (ins.Op)
        {
            case 0x00: Spill(); Line("unreachable();"); Dead(); return;
            case 0x01: return;
            case 0x02 or 0x03 or 0x06 or 0x1F: Begin(ins); return;
            case 0x04: Begin(ins); return;
            case 0x05: Else(); return;
            case 0x0B: End(); return;
            case 0x07 or 0x19:
                {
                    var f = _frames[^1];
                    _stack.RemoveRange(f.Height, _stack.Count - f.Height);
                    _indent--;
                    if (ins.Op == 0x07)
                    {
                        Line($"}} catch (tag_{ins.A}) {{");
                        if (_m.TagTypeIndex(ins.A) is { } tt && tt < _m.Types.Count)
                            for (int i = 0; i < _m.Types[(int)tt].Params.Length; i++) Push(new Ex($"exception[{i}]", 16, false, _m.Types[(int)tt].Params[i]));
                    }
                    else Line("} catch {");
                    _indent++;
                    return;
                }
            case 0x18:
                {
                    var f = _frames[^1];
                    _frames.RemoveAt(_frames.Count - 1);
                    _indent--;
                    Line($"}} /* exceptions delegated to depth {ins.A} */");
                    PushResults(f);
                    return;
                }
            case 0x08:
                {
                    int n = _m.TagTypeIndex(ins.A) is { } tt && tt < _m.Types.Count ? _m.Types[(int)tt].Params.Length : 0;
                    var args = Pop(n);
                    Spill();
                    Line($"throw tag_{ins.A}({string.Join(", ", args.Select(a => a.Text))});");
                    Dead();
                    return;
                }
            case 0x09: Spill(); Line("rethrow;"); Dead(); return;
            case 0x0A: { var e = Pop(); Spill(); Line($"throw_ref({e.Text});"); Dead(); return; }
            case 0x0C: Branch(ins.A, null); Dead(); return;
            case 0x0D: { var c = Pop(); Branch(ins.A, c); return; }
            case 0x0E: BrTable(ins); Dead(); return;
            case 0x0F: Return(); Dead(); return;
            case 0x10 or 0x12: Call(_m.FunctionType(ins.A), Identifier(_functionName(ins.A)), ins.Op == 0x12, null); return;
            case 0x11 or 0x13:
                {
                    var target = Pop();
                    var t = ins.A < _m.Types.Count ? _m.Types[(int)ins.A] : null;
                    Call(t, $"{Table(ins.B)}[{target.Text}]", ins.Op == 0x13, target);
                    return;
                }
            case 0x1A:
                {
                    var e = Pop();
                    if (e.Impure && e.Text.Contains('(')) { Spill(); Line(e.Text + ";"); }
                    return;
                }
            case 0x1B or 0x1C:
                {
                    var c = Pop();
                    var b = Pop();
                    var a = Pop();
                    Push(new Ex($"{Paren(c, 4)} ? {Paren(a, 4)} : {Paren(b, 4)}", 3, a.Impure || b.Impure || c.Impure, a.Type, Union(a, b, c)));
                    return;
                }
            case 0x20:
                Push(ins.A < _locals.Length ? new Ex(_locals[ins.A], 16, false, _localTypes[ins.A], [ins.A]) : new Ex($"local_{ins.A}", 16, false, WasmType.I32));
                return;
            case 0x21 or 0x22:
                {
                    var v = Pop();
                    Spill(ins.A);
                    string name = ins.A < _locals.Length ? _locals[ins.A] : $"local_{ins.A}";
                    Line($"{name} = {v.Text};");
                    if (ins.Op == 0x22) Push(new Ex(name, 16, false, v.Type, [ins.A]));
                    return;
                }
            case 0x23:
                Push(new Ex(Global(ins.A), 16, true, _m.GlobalTypeOf(ins.A)?.Type ?? WasmType.I32));
                return;
            case 0x24:
                {
                    var v = Pop();
                    Spill();
                    Line($"{Global(ins.A)} = {v.Text};");
                    return;
                }
            case 0x25:
                {
                    var i = Pop();
                    Push(new Ex($"{Table(ins.A)}[{i.Text}]", 16, true, _m.TableTypeOf(ins.A)?.Element ?? WasmType.FuncRef, Union(i)));
                    return;
                }
            case 0x26:
                {
                    var v = Pop();
                    var i = Pop();
                    Spill();
                    Line($"{Table(ins.A)}[{i.Text}] = {v.Text};");
                    return;
                }
            case 0x41: Push(Constant((int)ins.Value, WasmType.I32)); return;
            case 0x42: Push(Constant(ins.Value, WasmType.I64)); return;
            case 0x43: Push(new Ex(Float(BitConverter.Int32BitsToSingle((int)ins.Value), "f"), 16, false, WasmType.F32)); return;
            case 0x44: Push(new Ex(Float(BitConverter.Int64BitsToDouble(ins.Value), ""), 16, false, WasmType.F64)); return;
            case 0xD0: Push(new Ex("null", 16, false, ins.Value == -0x11 ? WasmType.ExternRef : WasmType.FuncRef)); return;
            case 0xD1: { var r = Pop(); Push(new Ex($"{Paren(r, 10)} == null", 9, r.Impure, WasmType.I32, Union(r))); return; }
            case 0xD2: Push(new Ex("&" + Identifier(_functionName(ins.A)), 15, false, WasmType.FuncRef)); return;
            case 0x3F: Push(new Ex($"memory_size({MemoryName(ins.Memory)})", 16, true, WasmType.I32)); return;
            case 0x40:
                {
                    var n = Pop();
                    Spill();
                    Push(new Ex(Temp(n.Type, $"memory_grow({n.Text}{MemoryArg(ins.Memory)})"), 16, false, n.Type));
                    return;
                }
        }
        if (info.IsMemoryAccess) { Memory(ins); return; }
        Operator(ins);
    }

    private void Dead() => _dead = 1;

    private void Begin(in WasmInstr ins)
    {
        var (ps, rs) = BlockType(ins.BlockType);
        Ex? condition = ins.Op == 0x04 ? Pop() : null;
        Spill(all: true);
        var args = Pop(ps.Length);
        var frame = new Frame { Id = ++_blocks, Op = ins.Op, Params = ps, Results = rs, Height = _stack.Count, Args = args };
        frame.ResultVars = [.. rs.Select((t, i) => $"b{frame.Id}_{i}")];
        foreach (var (t, v) in rs.Zip(frame.ResultVars)) Line($"{TypeName(t)} {v};");
        string label = _targeted.Contains(frame.Id) ? $"{Label(frame)}: " : "";
        Line(ins.Op switch
        {
            0x03 => $"{label}while (true) {{",
            0x04 => $"{label}if ({condition!.Text}) {{",
            0x06 => $"{label}try {{",
            _ => $"{label}{{",
        });
        _frames.Add(frame);
        _indent++;
        foreach (var a in args) Push(a);
    }

    private string Label(Frame f) => (f.Op == 0x03 ? "loop_" : "block_") + f.Id.ToString(CultureInfo.InvariantCulture);

    private void AssignResults(Frame f)
    {
        var values = Pop(f.Results.Length);
        for (int i = 0; i < values.Count && i < f.ResultVars.Length; i++) Line($"{f.ResultVars[i]} = {values[i].Text};");
    }

    private void Else()
    {
        var f = _frames[^1];
        if (f.Op != 0x04) { Line("// else outside an if"); return; }
        if (_dead == 0) AssignResults(f);
        _stack.RemoveRange(f.Height, _stack.Count - f.Height);
        foreach (var a in f.Args) Push(a); // the else branch starts from the if's parameters too
        _indent--;
        Line("} else {");
        _indent++;
    }

    private void End()
    {
        var f = _frames[^1];
        if (f.Op == -1)
        {
            if (_dead == 0 && _results.Length > 0) Return();
            _frames.RemoveAt(_frames.Count - 1);
            return;
        }
        if (_dead == 0)
        {
            AssignResults(f);
            if (f.Op == 0x03) Line("break;");
        }
        _stack.RemoveRange(f.Height, _stack.Count - f.Height);
        _frames.RemoveAt(_frames.Count - 1);
        _indent--;
        Line("}");
        PushResults(f);
    }

    private void PushResults(Frame f)
    {
        for (int i = 0; i < f.Results.Length; i++) Push(new Ex(f.ResultVars.Length > i ? f.ResultVars[i] : "?", 16, false, f.Results[i]));
    }

    /// <summary>A branch to depth <paramref name="depth"/>, conditional when <paramref name="condition"/> is given: values first, then break, continue or return.</summary>
    private void Branch(uint depth, Ex? condition)
    {
        if (depth >= _frames.Count) { Line($"// br {depth}: no such label"); return; }
        var target = _frames[^(1 + (int)depth)];
        Spill();
        string jump = Jump(target, out var assign);
        if (condition == null)
        {
            foreach (var a in assign) Line(a);
            Line(jump);
            return;
        }
        if (assign.Count == 0) { Line($"if ({condition.Text}) {jump}"); return; }
        Line($"if ({condition.Text}) {{");
        _indent++;
        foreach (var a in assign) Line(a);
        Line(jump);
        _indent--;
        Line("}");
    }

    /// <summary>The jump statement to a frame, with the assignments its values need (values stay on the stack for br_if).</summary>
    private string Jump(Frame target, out List<string> assign)
    {
        assign = [];
        if (target.Op == -1)
        {
            var values = _stack.TakeLast(_results.Length).Select(e => e.Text).ToList();
            return values.Count switch { 0 => "return;", 1 => $"return {values[0]};", _ => $"return ({string.Join(", ", values)});" };
        }
        if (target.Op == 0x03) return $"continue {Label(target)};";
        var top = _stack.TakeLast(target.Results.Length).ToList();
        for (int i = 0; i < top.Count && i < target.ResultVars.Length; i++) assign.Add($"{target.ResultVars[i]} = {top[i].Text};");
        return $"break {Label(target)};";
    }

    private void BrTable(in WasmInstr ins)
    {
        var index = Pop();
        Spill();
        var targets = WasmCode.Targets(_m.Bytes, ins);
        Line($"switch ({index.Text}) {{");
        _indent++;
        for (int i = 0; i < targets.Length - 1;)
        {
            int j = i;
            while (j + 1 < targets.Length - 1 && targets[j + 1] == targets[i]) j++;
            var cases = string.Join(" ", Enumerable.Range(i, j - i + 1).Select(c => $"case {c}:"));
            Line($"{cases} {Target(targets[i])}");
            i = j + 1;
        }
        Line($"default: {Target(targets[^1])}");
        _indent--;
        Line("}");

        string Target(uint depth)
        {
            if (depth >= _frames.Count) return $"/* br {depth}: no such label */";
            var jump = Jump(_frames[^(1 + (int)depth)], out var assign);
            return assign.Count == 0 ? jump : "{ " + string.Join(" ", assign) + " " + jump + " }";
        }
    }

    private void Return()
    {
        var values = Pop(_results.Length);
        Spill();
        Line(values.Count switch { 0 => "return;", 1 => $"return {values[0].Text};", _ => $"return ({string.Join(", ", values.Select(v => v.Text))});" });
    }

    private void Call(WasmFuncType? type, string callee, bool tail, Ex? target)
    {
        var args = Pop(type?.Params.Length ?? 0);
        Spill();
        string text = $"{callee}({string.Join(", ", args.Select(a => a.Text))})";
        if (tail) { Line($"return {text};"); Dead(); return; }
        var results = type?.Results ?? [];
        if (results.Length == 0) { Line(text + ";"); return; }
        if (results.Length == 1) { Push(new Ex(text, 16, true, results[0], Union([.. args, .. target != null ? [target] : Array.Empty<Ex>()]))); return; }
        var names = results.Select(_ => "t" + (++_temps).ToString(CultureInfo.InvariantCulture)).ToList();
        Line($"({string.Join(", ", results.Zip(names).Select(r => $"{TypeName(r.First)} {r.Second}"))}) = {text};");
        for (int i = 0; i < results.Length; i++) Push(new Ex(names[i], 16, false, results[i]));
    }

    private void Memory(in WasmInstr ins)
    {
        var info = ins.Info;
        var name = info.Name;
        int colon = info.Signature.IndexOf(':');
        var operands = Pop(colon);
        var address = operands[0];
        string pointer = Address(address, ins.MemOffset) + MemorySuffix(ins.Memory);
        bool atomic = ins.Op >> 16 == 0xFE, simd = ins.Op >> 16 == 0xFD;
        var resultType = colon + 1 < info.Signature.Length ? Letter(info.Signature[colon + 1]) : (WasmType?)null;
        if (!atomic && !simd && name.Contains(".load", StringComparison.Ordinal))
        {
            string cell = MemoryType(name);
            string text = $"*({cell}*){pointer}";
            if (resultType == WasmType.I64 && cell is not ("i64" or "u64")) text = "(i64)" + text;
            Push(new Ex(text, text.StartsWith('(') ? 15 : 15, true, resultType!.Value, Union(address)));
            return;
        }
        if (!atomic && !simd && name.Contains(".store", StringComparison.Ordinal))
        {
            Spill();
            Line($"*({MemoryType(name)}*){pointer} = {operands[1].Text};");
            return;
        }
        // atomics and SIMD memory access: function form, the address first
        string call = $"{Identifier(name)}({string.Join(", ", new[] { pointer }.Concat(operands.Skip(1).Select(o => o.Text)))}{(info.Imm == WasmImm.MemArgLane ? $", {ins.Lane}" : "")})";
        if (resultType == null) { Spill(); Line(call + ";"); return; }
        Spill();
        Push(new Ex(atomic ? Temp(resultType.Value, call) : call, 16, true, resultType.Value, Union(operands.ToArray())));
    }

    /// <summary>The element type a load or store name reads: i32.load16_u is u16, i64.store32 is u32.</summary>
    private static string MemoryType(string name)
    {
        string type = name[..3];
        int at = name.IndexOf(".load", StringComparison.Ordinal) is var l and >= 0 ? l + 5 : name.IndexOf(".store", StringComparison.Ordinal) + 6;
        var bits = name[at..];
        if (bits.Length == 0) return type;
        string width = bits.TrimEnd('_', 's', 'u');
        bool signed = bits.EndsWith("_s", StringComparison.Ordinal);
        return (signed ? "i" : "u") + width;
    }

    private string Address(Ex address, ulong offset)
    {
        if (offset == 0) return "(" + address.Text + ")";
        if (long.TryParse(address.Text, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out var c) && address.Prec == 16)
            return "(" + Annotated((ulong)(uint)(int)c + offset) + ")";
        return $"({Paren(address, 12)} + {offset.ToString(CultureInfo.InvariantCulture)})";
    }

    private string MemorySuffix(uint memory) => memory == 0 ? "" : $"@{MemoryName(memory)}";
    private string MemoryArg(uint memory) => memory == 0 ? "" : $", {MemoryName(memory)}";
    private string MemoryName(uint memory) => _m.Names.Memories.TryGetValue(memory, out var n) && Identifier(n) is { Length: > 0 } id ? id : memory == 0 ? "" : $"memory{memory}";

    private string Table(uint table) => _m.Names.Tables.TryGetValue(table, out var n) && Identifier(n) is { Length: > 0 } id ? id : $"table{table}";

    private string Global(uint global)
    {
        if (_m.Names.Globals.TryGetValue(global, out var n) && Identifier(n) is { Length: > 0 } id) return id;
        if (global < _m.ImportedGlobals && _m.ImportAt(WasmExternal.Global, global) is { } imp) return Identifier($"{imp.Module}.{imp.Name}");
        foreach (var e in _m.Exports) if (e.Kind == WasmExternal.Global && e.Index == global) return Identifier(e.Name);
        return $"global{global}";
    }

    private Ex Constant(long value, WasmType type)
    {
        string text = value.ToString(CultureInfo.InvariantCulture);
        if (type == WasmType.I32 && value >= 0) text = Annotated((ulong)value);
        return new Ex(text, value < 0 ? 15 : 16, false, type);
    }

    /// <summary>A memory address, with the string a data segment holds there as a comment.</summary>
    private string Annotated(ulong address)
    {
        string text = address.ToString(CultureInfo.InvariantCulture);
        if (_memory?.FileOffset(address) is { } at && WasmMemoryMap.CString(_m.Bytes, at) is { } s)
            text += " /* \"" + Escape(s.Length > 80 ? s[..80] + "…" : s) + "\" */";
        return text;
    }

    private static string Escape(string s) => s.Replace("\\", "\\\\").Replace("\"", "\\\"").Replace("\n", "\\n").Replace("\r", "\\r").Replace("\t", "\\t").Replace("*/", "*\\/");

    private static string Float(double v, string suffix)
    {
        if (double.IsNaN(v)) return "NAN";
        if (double.IsInfinity(v)) return v < 0 ? "-INFINITY" : "INFINITY";
        var s = suffix == "f" ? ((float)v).ToString("R", CultureInfo.InvariantCulture) : v.ToString("R", CultureInfo.InvariantCulture);
        if (!s.Contains('.') && !s.Contains('E')) s += ".0";
        return s + suffix;
    }

    private void Operator(in WasmInstr ins)
    {
        var info = ins.Info;
        var sig = info.Signature;
        if (sig == "*" || !sig.Contains(':')) { Spill(); Line($"{Identifier(info.Name)}();"); return; }
        int colon = sig.IndexOf(':');
        var args = Pop(colon);
        var type = colon + 1 < sig.Length ? Letter(sig[colon + 1]) : WasmType.I32;
        var name = info.Name;
        var reads = Union([.. args]);
        bool impure = args.Any(a => a.Impure);
        string op = name.Contains('.') ? name[(name.IndexOf('.') + 1)..] : name;
        bool scalar = name.Length > 3 && name[3] == '.' && name[0] is 'i' or 'f';
        if (scalar && args.Count == 2 && Infix(op) is { } infix)
        {
            string u = op.EndsWith("_u", StringComparison.Ordinal) && op != "shr_u" ? (name[1] == '6' ? "(u64)" : "(u32)") : "";
            string a = u.Length > 0 ? u + Paren(args[0], 15) : Paren(args[0], infix.Prec);
            string b = u.Length > 0 ? u + Paren(args[1], 15) : Paren(args[1], infix.Prec + 1);
            Push(new Ex($"{a} {infix.Symbol} {b}", infix.Prec, impure, type, reads));
            return;
        }
        if (scalar && args.Count == 1)
        {
            if (op == "eqz") { Push(name[1] == '3' ? new Ex("!" + Paren(args[0], 15), 15, impure, type, reads) : new Ex($"{Paren(args[0], 10)} == 0", 9, impure, type, reads)); return; }
            if (op == "neg") { Push(new Ex("-" + Paren(args[0], 15), 15, impure, type, reads)); return; }
            if (Cast(name) is { } cast) { Push(new Ex(cast + Paren(args[0], 15), 15, impure, type, reads)); return; }
        }
        if (info.Imm == WasmImm.Lane) args.Add(new Ex(ins.Lane.ToString(CultureInfo.InvariantCulture), 16, false, WasmType.I32));
        if (info.Imm == WasmImm.Shuffle) args.Add(new Ex("[" + string.Join(", ", _m.Bytes.AsSpan(ins.ImmStart, 16).ToArray()) + "]", 16, false, WasmType.I32));
        if (info.Imm == WasmImm.V128)
        {
            Push(new Ex("v128(0x" + Convert.ToHexStringLower(_m.Bytes.AsSpan(ins.ImmStart, 16).ToArray().Reverse().ToArray()) + ")", 16, false, WasmType.V128));
            return;
        }
        Push(new Ex($"{Function(name)}({string.Join(", ", args.Select(a => a.Text))})", 16, impure, type, reads));
    }

    private static (string Symbol, int Prec)? Infix(string op) => op switch
    {
        "add" => ("+", 12), "sub" => ("-", 12), "mul" => ("*", 13), "div_s" or "div_u" or "div" => ("/", 13), "rem_s" or "rem_u" => ("%", 13),
        "and" => ("&", 8), "or" => ("|", 6), "xor" => ("^", 7), "shl" => ("<<", 11), "shr_s" => (">>", 11), "shr_u" => (">>>", 11),
        "eq" => ("==", 9), "ne" => ("!=", 9), "lt_s" or "lt_u" or "lt" => ("<", 10), "gt_s" or "gt_u" or "gt" => (">", 10),
        "le_s" or "le_u" or "le" => ("<=", 10), "ge_s" or "ge_u" or "ge" => (">=", 10),
        _ => null,
    };

    /// <summary>Conversions written as casts: (i64)x, (i64)(u32)x, (f32)x, (i32)(i8)x.</summary>
    private static string? Cast(string name) => name switch
    {
        "i32.wrap_i64" => "(i32)", "i64.extend_i32_s" => "(i64)", "i64.extend_i32_u" => "(i64)(u32)",
        "i32.trunc_f32_s" or "i32.trunc_f64_s" => "(i32)", "i32.trunc_f32_u" or "i32.trunc_f64_u" => "(u32)",
        "i64.trunc_f32_s" or "i64.trunc_f64_s" => "(i64)", "i64.trunc_f32_u" or "i64.trunc_f64_u" => "(u64)",
        "f32.convert_i32_s" or "f32.convert_i64_s" or "f32.demote_f64" => "(f32)", "f32.convert_i32_u" => "(f32)(u32)", "f32.convert_i64_u" => "(f32)(u64)",
        "f64.convert_i32_s" or "f64.convert_i64_s" or "f64.promote_f32" => "(f64)", "f64.convert_i32_u" => "(f64)(u32)", "f64.convert_i64_u" => "(f64)(u64)",
        "i32.extend8_s" => "(i32)(i8)", "i32.extend16_s" => "(i32)(i16)", "i64.extend8_s" => "(i64)(i8)", "i64.extend16_s" => "(i64)(i16)", "i64.extend32_s" => "(i64)(i32)",
        _ => null,
    };

    /// <summary>The function form of an operator: f64.sqrt is sqrt, i32.clz is clz, i32x4.add is i32x4_add.</summary>
    private static string Function(string name)
    {
        if (name.Length > 4 && name[3] == '.' && name[0] is 'i' or 'f')
        {
            var op = name[4..];
            if (name[0] == 'f' && op is "abs" or "ceil" or "floor" or "trunc" or "nearest" or "sqrt" or "min" or "max" or "copysign")
                return (op == "abs" ? "fabs" : op == "nearest" ? "rint" : op is "min" or "max" ? "f" + op : op) + (name[1] == '3' ? "f" : "");
            if (op is "clz" or "ctz" or "popcnt" or "rotl" or "rotr") return op + (name[1] == '6' ? "64" : "");
        }
        return Identifier(name);
    }

    private (WasmType[] Params, WasmType[] Results) BlockType(long bt)
    {
        if (bt == -0x40) return ([], []);
        if (bt < 0) return ([], [(WasmType)(byte)(bt & 0x7F)]);
        if (bt < _m.Types.Count) return (_m.Types[(int)bt].Params, _m.Types[(int)bt].Results);
        return ([], []);
    }

    private static WasmType Letter(char c) => c switch
    {
        'l' => WasmType.I64, 'f' => WasmType.F32, 'd' => WasmType.F64, 'v' => WasmType.V128, _ => WasmType.I32,
    };

    private static string TypeName(WasmType t) => WasmBinary.TypeName(t);

    /// <summary>A name usable in the text: letters, digits and '_' kept, the rest '_'.</summary>
    public static string Identifier(string name)
    {
        var sb = new StringBuilder(name.Length);
        foreach (char c in name) sb.Append(char.IsLetterOrDigit(c) || c == '_' || c == '$' ? c : '_');
        if (sb.Length > 0 && char.IsDigit(sb[0])) sb.Insert(0, '_');
        return sb.ToString();
    }
}
