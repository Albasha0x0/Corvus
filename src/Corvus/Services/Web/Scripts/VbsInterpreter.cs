using System.Globalization;
using System.Text;
using static Corvus.Services.Web.Scripts.PsConvert;

namespace Corvus.Services.Web.Scripts;

/// <summary>A COM object a script made (CreateObject): its ProgID and the properties set on it.</summary>
internal sealed class VbObject(string progId)
{
    public string ProgId { get; } = progId;
    public Dictionary<string, object?> Properties { get; } = new(StringComparer.OrdinalIgnoreCase);
    /// <summary>ADODB.Stream contents.</summary>
    public List<byte> Buffer { get; } = [];
}

/// <summary>
/// A bounded VBScript / VBA evaluator: statements, loops and user functions over constants with the string built-ins
/// (Chr, Mid, StrReverse, Replace, Split / Join, Hex, Asc, Escape) and the base64 decoders scripts reach through
/// MSXML and ADODB.Stream. Execute, ExecuteGlobal and Eval of constant text are peeled as layers; WScript.Shell Run and
/// Exec command lines are read as batch layers. VBA auto-run procedures are followed. Nothing is run.
/// </summary>
internal sealed class VbsInterpreter
{
    private const int MaxCallDepth = 64, MaxEvalDepth = 300, MaxFold = 32_768;
    private static readonly string[] AutoRun =
    [
        "AutoOpen", "Auto_Open", "AutoExec", "AutoNew", "AutoClose", "Auto_Close", "Document_Open", "Document_New", "Document_Close",
        "Workbook_Open", "Workbook_Activate", "Workbook_BeforeClose", "Presentation_Open", "Workbook_Close", "Window_Onload", "Main",
    ];

    private readonly ScriptContext _ctx;
    private readonly ScriptBudget _budget;
    private readonly Dictionary<string, object?> _globals = new(StringComparer.OrdinalIgnoreCase);
    private readonly List<Dictionary<string, object?>> _frames = [];
    private readonly Dictionary<string, (VbProcedure Proc, TextEdits Layer)> _procs = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<(TextEdits, int)> _peeled = [];
    private readonly Stack<object?> _with = new();
    private TextEdits _layer = null!;
    private int _depth, _evalDepth, _callDepth;
    private bool _fold;

    private VbsInterpreter(ScriptContext ctx)
    {
        _ctx = ctx;
        _budget = ctx.Budget;
    }

    private sealed class BudgetSignal : Exception;
    private sealed class ExitSignal(string what) : Exception
    {
        public string What { get; } = what;
    }

    public static string Read(string text, ScriptContext ctx, int depth) => new VbsInterpreter(ctx).RunLayer(text, depth, global: true);

    private string RunLayer(string text, int depth, bool global)
    {
        var layer = new TextEdits(text);
        var body = VbParser.Parse(text, _budget);
        var saved = (_layer, _depth);
        (_layer, _depth) = (layer, depth);
        try
        {
            foreach (var p in body.OfType<VbProcedure>()) _procs[p.Name] = (p, layer);
            try
            {
                Exec(body);
                if (depth == 0)
                    foreach (var name in AutoRun)
                        if (_procs.TryGetValue(name, out var auto) && auto.Layer == layer) CallProc(auto.Proc, auto.Layer, []);
            }
            catch (ExitSignal) { }
            bool fold = _fold;
            _fold = true;
            try { Exec(body); }
            catch (ExitSignal) { }
            finally { _fold = fold; }
        }
        catch (BudgetSignal)
        {
            if (!_ctx.Incomplete) _ctx.Note("The evaluation budget ran out: later layers and folds are not shown.");
            _ctx.Incomplete = true;
            if (depth > 0) { (_layer, _depth) = saved; throw; }
        }
        finally { (_layer, _depth) = saved; }
        _ctx.Folded += layer.Count;
        return layer.Render();
    }

    private void Step()
    {
        if (!_budget.Step()) throw new BudgetSignal();
    }

    // --- statements ---

    private void Exec(List<VbStatement> body)
    {
        foreach (var st in body) Exec(st);
    }

    private void Exec(VbStatement st)
    {
        Step();
        switch (st)
        {
            case VbAssign a:
            {
                var v = Eval(a.Value);
                if (_fold) { if (a.Target is VbCall tc) foreach (var x in tc.Args) if (x != null) Eval(x); break; }
                Assign(a.Target, v);
                break;
            }
            case VbCallStatement c:
                CallStatement(c);
                break;
            case VbIf i:
                if (_fold)
                {
                    foreach (var (cond, b) in i.Clauses) { Eval(cond); Exec(b); }
                    if (i.Else != null) Exec(i.Else);
                    break;
                }
                foreach (var (cond, b) in i.Clauses)
                {
                    var c = Truth(Eval(cond));
                    if (c == null) return;
                    if (c == true) { Exec(b); return; }
                }
                if (i.Else != null) Exec(i.Else);
                break;
            case VbFor f:
            {
                var from = Eval(f.From);
                var to = Eval(f.To);
                var step = f.StepBy != null ? Eval(f.StepBy) : 1L;
                if (_fold) { Exec(f.Body); break; }
                if (Double(from) is not { } a || Double(to) is not { } b || Double(step) is not { } s || s == 0) { Set(f.Variable, PsUnknown.Value); break; }
                try
                {
                    for (double i = a; s > 0 ? i <= b : i >= b; i += s)
                    {
                        Step();
                        Set(f.Variable, i == Math.Floor(i) ? (long)i : i);
                        Exec(f.Body);
                        if (Double(Get(f.Variable)) is { } cur) i = cur;
                    }
                }
                catch (ExitSignal e) when (e.What == "for") { }
                break;
            }
            case VbForEach fe:
            {
                var coll = Eval(fe.Collection);
                if (_fold) { Exec(fe.Body); break; }
                if (coll is not object[] items) { Set(fe.Variable, PsUnknown.Value); break; }
                try
                {
                    foreach (var item in items.ToList())
                    {
                        Step();
                        Set(fe.Variable, item);
                        Exec(fe.Body);
                    }
                }
                catch (ExitSignal e) when (e.What == "for") { }
                break;
            }
            case VbDo d:
                if (_fold) { if (d.Condition != null) Eval(d.Condition); Exec(d.Body); break; }
                try
                {
                    while (true)
                    {
                        Step();
                        if (d.Kind is "while" or "until" && Test(d) is not true) break;
                        Exec(d.Body);
                        if (d.Kind is "loop-while" or "loop-until" && Test(d) is not true) break;
                        if (d.Kind == "plain" && _budget.Exhausted) break;
                    }
                }
                catch (ExitSignal e) when (e.What == "do") { }
                break;
            case VbProcedure p:
                if (_fold) Exec(p.Body);
                else _procs[p.Name] = (p, _layer);
                break;
            case VbDim dim:
                if (!_fold && _frames.Count > 0) _frames[^1].TryAdd(dim.Name, null);
                break;
            case VbExit x:
                if (!_fold) throw new ExitSignal(x.What);
                break;
            case VbBlock b:
                foreach (var e in b.Exprs) Eval(e);
                if (b.Exprs.Count > 0 && !_fold && b.Body.Count > 0 && b.Exprs[0] is { } with && b.Start < b.End)
                {
                    _with.Push(Eval(with));
                    try { Exec(b.Body); }
                    finally { _with.Pop(); }
                }
                else if (b.Exprs.Count == 0 || _fold) Exec(b.Body);
                break;
        }
    }

    /// <summary>A Do loop's test: true to go on.</summary>
    private bool? Test(VbDo d)
    {
        var c = Truth(Eval(d.Condition!));
        if (c == null) return null;
        return d.Kind.EndsWith("while", StringComparison.Ordinal) ? c : !c;
    }

    private static bool? Truth(object? v) => v switch
    {
        bool b => b,
        null => false,
        long l => l != 0,
        double d => d != 0,
        string s when s.Equals("true", StringComparison.OrdinalIgnoreCase) => true,
        string s when s.Equals("false", StringComparison.OrdinalIgnoreCase) => false,
        string s when Double(s) is { } n => n != 0,
        _ => null,
    };

    private void Assign(VbExpr target, object? v)
    {
        switch (target)
        {
            case VbName { Target: null } n:
                Set(n.Name, v);
                break;
            case VbName { Target: { } t } m:
            {
                var obj = Eval(t);
                if (obj is VbObject o) SetProperty(o, m.Name, v);
                break;
            }
            case VbCall { Callee: VbName { Target: null } arr } c when c.Args.Count == 1 && c.Args[0] is { } ix:
            {
                if (Get(arr.Name) is object[] items && Long(Eval(ix)) is { } i && i >= 0 && i < items.Length) items[i] = v!;
                else Set(arr.Name, PsUnknown.Value);
                break;
            }
        }
    }

    private void Set(string name, object? v)
    {
        if (_frames.Count > 0 && (_frames[^1].ContainsKey(name) || !_globals.ContainsKey(name))) _frames[^1][name] = v;
        else _globals[name] = v;
    }

    private object? Get(string name)
    {
        if (_fold) return Constant(name);
        if (_frames.Count > 0 && _frames[^1].TryGetValue(name, out var local)) return local;
        if (_globals.TryGetValue(name, out var g)) return g;
        return Constant(name);
    }

    /// <summary>The language's named constants.</summary>
    private static object? Constant(string name) => name.ToLowerInvariant() switch
    {
        "vbcrlf" or "vbnewline" => "\r\n",
        "vbcr" => "\r",
        "vblf" => "\n",
        "vbtab" => "\t",
        "vbnullstring" => "",
        "vbnullchar" => "\0",
        "vbtextcompare" => 1L,
        "vbbinarycompare" => 0L,
        "vbhide" => 0L,
        "vbnormalfocus" => 1L,
        _ => PsUnknown.Value,
    };

    // --- expressions ---

    private object? Eval(VbExpr e)
    {
        Step();
        if (++_evalDepth > MaxEvalDepth) { _evalDepth--; return PsUnknown.Value; }
        try
        {
            var v = EvalCore(e);
            Fold(e, v);
            return v;
        }
        finally { _evalDepth--; }
    }

    private void Fold(VbExpr e, object? v)
    {
        if (v is not string s || s.Length > MaxFold || e is VbLiteral || e is VbName { Target: null }) return;
        if (e is VbCall { Callee: VbName { Name: "(" } } || !ScriptText.Printable(s) && s.Length > 0) return;
        _layer.Set(e.Start, e.End, Literal(s), weak: _fold);
    }

    /// <summary>A VBScript string literal; line breaks and control characters as the named constants or Chr().</summary>
    internal static string Literal(string s)
    {
        var parts = new List<string>();
        var run = new StringBuilder();
        void Flush()
        {
            if (run.Length > 0) { parts.Add("\"" + run.ToString().Replace("\"", "\"\"") + "\""); run.Clear(); }
        }
        for (int i = 0; i < s.Length; i++)
        {
            char c = s[i];
            if (c >= ' ' || c == '\t' && false) { run.Append(c); continue; }
            Flush();
            if (c == '\r' && i + 1 < s.Length && s[i + 1] == '\n') { parts.Add("vbCrLf"); i++; }
            else parts.Add(c switch { '\n' => "vbLf", '\r' => "vbCr", '\t' => "vbTab", _ => $"Chr({(int)c})" });
        }
        Flush();
        return parts.Count == 0 ? "\"\"" : string.Join(" & ", parts);
    }

    private object? EvalCore(VbExpr e)
    {
        switch (e)
        {
            case VbLiteral l: return l.Value;
            case VbUnary u:
            {
                var x = Eval(u.Operand);
                if (!Known(x)) return PsUnknown.Value;
                return u.Op switch
                {
                    "-" => x is double d ? -d : Long(x) is { } n ? -n : PsUnknown.Value,
                    "+" => x,
                    _ => x is bool b ? !b : Long(x) is { } bn ? ~bn : PsUnknown.Value,
                };
            }
            case VbBinary b: return Binary(b.Op, Eval(b.Left), Eval(b.Right));
            case VbName { Target: null } n:
            {
                if (n.Name.Equals("with", StringComparison.Ordinal) && n.Start == n.End) return _with.Count > 0 ? _with.Peek() : PsUnknown.Value;
                var v = Get(n.Name);
                if (Known(v) || _fold) return v;
                if (_procs.ContainsKey(n.Name) || Builtin(n.Name, []) is var r && Known(r)) return Call(n, []);
                return IsBuiltinName(n.Name) ? v : null; // an unset variable is Empty
            }
            case VbName m:
            {
                var target = Eval(m.Target!);
                return target is VbObject o ? Property(o, m.Name, m.Start, m.End) : PsUnknown.Value;
            }
            case VbCall c:
            {
                if (c.Callee is VbName { Name: "(" } && c.Callee.Start == c.Callee.End && c.Args.Count == 1) return Eval(c.Args[0]!);
                return Call(c.Callee, c.Args);
            }
        }
        return PsUnknown.Value;
    }

    private object? Binary(string op, object? l, object? r)
    {
        if (!Known(l) || !Known(r)) return PsUnknown.Value;
        switch (op)
        {
            case "&":
            {
                var s = Text(l) + Text(r);
                return s.Length > _budget.MaxChars ? PsUnknown.Value : s;
            }
            case "+":
                if (l is string ls && r is string rs) return ls.Length + rs.Length > _budget.MaxChars ? PsUnknown.Value : ls + rs;
                return Arith(op, l, r);
            case "-" or "*" or "/" or "\\" or "mod" or "^": return Arith(op, l, r);
            case "=" or "<>" or "<" or ">" or "<=" or ">=":
            {
                int c;
                if (l is string && r is string || l is string && r == null || l == null && r is string) c = string.CompareOrdinal(Text(l), Text(r));
                else if (Double(l) is { } a && Double(r) is { } b2) c = a.CompareTo(b2);
                else return PsUnknown.Value;
                return op switch { "=" => c == 0, "<>" => c != 0, "<" => c < 0, ">" => c > 0, "<=" => c <= 0, _ => c >= 0 };
            }
            case "and" or "or" or "xor" or "eqv" or "imp":
                if (l is bool x && r is bool y) return op switch { "and" => x && y, "or" => x || y, "xor" => x ^ y, "eqv" => x == y, _ => !x || y };
                if (Long(l) is { } a2 && Long(r) is { } b3) return op switch { "and" => a2 & b3, "or" => a2 | b3, "xor" => a2 ^ b3, "eqv" => ~(a2 ^ b3), _ => ~a2 | b3 };
                return PsUnknown.Value;
            case "is": return ReferenceEquals(l, r);
        }
        return PsUnknown.Value;
    }

    private static string Text(object? v) => v switch
    {
        null => "",
        bool b => b ? "True" : "False",
        double d => d.ToString(CultureInfo.InvariantCulture),
        _ => Str(v) ?? "",
    };

    private static object Arith(string op, object? l, object? r)
    {
        if (Double(l) is not { } a || Double(r) is not { } b) return PsUnknown.Value;
        double v;
        switch (op)
        {
            case "+": v = a + b; break;
            case "-": v = a - b; break;
            case "*": v = a * b; break;
            case "/": if (b == 0) return PsUnknown.Value; v = a / b; break;
            case "^": v = Math.Pow(a, b); break;
            case "\\":
            {
                long x = (long)Math.Round(a, MidpointRounding.ToEven), y = (long)Math.Round(b, MidpointRounding.ToEven);
                return y == 0 ? PsUnknown.Value : x / y;
            }
            default:
            {
                long x = (long)Math.Round(a, MidpointRounding.ToEven), y = (long)Math.Round(b, MidpointRounding.ToEven);
                return y == 0 ? PsUnknown.Value : x % y;
            }
        }
        return v == Math.Floor(v) && Math.Abs(v) < 9e15 ? (long)v : v;
    }

    // --- calls ---

    private void CallStatement(VbCallStatement c)
    {
        var result = Call(c.Callee, c.Args, statement: c);
        _ = result;
    }

    private object? Call(VbExpr callee, List<VbExpr?> argExprs, VbCallStatement? statement = null)
    {
        int siteStart = statement?.Start ?? callee.Start, siteEnd = statement?.End ?? (argExprs.Count > 0 ? argExprs[^1]?.End ?? callee.End : callee.End);
        if (callee is VbName { Target: { } target } member)
        {
            var obj = Eval(target);
            var margs = argExprs.Select(a => a == null ? null : Eval(a)).ToList();
            if (obj is VbObject o) return Method(o, member.Name, margs, siteStart, siteEnd);
            if (obj is PsUnknown && target is VbName { Target: null, Name: var on } && on.Equals("WScript", StringComparison.OrdinalIgnoreCase))
                return WScript(member.Name, margs);
            if (obj is object[] arr && margs.Count == 1 && Long(margs[0]) is { } ai) return ai >= 0 && ai < arr.Length ? arr[ai] : PsUnknown.Value;
            return PsUnknown.Value;
        }
        if (callee is VbCall inner)
        {
            // a(1)(2): an index of a call's result
            var v = Eval(inner);
            var idx = argExprs.Select(a => a == null ? null : Eval(a)).ToList();
            return v is object[] items && idx.Count == 1 && Long(idx[0]) is { } k && k >= 0 && k < items.Length ? items[k] : PsUnknown.Value;
        }
        if (callee is not VbName { Target: null } named) return PsUnknown.Value;
        var name = named.Name;
        var args = argExprs.Select(a => a == null ? null : Eval(a)).ToList();
        if (!_fold && (_frames.Count > 0 && _frames[^1].TryGetValue(name, out var local) ? local : _globals.GetValueOrDefault(name)) is object[] array)
            return args.Count == 1 && Long(args[0]) is { } i && i >= 0 && i < array.Length ? array[i] : PsUnknown.Value;
        if (_procs.TryGetValue(name, out var proc)) return _fold ? PsUnknown.Value : CallProc(proc.Proc, proc.Layer, args);
        switch (name.ToLowerInvariant())
        {
            case "execute" or "executeglobal" when args.Count > 0:
                if (Known(args[0]) && Str(args[0]) is { } code) return Peel(code, name.Equals("execute", StringComparison.OrdinalIgnoreCase) ? "Execute" : "ExecuteGlobal", siteStart, siteEnd, expression: false);
                Record(name);
                return PsUnknown.Value;
            case "eval" when args.Count > 0:
                if (Known(args[0]) && Str(args[0]) is { } expr) return Peel(expr, "Eval", siteStart, siteEnd, expression: true);
                Record(name);
                return PsUnknown.Value;
            case "createobject" or "getobject" when args.Count > 0:
            {
                var prog = Known(args[0]) ? Str(args[0]) : null;
                if (prog == null) return PsUnknown.Value;
                Record($"{(name.Equals("getobject", StringComparison.OrdinalIgnoreCase) ? "GetObject" : "CreateObject")}(\"{prog}\")");
                return new VbObject(prog);
            }
            case "shell" when args.Count > 0:
                if (Known(args[0]) && Str(args[0]) is { } command) RunCommand(command, "Shell", siteStart, siteEnd);
                else Record("Shell");
                return PsUnknown.Value;
            case "msgbox" or "inputbox":
                return PsUnknown.Value;
        }
        var r = Builtin(name, args);
        if (!Known(r) && !_fold && args.All(Known) && !IsBuiltinName(name)) Record(name);
        return r;
    }

    private object? CallProc(VbProcedure proc, TextEdits layer, List<object?> args)
    {
        if (_fold) return PsUnknown.Value;
        if (++_callDepth > MaxCallDepth) { _callDepth--; return PsUnknown.Value; }
        var frame = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase);
        for (int i = 0; i < proc.Parameters.Count; i++) frame[proc.Parameters[i]] = i < args.Count ? args[i] : null;
        if (proc.Function) frame[proc.Name] = null;
        _frames.Add(frame);
        var saved = _layer;
        _layer = layer;
        try
        {
            try { Exec(proc.Body); }
            catch (ExitSignal e) when (e.What is "function" or "sub" or "property") { }
            return proc.Function ? frame[proc.Name] : null;
        }
        finally
        {
            _layer = saved;
            _frames.RemoveAt(_frames.Count - 1);
            _callDepth--;
        }
    }

    /// <summary>Execute / ExecuteGlobal / Eval of constant text: a nested layer in this session.</summary>
    private object? Peel(string code, string via, int siteStart, int siteEnd, bool expression)
    {
        if (!_peeled.Add((_layer, siteStart)) && _fold) return PsUnknown.Value;
        if (_ctx.Layers.Count >= ScriptContext.MaxLayers) { _ctx.Incomplete = true; return PsUnknown.Value; }
        if (++_callDepth > MaxCallDepth) { _callDepth--; return PsUnknown.Value; }
        try
        {
            _ctx.Layers.Add(new ScriptLayer(_depth + 1, "vbscript", via, code));
            var outer = _layer;
            if (expression)
            {
                var layer = new TextEdits(code);
                var saved = (_layer, _depth);
                (_layer, _depth) = (layer, _depth + 1);
                object? v;
                try
                {
                    var tokens = VbParser.Parse("__eval = " + code, _budget);
                    v = tokens is [VbAssign a] ? Eval(a.Value) : PsUnknown.Value;
                }
                finally { (_layer, _depth) = saved; }
                outer.Set(siteStart, siteEnd, code.Trim());
                return v;
            }
            var plain = RunLayer(code, _depth + 1, global: true);
            outer.Set(siteStart, siteEnd, plain.TrimEnd('\r', '\n'));
            return null;
        }
        finally { _callDepth--; }
    }

    /// <summary>A command line a script runs (WScript.Shell Run / Exec, Shell, ShellExecute), read as a batch layer.</summary>
    private void RunCommand(string command, string via, int siteStart, int siteEnd)
    {
        Record($"{via} \"{(command.Length > 160 ? command[..160] + "…" : command)}\"");
        if (_fold || !_peeled.Add((_layer, siteStart))) return;
        if (_ctx.Peel("batch", command, via, _depth + 1) is { } plain && plain.Trim() != command.Trim())
            _layer.Set(siteStart, siteEnd, plain.TrimEnd('\r', '\n'));
    }

    private object? WScript(string name, List<object?> args)
    {
        if (name.Equals("CreateObject", StringComparison.OrdinalIgnoreCase) && args.Count > 0 && Str(args[0]) is { } prog && Known(args[0]))
        {
            Record($"CreateObject(\"{prog}\")");
            return new VbObject(prog);
        }
        return PsUnknown.Value;
    }

    private void Record(string call)
    {
        if (!_fold && _ctx.Calls.Count < 200 && call.Length <= 220) _ctx.Calls.Add(call);
    }

    /// <summary>A property read, or a method called without arguments.</summary>
    private object? Property(VbObject o, string name, int start, int end)
    {
        if (o.Properties.TryGetValue(name, out var v)) return v;
        var prog = o.ProgId.ToLowerInvariant();
        var n = name.ToLowerInvariant();
        if (prog.StartsWith("msxml", StringComparison.Ordinal) || prog.StartsWith("microsoft.xmldom", StringComparison.Ordinal) || prog == "element")
        {
            if (n is "nodetypedvalue")
            {
                var type = Str(o.Properties.GetValueOrDefault("datatype"))?.ToLowerInvariant();
                var text = Str(o.Properties.GetValueOrDefault("text"));
                if (text == null) return PsUnknown.Value;
                if (type == "bin.base64" && ScriptText.FromBase64(text) is { } bytes) return bytes;
                if (type == "bin.hex")
                {
                    try { return Convert.FromHexString(text.Trim()); } catch (FormatException) { return PsUnknown.Value; }
                }
                return text;
            }
        }
        if (prog.StartsWith("adodb.stream", StringComparison.Ordinal) && n == "size") return (long)o.Buffer.Count;
        return _fold ? PsUnknown.Value : Method(o, name, [], start, end);
    }

    private void SetProperty(VbObject o, string name, object? v)
    {
        o.Properties[name] = v;
        if (o.ProgId.StartsWith("adodb.stream", StringComparison.OrdinalIgnoreCase) && name.Equals("position", StringComparison.OrdinalIgnoreCase)) { }
    }

    private object? Method(VbObject o, string name, List<object?> args, int siteStart, int siteEnd)
    {
        var prog = o.ProgId.ToLowerInvariant();
        var n = name.ToLowerInvariant();
        string? A(int i) => i < args.Count && Known(args[i]) ? Str(args[i]) : null;
        if (prog.StartsWith("msxml", StringComparison.Ordinal) || prog.StartsWith("microsoft.xmldom", StringComparison.Ordinal))
        {
            if (n is "createelement") return new VbObject("element");
        }
        if (prog.StartsWith("adodb.stream", StringComparison.Ordinal))
        {
            switch (n)
            {
                case "open" or "close" or "settoeos" or "flush": return null;
                case "write" when args.Count > 0:
                    if (args[0] is byte[] b) o.Buffer.AddRange(b);
                    else o.Properties["unknown"] = true;
                    return null;
                case "writetext" when args.Count > 0:
                    if (A(0) is { } wt) o.Buffer.AddRange(StreamEncoding(o).GetBytes(wt));
                    return null;
                case "readtext":
                    if (o.Properties.ContainsKey("unknown")) return PsUnknown.Value;
                    return StreamEncoding(o).GetString(o.Buffer.ToArray());
                case "read":
                    return o.Properties.ContainsKey("unknown") ? PsUnknown.Value : o.Buffer.ToArray();
                case "savetofile":
                    Record($"ADODB.Stream.SaveToFile(\"{A(0)}\")");
                    return null;
            }
        }
        if (prog is "wscript.shell" && n is "run" or "exec" && A(0) is { } command)
        {
            RunCommand(command, "WScript.Shell." + (n == "run" ? "Run" : "Exec"), siteStart, siteEnd);
            return PsUnknown.Value;
        }
        if (prog is "shell.application" && n == "shellexecute" && A(0) is { } file)
        {
            RunCommand((file + " " + (A(1) ?? "")).Trim(), "Shell.Application.ShellExecute", siteStart, siteEnd);
            return PsUnknown.Value;
        }
        if (prog.StartsWith("wscript.shell", StringComparison.Ordinal) && n == "expandenvironmentstrings" && A(0) is { } env)
            return System.Text.RegularExpressions.Regex.Replace(env, "%([^%]+)%", m => _ctx.Environment.GetValueOrDefault(m.Groups[1].Value) ?? ScriptEnvironment.Defaults.GetValueOrDefault(m.Groups[1].Value) ?? m.Value);
        var shown = args.Select(a => a is string s ? "\"" + (s.Length > 120 ? s[..120] + "…" : s) + "\"" : a is long or double or bool ? Text(a) : "…");
        Record($"{o.ProgId}.{name}({string.Join(", ", shown)})");
        return PsUnknown.Value;
    }

    private static Encoding StreamEncoding(VbObject o) => Str(o.Properties.GetValueOrDefault("charset"))?.ToLowerInvariant() switch
    {
        "utf-8" => new UTF8Encoding(false),
        "unicode" or "utf-16" => Encoding.Unicode,
        "us-ascii" or "ascii" => Encoding.ASCII,
        _ => Encoding.Latin1,
    };

    private static readonly HashSet<string> BuiltinNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "chr", "chrw", "chrb", "asc", "ascw", "ascb", "len", "mid", "left", "right", "strreverse", "replace", "lcase", "ucase", "trim", "ltrim",
        "rtrim", "split", "join", "array", "ubound", "lbound", "instr", "instrrev", "cstr", "cint", "clng", "cbyte", "cdbl", "csng", "int", "fix",
        "abs", "hex", "oct", "space", "string", "escape", "unescape", "isnumeric", "isarray", "cbool", "sgn", "strcomp", "isempty", "isnull",
        "isobject", "typename", "vartype", "rnd", "now", "date", "time", "timer", "val", "mid$", "chr$", "strconv", "filter", "close",
    };

    private static bool IsBuiltinName(string name) => BuiltinNames.Contains(name);

    private object? Builtin(string name, List<object?> a)
    {
        if (a.Any(x => !Known(x))) return PsUnknown.Value;
        string S(int i) => i < a.Count ? Text(a[i]) : "";
        long? L(int i) => i < a.Count ? Long(a[i] is double d ? Math.Round(d, MidpointRounding.ToEven) : a[i]) : null;
        try
        {
            switch (name.ToLowerInvariant())
            {
                case "chr" or "chrw" or "chrb" or "chr$" when L(0) is { } code && code is >= 0 and <= 0xFFFF: return ((char)code).ToString();
                case "asc" or "ascw" or "ascb" when S(0).Length > 0: return (long)S(0)[0];
                case "len": return a.Count > 0 && a[0] is object[] arr ? PsUnknown.Value : (long)S(0).Length;
                case "mid" or "mid$" when L(1) is { } start && start >= 1:
                {
                    var s = S(0);
                    if (start > s.Length) return "";
                    int len = a.Count > 2 && L(2) is { } n ? (int)Math.Min(n, s.Length - start + 1) : s.Length - (int)start + 1;
                    return len <= 0 ? "" : s.Substring((int)start - 1, len);
                }
                case "left" when L(1) is { } ln: return S(0)[..(int)Math.Clamp(ln, 0, S(0).Length)];
                case "right" when L(1) is { } rn: return S(0)[^(int)Math.Clamp(rn, 0, S(0).Length)..];
                case "strreverse":
                {
                    var c = S(0).ToCharArray();
                    System.Array.Reverse(c);
                    return new string(c);
                }
                case "replace" when a.Count >= 3:
                {
                    var find = S(1);
                    if (find.Length == 0) return S(0);
                    var cmp = a.Count > 5 && L(5) == 1 ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal;
                    var s = S(0);
                    if (a.Count > 3 && L(3) is { } from && from > 1) s = s[(int)Math.Min(from - 1, s.Length)..];
                    var r = s.Replace(find, S(2), cmp);
                    return r.Length > _budget.MaxChars ? PsUnknown.Value : r;
                }
                case "lcase": return S(0).ToLowerInvariant();
                case "ucase": return S(0).ToUpperInvariant();
                case "trim": return S(0).Trim(' ');
                case "ltrim": return S(0).TrimStart(' ');
                case "rtrim": return S(0).TrimEnd(' ');
                case "split":
                {
                    var sep = a.Count > 1 ? S(1) : " ";
                    var parts = sep.Length == 0 ? [S(0)] : S(0).Split(sep);
                    return parts.Cast<object?>().ToArray();
                }
                case "join" when a.Count > 0 && a[0] is object[] items: return Join(items.Select(x => (object?)Text(x)).ToArray(), a.Count > 1 ? S(1) : " ") ?? (object)PsUnknown.Value;
                case "array": return a.ToArray();
                case "ubound" when a.Count > 0 && a[0] is object[] ub: return (long)ub.Length - 1;
                case "lbound": return 0L;
                case "instr":
                {
                    int start = 1;
                    string hay, needle;
                    if (a.Count >= 3 && a[0] is long or double) { start = (int)(L(0) ?? 1); hay = S(1); needle = S(2); }
                    else { hay = S(0); needle = S(1); }
                    if (start < 1 || start > hay.Length + 1) return 0L;
                    return (long)(hay.IndexOf(needle, start - 1, StringComparison.Ordinal) + 1);
                }
                case "instrrev": return (long)(S(0).LastIndexOf(S(1), StringComparison.Ordinal) + 1);
                case "cstr": return S(0);
                case "cint" or "clng" or "cbyte":
                    if (a.ElementAtOrDefault(0) is string hs && hs.Trim() is var ht && ht.Length > 2 && ht[0] == '&' && ht[1] is 'h' or 'H' or 'o' or 'O')
                    {
                        try { return Convert.ToInt64(ht[2..], ht[1] is 'h' or 'H' ? 16 : 8); }
                        catch (Exception ex) when (ex is FormatException or OverflowException) { return PsUnknown.Value; }
                    }
                    return L(0) ?? (object)PsUnknown.Value;
                case "cdbl" or "csng" or "val": return Double(a.ElementAtOrDefault(0)) ?? (object)PsUnknown.Value;
                case "int": return Double(a.ElementAtOrDefault(0)) is { } d1 ? (long)Math.Floor(d1) : PsUnknown.Value;
                case "fix": return Double(a.ElementAtOrDefault(0)) is { } d2 ? (long)Math.Truncate(d2) : PsUnknown.Value;
                case "abs": return Double(a.ElementAtOrDefault(0)) is { } d3 ? Arith("+", Math.Abs(d3), 0L) : PsUnknown.Value;
                case "sgn": return Double(a.ElementAtOrDefault(0)) is { } d4 ? (long)Math.Sign(d4) : PsUnknown.Value;
                case "hex": return L(0) is { } h ? h.ToString(h < 0 ? "X8" : "X", CultureInfo.InvariantCulture) : PsUnknown.Value;
                case "oct": return L(0) is { } o ? Convert.ToString(o, 8) : PsUnknown.Value;
                case "space": return L(0) is { } sp && sp is >= 0 and <= 1 << 20 ? new string(' ', (int)sp) : PsUnknown.Value;
                case "string" when L(0) is { } count && count is >= 0 and <= 1 << 20:
                {
                    char ch = a.ElementAtOrDefault(1) is string cs && cs.Length > 0 ? cs[0] : L(1) is { } cc ? (char)cc : ' ';
                    return new string(ch, (int)count);
                }
                case "escape": return Uri.EscapeDataString(S(0));
                case "unescape": return UnescapeJs(S(0));
                case "isnumeric": return Double(a.ElementAtOrDefault(0)) != null;
                case "isarray": return a.ElementAtOrDefault(0) is object[];
                case "isempty" or "isnull": return a.ElementAtOrDefault(0) == null;
                case "cbool": return Truth(a.ElementAtOrDefault(0)) ?? (object)PsUnknown.Value;
                case "strcomp": return (long)Math.Sign(string.CompareOrdinal(S(0), S(1)));
                case "filter" when a.Count > 1 && a[0] is object[] fs: return fs.Where(x => Text(x).Contains(S(1), StringComparison.Ordinal)).ToArray();
            }
        }
        catch (ArgumentException) { }
        return PsUnknown.Value;
    }

    /// <summary>%XX and %uXXXX escapes, as JavaScript's unescape reads them.</summary>
    internal static string UnescapeJs(string s)
    {
        var sb = new StringBuilder(s.Length);
        for (int i = 0; i < s.Length; i++)
        {
            if (s[i] == '%' && i + 5 < s.Length && s[i + 1] is 'u' or 'U' && int.TryParse(s.AsSpan(i + 2, 4), NumberStyles.HexNumber, null, out var u)) { sb.Append((char)u); i += 5; }
            else if (s[i] == '%' && i + 2 < s.Length && int.TryParse(s.AsSpan(i + 1, 2), NumberStyles.HexNumber, null, out var b)) { sb.Append((char)b); i += 2; }
            else sb.Append(s[i]);
        }
        return sb.ToString();
    }
}
