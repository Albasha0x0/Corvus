using System.Globalization;
using System.Runtime.CompilerServices;
using System.Text;
using System.Text.RegularExpressions;
using Corvus.Core;
using static Corvus.Services.Web.Scripts.PsConvert;

namespace Corvus.Services.Web.Scripts;

/// <summary>
/// A bounded PowerShell evaluator: straight-line code, loops and functions over constants, with the decoders layered
/// scripts carry
/// (base64, char codes, XOR, format, replace, reverse, deflate / gzip, SecureString). Commands are never run: the
/// invocations of code (Invoke-Expression and its spellings, script blocks, encoded commands) are peeled as layers, and
/// constant expressions are folded to literals in place. Anything not modelled is unknown.
/// </summary>
internal sealed partial class PsInterpreter
{
    private const int MaxCallDepth = 64, MaxEvalDepth = 300, MaxFold = 32_768;

    private readonly ScriptContext _ctx;
    private readonly ScriptBudget _budget;
    private readonly List<Dictionary<string, object?>> _scopes = [new(StringComparer.OrdinalIgnoreCase)];
    private readonly Dictionary<string, (PsFunction Function, PsLayerText Layer)> _functions = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, string> _aliases = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<(PsLayerText, int, int)> _peeled = [];
    private readonly ConditionalWeakTable<object, string[]> _chains = new();
    private readonly List<string> _numericSteps = [];
    private PsLayerText _layer = null!;
    private bool _fold;
    private int _evalDepth, _callDepth;

    private PsInterpreter(ScriptContext ctx)
    {
        _ctx = ctx;
        _budget = ctx.Budget;
    }

    private sealed class BudgetSignal : Exception;
    private sealed class BreakSignal : Exception;
    private sealed class ContinueSignal : Exception;
    private sealed class ExitSignal : Exception;
    private sealed class ReturnSignal(object? value) : Exception
    {
        public object? Value { get; } = value;
    }

    /// <summary>The plain text of a PowerShell layer: its peeled layers in place and its constants folded.</summary>
    public static string Read(string text, ScriptContext ctx, int depth) => new PsInterpreter(ctx).RunLayer(text, depth, out _);

    private string RunLayer(string text, int depth, out List<object?> outputs)
    {
        var layer = new PsLayerText(text, depth);
        var statements = PsParser.Parse(text, _budget);
        var saved = _layer;
        _layer = layer;
        outputs = [];
        try
        {
            try { ExecBody(statements, outputs); }
            catch (ExitSignal) { }
            catch (ReturnSignal) { }
            catch (BreakSignal) { }
            catch (ContinueSignal) { }
            bool fold = _fold;
            _fold = true;
            try { ExecBody(statements, []); }
            catch (Exception ex) when (ex is ExitSignal or ReturnSignal or BreakSignal or ContinueSignal) { }
            finally { _fold = fold; }
        }
        catch (BudgetSignal)
        {
            if (!_ctx.Incomplete) _ctx.Note("The evaluation budget ran out: later layers and folds are not shown.");
            _ctx.Incomplete = true;
            if (depth > 0 || saved != null) { _layer = saved!; throw; }
        }
        finally { _layer = saved!; }
        _ctx.Folded += layer.Count;
        return layer.Render();
    }

    private void Step(int n = 1)
    {
        if (!_budget.Step(n)) throw new BudgetSignal();
    }

    // --- statements ---

    private void ExecBody(List<PsStatement> body, List<object?> outputs)
    {
        foreach (var st in body) Exec(st, outputs);
    }

    private static void Output(List<object?> outputs, object? v)
    {
        if (v is PsVoid) return;
        if (v is object[] a) outputs.AddRange(a);
        else outputs.Add(v);
    }

    private void Exec(PsStatement st, List<object?> outputs)
    {
        Step();
        switch (st)
        {
            case PsPipeline p:
                Output(outputs, Pipeline(p));
                break;
            case PsAssignment a:
                Assign(a);
                break;
            case PsIf i:
                if (_fold)
                {
                    foreach (var (cond, body) in i.Clauses) { Value(cond); ExecBody(body, []); }
                    if (i.Else != null) ExecBody(i.Else, []);
                    break;
                }
                foreach (var (cond, body) in i.Clauses)
                {
                    var c = Bool(Value(cond));
                    if (c == null) return; // undecided: the fold pass reads the branches
                    if (c == true) { ExecBody(body, outputs); return; }
                }
                if (i.Else != null) ExecBody(i.Else, outputs);
                break;
            case PsLoop l:
                Loop(l, outputs);
                break;
            case PsFunction f:
                if (_fold) ExecBody(f.Body, []);
                else _functions[f.Name] = (f, _layer);
                break;
            case PsFlow f:
            {
                var v = f.Value != null ? Value(f.Value) : null;
                if (_fold) break;
                switch (f.Keyword)
                {
                    case "return":
                        if (v is not PsVoid) Output(outputs, v);
                        throw new ReturnSignal(null);
                    case "break": throw new BreakSignal();
                    case "continue": throw new ContinueSignal();
                    default: throw new ExitSignal();
                }
            }
            case PsBlock b:
                ExecBody(b.Body, outputs);
                break;
        }
    }

    private object? Value(PsStatement st)
    {
        switch (st)
        {
            case PsPipeline p: return Pipeline(p);
            case PsAssignment a: return Assign(a);
            default:
                var outputs = new List<object?>();
                Exec(st, outputs);
                return outputs.Count switch { 0 => null, 1 => outputs[0], _ => outputs.ToArray() };
        }
    }

    private void Loop(PsLoop l, List<object?> outputs)
    {
        if (_fold)
        {
            if (l.Init != null) Value(l.Init);
            if (l.Condition != null) Value(l.Condition);
            if (l.Iterator != null) Value(l.Iterator);
            ExecBody(l.Body, []);
            return;
        }
        bool Body()
        {
            try { ExecBody(l.Body, outputs); }
            catch (BreakSignal) { return false; }
            catch (ContinueSignal) { }
            return true;
        }
        switch (l.Kind)
        {
            case "foreach":
            {
                var coll = Value(l.Condition!);
                if (!Known(coll)) { SetVar(l.Variable!, PsUnknown.Value); return; }
                foreach (var item in Items(coll).ToList())
                {
                    Step();
                    SetVar(l.Variable!, item);
                    if (!Body()) break;
                }
                break;
            }
            case "for":
                if (l.Init != null) Value(l.Init);
                while (true)
                {
                    Step();
                    if (l.Condition != null && Bool(Value(l.Condition)) is not true) break;
                    if (!Body()) break;
                    if (l.Iterator != null) Value(l.Iterator);
                }
                break;
            case "while":
                while (Bool(Value(l.Condition!)) is true)
                {
                    Step();
                    if (!Body()) break;
                }
                break;
            default: // do-while, do-until
                while (true)
                {
                    Step();
                    if (!Body()) break;
                    var c = Bool(Value(l.Condition!));
                    if (c == null || (l.Kind == "do-while" ? c == false : c == true)) break;
                }
                break;
        }
    }

    private object? Assign(PsAssignment a)
    {
        var v = Value(a.Value);
        if (v is PsVoid) v = null;
        if (a.Target is PsCast cast && cast.Operand is PsVariable cv)
        {
            v = Cast(cast.Type, v, cast);
            if (!_fold) SetVar(cv.Name, v);
            return PsVoid.Value;
        }
        if (a.Op != "=")
        {
            var old = Eval(a.Target);
            v = Binary(a.Op[..1], old, v);
        }
        if (_fold)
        {
            if (a.Target is PsVariable fv) Unbrace(fv);
            return PsVoid.Value;
        }
        switch (a.Target)
        {
            case PsVariable variable:
                Unbrace(variable);
                SetVar(variable.Name, v);
                break;
            case PsIndex ix:
            {
                var target = Eval(ix.Target);
                var index = Eval(ix.Index);
                if (target is object[] arr && Long(index) is { } i && index is not string)
                {
                    if (i < 0) i += arr.Length;
                    if (i >= 0 && i < arr.Length) arr[i] = v!;
                }
                else if (target is PsHashValue h && Str(index) is { } key) h.Items[key] = v;
                else if (ix.Target is PsVariable tv) SetVar(tv.Name, PsUnknown.Value);
                break;
            }
            case PsMember m when Eval(m.Target) is PsHashValue h && MemberName(m) is { } key:
                h.Items[key] = v;
                break;
        }
        return PsVoid.Value;
    }

    /// <summary>${name} written as $name when the name needs no braces.</summary>
    private void Unbrace(PsVariable v)
    {
        if (v.Braced && Regex.IsMatch(v.Name, @"^(?:[A-Za-z]+:)?[A-Za-z_]\w*$")) _layer.Set(v.Start, v.End, "$" + v.Name, weak: _fold);
    }

    // --- variables ---

    private static string Unscoped(string name)
    {
        int colon = name.IndexOf(':');
        if (colon > 0 && name[..colon].ToLowerInvariant() is "global" or "script" or "local" or "private" or "using" or "variable")
            return name[(colon + 1)..];
        return name;
    }

    private void SetVar(string name, object? value)
    {
        if (name.StartsWith("env:", StringComparison.OrdinalIgnoreCase))
        {
            if (Known(value) && Str(value) is { } s) _ctx.Environment[name[4..]] = s;
            else _ctx.Environment.Remove(name[4..]);
            return;
        }
        bool global = name.StartsWith("global:", StringComparison.OrdinalIgnoreCase) || name.StartsWith("script:", StringComparison.OrdinalIgnoreCase);
        name = Unscoped(name);
        (global ? _scopes[0] : _scopes[^1])[name] = value;
    }

    private object? GetVar(string name)
    {
        if (name.StartsWith("env:", StringComparison.OrdinalIgnoreCase))
            return Env(name[4..]) is { } e ? e : _fold ? PsUnknown.Value : null;
        name = Unscoped(name);
        if (!_fold)
            for (int i = _scopes.Count - 1; i >= 0; i--)
                if (_scopes[i].TryGetValue(name, out var v)) return v;
        if (!_fold && name.Equals("input", StringComparison.OrdinalIgnoreCase) && _ctx.Stdin is { } stdin) return stdin;
        return Automatic(name);
    }

    /// <summary>$OFS, the separator of arrays converted to text.</summary>
    private string Ofs => _fold ? " " : GetVar("OFS") is string ofs ? ofs : " ";

    private string? Env(string name) =>
        _ctx.Environment.TryGetValue(name, out var v) ? v : ScriptEnvironment.Defaults.TryGetValue(name, out var d) ? d : null;

    /// <summary>Automatic variables at their defaults on Windows PowerShell 5.1.</summary>
    private static object? Automatic(string name) => name.ToLowerInvariant() switch
    {
        "true" => true,
        "false" => false,
        "null" => null,
        "?" => true,
        "shellid" => "Microsoft.PowerShell",
        "pshome" => @"C:\Windows\System32\WindowsPowerShell\v1.0",
        "verbosepreference" or "debugpreference" => "SilentlyContinue",
        "erroractionpreference" or "warningpreference" or "progresspreference" or "informationpreference" => name.Equals("informationpreference", StringComparison.OrdinalIgnoreCase) ? "SilentlyContinue" : "Continue",
        "confirmpreference" => "High",
        "whatifpreference" => false,
        "maximumdrivecount" or "maximumfunctioncount" or "maximumaliascount" or "maximumvariablecount" or "maximumhistorycount" => 4096L,
        "maximumerrorcount" => 256L,
        "nestedpromptlevel" => 0L,
        "ofs" => " ",
        "executioncontext" => new PsOpaque("ExecutionContext"),
        "host" => new PsOpaque("Host"),
        _ => PsUnknown.Value,
    };

    /// <summary>The automatic variables a Get-Variable wildcard can name.</summary>
    private static readonly string[] AutomaticNames =
    [
        "$", "?", "^", "args", "ConfirmPreference", "ConsoleFileName", "DebugPreference", "Error", "ErrorActionPreference", "ErrorView",
        "ExecutionContext", "false", "FormatEnumerationLimit", "HOME", "Host", "InformationPreference", "input", "MaximumAliasCount",
        "MaximumDriveCount", "MaximumErrorCount", "MaximumFunctionCount", "MaximumHistoryCount", "MaximumVariableCount", "MyInvocation",
        "NestedPromptLevel", "null", "OutputEncoding", "PID", "PROFILE", "ProgressPreference", "PSBoundParameters", "PSCommandPath",
        "PSCulture", "PSDefaultParameterValues", "PSEmailServer", "PSHOME", "PSScriptRoot", "PSSessionApplicationName",
        "PSSessionConfigurationName", "PSSessionOption", "PSUICulture", "PSVersionTable", "PWD", "ShellId", "StackTrace", "true",
        "VerbosePreference", "WarningPreference", "WhatIfPreference",
    ];

    // --- expressions ---

    private object? Eval(PsExpr e)
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

    private void Fold(PsExpr e, object? v)
    {
        if (v is not (string or char)) return;
        var s = Str(v)!;
        if (s.Length > MaxFold || s.Contains('\0') || !ScriptText.Printable(s) && s.Length > 0) return;
        bool candidate = e switch
        {
            PsBinary or PsCast or PsInvoke or PsIndex or PsExpandable => true,
            PsUnary u => u.Op is "join" or "split" or "+" ,
            PsGroup g => g.Kind is '(' or '$' && g.Body is [PsPipeline { Elements: [PsExpr] }],
            PsMember m => m.Static,
            PsLiteral { Raw: false } l => l.Value is string && _layer.Text.AsSpan(l.Start, l.End - l.Start).IndexOfAny('`', '\u2018', '\u201C') >= 0,
            _ => false,
        };
        if (candidate) _layer.Set(e.Start, e.End, ScriptText.SingleQuoted(s), weak: _fold);
    }

    private object? EvalCore(PsExpr e)
    {
        switch (e)
        {
            case PsLiteral l: return l.Value;
            case PsExpandable x:
            {
                var sb = new StringBuilder();
                foreach (var part in x.Parts)
                {
                    if (part is string s) { sb.Append(s); continue; }
                    var v = Eval((PsExpr)part);
                    if (!Known(v) || Str(v, Ofs) is not { } t) return PsUnknown.Value;
                    sb.Append(t);
                    if (sb.Length > _budget.MaxChars) return PsUnknown.Value;
                }
                return sb.ToString();
            }
            case PsVariable v:
                Unbrace(v);
                return GetVar(v.Name);
            case PsTypeLiteral t: return new PsTypeValue(t.Name);
            case PsCast c: return Cast(c.Type, Eval(c.Operand), c);
            case PsBinary b: return BinaryNode(b);
            case PsUnary u: return Unary(u);
            case PsArrayList a:
            {
                var items = new object?[a.Items.Count];
                bool known = true;
                for (int i = 0; i < items.Length; i++)
                {
                    items[i] = Eval(a.Items[i]);
                    known &= Known(items[i]);
                }
                return known ? Tag(items, items) : PsUnknown.Value;
            }
            case PsGroup g: return Group(g);
            case PsHash h:
            {
                var hash = new PsHashValue();
                foreach (var (k, val) in h.Entries)
                {
                    var key = Eval(k);
                    var value = Value(val);
                    if (Known(key) && Str(key) is { } ks) hash.Items[ks] = value;
                }
                return hash;
            }
            case PsScriptBlockExpr sb:
                if (_fold) ExecBody(sb.Body, []);
                return new PsBlockValue(sb.Body, sb.Parameters, _layer, _layer.Text[(sb.Start + 1)..Math.Max(sb.Start + 1, sb.End - 1)]);
            case PsIndex ix: return Index(Eval(ix.Target), Eval(ix.Index));
            case PsMember m:
            {
                var target = Eval(m.Target);
                var name = MemberName(m);
                if (name == null || !Known(target)) return PsUnknown.Value;
                return GetMember(target, name, m.Static);
            }
            case PsInvoke inv:
            {
                var target = Eval(inv.Member.Target);
                var name = MemberName(inv.Member);
                var args = inv.Args.Select(Eval).ToList();
                if (name == null || !Known(target)) return PsUnknown.Value;
                return Invoke(target, name, args, inv);
            }
        }
        return PsUnknown.Value;
    }

    /// <summary>A member's name, folding a computed one (.('Down'+'loadString')) to a plain member name in the text.</summary>
    private string? MemberName(PsMember m)
    {
        if (m.Name is PsLiteral { Raw: true, Value: string plain })
        {
            if (_layer.Text.AsSpan(m.NameStart, m.Name.End - m.NameStart).Contains('`')) _layer.Set(m.NameStart, m.Name.End, plain, weak: _fold);
            return plain;
        }
        var v = Eval(m.Name);
        if (!Known(v) || Str(v) is not { } name) return null;
        if (Regex.IsMatch(name, @"^[A-Za-z_]\w*$")) _layer.Set(m.NameStart, m.Name.End, name, weak: _fold);
        return name;
    }

    private object? Group(PsGroup g)
    {
        if (g.Kind == '(' && g.Body.Count == 1)
        {
            var v = g.Body[0] is PsAssignment a ? AssignValue(a) : Value(g.Body[0]);
            return v is PsVoid ? null : v;
        }
        var outputs = new List<object?>();
        ExecBody(g.Body, outputs);
        if (outputs.Any(o => !Known(o))) return PsUnknown.Value;
        if (g.Kind == '@') return outputs.ToArray();
        return outputs.Count switch { 0 => null, 1 => outputs[0], _ => outputs.ToArray() };
    }

    private object? AssignValue(PsAssignment a)
    {
        Assign(a);
        return a.Target is PsVariable v && !_fold ? GetVar(v.Name) : PsUnknown.Value;
    }

    private object? BinaryNode(PsBinary b)
    {
        if (b.Op is "and" or "or")
        {
            var l = Bool(Eval(b.Left));
            if (l == null) { Eval(b.Right); return PsUnknown.Value; }
            if (b.Op == "and" && l == false || b.Op == "or" && l == true) { if (_fold) Eval(b.Right); return l; }
            return Bool(Eval(b.Right)) is { } r ? r : PsUnknown.Value;
        }
        return Binary(b.Op, Eval(b.Left), Eval(b.Right));
    }

    private object? Unary(PsUnary u)
    {
        if (u.Op is "++" or "--")
        {
            var old = Eval(u.Operand);
            var updated = Binary(u.Op[..1], old, 1L);
            if (!_fold && u.Operand is PsVariable v) SetVar(v.Name, updated);
            return u.Postfix ? PsVoid.Value : updated;
        }
        var x = Eval(u.Operand);
        if (!Known(x)) return PsUnknown.Value;
        switch (u.Op)
        {
            case "-": return x is double d ? -d : Long(x) is { } n ? -n : Double(x) is { } f ? -f : PsUnknown.Value;
            case "+": return x is double ? x : Long(x) is { } pn && x is not char ? pn : PsUnknown.Value;
            case "not": return Bool(x) is { } bv ? !bv : PsUnknown.Value;
            case "bnot": return Long(x) is { } bn ? ~bn : PsUnknown.Value;
            case "join": return JoinItems(x, "");
            case "split": return Array(x) is { } items ? Tag(items.SelectMany(i => (Str(i) ?? "").Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries)).Cast<object?>().ToArray(), x) : PsUnknown.Value;
        }
        return PsUnknown.Value;
    }

    // --- provenance of decoded values ---

    private T Tag<T>(T result, params object?[] sources) where T : class => TagStep(result, null, sources);

    /// <summary>Records how a value was made: the steps of its sources and <paramref name="step"/>.</summary>
    private T TagStep<T>(T result, string? step, params object?[] sources) where T : class
    {
        var steps = new List<string>();
        foreach (var s in sources)
            if (s != null && s is not (string { Length: 0 }) && !s.GetType().IsValueType && _chains.TryGetValue(s, out var c))
                foreach (var x in c) if (!steps.Contains(x)) steps.Add(x);
        if (step != null && !steps.Contains(step)) steps.Add(step);
        if (steps.Count > 0 && result is not string { Length: 0 })
        {
            try { _chains.AddOrUpdate(result, steps.Take(10).ToArray()); }
            catch (ArgumentException) { }
        }
        return result;
    }

    private string Chain(object? v) => v != null && !v.GetType().IsValueType && _chains.TryGetValue(v, out var c) ? string.Join(" > ", c) : "";

    private object JoinItems(object? x, string sep)
    {
        if (Array(x) is not { } items || Join(items, sep) is not { } joined) return PsUnknown.Value;
        string? step = null;
        if (items.Length > 1 && items.All(i => i is char))
        {
            step = "char codes";
            if (_numericSteps.Count > 0) { step = string.Join(" > ", _numericSteps.Append("char codes")); _numericSteps.Clear(); }
        }
        return TagStep(joined, step, x);
    }

    // --- operators ---

    private static bool IsNumber(object? v) => v is long or int or double or byte or char or bool;

    private object? Binary(string op, object? l, object? r)
    {
        if (!Known(l) || !Known(r)) return PsUnknown.Value;
        bool ci = !op.StartsWith('c');
        var bare = op.Length > 2 && op[0] is 'c' or 'i' && op is not ("contains" or "in" or "is" or "isnot" or "as") ? op[1..] : op;
        switch (bare)
        {
            case "+":
                if (l is string ls)
                {
                    var rs = Str(r, Ofs);
                    if (rs == null || ls.Length + rs.Length > _budget.MaxChars) return PsUnknown.Value;
                    return TagStep(ls + rs, "concatenation", l, r);
                }
                if (l is object[] la) return Tag(la.Concat(Items(r)).ToArray(), l, r);
                if (l is byte[] lb) return Tag(Items(lb).Concat(Items(r)).ToArray(), l, r);
                if (l == null) return r;
                if (l is char lc) return Str(r, Ofs) is { } rc ? TagStep(lc + rc, "concatenation", r) : PsUnknown.Value; // a char adds as text
                return Arith(op, l, r);
            case "*":
            {
                if (l is string s && Long(r) is { } count)
                    return count >= 0 && s.Length * count <= _budget.MaxChars ? string.Concat(Enumerable.Repeat(s, (int)count)) : PsUnknown.Value;
                if (l is object[] a && Long(r) is { } times)
                    return times >= 0 && a.Length * times <= 1_000_000 ? Enumerable.Repeat(a, (int)times).SelectMany(x => x).ToArray() : PsUnknown.Value;
                return Arith(op, l, r);
            }
            case "-" or "/" or "%": return Arith(op, l, r);
            case "f": return Format(l, r);
            case "join": return Str(r) is { } sep ? JoinItems(l, sep) : PsUnknown.Value;
            case "split": return Split(l, r, ci);
            case "replace": return Replace(l, r, ci);
            case "eq" or "ne" or "gt" or "ge" or "lt" or "le": return Compare(bare, l, r, ci);
            case "like" or "notlike":
            {
                if (Str(l) is not { } a || Str(r) is not { } p) return PsUnknown.Value;
                bool m = WildcardMatch(a, p, ci);
                return bare == "like" ? m : !m;
            }
            case "match" or "notmatch":
            {
                if (Str(l) is not { } a || Str(r) is not { } p || SafeRegex(p, ci) is not { } rx) return PsUnknown.Value;
                try
                {
                    bool m = rx.IsMatch(a);
                    return bare == "match" ? m : !m;
                }
                catch (RegexMatchTimeoutException) { return PsUnknown.Value; }
            }
            case "contains" or "notcontains":
            {
                bool has = Items(l).Any(i => Compare("eq", i, r, ci) is true);
                return bare == "contains" ? has : !has;
            }
            case "in" or "notin":
            {
                bool has = Items(r).Any(i => Compare("eq", i, l, ci) is true);
                return bare == "in" ? has : !has;
            }
            case "band" or "bor" or "bxor" or "shl" or "shr":
            {
                if (Long(l) is not { } a || Long(r) is not { } b) return PsUnknown.Value;
                if (bare == "bxor" && !_numericSteps.Contains("xor")) _numericSteps.Add("xor");
                return bare switch
                {
                    "band" => a & b,
                    "bor" => a | b,
                    "bxor" => a ^ b,
                    "shl" => a << (int)(b & 63),
                    _ => a >> (int)(b & 63),
                };
            }
            case "xor": return Bool(l) is { } x && Bool(r) is { } y ? x ^ y : PsUnknown.Value;
            case "..":
            {
                if (l is string { Length: 1 } a && r is string { Length: 1 } b)
                {
                    int step = a[0] <= b[0] ? 1 : -1, n = Math.Abs(b[0] - a[0]) + 1;
                    return Enumerable.Range(0, n).Select(i => (object?)(char)(a[0] + i * step)).ToArray();
                }
                if (Long(l) is not { } from || Long(r) is not { } to || Math.Abs(to - from) > 1_000_000) return PsUnknown.Value;
                int dir = from <= to ? 1 : -1;
                var list = new object?[Math.Abs(to - from) + 1];
                for (long i = 0; i < list.Length; i++) list[i] = from + i * dir;
                return list;
            }
            case "as": return Str(r) is { } type ? Cast(type, l, null) : PsUnknown.Value;
            case "is" or "isnot": return PsUnknown.Value;
        }
        return PsUnknown.Value;
    }

    private static object Arith(string op, object? l, object? r)
    {
        if (l is double || r is double || l is string ls && ls.Contains('.') || r is string rs && rs.Contains('.'))
        {
            if (Double(l) is not { } a || Double(r) is not { } b) return PsUnknown.Value;
            return op switch { "+" => a + b, "-" => a - b, "*" => a * b, "/" => b == 0 ? PsUnknown.Value : a / b, _ => b == 0 ? PsUnknown.Value : a % b };
        }
        if (Long(l) is not { } x || Long(r) is not { } y) return PsUnknown.Value;
        try
        {
            return op switch
            {
                "+" => checked(x + y),
                "-" => checked(x - y),
                "*" => checked(x * y),
                "/" => y == 0 ? PsUnknown.Value : x % y == 0 ? x / y : (double)x / y,
                _ => y == 0 ? PsUnknown.Value : x % y,
            };
        }
        catch (OverflowException) { return PsUnknown.Value; }
    }

    private static object Compare(string op, object? l, object? r, bool ci)
    {
        if (l is object[] arr) return arr.Where(i => Compare(op, i, r, ci) is true).ToArray();
        int c;
        if (IsNumber(l) && l is not char || l is char && IsNumber(r) && r is not char)
        {
            if (Double(l) is not { } a || Double(r) is not { } b) return op == "ne";
            c = a.CompareTo(b);
        }
        else
        {
            if (Str(l) is not { } a || Str(r) is not { } b) return PsUnknown.Value;
            c = string.Compare(a, b, ci ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal);
        }
        return op switch { "eq" => c == 0, "ne" => c != 0, "gt" => c > 0, "ge" => c >= 0, "lt" => c < 0, _ => c <= 0 };
    }

    private static bool WildcardMatch(string text, string pattern, bool ci)
    {
        var rx = "^" + Regex.Escape(pattern).Replace(@"\*", ".*").Replace(@"\?", ".").Replace(@"\[", "[").Replace(@"\]", "]") + "$";
        try { return RegexTimeouts.Create(rx, (ci ? RegexOptions.IgnoreCase : 0) | RegexOptions.CultureInvariant | RegexOptions.Singleline, TimeSpan.FromMilliseconds(100)).IsMatch(text); }
        catch (ArgumentException) { return false; }
        catch (RegexMatchTimeoutException) { return false; }
    }

    private static Regex? SafeRegex(string pattern, bool ci, RegexOptions extra = 0)
    {
        try { return RegexTimeouts.Create(pattern, (ci ? RegexOptions.IgnoreCase : 0) | RegexOptions.CultureInvariant | extra, TimeSpan.FromMilliseconds(200)); }
        catch (ArgumentException) { return null; }
    }

    private object? Format(object? l, object? r)
    {
        if (Str(l) is not { } fmt || Array(r) is not { } items) return PsUnknown.Value;
        var args = new object?[items.Length];
        for (int i = 0; i < items.Length; i++)
        {
            args[i] = items[i] switch { null or string or long or double or char or bool => items[i], _ => Str(items[i]) };
            if (args[i] == null && items[i] != null) return PsUnknown.Value;
        }
        try
        {
            var s = string.Format(CultureInfo.InvariantCulture, fmt, args);
            return s.Length > _budget.MaxChars ? PsUnknown.Value : TagStep(s, "format", l, r);
        }
        catch (FormatException) { return PsUnknown.Value; }
    }

    private object? Split(object? l, object? r, bool ci)
    {
        var args = Array(r) ?? [];
        if (args.Length == 0 || Str(args[0]) is not { } pattern) return PsUnknown.Value;
        int max = args.Length > 1 && Long(args[1]) is { } m ? (int)Math.Clamp(m, 0, int.MaxValue) : 0;
        if (SafeRegex(pattern, ci) is not { } rx) return PsUnknown.Value;
        var parts = new List<object?>();
        foreach (var item in Items(l))
        {
            if (Str(item) is not { } s) return PsUnknown.Value;
            try { parts.AddRange(max > 0 ? rx.Split(s, max) : rx.Split(s)); }
            catch (RegexMatchTimeoutException) { return PsUnknown.Value; }
        }
        return TagStep(parts.ToArray(), null, l);
    }

    private object? Replace(object? l, object? r, bool ci)
    {
        var args = Array(r) ?? [];
        if (args.Length == 0 || Str(args[0]) is not { } pattern) return PsUnknown.Value;
        var replacement = args.Length > 1 ? Str(args[1]) : "";
        if (replacement == null || SafeRegex(pattern, ci) is not { } rx) return PsUnknown.Value;
        object? One(object? item)
        {
            if (Str(item) is not { } s) return PsUnknown.Value;
            try
            {
                var result = rx.Replace(s, replacement);
                return result.Length > _budget.MaxChars ? PsUnknown.Value : TagStep(result, "replace", item);
            }
            catch (RegexMatchTimeoutException) { return PsUnknown.Value; }
        }
        if (l is object[] arr)
        {
            var mapped = arr.Select(One).ToArray();
            return mapped.All(Known) ? mapped : PsUnknown.Value;
        }
        return One(l);
    }

    private object? Index(object? target, object? index)
    {
        if (!Known(target) || !Known(index)) return PsUnknown.Value;
        if (index is object[] many)
        {
            var list = new object?[many.Length];
            for (int i = 0; i < many.Length; i++)
            {
                list[i] = Index(target, many[i]);
                if (!Known(list[i])) return PsUnknown.Value;
            }
            bool reversed = many.Length > 1 && many.Zip(many.Skip(1)).All(p => Long(p.First) > Long(p.Second));
            return TagStep(list, reversed ? "reverse" : null, target);
        }
        switch (target)
        {
            case string s when Long(index) is { } i:
                if (i < 0) i += s.Length;
                return i >= 0 && i < s.Length ? s[(int)i] : null;
            case object[] a when Long(index) is { } i:
                if (i < 0) i += a.Length;
                return i >= 0 && i < a.Length ? a[i] : null;
            case byte[] b when Long(index) is { } i:
                if (i < 0) i += b.Length;
                return i >= 0 && i < b.Length ? (long)b[i] : null;
            case PsHashValue h when Str(index) is { } key:
                return h.Items.TryGetValue(key, out var v) ? v : null;
            case PsMatchValue m when Long(index) is 0:
                return m.Value;
        }
        return PsUnknown.Value;
    }

    private object? Cast(string type, object? v, PsCast? node)
    {
        if (!Known(v)) return PsUnknown.Value;
        switch (TypeKey(type))
        {
            case "string": return v is object[] a ? (Join(a, Ofs) is { } j ? TagStep(j, a.All(x => x is char) && a.Length > 1 ? "char codes" : null, v) : PsUnknown.Value) : Str(v) ?? (object)PsUnknown.Value;
            case "char": return Char(v) is { } c ? c : PsUnknown.Value;
            case "char[]":
            {
                if (v is string s) return s.ToCharArray().Select(x => (object?)x).ToArray();
                if (Array(v) is { } items)
                {
                    var chars = items.Select(x => Char(x) is { } ch ? (object?)ch : PsUnknown.Value).ToArray();
                    return chars.All(Known) ? Tag(chars, v) : PsUnknown.Value;
                }
                return PsUnknown.Value;
            }
            case "int" or "long" or "short" or "byte" or "uint" or "ushort" or "ulong" or "sbyte":
                if (v is string str && str.Trim().Length == 0) return 0L;
                return Long(v) is { } n ? n : PsUnknown.Value;
            case "double": return Double(v) is { } d ? d : PsUnknown.Value;
            case "bool": return Bool(v) is { } b ? b : PsUnknown.Value;
            case "byte[]": return Bytes(Array(v)) is { } bytes ? Tag(bytes, v) : PsUnknown.Value;
            case "int[]":
            {
                var items = Array(v);
                if (items == null) return PsUnknown.Value;
                var nums = items.Select(x => Long(x) is { } n ? (object?)n : PsUnknown.Value).ToArray();
                return nums.All(Known) ? nums : PsUnknown.Value;
            }
            case "string[]": return Array(v) is { } sa ? sa.Select(x => (object?)(Str(x) ?? "")).ToArray() : PsUnknown.Value;
            case "object[]": return Array(v) ?? (object)PsUnknown.Value;
            case "scriptblock":
                if (v is PsBlockValue) return v;
                if (Str(v) is { } code && node != null) return CodeBlock(code, "[ScriptBlock] cast", node.Start, node.End, v);
                return PsUnknown.Value;
            case "type":
                if (Str(v) is not { } name) return PsUnknown.Value;
                if (node != null && Regex.IsMatch(name, @"^[\w.`+\[\],]+$")) _layer.Set(node.Start, node.End, "[" + name + "]", weak: _fold);
                return new PsTypeValue(name);
            case "regex" or "uri": return Str(v) ?? (object)PsUnknown.Value;
            case "io.memorystream": return Bytes(v) is { } mb ? new PsStreamValue(mb) : PsUnknown.Value;
            case "securestring": return v;
        }
        return PsUnknown.Value;
    }
}
