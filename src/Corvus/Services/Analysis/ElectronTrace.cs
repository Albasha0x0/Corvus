using System.Text.RegularExpressions;
using Acornima.Ast;
using Corvus.Services.Web;

namespace Corvus.Services.Analysis;

/// <summary>A feature traced from a literal: the file it is in, the literal, and the steps to where the chain ends.</summary>
internal sealed record FeatureTrace(string File, string Literal, IReadOnlyList<string> Steps, string? Addon, string? Function);

/// <summary>
/// search_container kind=feature: a UI or log literal followed through the app. The literal's handler (a sibling
/// on*/click/action function in the same object, as compiled JSX props and menu templates hold them, else the enclosing
/// function) and the functions it calls in that file (three levels); the IPC sends, bridge calls and native calls they
/// reach; each channel to its main-process handler and what that reaches; each native call to the add-on function.
/// </summary>
internal sealed partial class ElectronGraph
{
    private const int MaxSeeds = 20, MaxReached = 60, MaxTraces = 200;
    private readonly Dictionary<string, string> _texts = new(StringComparer.Ordinal);
    private readonly Dictionary<string, JsProgram?> _programs = new(StringComparer.Ordinal);

    /// <summary>Keep each parsed script's text, for <see cref="Trace"/>.</summary>
    public bool KeepTexts { get; init; }

    public List<FeatureTrace> Trace(string query, CancellationToken ct)
    {
        var traces = new List<FeatureTrace>();
        foreach (var (file, text) in _texts.OrderBy(t => t.Key, StringComparer.Ordinal))
        {
            if (traces.Count >= MaxTraces) break;
            if (!text.Contains(query, StringComparison.OrdinalIgnoreCase) || Program(file) is not { } p) continue;
            var seeds = new List<(Node Literal, string Value, JsScope Scope)>();
            var objects = new List<(ObjectExpression Object, JsScope Scope)>();
            p.Walk((node, scope) =>
            {
                if (seeds.Count >= MaxSeeds) return;
                if (node is StringLiteral s && s.Value.Contains(query, StringComparison.OrdinalIgnoreCase)) seeds.Add((s, s.Value, scope));
                else if (node is TemplateElement t && t.Value.Cooked?.Contains(query, StringComparison.OrdinalIgnoreCase) == true) seeds.Add((t, t.Value.Cooked, scope));
                else if (node is ObjectExpression o) objects.Add((o, scope));
            }, ct);
            foreach (var (literal, value, scope) in seeds)
            {
                ct.ThrowIfCancellationRequested();
                var steps = new List<string> { $"literal \"{Clip(value)}\" at {p.Site(literal)}" };
                if (Handlers(p, literal, objects, steps) is { } handlers && Follow(p, handlers, steps, traces, file, value, 0, ct)) continue;
                // a callback's literal (console.log in onConnect) leads nowhere itself: the functions around it, innermost first
                var outer = Enclosing(p, literal);
                bool reached = false;
                foreach (var (fn, fnScope) in outer.Take(3))
                    if (reached = Follow(p, [(fn, fnScope)], [.. steps, $"in function {Name(fn)}at {p.Site(fn)}"], traces, file, value, 0, ct, quiet: true)) break;
                if (!reached) traces.Add(new FeatureTrace(file, value, [.. steps, outer.Count > 0 ? $"in function {Name(outer[0].Function)}at {p.Site(outer[0].Function)}" : "at the top level",
                    "no IPC, bridge, sink or native call reached"], null, null));
            }
        }
        return traces;
    }

    private JsProgram? Program(string file)
    {
        if (_programs.TryGetValue(file, out var p)) return p;
        return _programs[file] = _texts.TryGetValue(file, out var text) ? JsProgram.Build(file, text, [], default) : null;
    }

    /// <summary>Function-valued siblings of the literal in its object (onClick, click, action, handler...).</summary>
    private static List<(Node Function, JsScope Scope)>? Handlers(JsProgram p, Node literal, List<(ObjectExpression Object, JsScope Scope)> objects, List<string> steps)
    {
        for (int i = objects.Count - 1; i >= 0; i--) // innermost first
        {
            var (o, scope) = objects[i];
            if (o.Start > literal.Start || o.End < literal.End) continue;
            var props = o.Properties.OfType<Property>().ToList();
            if (!props.Any(x => x.Value.Start <= literal.Start && literal.End <= x.Value.End && (ReferenceEquals(x.Value, literal) || x.Value is ArrayExpression or TemplateLiteral))) continue;
            var found = new List<(Node, JsScope)>();
            foreach (var x in props)
                if (JsProgram.KeyName(x.Key) is { } key && HandlerKey().IsMatch(key))
                {
                    if (x.Value is FunctionExpression or ArrowFunctionExpression) found.Add((x.Value, scope));
                    else if (p.Eval(x.Value, scope) is JsFunction f) found.Add(((Node)f.Node, f.Scope));
                    if (found.Count > 0) steps.Add($"handler {key} at {p.Site(x)}");
                }
            if (found.Count > 0) return found;
        }
        return null;
    }

    /// <summary>The functions holding the literal, innermost first; a bundle's module factories are not functions of the app.</summary>
    private static List<(Node Function, JsScope Scope)> Enclosing(JsProgram p, Node literal)
    {
        var found = new List<(Node, JsScope)>();
        p.Walk((node, scope) =>
        {
            // a module wrapper spanning most of a large file reaches everything: not a lead
            if (node is IFunction && node.Start <= literal.Start && literal.End <= node.End && scope.Factory == null
                && !(p.Text.Length > 20_000 && node.End - node.Start > p.Text.Length / 2)) found.Add((node, scope));
        }, default);
        found.Reverse();
        return found;
    }

    private static string Name(Node fn) => fn is IFunction { Id: { } id } ? id.Name + " " : "";

    /// <summary>The functions the handlers reach in their file, and the graph rows inside them: one trace per reached end.</summary>
    /// <returns>Whether a boundary was reached; with <paramref name="quiet"/> nothing is recorded when none was.</returns>
    private bool Follow(JsProgram p, List<(Node Function, JsScope Scope)> handlers, List<string> steps, List<FeatureTrace> traces, string file, string literal, int depth,
        CancellationToken ct, bool quiet = false)
    {
        var reached = Reach(p, handlers, ct);
        var rows = _rows.Where(r => r.File == p.Path && reached.Any(x => x.Start <= r.Start && r.Start < x.End)
                                    && (r.Role is "send-main" or "send-renderer" || r.Kind is "bridge-call" or "native-call" || r.Kind.StartsWith("sink-", StringComparison.Ordinal)))
            .DistinctBy(r => (r.Kind, r.Value, r.Start)).Take(20).ToList();
        if (rows.Count == 0)
        {
            if (!quiet) Add([.. steps, "no IPC, bridge, sink or native call reached"], null, null);
            return false;
        }
        foreach (var r in rows)
        {
            var here = new List<string>(steps) { $"{r.Kind} {r.Call} {r.Value} at {r.Site}" };
            if (r.Kind == "native-call") Add(here, r.Link, r.Value);
            else if (r.Kind.StartsWith("sink-", StringComparison.Ordinal)) Add(here, null, null);
            else if (depth < 2 && r.Kind == "bridge-call" && _bridge.FirstOrDefault(b => b.Name == r.Value) is { } bm && Program(bm.File) is { } bp && Function(bp, bm.Start, bm.End) is { } bf)
                Follow(bp, [bf], [.. here, $"bridge method {bm.Name} at {bm.Site}"], traces, file, literal, depth + 1, ct);
            else if (depth < 2 && r.Role == "send-main" && r.Literal)
            {
                var listeners = _rows.Where(l => l.Role == "listen-main" && l.Value == r.Value && l.HandlerStart >= 0).Take(3).ToList();
                if (listeners.Count == 0) Add([.. here, "no main-process handler for this channel"], null, null);
                foreach (var l in listeners)
                    if (Program(l.File) is { } lp && Function(lp, l.HandlerStart, l.HandlerEnd) is { } lf)
                        Follow(lp, [lf], [.. here, $"{l.Call} at {l.Site}"], traces, file, literal, depth + 1, ct);
            }
            else Add(here, null, null);
        }
        return true;

        void Add(List<string> chain, string? addon, string? function)
        {
            if (traces.Count < MaxTraces) traces.Add(new FeatureTrace(file, literal, chain, addon, function));
        }
    }

    /// <summary>The handler functions and those they call in the same file, three levels down, as ranges.</summary>
    private static List<(int Start, int End)> Reach(JsProgram p, List<(Node Function, JsScope Scope)> roots, CancellationToken ct)
    {
        var seen = new HashSet<Node>();
        var ranges = new List<(int, int)>();
        var queue = new Queue<(Node Function, JsScope Scope, int Level)>(roots.Select(r => (r.Function, r.Scope, 0)));
        while (queue.Count > 0 && ranges.Count < MaxReached)
        {
            var (fn, scope, level) = queue.Dequeue();
            if (!seen.Add(fn)) continue;
            ranges.Add((fn.Start, fn.End));
            if (level >= 3) continue;
            p.Walk(fn, scope, (node, s) =>
            {
                if (node is CallExpression c && JsProgram.Unwrap(c.Callee) is Identifier or MemberExpression && p.Eval(c.Callee, s) is JsFunction f && !seen.Contains((Node)f.Node))
                    queue.Enqueue(((Node)f.Node, f.Scope, level + 1));
            }, ct);
        }
        return ranges;
    }

    /// <summary>The function node at a range, with its enclosing scope.</summary>
    private static (Node, JsScope)? Function(JsProgram p, int start, int end)
    {
        (Node, JsScope)? found = null;
        p.Walk((node, scope) =>
        {
            if (found == null && node is IFunction && node.Start == start && node.End == end) found = (node, scope);
        }, default);
        return found;
    }

    [GeneratedRegex("^(on[A-Z].*|click|action|handler|callback|command|run|execute|select|onclick|fn|cb)$")]
    private static partial Regex HandlerKey();
}
