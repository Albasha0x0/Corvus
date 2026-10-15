using System.Text;
using Acornima.Ast;

namespace Corvus.Services.Web;

/// <summary>A chunk the runtime can load: its id and the file name its chunk-filename function builds.</summary>
public sealed record JsChunk(string Id, string? File);

/// <summary>An async load: the chunks a site ensures (require.e) and the module it then requires.</summary>
public sealed record JsAsyncLoad(string Site, IReadOnlyList<string> Chunks, string? Module);

/// <summary>analyze_js view=runtime: the webpack runtime of a bundle.</summary>
public sealed record JsRuntimeFacts(
    [property: System.ComponentModel.Description("The runtime's require function (__webpack_require__, minified or not) and its module table.")] string? Require, string? ModuleTable,
    [property: System.ComponentModel.Description("Chunk loading globals (self.webpackChunk..., webpackJsonp).")] IReadOnlyList<string> ChunkGlobals,
    [property: System.ComponentModel.Description("Ids of the chunks this file pushes.")] IReadOnlyList<string> ChunkIds,
    string? PublicPath,
    [property: System.ComponentModel.Description("Runtime helpers set on require: e (ensure chunk), u (chunk file name), p (public path)...")] IReadOnlyList<string> Helpers,
    IReadOnlyList<JsChunk> Chunks, IReadOnlyList<JsAsyncLoad> AsyncLoads);

/// <summary>
/// The webpack runtime read from the syntax tree: the require function (a one-parameter function calling the module
/// table entry with itself), its helpers, the chunk-filename map (require.u: the id maps and string parts folded per
/// chunk), the public path, the chunk loading global and pushed chunk ids, and each require.e site with its module.
/// </summary>
internal static class JsRuntime
{
    private const int MaxRows = 5000;

    private static readonly Dictionary<string, string> HelperNames = new(StringComparer.Ordinal)
    {
        ["e"] = "ensure chunk", ["u"] = "chunk file name", ["p"] = "public path", ["d"] = "define exports", ["o"] = "has own property", ["r"] = "mark ES module",
        ["n"] = "default export getter", ["t"] = "namespace object", ["l"] = "load script", ["f"] = "chunk loading handlers", ["O"] = "on chunks loaded",
        ["g"] = "global", ["m"] = "module table", ["c"] = "module cache", ["miniCssF"] = "CSS chunk file name", ["nmd"] = "node module decorator", ["b"] = "base URI",
        ["h"] = "full hash", ["j"] = "runtime chunk id", ["S"] = "share scopes", ["I"] = "init sharing", ["a"] = "async module", ["x"] = "startup",
    };

    public static JsRuntimeFacts Read(JsProgram p, CancellationToken ct)
    {
        string? require = null, table = null, publicPath = null;
        var globals = new SortedSet<string>(StringComparer.Ordinal);
        var chunkIds = new List<string>();
        var helpers = new SortedDictionary<string, string>(StringComparer.Ordinal);
        ArrowFunctionExpression? filename = null;
        IFunction? filenameFn = null;
        var ensures = new List<(CallExpression Call, JsScope Scope)>();
        p.Walk((node, scope) =>
        {
            switch (node)
            {
                case FunctionDeclaration { Id: { } id, Params: [Identifier param] } fd when require == null && Table(fd, id.Name, param.Name) is { } t:
                    (require, table) = (id.Name, t);
                    break;
                case MemberExpression { Property: Identifier { Name: var name }, Computed: false } m when name.StartsWith("webpackChunk", StringComparison.Ordinal) || name == "webpackJsonp":
                    globals.Add(JsProgram.Chain(m) ?? name);
                    break;
                case CallExpression { Callee: MemberExpression { Property: Identifier { Name: "push" } } push, Arguments: [ArrayExpression { Elements: [ArrayExpression ids, ..] }, ..] }
                    when JsProgram.Chain(push.Object)?.Contains("webpackChunk", StringComparison.Ordinal) == true || Text(p, push.Object).Contains("webpackChunk", StringComparison.Ordinal)
                         || Text(p, push.Object).Contains("webpackJsonp", StringComparison.Ordinal):
                    chunkIds.AddRange(ids.Elements.OfType<Literal>().Select(l => JsProgram.Literal(l) ?? l.Raw));
                    break;
                case AssignmentExpression { Left: MemberExpression { Object: Identifier obj, Property: Identifier { Name: var helper }, Computed: false }, Right: var value }
                    when require != null && obj.Name == require || obj.Name == "__webpack_require__":
                    helpers[helper] = HelperNames.GetValueOrDefault(helper, "helper");
                    if (helper == "p" && p.Eval(value, scope) is JsString { Exact: true } pp) publicPath = pp.Text;
                    if (helper == "u" && value is ArrowFunctionExpression arrow) filename = arrow;
                    if (helper == "u" && value is FunctionExpression fe) filenameFn = fe;
                    break;
                case CallExpression { Callee: MemberExpression { Property: Identifier { Name: "e" }, Computed: false }, Arguments: [Literal] } e:
                    ensures.Add((e, scope));
                    break;
            }
        }, ct);

        var loads = new List<JsAsyncLoad>();
        foreach (var (call, scope) in ensures.Take(MaxRows))
        {
            // n.e(1) alone, or inside Promise.all([n.e(1), n.e(2)]).then(n.bind(n, 456)) or .then(() => n(456))
            var owner = JsProgram.Unwrap(((MemberExpression)call.Callee).Object);
            if (owner is not Identifier ownerId || !IsRequire(p, scope, ownerId.Name, require)) continue;
            loads.Add(new JsAsyncLoad(p.Site(call), [JsProgram.Literal(call.Arguments[0]) ?? ((Literal)call.Arguments[0]).Raw], null));
        }
        Group(p, loads, ensures, require);
        var chunks = ((IFunction?)filename ?? filenameFn) is { } fn ? Filenames(p, fn, loads.SelectMany(l => l.Chunks)) : [];
        return new JsRuntimeFacts(require, table, [.. globals], chunkIds.Distinct().ToList(), publicPath, helpers.Select(h => $"{h.Key}: {h.Value}").ToList(), chunks, loads);
    }

    /// <summary>The module table a require function calls: M[id].call(..., require) or M[id](..., require).</summary>
    internal static string? Table(FunctionDeclaration fd, string self, string param)
    {
        var stack = new Stack<Node>();
        stack.Push(fd.Body);
        while (stack.Count > 0)
        {
            var n = stack.Pop();
            if (n is CallExpression c && c.Arguments.Any(a => a is Identifier { Name: var x } && x == self))
            {
                var callee = c.Callee is MemberExpression { Property: Identifier { Name: "call" }, Object: var o } ? o : c.Callee;
                if (callee is MemberExpression { Computed: true, Object: Identifier modules, Property: Identifier { Name: var key } } && key == param) return modules.Name;
            }
            if (n is FunctionExpression or ArrowFunctionExpression) continue;
            foreach (var ch in n.ChildNodes)
                if (ch != null) stack.Push(ch);
        }
        return null;
    }

    private static bool IsRequire(JsProgram p, JsScope scope, string name, string? runtime) =>
        name == runtime || name == "__webpack_require__" || scope.Lookup(name) is { ParamIndex: 2 } b && b.Scope.Factory != null;

    /// <summary>Each Promise.all of ensures becomes one load naming all its chunks and the module required after it.</summary>
    private static void Group(JsProgram p, List<JsAsyncLoad> loads, List<(CallExpression Call, JsScope Scope)> ensures, string? runtime)
    {
        var bySite = loads.ToDictionary(l => l.Site);
        var grouped = new List<JsAsyncLoad>();
        var used = new HashSet<string>();
        p.Walk((node, scope) =>
        {
            // X.then(after) where X is n.e(..) or Promise.all([n.e(..), ...])
            if (node is not CallExpression { Callee: MemberExpression { Property: Identifier { Name: "then" }, Object: var before }, Arguments: [var after, ..] } then) return;
            var calls = JsProgram.Unwrap(before) switch
            {
                CallExpression { Callee: MemberExpression { Property: Identifier { Name: "e" } } } single => [single],
                CallExpression { Callee: MemberExpression { Property: Identifier { Name: "all" } }, Arguments: [ArrayExpression arr, ..] } => arr.Elements.OfType<CallExpression>().ToList(),
                _ => [],
            };
            var sites = calls.Select(c => p.Site(c)).Where(bySite.ContainsKey).ToList();
            if (sites.Count == 0) return;
            used.UnionWith(sites);
            grouped.Add(new JsAsyncLoad(p.Site(then), sites.SelectMany(s => bySite[s].Chunks).ToList(), Module(after)));
        }, default);
        loads.RemoveAll(l => used.Contains(l.Site));
        loads.AddRange(grouped);
        loads.Sort((a, b) => string.CompareOrdinal(a.Site, b.Site));
    }

    /// <summary>The module id after an ensure: n.bind(n, 456), n.t.bind(n, 456, 23), or () => n(456).</summary>
    private static string? Module(Node after)
    {
        switch (after)
        {
            case CallExpression { Callee: MemberExpression { Property: Identifier { Name: "bind" } }, Arguments: [_, Literal id, ..] }:
                return JsProgram.Literal(id) ?? id.Raw;
            case ArrowFunctionExpression { Body: CallExpression { Arguments: [Literal id, ..] } }:
                return JsProgram.Literal(id) ?? id.Raw;
            case ArrowFunctionExpression { Body: CallExpression { Arguments: [CallExpression { Arguments: [Literal inner, ..] }, ..] } }:
                return JsProgram.Literal(inner) ?? inner.Raw;
            default:
                return null;
        }
    }

    /// <summary>
    /// require.u's file names per chunk id: the body's object literals keyed by chunk id give the parts ({1:"a1b2"}[e]),
    /// the parameter is the id, string parts are kept; a chunk missing from a map uses the id ((map[e] || e)).
    /// </summary>
    private static List<JsChunk> Filenames(JsProgram p, IFunction fn, IEnumerable<string> ensured)
    {
        if (fn.Params is not [Identifier param]) return [];
        var body = fn.Body is BlockStatement { Body: [.., ReturnStatement { Argument: { } r }] } ? r : fn.Body as Expression;
        if (body == null) return [];
        var maps = new List<ObjectExpression>();
        var stack = new Stack<Node>();
        stack.Push(body);
        while (stack.Count > 0)
        {
            var n = stack.Pop();
            if (n is ObjectExpression o) maps.Add(o);
            foreach (var c in n.ChildNodes)
                if (c != null) stack.Push(c);
        }
        // the ids the maps key, and those the file ensures (a filename function without maps: e => e + "/index.js")
        var ids = maps.SelectMany(m => m.Properties.OfType<Property>()).Select(x => JsProgram.KeyName(x.Key)).OfType<string>().Concat(ensured).Distinct().Take(MaxRows).ToList();
        var chunks = new List<JsChunk>();
        foreach (var id in ids)
        {
            var sb = new StringBuilder();
            chunks.Add(new JsChunk(id, Render(body, param.Name, id, sb) ? sb.ToString() : null));
        }
        return chunks;
    }

    /// <summary>Folds the filename expression for one id; false when a part is not a string, the id, or a map lookup.</summary>
    private static bool Render(Node n, string param, string id, StringBuilder sb)
    {
        switch (n)
        {
            case BinaryExpression { Operator: Acornima.Operator.Addition } b:
                return Render(b.Left, param, id, sb) && Render(b.Right, param, id, sb);
            case StringLiteral s: sb.Append(s.Value); return true;
            case NumericLiteral num: sb.Append(num.Raw); return true;
            case Identifier i when i.Name == param: sb.Append(id); return true;
            case TemplateLiteral t:
                for (int k = 0; k < t.Quasis.Count; k++)
                {
                    sb.Append(t.Quasis[k].Value.Cooked);
                    if (k < t.Expressions.Count && !Render(t.Expressions[k], param, id, sb)) return false;
                }
                return true;
            case MemberExpression { Computed: true, Object: ObjectExpression map, Property: Identifier key } when key.Name == param:
                var value = map.Properties.OfType<Property>().FirstOrDefault(x => JsProgram.KeyName(x.Key) == id)?.Value;
                if (value is StringLiteral v) { sb.Append(v.Value); return true; }
                return false;
            case LogicalExpression { Operator: Acornima.Operator.LogicalOr } or:
                var left = new StringBuilder();
                if (Render(or.Left, param, id, left)) { sb.Append(left); return true; }
                return Render(or.Right, param, id, sb);
            case ParenthesizedExpression pe: return Render(pe.Expression, param, id, sb);
            default: return false;
        }
    }

    private static string Text(JsProgram p, Node n) => n.Start >= 0 && n.End <= p.Text.Length && n.End - n.Start < 200 ? p.Text[n.Start..n.End] : "";
}
