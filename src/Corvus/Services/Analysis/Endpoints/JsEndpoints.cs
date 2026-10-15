using Acornima.Ast;
using Corvus.Services.Web;

namespace Corvus.Services.Analysis.Endpoints;

/// <summary>
/// Endpoints a JavaScript file names, on its syntax tree: fetch, axios (and axios.create base URLs), XMLHttpRequest.open,
/// jQuery ajax, sendBeacon, WebSocket and EventSource targets, method calls of HTTP clients (get, post...) on path-like
/// URLs, GraphQL operations in gql / graphql templates, router path tables (React Router, Vue Router, Angular, Next.js
/// build manifests) as ROUTE rows, and absolute URL literals no call names. Constants, concatenations and templates are
/// folded ({name} for what stays computed); a function that passes its parameter into the URL is followed to its callers.
/// </summary>
internal static class JsEndpoints
{
    private const int MaxRows = 5000;
    private static readonly HashSet<string> Verbs = new(StringComparer.Ordinal) { "get", "post", "put", "delete", "patch", "head", "options" };
    private static readonly HashSet<string> RouteKeys = new(StringComparer.Ordinal)
    {
        "component", "element", "Component", "loadComponent", "loadChildren", "children", "redirectTo", "lazy", "pathMatch", "redirect", "components",
    };

    private static readonly string[] AngularKeys = ["loadChildren", "loadComponent", "pathMatch", "redirectTo", "canActivate", "canDeactivate", "canMatch", "resolve", "outlet", "data"];
    private static readonly string[] VueKeys = ["components", "redirect", "meta", "props", "beforeEnter", "alias", "name"];

    private sealed record Wrapper(int Index, string Template, string Placeholder, string Verb, string Client);

    /// <summary>The endpoints of one parsed file; <paramref name="file"/> names it in the rows, Location is line:column.</summary>
    public static void Scan(JsProgram p, string file, List<CodeEndpoint> endpoints, CancellationToken ct)
    {
        var named = new HashSet<StringLiteral>();
        var wrappers = new Dictionary<IFunction, Wrapper>();
        var names = new Dictionary<Node, string>();
        var calls = new List<(CallExpression Call, JsScope Scope)>();
        int start = endpoints.Count;

        void Add(string verb, JsValue? url, Node at, string client, Node? urlNode, JsScope scope)
        {
            if (endpoints.Count - start >= MaxRows || url is not JsString s) return;
            var text = s.Text.Trim();
            // a URL built from a parameter of the enclosing function: the function is a wrapper, its callers give the URL
            if (!s.Exact && urlNode != null && Param(p, urlNode, scope) is { } param && text.Contains("{" + param.Name + "}", StringComparison.Ordinal))
            {
                var placeholder = "{" + param.Name + "}";
                wrappers.TryAdd(param.ParamOf!, new Wrapper(param.ParamIndex, text, placeholder, verb, client));
                // a parameter that is a whole segment (/users/{id}) leaves an endpoint; one that is the path (BASE + path) does not
                int pos = text.IndexOf(placeholder, StringComparison.Ordinal);
                if (pos == 0 || text[pos - 1] is not ('/' or '=' or '-' or '.' or '_')) return;
            }
            if (!Plausible(text, strict: false)) return;
            if (urlNode is StringLiteral lit) named.Add(lit);
            endpoints.Add(new CodeEndpoint(verb, EndpointTemplates.Rooted(text), client, file, Module(p, at), Line(at)));
        }

        p.Walk((node, scope) =>
        {
            switch (node)
            {
                case VariableDeclarator { Id: Identifier id, Init: FunctionExpression or ArrowFunctionExpression } d: names[d.Init!] = id.Name; break;
                case FunctionDeclaration { Id: { } fid } fd: names[fd] = fid.Name; break;
                case Property { Value: FunctionExpression or ArrowFunctionExpression } pr when JsProgram.KeyName(pr.Key) is { } pk: names[pr.Value] = pk; break;
                case MethodDefinition { Value: var mv } md when JsProgram.KeyName(md.Key) is { } mk: names[mv] = mk; break;
                case CallExpression c:
                    if (c.Arguments.Count > 0) calls.Add((c, scope));
                    Call(p, c, scope, Add);
                    break;
                case NewExpression n when n.Arguments.Count > 0 && (JsProgram.Chain(n.Callee)?.Split('.')[^1]) is "WebSocket" or "EventSource" or "ReconnectingWebSocket":
                    Add("GET", p.Eval(n.Arguments[0], scope), n, JsProgram.Chain(n.Callee)!.Split('.')[^1] == "EventSource" ? "eventsource" : "websocket", n.Arguments[0], scope);
                    break;
                case TaggedTemplateExpression t when JsProgram.Chain(t.Tag)?.Split('.')[^1] is "gql" or "graphql":
                    var op = string.Concat(t.Quasi.Quasis.Select(q => q.Value.Cooked ?? q.Value.Raw));
                    if (System.Text.RegularExpressions.Regex.Match(op, @"\b(query|mutation|subscription)\s+([A-Za-z_][A-Za-z0-9_]*)", System.Text.RegularExpressions.RegexOptions.None, TimeSpan.FromMilliseconds(50)) is { Success: true } m)
                        endpoints.Add(new CodeEndpoint("POST", $"{{graphql}}#{m.Groups[1].Value} {m.Groups[2].Value}", "graphql", file, Module(p, t), Line(t)));
                    break;
                case ObjectExpression o:
                    Route(p, o, file, endpoints);
                    break;
                case AssignmentExpression { Left: MemberExpression { Property: Identifier { Name: "__BUILD_MANIFEST" } }, Right: ObjectExpression manifest } a:
                    foreach (var prop in manifest.Properties.OfType<Property>())
                        if (JsProgram.KeyName(prop.Key) is { } route && route.StartsWith('/'))
                            endpoints.Add(new CodeEndpoint("ROUTE", route, "next", file, null, Line(prop)));
                    break;
            }
        }, ct);

        // callers of URL wrappers: a literal (or folded constant) at the wrapper's parameter
        if (wrappers.Count > 0)
        {
            var wrapperNames = wrappers.Keys.Select(f => names.GetValueOrDefault((Node)f)).OfType<string>().ToHashSet(StringComparer.Ordinal);
            foreach (var (call, scope) in calls)
            {
                var callee = JsProgram.Unwrap(call.Callee);
                var name = callee switch { Identifier i => i.Name, MemberExpression { Property: Identifier pi, Computed: false } => pi.Name, _ => null };
                if (name == null || !wrapperNames.Contains(name) || p.Eval(callee, scope) is not JsFunction f || !wrappers.TryGetValue(f.Node, out var w)
                    || w.Index >= call.Arguments.Count || p.Eval(call.Arguments[w.Index], scope) is not JsString arg) continue;
                var url = w.Template.Replace(w.Placeholder, arg.Text, StringComparison.Ordinal);
                if (Plausible(url, strict: false) && endpoints.Count - start < MaxRows)
                {
                    if (call.Arguments[w.Index] is StringLiteral lit) named.Add(lit);
                    endpoints.Add(new CodeEndpoint(w.Verb, EndpointTemplates.Rooted(url), $"{w.Client} via {name}", file, Module(p, call), Line(call)));
                }
            }
        }

        // absolute URL literals no call named
        p.Walk((node, _) =>
        {
            if (node is StringLiteral s && !named.Contains(s) && s.Value.Length is >= 10 and <= 2048 && EndpointTemplates.IsLinkUrl(s.Value) && endpoints.Count - start < MaxRows)
                endpoints.Add(new CodeEndpoint("*", s.Value, "url", file, Module(p, s), Line(s)));
        }, ct);
    }

    private delegate void Adder(string verb, JsValue? url, Node at, string client, Node? urlNode, JsScope scope);

    private static void Call(JsProgram p, CallExpression c, JsScope scope, Adder add)
    {
        var callee = JsProgram.Unwrap(c.Callee);
        var args = c.Arguments;
        var target = p.Eval(callee, scope);
        var chain = target is JsRef r ? (r.Module.Length == 0 ? r.Path : r.Module + "." + r.Path) : JsProgram.Chain(callee);
        var parts = chain?.Split('.') ?? [];
        var method = parts.Length > 0 ? parts[^1] : null;
        var owner = parts.Length > 1 ? parts[^2] : null;
        var obj = callee is MemberExpression me ? p.Eval(me.Object, scope) : null;
        switch (method)
        {
            case "fetch" when parts.Length == 1 || owner is "window" or "globalThis" or "self":
                if (args.Count == 0) return;
                var verb = args.Count > 1 && p.Get(p.Eval(args[1], scope), "method") is JsString { Exact: true } m ? m.Text.ToUpperInvariant() : "GET";
                add(verb, p.Eval(args[0], scope), c, "fetch", args[0], scope);
                return;
            case "sendBeacon" when args.Count > 0:
                add("POST", p.Eval(args[0], scope), c, "beacon", args[0], scope);
                return;
            case "open" when args.Count >= 2 && p.Eval(args[0], scope) is JsString { Exact: true } xv && Verbs.Contains(xv.Text.ToLowerInvariant()):
                add(xv.Text.ToUpperInvariant(), p.Eval(args[1], scope), c, "xhr", args[1], scope);
                return;
            case "ajax" or "axios" or "request" when args.Count > 0 && p.Eval(args[0], scope) is JsObject cfg && p.Get(cfg, "url") is JsString:
                var cv = (p.Get(cfg, "method") ?? p.Get(cfg, "type")) is JsString { Exact: true } cm ? cm.Text.ToUpperInvariant() : "GET";
                add(cv, Based(p, obj, p.Get(cfg, "url"), p.Get(cfg, "baseURL")), c, method == "ajax" ? "jquery" : "axios", null, scope);
                return;
            case "getJSON" when args.Count > 0:
                add("GET", p.Eval(args[0], scope), c, "jquery", args[0], scope);
                return;
        }
        if (method != null && Verbs.Contains(method) && args.Count > 0)
        {
            var client = obj is JsClient jc ? jc.Name : chain?.Contains("axios", StringComparison.Ordinal) == true ? "axios" : owner is "$" or "jQuery" ? "jquery" : "http";
            var url = p.Eval(args[0], scope);
            // a generic get/post: only a URL-shaped first argument counts
            if (client == "http" && (url is not JsString us || !Plausible(us.Text, strict: true))) return;
            add(method.ToUpperInvariant(), Based(p, obj, url, null), c, client, args[0], scope);
        }
        else if (target is JsRef { Path: "" or "default" } ar && ar.Module.Contains("axios", StringComparison.Ordinal) || chain == "axios")
        {
            if (args.Count > 0 && p.Eval(args[0], scope) is JsString s)
                add("GET", s, c, "axios", args[0], scope);
        }
    }

    /// <summary>A URL joined to its client's base (axios.create({ baseURL })), or to a baseURL in the same config.</summary>
    private static JsValue? Based(JsProgram p, JsValue? client, JsValue? url, JsValue? baseUrl)
    {
        var b = client is JsClient { Base: { } cb } ? cb : baseUrl is JsString bs ? bs.Text : null;
        // axios joins as combineURLs does: the base without trailing slashes, '/', the URL without leading ones
        return b != null && url is JsString u && !EndpointTemplates.IsAbsoluteUrl(u.Text) ? new JsString(b.TrimEnd('/') + "/" + u.Text.TrimStart('/'), u.Exact) : url;
    }

    /// <summary>A route table entry: an object literal with a string path and a component, element, children or redirect.</summary>
    private static void Route(JsProgram p, ObjectExpression o, string file, List<CodeEndpoint> endpoints)
    {
        string? path = null;
        var keys = new HashSet<string>(StringComparer.Ordinal);
        foreach (var prop in o.Properties.OfType<Property>())
            if (JsProgram.KeyName(prop.Key) is { } k)
            {
                keys.Add(k);
                if (k == "path" && prop.Value is StringLiteral s) path = s.Value;
            }
        if (path == null || !keys.Overlaps(RouteKeys) || path.Contains(' ') || path.Length > 300) return;
        var client = keys.Contains("element") || keys.Contains("Component") || keys.Contains("lazy") ? "react-router"
            : keys.Overlaps(AngularKeys) ? "angular"
            : keys.Overlaps(VueKeys) ? "vue-router" : "router";
        endpoints.Add(new CodeEndpoint("ROUTE", path.Length == 0 ? "/" : path, client, file, null, Line(o)));
    }

    /// <summary>URL-shaped: absolute, or a rooted path of word characters; strict also refuses paths with no letters and file names.</summary>
    private static bool Plausible(string text, bool strict)
    {
        if (text.Length is 0 or > 2048 || text.Any(char.IsWhiteSpace)) return false;
        if (EndpointTemplates.IsAbsoluteUrl(text)) return true;
        if (text.StartsWith('{')) return text.Contains('/', StringComparison.Ordinal) && !strict;
        if (!text.StartsWith('/') && strict) return false;
        if (!text.Any(char.IsLetter)) return false;
        if (text.StartsWith("//", StringComparison.Ordinal)) return true;
        if (!strict) return text.StartsWith('/') || text.Contains('/', StringComparison.Ordinal);
        var last = text.Split('?')[0].Split('/')[^1];
        return !System.Text.RegularExpressions.Regex.IsMatch(last, @"\.(png|jpe?g|gif|svg|css|woff2?|ttf|ico|webp|mp3|mp4|map)$", System.Text.RegularExpressions.RegexOptions.IgnoreCase, TimeSpan.FromMilliseconds(50));
    }

    private static JsBinding? Param(JsProgram p, Node urlNode, JsScope scope)
    {
        var found = (JsBinding?)null;
        var stack = new Stack<Node>();
        stack.Push(urlNode);
        while (stack.Count > 0 && found == null)
        {
            var n = stack.Pop();
            if (n is Identifier id && scope.Lookup(id.Name) is { ParamOf: not null } b) found = b;
            if (n is not (FunctionExpression or ArrowFunctionExpression))
                foreach (var c in n.ChildNodes)
                    if (c != null) stack.Push(c);
        }
        return found;
    }

    private static string? Module(JsProgram p, Node at) => p.Modules.LastOrDefault(m => m.Start <= at.Start && at.End <= m.End) is { } m ? "module " + m.Id : null;

    private static string Line(Node n) => $"{n.Location.Start.Line}:{n.Location.Start.Column + 1}";
}
