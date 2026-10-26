using System.Text;
using Acornima.Ast;

namespace Corvus.Services.Web;

/// <summary>A React component of a bundle: its name, kind (function, class, memo or forwardRef), site, the hooks it calls and the components it renders.</summary>
public sealed record JsComponent(string Name, string Kind, int Line, int Column, string? Module, int Elements, IReadOnlyList<string> Hooks, IReadOnlyList<string> Renders);

/// <summary>
/// analyze_js view=react: the React versions found, the components (a page of them) and their total, element calls
/// found and the number components hold, and notes. The tool returns it as text; its record carries the total only.
/// </summary>
public sealed record JsReactResult(IReadOnlyList<string> Versions, IReadOnlyList<JsComponent> Components, int Total, int Calls, int Attributed, IReadOnlyList<string> Notes);

/// <summary>
/// React structure of a compiled bundle, read from its element factory calls: a component is a function that creates
/// elements (callbacks inside it count as it), or a class whose superclass is Component or PureComponent. Names come
/// from declarations, the bindings a function is assigned to (through memo and forwardRef) and displayName.
/// </summary>
internal static class JsReact
{
    public const int MaxComponents = 5000;
    private static readonly HashSet<string> Factories = new(StringComparer.Ordinal) { "jsx", "jsxs", "jsxDEV", "_jsx", "_jsxs", "createElement" };
    private static readonly HashSet<string> Wrappers = new(StringComparer.Ordinal) { "memo", "forwardRef" };

    internal sealed class Info(Node node)
    {
        public Node Node { get; } = node;
        public string? Name;
        public string Kind = "function";
        public int Elements;
        public readonly Dictionary<string, int> Hooks = new(StringComparer.Ordinal);
        public readonly List<string> Renders = [];
    }

    /// <summary>One bundle's components, collected once for any number of reads and JSX views.</summary>
    public sealed class Analysis
    {
        private readonly State _s;
        internal Analysis(State s) => _s = s;
        public JsReactResult Read(string? filter, int offset, int limit, CancellationToken ct) => JsReact.Read(_s, filter, offset, limit, ct);
        public string? Jsx(string name) => JsReact.Jsx(_s, name);
    }

    /// <summary>Collects the components of a parsed bundle.</summary>
    public static Analysis Analyze(JsProgram p, CancellationToken ct) => new(Collect(p, ct));

    internal sealed class State(JsProgram p)
    {
        public JsProgram P { get; } = p;
        public readonly Dictionary<Node, string> Names = new();
        public readonly Dictionary<Node, string> Wrapped = new();
        public readonly Dictionary<JsBinding, Node> BoundTo = new();
        public readonly Dictionary<Node, Node> MethodClass = new();
        public readonly Dictionary<Node, Info> Components = new();
        public readonly Dictionary<CallExpression, string> Types = new();
        public int Calls;
    }

    /// <summary>Versions, components (those whose name contains <paramref name="filter"/> when given; paged by offset and limit, in source order) and notes of a parsed bundle.</summary>
    public static JsReactResult Read(JsProgram p, string? filter, int offset, int limit, CancellationToken ct) => Read(Collect(p, ct), filter, offset, limit, ct);

    private static JsReactResult Read(State s, string? filter, int offset, int limit, CancellationToken ct)
    {
        var p = s.P;
        var all = s.Components.Values.Where(i => string.IsNullOrEmpty(filter) || (i.Name ?? "").Contains(filter, StringComparison.OrdinalIgnoreCase)).OrderBy(i => i.Node.Start).ToList();
        var notes = new List<string>();
        if (all.Count == 0) notes.Add("no element factory calls (jsx, jsxs, createElement) were found: not React code, or the factory is called through a renamed property");
        if (all.Count > MaxComponents) notes.Add($"only the first {MaxComponents} components are read");
        var rows = all.Take(MaxComponents).Skip(Math.Max(0, offset)).Take(Math.Max(0, limit)).Select(i => Row(s, i)).ToList();
        return new JsReactResult(Versions(p, ct), rows, Math.Min(all.Count, MaxComponents), s.Calls, s.Components.Values.Sum(i => i.Elements), notes);
    }

    /// <summary>The JSX a component's element calls stand for, one tree per top-level call; null when no component has that name.</summary>
    public static string? Jsx(JsProgram p, string name, CancellationToken ct) => Jsx(Collect(p, ct), name);

    private static string? Jsx(State s, string name)
    {
        var info = s.Components.Values.OrderBy(i => i.Node.Start).FirstOrDefault(i => i.Name == name);
        if (info == null) return null;
        var sb = new StringBuilder();
        var row = Row(s, info);
        sb.Append($"// {row.Name} ({row.Kind}) at {row.Line}:{row.Column}");
        if (row.Hooks.Count > 0) sb.Append("; hooks: " + string.Join(", ", row.Hooks));
        sb.Append('\n');
        foreach (var call in TopElements(s, info.Node))
        {
            sb.Append(Element(s, call, 0));
            sb.Append("\n\n");
        }
        return sb.ToString().TrimEnd() + "\n";
    }

    private static JsComponent Row(State s, Info i)
    {
        var at = i.Node.Location.Start;
        var module = s.P.Modules.LastOrDefault(m => m.Start <= i.Node.Start && i.Node.End <= m.End)?.Id;
        return new JsComponent(i.Name ?? "(anonymous)", i.Kind, at.Line, at.Column + 1, module, i.Elements,
            i.Hooks.Select(h => h.Value > 1 ? $"{h.Key} x{h.Value}" : h.Key).ToList(), i.Renders.Distinct().ToList());
    }

    private static State Collect(JsProgram p, CancellationToken ct)
    {
        var s = new State(p);
        // Names, wrappers and class methods first, so the second pass can attribute calls.
        p.Walk((node, scope) =>
        {
            switch (node)
            {
                case FunctionDeclaration { Id: { } id } fd: s.Names.TryAdd(fd, id.Name); break;
                case FunctionExpression { Id: { } fid } fe: s.Names.TryAdd(fe, fid.Name); break;
                case VariableDeclarator { Id: Identifier v, Init: { } init }: Bind(s, scope, v.Name, init); break;
                case AssignmentExpression { Left: Identifier, Right: ArrayExpression inline }: CompiledClass(s, null, inline, scope); break;
                case AssignmentExpression { Left: Identifier a, Right: var r }: Bind(s, scope, a.Name, r); break;
                case AssignmentExpression { Left: MemberExpression { Computed: false, Property: Identifier mp } m, Right: var r2 }:
                    if (mp.Name == "displayName" && JsProgram.Unwrap(r2) is StringLiteral dn && Target(s, m.Object, scope) is { } shown) s.Names[shown] = dn.Value;
                    else if (Function(s, r2) is { } fn) s.Names.TryAdd(fn, mp.Name);
                    break;
                case Property { Computed: false, Value: var pv } pr when JsProgram.KeyName(pr.Key) is { } key && Function(s, pv) is { } pfn: s.Names.TryAdd(pfn, key); break;
                case ClassDeclaration or ClassExpression:
                    Class(s, node);
                    break;
                case CallExpression { Arguments.Count: >= 2 } cc when JsProgram.Unwrap(cc.Arguments[1]) is ArrayExpression methods:
                    CompiledClass(s, cc.Arguments[0], methods, scope);
                    break;
            }
        }, ct);
        p.Walk((node, scope) =>
        {
            if (node is not CallExpression call || Callee(call.Callee) is not { } callee) return;
            if (Factories.Contains(callee) && IsElement(call, callee))
            {
                s.Calls++;
                if (Owner(s, scope) is not { } owner) return;
                var info = Component(s, owner);
                info.Elements++;
                if (call.Arguments.Count > 0 && JsProgram.Unwrap(call.Arguments[0]) is not StringLiteral)
                {
                    // Resolved here, where the call's scope is known; the JSX writer reuses it.
                    var type = TypeName(s, call.Arguments[0], scope);
                    s.Types[call] = type;
                    info.Renders.Add(type);
                }
            }
            else if (IsHook(callee) && Owner(s, scope) is { } hookOwner && (s.Components.ContainsKey(hookOwner) || !IsHook(s.Names.GetValueOrDefault(hookOwner) ?? "")))
            {
                var info = Component(s, hookOwner);
                info.Hooks[callee] = info.Hooks.GetValueOrDefault(callee) + 1;
            }
        }, ct);
        // Names seen after a component was first met (a later displayName, a class registered early) apply too.
        foreach (var info in s.Components.Values) info.Name = s.Names.GetValueOrDefault(info.Node) ?? info.Name;
        // A function with hooks but no elements is a custom hook or a helper, not a component.
        foreach (var key in s.Components.Where(c => c.Value.Elements == 0 && c.Value.Kind != "class").Select(c => c.Key).ToList()) s.Components.Remove(key);
        return s;
    }

    private static Info Component(State s, Node owner)
    {
        if (!s.Components.TryGetValue(owner, out var info))
        {
            s.Components[owner] = info = new Info(owner) { Name = s.Names.GetValueOrDefault(owner) };
            if (s.Wrapped.TryGetValue(owner, out var w)) info.Kind = w;
            if (owner is ClassDeclaration or ClassExpression) info.Kind = "class";
        }
        return info;
    }

    // name = function, name = memo(function), name = forwardRef(function): the function is named and the binding bound to it.
    private static void Bind(State s, JsScope scope, string name, Node init)
    {
        // name = function (e) { ... }(React.Component): a compiled class, named by its binding.
        if (JsProgram.Unwrap(init) is CallExpression { Arguments: [var super] } iife && JsProgram.Unwrap(iife.Callee) is FunctionExpression body
            && Callee(super) is "Component" or "PureComponent")
            s.Names.TryAdd(body, name);
        if (Function(s, init) is not { } fn) return;
        s.Names.TryAdd(fn, name);
        if (scope.Lookup(name) is { } b) s.BoundTo.TryAdd(b, fn);
    }

    // The function an expression is, or the one memo or forwardRef wraps (recorded with its kind).
    private static Node? Function(State s, Node expr)
    {
        expr = JsProgram.Unwrap(expr);
        if (expr is IFunction and (FunctionExpression or ArrowFunctionExpression)) return expr;
        if (expr is ClassExpression) return expr;
        if (expr is CallExpression { Arguments.Count: >= 1 } c && Callee(c.Callee) is { } w && Wrappers.Contains(w) && Function(s, c.Arguments[0]) is { } inner)
        {
            s.Wrapped.TryAdd(inner, w);
            return inner;
        }
        return null;
    }

    // Class components: render and the other methods attribute their calls to the class.
    private static void Class(State s, Node node)
    {
        var (super, body, id) = node switch
        {
            ClassDeclaration d => (d.SuperClass, d.Body, d.Id),
            ClassExpression e => (e.SuperClass, e.Body, e.Id),
            _ => (null, null, null),
        };
        if (super == null || body == null || Callee(super) is not ("Component" or "PureComponent")) return;
        if (id != null) s.Names.TryAdd(node, id.Name);
        foreach (var m in body.Body.OfType<MethodDefinition>())
            if (m.Value is FunctionExpression f) s.MethodClass[f] = node;
        var info = Component(s, node);
        info.Kind = "class";
    }

    // Babel's and TypeScript's class helper: _createClass(C, [{ key: "render", value: function () { ... } }, ...]).
    // A method list with render makes C a class component and its methods belong to it.
    // Loose mode inlines the helper as (r = [ ... ]) && o(n.prototype, r) inside the class's own function.
    private static void CompiledClass(State s, Node? target, ArrayExpression methods, JsScope scope)
    {
        var pairs = new List<(string Key, Node Value)>();
        foreach (var e in methods.Elements)
        {
            if (e is not ObjectExpression o) return;
            var props = o.Properties.OfType<Property>().Where(x => !x.Computed).ToDictionary(x => JsProgram.KeyName(x.Key) ?? "", x => x.Value);
            if (!props.TryGetValue("key", out var k) || JsProgram.Unwrap(k) is not StringLiteral key) return;
            // A method has value; an accessor has get, set or both.
            var members = new[] { "value", "get", "set" }.Where(props.ContainsKey).Select(m => JsProgram.Unwrap(props[m])).ToList();
            if (members.Count == 0) return;
            pairs.AddRange(members.Select(m => (key.Value, m)));
        }
        if (!pairs.Any(x => x.Key == "render")) return;
        var cls = target != null ? Target(s, target, scope) : scope.FunctionScope is { Owner: IFunction, Factory: null } fs ? fs.Owner : null;
        if (cls == null) return;
        foreach (var (_, fn) in pairs)
            if (fn is IFunction) s.MethodClass[fn] = cls;
        Component(s, cls).Kind = "class";
    }

    // The component a call belongs to: the innermost named function, climbing out of anonymous callbacks
    // but never into a bundler's module factory; class methods belong to their class.
    private static Node? Owner(State s, JsScope scope)
    {
        var fs = scope.FunctionScope;
        while (true)
        {
            if (fs.Owner is Acornima.Ast.Program || fs.Factory != null) return null;
            if (s.MethodClass.TryGetValue(fs.Owner, out var cls)) return cls;
            if (s.Names.ContainsKey(fs.Owner) || s.Components.ContainsKey(fs.Owner)) return fs.Owner;
            var parent = fs.Parent?.FunctionScope;
            if (parent == null || parent.Owner is Acornima.Ast.Program || parent.Factory != null) return fs.Owner;
            fs = parent;
        }
    }

    // The function or class an expression names: through bindings, memo/forwardRef assignments and the evaluator.
    private static Node? Target(State s, Node expr, JsScope scope)
    {
        expr = JsProgram.Unwrap(expr);
        if (expr is not Identifier id || scope.Lookup(id.Name) is not { } b) return null;
        if (s.BoundTo.TryGetValue(b, out var fn)) return fn;
        return s.P.Value(b) is JsFunction f ? (Node)f.Node : b.Sources.Count == 1 && JsProgram.Unwrap(b.Sources[0].Expr) is ClassExpression ce ? ce : null;
    }

    private static string TypeName(State s, Node type, JsScope scope)
    {
        if (Target(s, type, scope) is { } t && s.Names.TryGetValue(t, out var n)) return n;
        if (JsProgram.Unwrap(type) is MemberExpression { Computed: false, Property: Identifier { Name: "Fragment" } }) return "Fragment";
        if (JsProgram.Unwrap(type) is IFunction) return "(inline function)";
        var text = s.P.Text[type.Start..type.End];
        return text.Length > 60 ? text[..57] + "..." : text;
    }

    /// <summary>The property or identifier name a callee ends in, through (0, x.f) and parentheses.</summary>
    private static string? Callee(Node callee) => JsProgram.Unwrap(callee) switch
    {
        Identifier i => i.Name,
        MemberExpression { Computed: false, Property: Identifier p } => p.Name,
        MemberExpression { Computed: true, Property: StringLiteral sl } => sl.Value,
        _ => null,
    };

    // document.createElement("div") makes a DOM node: React's createElement takes props or children too, and is
    // never called on document.
    private static bool IsElement(CallExpression call, string callee) =>
        callee != "createElement" || call.Arguments.Count >= 2 && !(JsProgram.Unwrap(call.Callee) is MemberExpression { Object: var o } && JsProgram.Chain(o) is "document" or "window.document");

    private static bool IsHook(string name) => name == "use" || name.Length > 3 && name.StartsWith("use", StringComparison.Ordinal) && char.IsUpper(name[3]);

    /// <summary>Element calls of a component not nested in another element call's arguments.</summary>
    private static List<CallExpression> TopElements(State s, Node root)
    {
        var found = new List<CallExpression>();
        var stack = new Stack<Node>();
        foreach (var c in root.ChildNodes) if (c != null) stack.Push(c);
        while (stack.Count > 0 && found.Count < 200)
        {
            var n = stack.Pop();
            if (n is CallExpression call && Callee(call.Callee) is { } callee && Factories.Contains(callee) && IsElement(call, callee)) { found.Add(call); continue; }
            // A nested class or named function is its own component.
            if (n != root && (n is ClassDeclaration or ClassExpression || s.Components.ContainsKey(n))) continue;
            foreach (var c in n.ChildNodes) if (c != null) stack.Push(c);
        }
        found.Sort((a, b) => a.Start.CompareTo(b.Start));
        return found;
    }

    // One element as JSX: the type, props as attributes, children indented one level per depth.
    private static string Element(State s, CallExpression call, int depth)
    {
        var args = call.Arguments;
        var type = args.Count > 0 ? JsProgram.Unwrap(args[0]) : null;
        string tag = type switch
        {
            StringLiteral sl => sl.Value,
            null => "",
            _ => (s.Types.GetValueOrDefault(call) ?? TypeName(s, type, s.P.Root)) is var n && n == "Fragment" ? "" : n,
        };
        var attrs = new List<string>();
        var children = new List<Node>();
        bool jsx = Callee(call.Callee) != "createElement";
        if (args.Count > 1 && JsProgram.Unwrap(args[1]) is ObjectExpression props)
            foreach (var prop in props.Properties)
            {
                if (prop is SpreadElement sp) { attrs.Add("{..." + Source(s, sp.Argument, depth) + "}"); continue; }
                if (prop is not Property { Computed: false } pr || JsProgram.KeyName(pr.Key) is not { } key) continue;
                if (jsx && key == "children")
                {
                    if (JsProgram.Unwrap(pr.Value) is ArrayExpression arr) children.AddRange(arr.Elements.OfType<Node>());
                    else children.Add(pr.Value);
                    continue;
                }
                attrs.Add(JsProgram.Unwrap(pr.Value) is StringLiteral v && !v.Value.Contains('"') ? $"{key}=\"{v.Value}\"" : $"{key}={{{Source(s, pr.Value, depth)}}}");
            }
        else if (args.Count > 1 && JsProgram.Unwrap(args[1]) is not (NullLiteral or Identifier { Name: "undefined" }))
            attrs.Add("{..." + Source(s, args[1], depth) + "}");
        if (jsx && args.Count > 2) attrs.Insert(0, $"key={{{Source(s, args[2], depth)}}}");
        if (!jsx) children.AddRange(args.Skip(2));
        var pad = new string(' ', depth * 2);
        var open = tag + (attrs.Count > 0 ? " " + string.Join(" ", attrs) : "");
        if (children.Count == 0) return $"{pad}<{open}{(tag.Length == 0 ? "></>" : " />")}";
        var sb = new StringBuilder($"{pad}<{open}>\n");
        foreach (var child in children)
        {
            var c = JsProgram.Unwrap(child);
            if (c is CallExpression cc && Callee(cc.Callee) is { } cn && Factories.Contains(cn) && IsElement(cc, cn)) sb.Append(Element(s, cc, depth + 1)).Append('\n');
            else if (JsProgram.Literal(c) is { } text && c is StringLiteral or TemplateLiteral) sb.Append(pad).Append("  ").Append(text.Replace("{", "{'{'}", StringComparison.Ordinal)).Append('\n');
            else sb.Append(pad).Append("  {").Append(Source(s, c, depth + 1)).Append("}\n");
        }
        return sb.Append($"{pad}</{tag}>").ToString();
    }

    // Source text of an expression with each element call in it written as JSX.
    private static string Source(State s, Node expr, int depth)
    {
        var nested = new List<CallExpression>();
        var stack = new Stack<Node>();
        stack.Push(expr);
        while (stack.Count > 0)
        {
            var n = stack.Pop();
            if (n is CallExpression call && Callee(call.Callee) is { } callee && Factories.Contains(callee) && IsElement(call, callee)) { nested.Add(call); continue; }
            foreach (var c in n.ChildNodes) if (c != null) stack.Push(c);
        }
        var text = s.P.Text;
        if (nested.Count == 0) return text[expr.Start..expr.End];
        nested.Sort((a, b) => a.Start.CompareTo(b.Start));
        var sb = new StringBuilder();
        int at = expr.Start;
        foreach (var call in nested)
        {
            sb.Append(text, at, call.Start - at);
            sb.Append(Element(s, call, depth + 1).TrimStart());
            at = call.End;
        }
        return sb.Append(text, at, expr.End - at).ToString();
    }

    // version = "x.y.z" assigned in a module or function that also assigns React's or ReactDOM's exports.
    private static List<string> Versions(JsProgram p, CancellationToken ct)
    {
        var byOwner = new Dictionary<Node, (string? Version, bool React, bool Dom)>();
        p.Walk((node, scope) =>
        {
            string? key = null;
            Node? value = null;
            if (node is AssignmentExpression { Left: MemberExpression { Computed: false, Property: Identifier k }, Right: var r }) (key, value) = (k.Name, r);
            else if (node is Property { Computed: false } pr && JsProgram.KeyName(pr.Key) is { } pk) (key, value) = (pk, pr.Value);
            if (key == null) return;
            var owner = scope.FunctionScope.Owner;
            var e = byOwner.GetValueOrDefault(owner);
            if (key == "version" && value != null && JsProgram.Unwrap(value) is StringLiteral v && v.Value.Length < 40 && char.IsDigit(v.Value.FirstOrDefault()) && v.Value.Count(c => c == '.') >= 2) e.Version ??= v.Value;
            else if (key is "useState" or "useEffect") e.React = true;
            else if (key is "createRoot" or "hydrateRoot" or "findDOMNode" or "createPortal" && !e.React) e.Dom = true;
            else return;
            byOwner[owner] = e;
        }, ct);
        return byOwner.Values.Where(e => e.Version != null && (e.React || e.Dom)).Select(e => $"{(e.React ? "react" : "react-dom")} {e.Version}").Distinct().Order(StringComparer.Ordinal).ToList();
    }
}
