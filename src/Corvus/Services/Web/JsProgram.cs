using Acornima;
using Acornima.Ast;

namespace Corvus.Services.Web;

/// <summary>A value the resolver can name: a string (exact or with {…} placeholders), a module member, a function or an object literal.</summary>
internal abstract record JsValue;

/// <param name="Exact">False when a part is computed and stands as a {name} placeholder.</param>
internal sealed record JsString(string Text, bool Exact) : JsValue;

/// <summary>A module's export path: Module "" is a global (an unbound name), Path "" the module itself.</summary>
internal sealed record JsRef(string Module, string Path) : JsValue
{
    public JsRef Member(string key) => this with { Path = Path.Length == 0 ? key : Path + "." + key };
}

internal sealed record JsFunction(IFunction Node, JsScope Scope) : JsValue;

internal sealed record JsObject(ObjectExpression Node, JsScope Scope) : JsValue;

/// <summary>A bundled module's exports (webpack table entry), read through its exports assignment and getter map.</summary>
internal sealed record JsModuleValue(JsModule Module) : JsValue;

/// <summary>An HTTP client instance with its base URL (axios.create).</summary>
internal sealed record JsClient(string Name, string? Base) : JsValue;

/// <summary>A lexical scope: its declarations, the function or block that owns it, and the bundle module when it is a module factory.</summary>
internal sealed class JsScope(JsScope? parent, Node owner, bool function)
{
    private Dictionary<string, JsBinding>? _names;
    public JsScope? Parent { get; } = parent;
    public Node Owner { get; } = owner;
    public bool IsFunction { get; } = function;
    public JsModule? Factory { get; set; }

    public JsScope FunctionScope
    {
        get
        {
            var s = this;
            while (!s.IsFunction && s.Parent != null) s = s.Parent;
            return s;
        }
    }

    public JsBinding Declare(string name)
    {
        _names ??= new Dictionary<string, JsBinding>(StringComparer.Ordinal);
        if (!_names.TryGetValue(name, out var b)) _names[name] = b = new JsBinding(name, this);
        return b;
    }

    public JsBinding? Lookup(string name)
    {
        for (var s = this; s != null; s = s.Parent)
            if (s._names != null && s._names.TryGetValue(name, out var b)) return b;
        return null;
    }
}

/// <summary>A declared name: its sources (initializers and assignments, with a destructuring path), or the parameter it is.</summary>
internal sealed class JsBinding(string name, JsScope scope)
{
    public string Name { get; } = name;
    public JsScope Scope { get; } = scope;
    public JsValue? Fixed { get; set; }
    public IFunction? ParamOf { get; set; }
    public int ParamIndex { get; set; } = -1;
    public List<(Node Expr, JsScope Scope, string[] Path)> Sources { get; } = [];
    internal JsValue? Cached;
    internal byte State; // 0 not evaluated, 1 evaluating, 2 done
}

/// <summary>
/// One parsed script with its scopes: names resolved to their declarations (var, let, const, function, class, parameters,
/// imports, destructuring), and a small evaluator that follows them to strings, module members (require, esbuild
/// __require, webpack module ids, interop wrappers, export getters), functions and object literals. Bounded depth, no execution.
/// </summary>
internal sealed class JsProgram
{
    private const int MaxDepth = 16;
    private static readonly HashSet<string> RequireNames = new(StringComparer.Ordinal) { "require", "__require", "__non_webpack_require__", "_require", "requireNative" };
    private static readonly HashSet<string> Interop = new(StringComparer.Ordinal)
    {
        "__toESM", "__toCommonJS", "__importDefault", "__importStar", "_interopRequireDefault", "_interopRequireWildcard",
        "_interop_require_default", "_interop_require_wildcard", "__importWildcard", "_$$_REQUIRE",
    };

    public string Path { get; }
    public string Text { get; }
    public Acornima.Ast.Program Tree { get; }
    public IReadOnlyList<JsModule> Modules { get; }
    public JsScope Root { get; }

    /// <summary>Names of the bundle's runtime require function outside the module factories (webpack's __webpack_require__, minified or not).</summary>
    public HashSet<string> RuntimeRequire { get; } = new(StringComparer.Ordinal) { "__webpack_require__" };

    private readonly Dictionary<string, JsModule> _byId = new(StringComparer.Ordinal);
    private readonly Dictionary<string, (Node Expr, JsScope Scope)> _exports = new(StringComparer.Ordinal);
    private readonly Dictionary<string, Dictionary<string, (Node Expr, JsScope Scope)>> _getters = new(StringComparer.Ordinal);

    private JsProgram(string path, string text, Acornima.Ast.Program tree, IReadOnlyList<JsModule> modules)
    {
        Path = path;
        Text = text;
        Tree = tree;
        Modules = modules;
        foreach (var m in modules) _byId.TryAdd(m.Id, m);
        Root = new JsScope(null, tree, true);
    }

    /// <summary>Parses and scopes <paramref name="text"/>; null with the reason in <paramref name="notes"/>.</summary>
    public static JsProgram? Build(string path, string text, List<string> notes, CancellationToken ct)
    {
        if (JsModules.Parse(text, notes) is not { } tree) return null;
        var program = new JsProgram(path, text, tree, JsModules.Find(text, tree, ct));
        program.Scope(ct);
        return program;
    }

    /// <summary>1-based line and column of <paramref name="node"/>, as editors show them.</summary>
    public string Site(Node node) => $"{Path}:{node.Location.Start.Line}:{node.Location.Start.Column + 1}";

    /// <summary>Every node in source order with its innermost scope.</summary>
    public void Walk(Action<Node, JsScope> visit, CancellationToken ct) => Walk(Tree, Root, visit, ct);

    /// <summary>The nodes under <paramref name="root"/> (whose enclosing scope is <paramref name="rootScope"/>) in source order with their scopes.</summary>
    public void Walk(Node root, JsScope rootScope, Action<Node, JsScope> visit, CancellationToken ct)
    {
        var stack = new Stack<(Node Node, JsScope Scope)>();
        stack.Push((root, rootScope));
        var children = new List<Node>();
        while (stack.Count > 0)
        {
            var (node, scope) = stack.Pop();
            if (node.UserData is JsScope own) scope = own;
            visit(node, scope);
            children.Clear();
            foreach (var c in node.ChildNodes)
                if (c != null) children.Add(c);
            for (int i = children.Count - 1; i >= 0; i--) stack.Push((children[i], scope));
            if ((stack.Count & 0xFFF) == 0) ct.ThrowIfCancellationRequested();
        }
    }

    // ---- scopes ----

    private readonly List<(string Name, JsScope Scope, Node Expr)> _assignments = [];

    private void Scope(CancellationToken ct)
    {
        Tree.UserData = Root;
        var factories = Modules.Where(m => m.Family is "webpack" or "browserify").GroupBy(m => m.Start).ToDictionary(g => g.Key, g => g.First());
        var stack = new Stack<(Node Node, JsScope Scope)>();
        foreach (var c in Tree.ChildNodes)
            if (c != null) stack.Push((c, Root));
        int n = 0;
        while (stack.Count > 0)
        {
            if ((++n & 0xFFF) == 0) ct.ThrowIfCancellationRequested();
            var (node, scope) = stack.Pop();
            switch (node)
            {
                case FunctionDeclaration fd:
                {
                    if (fd.Id != null) scope.Declare(fd.Id.Name).Fixed = new JsFunction(fd, scope);
                    if (fd is { Id: { } rid, Params: [Identifier rp] } && JsRuntime.Table(fd, rid.Name, rp.Name) != null) RuntimeRequire.Add(rid.Name);
                    var fs = Function(fd, scope, factories);
                    foreach (var s in fd.Body.Body) stack.Push((s, fs));
                    foreach (var p in fd.Params) PushDefaults(p, fs, stack);
                    continue;
                }
                case FunctionExpression fe:
                {
                    var fs = Function(fe, scope, factories);
                    if (fe.Id != null) fs.Declare(fe.Id.Name).Fixed = new JsFunction(fe, scope);
                    foreach (var s in fe.Body.Body) stack.Push((s, fs));
                    foreach (var p in fe.Params) PushDefaults(p, fs, stack);
                    continue;
                }
                case ArrowFunctionExpression af:
                {
                    var fs = Function(af, scope, factories);
                    if (af.Body is BlockStatement block) foreach (var s in block.Body) stack.Push((s, fs));
                    else stack.Push((af.Body, fs));
                    foreach (var p in af.Params) PushDefaults(p, fs, stack);
                    continue;
                }
                case BlockStatement or ForStatement or ForInStatement or ForOfStatement or SwitchStatement or StaticBlock:
                {
                    var bs = new JsScope(scope, node, false);
                    node.UserData = bs;
                    foreach (var c in node.ChildNodes)
                        if (c != null) stack.Push((c, bs));
                    continue;
                }
                case CatchClause cc:
                {
                    var cs = new JsScope(scope, node, false);
                    node.UserData = cs;
                    if (cc.Param != null) DeclarePattern(cc.Param, null, cs, [], cs);
                    stack.Push((cc.Body, cs));
                    continue;
                }
                case ClassDeclaration cd when cd.Id != null:
                    scope.Declare(cd.Id.Name);
                    break;
                case VariableDeclaration vd:
                {
                    var target = vd.Kind == VariableDeclarationKind.Var ? scope.FunctionScope : scope;
                    foreach (var d in vd.Declarations) DeclarePattern(d.Id, d.Init, scope, [], target);
                    break;
                }
                case ImportDeclaration id:
                    foreach (var s in id.Specifiers)
                    {
                        var path = s is ImportSpecifier { Imported: var imported } ? KeyName(imported) ?? "" : "";
                        scope.Declare(s.Local.Name).Fixed = new JsRef(id.Source.Value, path == "default" ? "" : path);
                    }
                    break;
                case AssignmentExpression { Operator: Operator.Assignment } ae:
                    if (ae.Left is Identifier li) _assignments.Add((li.Name, scope, ae.Right));
                    else if (ae.Left is MemberExpression me && scope.FunctionScope.Factory is { } module) Export(module, me, ae.Right, scope);
                    break;
                // webpack's export getters: r.d(exports, { name: () => value })
                case CallExpression { Callee: MemberExpression { Property: Identifier { Name: "d" }, Computed: false }, Arguments: [Identifier, ObjectExpression getters] }
                    when scope.FunctionScope.Factory is { } module:
                    foreach (var p in getters.Properties.OfType<Property>())
                        if (KeyName(p.Key) is { } key && Returned(p.Value) is { } returned)
                            Getters(module.Id)[key] = (returned, scope);
                    break;
            }
            foreach (var c in node.ChildNodes)
                if (c != null) stack.Push((c, scope));
        }
        foreach (var (name, scope, expr) in _assignments)
            if (scope.Lookup(name) is { } b && b.Fixed == null) b.Sources.Add((expr, scope, []));
        _assignments.Clear();
    }

    private static void PushDefaults(Node param, JsScope fs, Stack<(Node, JsScope)> stack)
    {
        if (param is AssignmentPattern ap) stack.Push((ap.Right, fs));
    }

    private static JsScope Function(IFunction fn, JsScope scope, Dictionary<int, JsModule> factories)
    {
        var node = (Node)fn;
        var fs = new JsScope(scope, node, true);
        node.UserData = fs;
        if (factories.TryGetValue(node.Start, out var m) && m.End == node.End) fs.Factory = m;
        for (int i = 0; i < fn.Params.Count; i++)
        {
            var p = fn.Params[i];
            if (p is Identifier or RestElement { Argument: Identifier })
            {
                var b = fs.Declare(p is Identifier id ? id.Name : ((Identifier)((RestElement)p).Argument).Name);
                b.ParamOf = fn;
                b.ParamIndex = i;
            }
            else DeclarePattern(p, null, fs, [], fs);
        }
        return fs;
    }

    private static void DeclarePattern(Node pattern, Node? init, JsScope initScope, string[] path, JsScope target)
    {
        switch (pattern)
        {
            case Identifier id:
                var b = target.Declare(id.Name);
                if (init != null) b.Sources.Add((init, initScope, path));
                break;
            case ObjectPattern op:
                foreach (var p in op.Properties)
                    if (p is Property prop && !prop.Computed && KeyName(prop.Key) is { } key) DeclarePattern(prop.Value, init, initScope, [.. path, key], target);
                    else if (p is RestElement rest) DeclarePattern(rest.Argument, null, initScope, path, target);
                break;
            case ArrayPattern ap:
                for (int i = 0; i < ap.Elements.Count; i++)
                    if (ap.Elements[i] is { } e) DeclarePattern(e, init, initScope, [.. path, "[" + i + "]"], target);
                break;
            case AssignmentPattern asg:
                DeclarePattern(asg.Left, init ?? asg.Right, init != null ? initScope : target, init != null ? path : [], target);
                break;
            case RestElement r:
                DeclarePattern(r.Argument, null, initScope, path, target);
                break;
        }
    }

    /// <summary>module.exports = v (the factory's first parameter) and exports.name = v (its second).</summary>
    private void Export(JsModule module, MemberExpression left, Node right, JsScope scope)
    {
        if (left is { Object: Identifier obj, Computed: false, Property: Identifier { Name: var prop } } && scope.Lookup(obj.Name) is { ParamIndex: var index } b
            && b.Scope.Factory == module)
        {
            if (index == 0 && prop == "exports") _exports[module.Id] = (right, scope);
            else if (index == 1) Getters(module.Id)[prop] = (right, scope);
        }
        else if (left is { Object: MemberExpression { Object: Identifier o2, Property: Identifier { Name: "exports" } }, Property: Identifier { Name: var key }, Computed: false }
                 && scope.Lookup(o2.Name) is { ParamIndex: 0 } m && m.Scope.Factory == module)
            Getters(module.Id)[key] = (right, scope);
    }

    private Dictionary<string, (Node, JsScope)> Getters(string id) =>
        _getters.TryGetValue(id, out var g) ? g : _getters[id] = new Dictionary<string, (Node, JsScope)>(StringComparer.Ordinal);

    /// <summary>The returned expression of a getter: an arrow's expression body or a single return statement.</summary>
    private static Node? Returned(Node fn) => fn switch
    {
        ArrowFunctionExpression { Body: Expression e } => e,
        IFunction { Body: BlockStatement { Body: [ReturnStatement { Argument: { } r }] } } => r,
        _ => null,
    };

    public static string? KeyName(Node? key) => key switch
    {
        Identifier i => i.Name,
        StringLiteral s => s.Value,
        NumericLiteral n => n.Raw,
        _ => null,
    };

    // ---- evaluation ----

    public JsValue? Eval(Node? expr, JsScope scope) => Eval(expr, scope, 0);

    private JsValue? Eval(Node? expr, JsScope scope, int depth)
    {
        if (expr == null || depth > MaxDepth) return null;
        switch (expr)
        {
            case StringLiteral s: return new JsString(s.Value, true);
            case NumericLiteral n: return new JsString(n.Raw, true);
            case TemplateLiteral t:
            {
                var sb = new System.Text.StringBuilder();
                bool exact = true;
                for (int i = 0; i < t.Quasis.Count; i++)
                {
                    sb.Append(t.Quasis[i].Value.Cooked ?? t.Quasis[i].Value.Raw);
                    if (i < t.Expressions.Count) exact &= Part(sb, Eval(t.Expressions[i], scope, depth + 1), t.Expressions[i]);
                }
                return new JsString(sb.ToString(), exact);
            }
            case BinaryExpression { Operator: Operator.Addition } b:
            {
                var l = Eval(b.Left, scope, depth + 1);
                var r = Eval(b.Right, scope, depth + 1);
                if (l is not JsString && r is not JsString) return null;
                var sb = new System.Text.StringBuilder();
                bool exact = Part(sb, l, b.Left);
                exact &= Part(sb, r, b.Right);
                return new JsString(sb.ToString(), exact);
            }
            case Identifier id:
                if (id.Name == "__dirname") return new JsString("{__dirname}", false);
                if (scope.Lookup(id.Name) is not { } binding) return new JsRef("", id.Name);
                return Value(binding, depth + 1);
            case MemberExpression m:
            {
                string? key = m.Computed ? (Eval(m.Property, scope, depth + 1) is JsString { Exact: true } ks ? ks.Text : null) : KeyName(m.Property);
                return key == null ? null : Member(Eval(m.Object, scope, depth + 1), key, depth);
            }
            case CallExpression c: return Call(c, scope, depth);
            case SequenceExpression seq: return seq.Expressions.Count > 0 ? Eval(seq.Expressions[^1], scope, depth + 1) : null;
            case ParenthesizedExpression p: return Eval(p.Expression, scope, depth + 1);
            case ChainExpression ch: return Eval(ch.Expression, scope, depth + 1);
            case AwaitExpression aw: return Eval(aw.Argument, scope, depth + 1);
            case ConditionalExpression ce: return Eval(ce.Consequent, scope, depth + 1) ?? Eval(ce.Alternate, scope, depth + 1);
            case LogicalExpression { Operator: Operator.LogicalAnd } la: return Eval(la.Right, scope, depth + 1);
            case LogicalExpression lo: return Eval(lo.Left, scope, depth + 1) ?? Eval(lo.Right, scope, depth + 1);
            case ObjectExpression o: return new JsObject(o, scope);
            case FunctionExpression or ArrowFunctionExpression: return new JsFunction((IFunction)expr, scope);
            case ImportExpression ie: return Eval(ie.Source, scope, depth + 1) is JsString { Exact: true } src ? new JsRef(src.Text, "") : null;
            default: return null;
        }
    }

    /// <summary>Appends a string part, or a {name} placeholder for a value that is not one; false when a placeholder was written.</summary>
    private static bool Part(System.Text.StringBuilder sb, JsValue? v, Node node)
    {
        if (v is JsString s)
        {
            sb.Append(s.Text);
            return s.Exact;
        }
        sb.Append('{').Append(node switch
        {
            Identifier i => i.Name,
            MemberExpression { Property: Identifier p, Computed: false } => p.Name,
            _ => "",
        }).Append('}');
        return false;
    }

    public JsValue? Value(JsBinding b) => Value(b, 0);

    /// <summary>A member of a value: an object literal's property, a module export, a module member path.</summary>
    public JsValue? Get(JsValue? obj, string key) => Member(obj, key, 0);

    private JsValue? Value(JsBinding b, int depth)
    {
        if (b.Fixed != null) return b.Fixed;
        if (b.State == 2) return b.Cached;
        if (b.State == 1) return null; // a cycle
        // one source, not counting null and undefined (let x; try { x = require(...) } catch { x = null })
        var sources = b.Sources.Count == 1 ? b.Sources : b.Sources.Where(s => s.Expr is not (NullLiteral or Identifier { Name: "undefined" } or UnaryExpression { Operator: Operator.Void })).ToList();
        if (sources.Count != 1) return null;
        b.State = 1;
        var (expr, scope, path) = sources[0];
        var v = Eval(expr, scope, depth + 1);
        foreach (var key in path) v = Member(v, key, depth);
        b.Cached = v;
        b.State = 2;
        return v;
    }

    private JsValue? Member(JsValue? obj, string key, int depth) => obj switch
    {
        JsRef r => key == "default" && r.Path.Length == 0 ? r : r.Member(key),
        JsObject o => Property(o, key, depth),
        JsModuleValue mv => ModuleMember(mv.Module, key, depth),
        JsString s when key == "length" => new JsString(s.Text.Length.ToString(System.Globalization.CultureInfo.InvariantCulture), s.Exact),
        _ => null,
    };

    private JsValue? Property(JsObject o, string key, int depth)
    {
        foreach (var p in o.Node.Properties)
            if (p is Property prop && !prop.Computed && KeyName(prop.Key) == key)
                return prop.Kind == PropertyKind.Get && Returned(prop.Value) is { } got ? Eval(got, o.Scope, depth + 1) : Eval(prop.Value, o.Scope, depth + 1);
        return null;
    }

    private JsValue? ModuleMember(JsModule m, string key, int depth)
    {
        if (_getters.TryGetValue(m.Id, out var g) && g.TryGetValue(key, out var getter)) return Eval(getter.Expr, getter.Scope, depth + 1);
        if (key == "default" && !(_getters.TryGetValue(m.Id, out var g2) && g2.ContainsKey("default"))) return new JsModuleValue(m);
        return new JsRef("#" + m.Id, key);
    }

    private JsValue? Call(CallExpression c, JsScope scope, int depth)
    {
        var callee = Unwrap(c.Callee);
        var args = c.Arguments;
        if (args.Count >= 1 && Literal(args[0]) is { } request)
        {
            if (callee is Identifier ci)
            {
                var b = scope.Lookup(ci.Name);
                // a webpack factory's third parameter (any name): the bundle's require
                if (b is { ParamIndex: 2 } && b.Scope.Factory != null || RuntimeRequire.Contains(ci.Name) && b?.Fixed is JsFunction) return Bundled(request, depth);
                // esbuild declares its __require shim; the names are distinctive enough to trust bound or not
                if (RequireNames.Contains(ci.Name)) return new JsRef(request, "");
                if (b != null && Value(b, depth + 1) is JsRef { Module: "", Path: var alias } && RequireNames.Contains(alias)) return new JsRef(request, "");
            }
            if (callee is MemberExpression { Object: Identifier { Name: "process" }, Property: Identifier { Name: "dlopen" } } && args.Count >= 2 && Literal(args[1]) is { } lib)
                return new JsRef(lib, "");
        }
        if (args.Count >= 1 && (callee is Identifier { Name: var wrapper } && Interop.Contains(wrapper)
                                || callee is MemberExpression { Property: Identifier { Name: "n" or "t" }, Computed: false } && args.Count <= 2))
            return Eval(args[0], scope, depth + 1);
        var target = Eval(callee, scope, depth + 1);
        switch (target)
        {
            case JsRef { Module: "bindings", Path: "" } when args.Count >= 1 && Eval(args[0], scope, depth + 1) is JsString { Exact: true } name:
                return new JsRef("bindings:" + name.Text, "");
            case JsRef r when r.Module is "path" or "node:path" && r.Path is "join" or "resolve" or "posix.join" || r is { Module: "", Path: "path.join" or "path.resolve" }:
                return Join(args, scope, depth);
            case JsRef r when r.Module.Contains("axios", StringComparison.Ordinal) && r.Path == "create" || r is { Module: "", Path: "axios.create" }:
                return new JsClient("axios", args.Count > 0 && Eval(args[0], scope, depth + 1) is JsObject cfg && Property(cfg, "baseURL", depth) is JsString b2 ? b2.Text : null);
            case JsRef r when args.Count == 0 && r.Path.Length == 0:
                return r; // a getter such as webpack's n.n(module)()
            case JsModuleValue mv when args.Count == 0:
                return mv;
            case JsFunction f when Returned((Node)f.Node) is { } returned && f.Node.Params.Count == 0:
                return Eval(returned, (JsScope?)((Node)f.Node).UserData ?? f.Scope, depth + 1);
        }
        return null;
    }

    /// <summary>A webpack require of a module id: the module's exports when they resolve, else the module itself.</summary>
    private JsValue? Bundled(string id, int depth)
    {
        if (!_byId.TryGetValue(id, out var m)) return new JsRef(id, "");
        if (_exports.TryGetValue(id, out var e) && Eval(e.Expr, e.Scope, depth + 1) is { } v and not JsObject) return v;
        return new JsModuleValue(m);
    }

    private JsString? Join(in NodeList<Expression> args, JsScope scope, int depth)
    {
        var parts = new List<string>();
        bool exact = true;
        foreach (var a in args)
        {
            var v = Eval(a, scope, depth + 1);
            if (v is JsString s) { parts.Add(s.Text); exact &= s.Exact; }
            else { parts.Add("{" + (a is Identifier i ? i.Name : "") + "}"); exact = false; }
        }
        if (parts.Count == 0) return null;
        var segments = new List<string>();
        foreach (var part in parts)
            foreach (var seg in part.Replace('\\', '/').Split('/', StringSplitOptions.RemoveEmptyEntries))
            {
                if (seg == ".") continue;
                if (seg == ".." && segments.Count > 0 && segments[^1] != ".." && !segments[^1].StartsWith('{')) segments.RemoveAt(segments.Count - 1);
                else segments.Add(seg);
            }
        return new JsString(string.Join('/', segments), exact);
    }

    public static Node Unwrap(Node n)
    {
        while (true)
        {
            switch (n)
            {
                case ParenthesizedExpression p: n = p.Expression; continue;
                case SequenceExpression { Expressions.Count: > 0 } s: n = s.Expressions[^1]; continue;
                case ChainExpression c: n = c.Expression; continue;
            }
            return n;
        }
    }

    public static string? Literal(Node n) => n switch
    {
        StringLiteral s => s.Value,
        NumericLiteral num => num.Raw,
        TemplateLiteral { Expressions.Count: 0, Quasis: [var q] } => q.Value.Cooked,
        _ => null,
    };

    /// <summary>The callee as a dotted chain of names (window.api.invoke), or null when a part is computed or a call.</summary>
    public static string? Chain(Node n)
    {
        var parts = new List<string>();
        for (n = Unwrap(n); ; n = Unwrap(((MemberExpression)n).Object))
        {
            switch (n)
            {
                case Identifier i: parts.Add(i.Name); parts.Reverse(); return string.Join('.', parts);
                case ThisExpression: parts.Add("this"); parts.Reverse(); return string.Join('.', parts);
                case MemberExpression { Computed: false, Property: Identifier p }: parts.Add(p.Name); continue;
                case MemberExpression { Computed: true, Property: StringLiteral s }: parts.Add(s.Value); continue;
                default: return null;
            }
        }
    }
}
