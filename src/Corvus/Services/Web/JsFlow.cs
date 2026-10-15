using System.Diagnostics;
using Acornima;
using Acornima.Ast;
using Corvus.Core;

namespace Corvus.Services.Web;

/// <summary>One step of a data flow: what the value passes through, at which generated line:column, in which module, and where that is in the original source.</summary>
public sealed record JsFlowStep(string Kind, string Text, string Site)
{
    public string? Module { get; init; }
    public string? Original { get; init; }
    /// <summary>A network sink's row, the same as analyze_js view=endpoints gives.</summary>
    public JsEndpoint? Endpoint { get; init; }
    /// <summary>An IPC sink's channel pairing from the Electron graph, or why a step is unknown.</summary>
    public string? Link { get; init; }
}

/// <summary>One flow from a seed to where it ends: a sink, an unknown, an origin (back) or a plain end.</summary>
public sealed record JsFlowPath(string End, IReadOnlyList<JsFlowStep> Steps);

/// <summary>analyze_js view=flow and view=origins: the flows of a query, their counts and whether a budget cut the walk short.</summary>
public sealed record JsFlowResult(string Query, int Seeds, int Steps, int Sinks, int Unknowns, int Origins, int Total, string? Partial,
    IReadOnlyList<JsFlowPath> Flows);

/// <summary>
/// Data flow over one parsed file, on its syntax tree: assignments and destructuring, call arguments to parameters, returns
/// to call sites (also through webpack module requires, exports and getters), closures, object and class properties,
/// promise chains (then, await, new Promise resolve), and effect sinks (fetch, XMLHttpRequest, WebSocket, EventSource,
/// sendBeacon, HTTP clients, child_process, fs, eval / Function, postMessage, Electron IPC, windows, shell, workers, dynamic import, DOM
/// HTML). Where the tree cannot follow (a computed key or call, an external module, a caller nobody resolves) the flow ends
/// in an explicit unknown step. Walks are breadth-first, each state once, inside a step, time and allocation budget.
/// </summary>
internal sealed class JsFlow
{
    public sealed record Budget(int Steps, TimeSpan Time, long Bytes)
    {
        public static readonly Budget Default = new(200_000, TimeSpan.FromSeconds(20), 512L * 1024 * 1024);
    }

    /// <summary>A resolved call: the functions it reaches (Shift: arguments before the first parameter, as in f.call), or the module member it names.</summary>
    private sealed record Target(IReadOnlyList<IFunction> Functions, int Shift, JsRef? Ref, string? Why)
    {
        /// <summary>Resolved by a method name unique in the file, the receiver unknown.</summary>
        public bool ByName { get; init; }
    }

    private sealed record Sink(string Category, string Call, int[]? Args, JsEndpoint? Endpoint);

    private sealed record Ret(IFunction Function);

    /// <summary>A property of one object: an object literal, a class (instances share it), or a bundled module ("module:id").</summary>
    private sealed record Slot(object Owner, string Key);

    private sealed record Step(string Kind, string Text, Node At, int From, string? End)
    {
        public JsEndpoint? Endpoint { get; init; }
        public string? Link { get; init; }
    }

    private static readonly HashSet<string> ChildProcess = new(StringComparer.Ordinal) { "child_process", "node:child_process" };
    private static readonly HashSet<string> Fs = new(StringComparer.Ordinal) { "fs", "node:fs", "fs/promises", "node:fs/promises", "original-fs", "fs-extra", "graceful-fs" };
    private static readonly HashSet<string> Http = new(StringComparer.Ordinal) { "http", "https", "node:http", "node:https", "http2", "node:http2", "undici", "node-fetch", "got", "request", "superagent", "axios" };
    private static readonly HashSet<string> ProcessCalls = new(StringComparer.Ordinal) { "exec", "execSync", "execFile", "execFileSync", "spawn", "spawnSync", "fork" };
    private static readonly HashSet<string> FsWrites = new(StringComparer.Ordinal)
    {
        "writeFile", "writeFileSync", "appendFile", "appendFileSync", "unlink", "unlinkSync", "rm", "rmSync", "rmdir", "rmdirSync", "rename", "renameSync",
        "copyFile", "copyFileSync", "cp", "cpSync", "chmod", "chmodSync", "createWriteStream", "symlink", "symlinkSync", "outputFile", "outputFileSync", "remove",
        "removeSync", "mkdir", "mkdirSync", "write", "writeSync", "truncate", "truncateSync", "writeJson", "writeJsonSync",
    };
    private static readonly HashSet<string> Globals = new(StringComparer.Ordinal) { "window", "globalThis", "self", "global" };

    // calls whose result carries their arguments: globals, module members and methods of any receiver
    private static readonly HashSet<string> PassCalls = new(StringComparer.Ordinal)
    {
        "JSON.stringify", "JSON.parse", "String", "Number", "encodeURIComponent", "encodeURI", "decodeURIComponent", "decodeURI", "escape", "unescape", "btoa", "atob",
        "Object.assign", "Object.freeze", "Object.values", "Object.entries", "Object.fromEntries", "Array.from", "Array.of", "Promise.resolve", "Promise.all",
        "Promise.allSettled", "Promise.race", "Promise.any", "Buffer.from", "structuredClone", "URL", "URLSearchParams", "Request", "Response", "Blob", "Headers",
        "String.raw", "Uint8Array", "TextEncoder", "TextDecoder", "FormData",
    };
    private static readonly HashSet<string> PassModules = new(StringComparer.Ordinal) { "path", "node:path", "url", "node:url", "querystring", "node:querystring", "util", "node:util" };
    private static readonly HashSet<string> ReceiverPass = new(StringComparer.Ordinal)
    {
        "trim", "trimStart", "trimEnd", "toLowerCase", "toUpperCase", "toLocaleLowerCase", "toLocaleUpperCase", "slice", "substring", "substr", "replace", "replaceAll",
        "split", "concat", "padStart", "padEnd", "normalize", "toString", "valueOf", "at", "charAt", "repeat", "join", "map", "filter", "flat", "flatMap", "reverse",
        "sort", "toJSON", "json", "text", "arrayBuffer", "blob", "formData", "clone", "encode", "decode", "finally", "catch", "get", "find", "pop", "shift", "values",
        "toSorted", "toReversed", "with", "subarray",
    };
    private static readonly HashSet<string> ArgPass = new(StringComparer.Ordinal)
    {
        "concat", "replace", "replaceAll", "padStart", "padEnd", "encode", "decode", "stringify", "parse", "from", "of", "assign", "resolve", "all", "allSettled",
        "race", "any", "join", "format", "fromEntries", "freeze",
    };
    private static readonly HashSet<string> AddTo = new(StringComparer.Ordinal) { "push", "unshift", "set", "add", "append", "splice" };
    private static readonly HashSet<string> Each = new(StringComparer.Ordinal) { "forEach", "map", "filter", "find", "findIndex", "findLast", "some", "every", "flatMap" };

    // method names of built-in types: never resolved by name alone
    private static readonly HashSet<string> Builtin = new(StringComparer.Ordinal)
    {
        "get", "set", "has", "add", "delete", "clear", "push", "pop", "shift", "unshift", "splice", "slice", "map", "filter", "forEach", "find", "includes",
        "indexOf", "join", "keys", "values", "entries", "then", "catch", "finally", "call", "apply", "bind", "toString", "valueOf", "on", "once", "off", "emit",
        "send", "write", "read", "close", "open", "start", "stop", "next", "resolve", "reject", "test", "exec", "match", "replace", "split", "concat", "sort",
        "reverse", "fill", "some", "every", "reduce", "at", "append", "remove", "appendChild", "removeChild", "setAttribute", "getAttribute", "addEventListener",
        "removeEventListener", "postMessage", "dispatchEvent", "abort", "cancel", "destroy", "dispose", "update", "render", "init", "run", "load", "parse",
        "toJSON", "json", "text", "clone", "copy", "equals", "compare", "create", "transform", "fetch", "request", "subscribe", "error", "log", "warn", "info",
    };

    private readonly JsProgram _p;
    private readonly SourceMap? _map;
    private readonly string? _fullPath;
    private readonly Dictionary<Node, Node> _parent = new(1 << 16);
    private readonly Dictionary<JsBinding, List<Identifier>> _reads = [];
    private readonly Dictionary<string, List<JsBinding>> _bindings = new(StringComparer.Ordinal);
    private readonly List<Node> _calls = [];
    private readonly Dictionary<Node, Target> _targets = [];
    private readonly Dictionary<IFunction, List<(Node Call, int Shift)>> _callers = [];
    private readonly Dictionary<IFunction, Node> _thenOf = [];
    private readonly Dictionary<IFunction, NewExpression> _executors = [];
    private readonly Dictionary<JsBinding, Node> _classes = [];
    private readonly Dictionary<JsBinding, Node> _iterated = [];
    private readonly Dictionary<JsBinding, Identifier> _declared = [];
    private readonly Dictionary<string, List<MemberExpression>> _members = new(StringComparer.Ordinal);
    private readonly Dictionary<string, List<IFunction>> _methods = new(StringComparer.Ordinal);
    private readonly Dictionary<string, List<Node>> _requires = new(StringComparer.Ordinal);
    private readonly Dictionary<Node, (string Module, string Key)> _exportExprs = [];
    private readonly Dictionary<string, List<(string Key, Node Expr)>> _exports = new(StringComparer.Ordinal);
    private readonly Dictionary<Node, object?> _owners = [];
    private readonly Dictionary<IFunction, List<Node>> _returns = [];
    private readonly Dictionary<Node, Sink?> _sinks = [];
    private readonly JsModule[] _modules;
    private Dictionary<string, JsEndpoint>? _endpoints;
    private Dictionary<string, string>? _ipc;
    private string? _ipcFile;

    public JsFlow(JsProgram program, SourceMap? map, string? fullPath, CancellationToken ct)
    {
        _p = program;
        _map = map;
        _fullPath = fullPath;
        _modules = [.. program.Modules.OrderBy(m => m.Start)];
        Index(ct);
    }

    // ---- index ----

    private void Index(CancellationToken ct)
    {
        var stack = new Stack<(Node Node, Node? Parent, JsScope Scope)>();
        stack.Push((_p.Tree, null, _p.Root));
        int n = 0;
        while (stack.Count > 0)
        {
            if ((++n & 0xFFF) == 0) ct.ThrowIfCancellationRequested();
            var (node, parent, scope) = stack.Pop();
            if (node.UserData is JsScope own) scope = own;
            if (parent != null) _parent[node] = parent;
            switch (node)
            {
                case Identifier id when parent != null:
                    if (Reference(id, parent) is var read && scope.Lookup(id.Name) is { } b)
                    {
                        if (read) Add(_reads, b, id);
                        else if (Declares(id, parent) && _declared.TryAdd(b, id)) Add(_bindings, id.Name, b);
                    }
                    break;
                case CallExpression or NewExpression:
                    _calls.Add(node);
                    break;
                case MemberExpression m when Key(m) is { } key:
                    Add(_members, key, m);
                    break;
                case MethodDefinition { Computed: false, Kind: PropertyKind.Method } md when ElementKey(md.Key) is { } mk:
                    Add(_methods, mk, md.Value);
                    break;
                case ClassDeclaration { Id: { } cid } cd when scope.Lookup(cid.Name) is { } cb:
                    _classes.TryAdd(cb, cd);
                    break;
                case ForOfStatement { Left: VariableDeclaration { Declarations: [{ Id: Identifier fid }] } } fo:
                    if (((JsScope?)fo.UserData ?? scope).Lookup(fid.Name) is { } ib) _iterated.TryAdd(ib, fo.Right);
                    break;
            }
            foreach (var c in node.ChildNodes)
                if (c != null) stack.Push((c, node, scope));
        }
        foreach (var (module, key, expr, _) in _p.Exports())
        {
            _exportExprs.TryAdd(expr, (module, key));
            if (!_exports.TryGetValue(module, out var list)) _exports[module] = list = [];
            list.Add((key, expr));
        }
        foreach (var call in _calls)
        {
            if ((++n & 0x3FF) == 0) ct.ThrowIfCancellationRequested();
            var scope = ScopeOf(call);
            if (call is CallExpression c && _p.BundledId(c, scope) is { } id) Add(_requires, id, call);
            var t = TargetOf(call);
            foreach (var f in t.Functions)
            {
                if (!_callers.TryGetValue(f, out var list)) _callers[f] = list = [];
                list.Add((call, t.Shift));
            }
            if (call is CallExpression { Callee: MemberExpression { Property: Identifier { Name: "then" or "catch" or "finally" }, Computed: false } } pc)
                foreach (var a in pc.Arguments)
                    if (FunctionValue(a, scope) is { } cb) _thenOf.TryAdd(cb, call);
            if (call is NewExpression { Callee: Identifier { Name: "Promise" }, Arguments: [var exec, ..] } ne && FunctionValue(exec, scope) is { } ef)
                _executors.TryAdd(ef, ne);
        }
    }

    /// <summary>A member's static name: an identifier, a private #name, or a literal computed key; null when the key is computed.</summary>
    private static string? Key(MemberExpression m) => m.Property switch
    {
        _ when m.Computed => JsProgram.Literal(m.Property),
        Identifier i => i.Name,
        PrivateIdentifier pi => "#" + pi.Name,
        _ => null,
    };

    /// <summary>A class element's name, private ones as #name.</summary>
    private static string? ElementKey(Node key) => key is PrivateIdentifier p ? "#" + p.Name : JsProgram.KeyName(key);

    private static void Add<TKey, TValue>(Dictionary<TKey, List<TValue>> d, TKey key, TValue value) where TKey : notnull
    {
        if (!d.TryGetValue(key, out var list)) d[key] = list = [];
        list.Add(value);
    }

    /// <summary>Whether an identifier reads its binding (false for declarations, plain assignment targets, keys and labels).</summary>
    private static bool Reference(Identifier id, Node parent) => parent switch
    {
        MemberExpression m => m.Computed || !ReferenceEquals(m.Property, id),
        Property p when ReferenceEquals(p.Value, id) => p is not AssignmentProperty,
        Property p => p.Computed && ReferenceEquals(p.Key, id),
        PropertyDefinition pd => ReferenceEquals(pd.Value, id) || pd.Computed && ReferenceEquals(pd.Key, id),
        MethodDefinition or AccessorProperty => false,
        VariableDeclarator d => !ReferenceEquals(d.Id, id),
        IFunction f => ReferenceEquals(f.Body, id),
        ClassDeclaration or ClassExpression => !ReferenceEquals(((IClass)parent).Id, id),
        AssignmentExpression a => !ReferenceEquals(a.Left, id) || a.Operator != Operator.Assignment,
        AssignmentPattern ap => !ReferenceEquals(ap.Left, id),
        ArrayPattern or ObjectPattern or RestElement or CatchClause => false,
        LabeledStatement or BreakStatement or ContinueStatement => false,
        ImportSpecifier or ImportDefaultSpecifier or ImportNamespaceSpecifier => false,
        ExportSpecifier e => ReferenceEquals(e.Local, id),
        MetaProperty => false,
        _ => true,
    };

    /// <summary>Whether an identifier declares its binding: a variable, parameter, function or class name, a pattern element, an import.</summary>
    private static bool Declares(Identifier id, Node parent) => parent switch
    {
        VariableDeclarator d => ReferenceEquals(d.Id, id),
        IFunction f => !ReferenceEquals(f.Body, id),
        AssignmentPattern ap => ReferenceEquals(ap.Left, id),
        AssignmentProperty p => ReferenceEquals(p.Value, id),
        ArrayPattern or RestElement or CatchClause or ClassDeclaration or ClassExpression => true,
        ImportSpecifier or ImportDefaultSpecifier or ImportNamespaceSpecifier => true,
        _ => false,
    };

    private Node? Up(Node? n) => n == null ? null : _parent.GetValueOrDefault(n);

    private JsScope ScopeOf(Node node)
    {
        for (Node? n = node; n != null; n = _parent.GetValueOrDefault(n))
            if (n.UserData is JsScope s) return s;
        return _p.Root;
    }

    private IFunction? FunctionOf(Node node)
    {
        for (var n = _parent.GetValueOrDefault(node); n != null; n = _parent.GetValueOrDefault(n))
            if (n is IFunction f) return f;
        return null;
    }

    private IFunction? FunctionValue(Node expr, JsScope scope) =>
        JsProgram.Unwrap(expr) is IFunction f ? f : _p.Eval(expr, scope) is JsFunction jf ? jf.Node : null;

    // ---- resolution ----

    private Target TargetOf(Node call)
    {
        if (_targets.TryGetValue(call, out var cached)) return cached;
        var t = Resolve(call);
        _targets[call] = t;
        return t;
    }

    private Target Resolve(Node call)
    {
        var scope = ScopeOf(call);
        var calleeNode = call is CallExpression c0 ? c0.Callee : ((NewExpression)call).Callee;
        var callee = JsProgram.Unwrap(calleeNode);
        if (call is NewExpression)
        {
            if (ClassOf(callee, scope) is { } cls)
                return Constructor(cls, 0) is { } ctor ? new Target([ctor], 0, null, null) : new Target([], 0, null, "class without a constructor");
        }
        if (callee is IFunction direct) return new Target([direct], 0, null, null);
        var v = _p.Eval(callee, scope);
        if (v is JsFunction f) return new Target([f.Node], 0, null, null);
        if (v is JsRef r) return new Target([], 0, r, null);
        if (callee is Super && SuperClass(call) is { } parent)
            return Constructor(parent, 0) is { } sc ? new Target([sc], 0, null, null) : new Target([], 0, null, "super class without a constructor");
        if (callee is MemberExpression me && Key(me) is { } key)
        {
            if (key is "call" or "apply" && FunctionValue(me.Object, scope) is { } fc) return new Target([fc], key == "call" ? 1 : int.MaxValue, null, null);
            if (me.Object is Super && SuperClass(call) is { } sup)
                return Method(sup, key, 0) is { } sm ? new Target([sm], 0, null, null) : new Target([], 0, null, $"super.{key} not found");
            var owner = OwnerOf(me.Object);
            if (owner is Node cls && cls is IClass && Method(cls, key, 0) is { } m) return new Target([m], 0, null, null);
            if (owner is ObjectExpression o && PropertyValue(o, key) is { } pv && FunctionValue(pv, ScopeOf(pv)) is { } of) return new Target([of], 0, null, null);
            // an unresolved receiver: a method name only one class of the file defines, and no built-in type has
            if (owner == null && !Builtin.Contains(key) && _methods.GetValueOrDefault(key) is [var only]) return new Target([only], 0, null, null) { ByName = true };
            return new Target([], 0, null, $".{key}() on an unresolved receiver ({Snip(me.Object)})");
        }
        if (callee is MemberExpression) return new Target([], 0, null, "computed call " + Snip(callee));
        if (callee is Identifier id && scope.Lookup(id.Name) is { } b)
            return new Target([], 0, null, b.ParamOf != null ? $"parameter {id.Name} called" : $"{id.Name} not resolved to a function");
        return new Target([], 0, null, "callee " + Snip(callee));
    }

    /// <summary>Higher-order calls: a parameter called inside f reaches the functions its callers pass at that index.</summary>
    private List<IFunction> Passed(Node call)
    {
        var found = new List<IFunction>();
        var callee = JsProgram.Unwrap(call is CallExpression c ? c.Callee : ((NewExpression)call).Callee);
        if (callee is not Identifier id || ScopeOf(call).Lookup(id.Name) is not { ParamOf: { } fn, ParamIndex: var index }) return found;
        foreach (var (site, shift) in _callers.GetValueOrDefault(fn) ?? [])
            if (Args(site) is var args && index + shift < args.Count && shift != int.MaxValue && FunctionValue(args[index + shift], ScopeOf(site)) is { } g && !found.Contains(g))
                found.Add(g);
        return found;
    }

    private static NodeList<Expression> Args(Node call) => call is CallExpression c ? c.Arguments : ((NewExpression)call).Arguments;

    private Node? ClassOf(Node expr, JsScope scope)
    {
        expr = JsProgram.Unwrap(expr);
        if (expr is ClassExpression or ClassDeclaration) return expr;
        if (expr is Identifier id && scope.Lookup(id.Name) is { } b)
        {
            if (_classes.TryGetValue(b, out var cls)) return cls;
            if (b.Sources is [{ Expr: var src, Path.Length: 0 }] && JsProgram.Unwrap(src) is ClassExpression ce) return ce;
        }
        return null;
    }

    private Node? SuperClass(Node at)
    {
        for (var n = _parent.GetValueOrDefault(at); n != null; n = _parent.GetValueOrDefault(n))
            if (n is IClass { SuperClass: { } s } cls) return ClassOf(s, ScopeOf((Node)cls));
        return null;
    }

    private IFunction? Method(Node cls, string key, int depth)
    {
        if (depth > 8 || cls is not IClass c) return null;
        foreach (var e in c.Body.Body)
            if (e is MethodDefinition { Computed: false } md && ElementKey(md.Key) == key && md.Kind != PropertyKind.Constructor) return md.Value;
        return c.SuperClass != null && ClassOf(c.SuperClass, ScopeOf(cls)) is { } sup ? Method(sup, key, depth + 1) : null;
    }

    private IFunction? Constructor(Node cls, int depth)
    {
        if (depth > 8 || cls is not IClass c) return null;
        foreach (var e in c.Body.Body)
            if (e is MethodDefinition { Kind: PropertyKind.Constructor } md) return md.Value;
        return c.SuperClass != null && ClassOf(c.SuperClass, ScopeOf(cls)) is { } sup ? Constructor(sup, depth + 1) : null;
    }

    private static Node? PropertyValue(ObjectExpression o, string key)
    {
        foreach (var p in o.Properties)
            if (p is Property { Computed: false } prop && JsProgram.KeyName(prop.Key) == key) return prop.Value;
        return null;
    }

    /// <summary>The object a property access reads from: an object literal, a class (this, new C, C itself) or a bundled module.</summary>
    private object? OwnerOf(Node expr)
    {
        expr = JsProgram.Unwrap(expr);
        if (_owners.TryGetValue(expr, out var cached)) return cached;
        _owners[expr] = null; // cycles
        var owner = Owner(expr);
        _owners[expr] = owner;
        return owner;
    }

    private object? Owner(Node expr)
    {
        if (expr is ThisExpression) return ThisOwner(expr);
        if (expr is ObjectExpression) return expr;
        var scope = ScopeOf(expr);
        if (expr is CallExpression c && _p.BundledId(c, scope) is { } id) return "module:" + id;
        if (ClassOf(expr, scope) is { } cls) return cls;
        if (expr is Identifier ident && scope.Lookup(ident.Name) is { Fixed: null, Sources: [{ Path.Length: 0 } src] })
        {
            var s = JsProgram.Unwrap(src.Expr);
            if (s is ThisExpression) return ThisOwner(s);
            if (s is NewExpression ne && ClassOf(ne.Callee, ScopeOf(ne)) is { } ncls) return ncls;
            if (s is CallExpression sc && _p.BundledId(sc, src.Scope) is { } sid) return "module:" + sid;
        }
        return _p.Eval(expr, scope) switch
        {
            JsObject o => o.Node,
            JsModuleValue mv => "module:" + mv.Module.Id,
            _ => null,
        };
    }

    /// <summary>What this is inside the nearest non-arrow function: its class, or the object literal holding the method.</summary>
    private Node? ThisOwner(Node at)
    {
        for (var n = _parent.GetValueOrDefault(at); n != null; n = _parent.GetValueOrDefault(n))
        {
            if (n is ArrowFunctionExpression) continue;
            if (n is PropertyDefinition or StaticBlock) return Up(Up(n));
            if (n is not IFunction) continue;
            var up = _parent.GetValueOrDefault(n);
            if (up is MethodDefinition md) return Up(Up(md));
            if (up is Property && _parent.GetValueOrDefault(up) is ObjectExpression o) return o;
            return null;
        }
        return null;
    }

    private string OwnerName(object owner) => owner switch
    {
        string s => s,
        IClass { Id: { } id } => id.Name,
        IClass c => "class at " + Line((Node)c),
        Node n => "object at " + Line(n),
        _ => "?",
    };

    private List<Node> Returns(IFunction f)
    {
        if (_returns.TryGetValue(f, out var list)) return list;
        list = [];
        if (f is ArrowFunctionExpression { Body: Expression e }) list.Add(e);
        else
        {
            var stack = new Stack<Node>();
            stack.Push(f.Body);
            while (stack.Count > 0)
            {
                var n = stack.Pop();
                if (n is ReturnStatement { Argument: { } a }) list.Add(a);
                foreach (var c in n.ChildNodes)
                    if (c != null && c is not IFunction && c is not IClass) stack.Push(c);
            }
        }
        _returns[f] = list;
        return list;
    }

    private string FnName(IFunction f)
    {
        var node = (Node)f;
        if (f.Id is { } id) return id.Name;
        var up = _parent.GetValueOrDefault(node);
        switch (up)
        {
            case VariableDeclarator { Id: Identifier vid }: return vid.Name;
            case MethodDefinition md when ElementKey(md.Key) is { } mk:
                var cls = Up(Up(md)) as IClass;
                return (cls?.Id?.Name is { } cn ? cn + "." : "") + (md.Kind == PropertyKind.Constructor ? "constructor" : mk);
            case Property pr when JsProgram.KeyName(pr.Key) is { } pk: return pk;
            case AssignmentExpression { Left: var left } when JsProgram.Chain(left) is { } chain: return chain;
        }
        var outer = FunctionOf(node);
        return "function at " + Line(node) + (outer != null && outer is not ArrowFunctionExpression && outer.Id is { } oid ? " in " + oid.Name : "");
    }

    // ---- sinks ----

    private Sink? SinkOf(Node call)
    {
        if (_sinks.TryGetValue(call, out var cached)) return cached;
        var s = Classify(call);
        _sinks[call] = s;
        return s;
    }

    private Sink? Classify(Node call)
    {
        var scope = ScopeOf(call);
        var callee = JsProgram.Unwrap(call is CallExpression c ? c.Callee : ((NewExpression)call).Callee);
        var args = Args(call);
        var r = TargetOf(call).Ref;
        var chain = r != null ? (r.Module.Length == 0 ? r.Path : r.Module + "." + r.Path) : JsProgram.Chain(callee);
        var parts = (chain ?? "").Split('.');
        while (parts.Length > 1 && Globals.Contains(parts[0])) parts = parts[1..];
        var name = parts[^1];
        var owner = parts.Length > 1 ? parts[^2] : null;
        // a URL wrapper's row sits at its caller: the flow goes into the wrapper and meets the row there (EndpointOf)
        if (Endpoints().TryGetValue(Line(call), out var endpoint) && endpoint.Client.Split(' ')[0] is not ("url" or "next" or "graphql")
            && !endpoint.Client.Contains(" via ", StringComparison.Ordinal))
            return new Sink("network", endpoint.Client, null, endpoint);
        if (call is NewExpression)
            return name switch
            {
                "WebSocket" or "ReconnectingWebSocket" => new Sink("network", "new WebSocket", [0], null),
                "EventSource" => new Sink("network", "new EventSource", [0], null),
                "Worker" or "SharedWorker" => new Sink("code", "new " + name, [0], null),
                "Function" => new Sink("eval", "new Function", null, null),
                "BrowserWindow" or "BrowserView" or "WebContentsView" => new Sink("window", "new " + name, [0], null),
                _ => null,
            };
        if (r != null && r.Module.Length > 0)
        {
            var path = r.Path.Split('.');
            if (ChildProcess.Contains(r.Module) && ProcessCalls.Contains(path[^1])) return new Sink("child_process", "child_process." + r.Path, null, null);
            if (Fs.Contains(r.Module) && r.Path.Length > 0) return new Sink(FsWrites.Contains(path[^1]) ? "fs-write" : "fs", "fs." + r.Path, null, null);
            if (Http.Contains(r.Module) && path[^1] is "request" or "get" or "post" or "put" or "delete" or "patch" or "fetch" or "" or "default")
                return new Sink("network", r.Module + (r.Path.Length > 0 ? "." + r.Path : ""), [0, 1], null);
        }
        if (owner is "ipcRenderer" && name is "invoke" or "send" or "sendSync" or "postMessage" or "sendToHost"
            || owner is "ipcMain" && name is "handle" or "handleOnce" or "on" or "once"
            || owner is "webContents" or "sender" && name is "send" or "postMessage")
            return new Sink("ipc", owner + "." + name, null, null);
        switch (name)
        {
            case "fetch" when owner == null: return new Sink("network", "fetch", [0, 1], null);
            case "sendBeacon": return new Sink("network", "navigator.sendBeacon", [0, 1], null);
            case "eval" when owner == null: return new Sink("eval", "eval", [0], null);
            case "Function" when owner == null: return new Sink("eval", "Function", null, null);
            case "importScripts" when owner == null: return new Sink("code", "importScripts", null, null);
            case "setTimeout" or "setInterval" when owner == null && args.Count > 0 && args[0] is not (IFunction or Identifier or MemberExpression):
                return new Sink("eval", name + " with a string", [0], null);
            case "postMessage": return new Sink("postMessage", (owner ?? "") + ".postMessage", [0], null);
            case "write" or "writeln" when owner == "document": return new Sink("dom", "document." + name, null, null);
            case "insertAdjacentHTML": return new Sink("dom", "insertAdjacentHTML", [1], null);
            case "loadURL" or "loadFile": return new Sink("navigation", (owner ?? "") + "." + name, [0], null);
            case "openExternal" or "openPath" when owner == "shell": return new Sink("shell", "shell." + name, [0], null);
            case "open" when args.Count >= 2 && JsProgram.Literal(args[0]) is { } verb && verb.ToUpperInvariant() is "GET" or "POST" or "PUT" or "DELETE" or "PATCH" or "HEAD":
                return new Sink("network", "XMLHttpRequest.open", [1], null);
            case "send" when callee is MemberExpression sm && Constructed(sm.Object) is { } ctor && ctor is "XMLHttpRequest" or "WebSocket" or "ReconnectingWebSocket":
                return new Sink("network", ctor + ".send", [0], null);
            case "require" or "__require" when args.Count > 0 && JsProgram.Literal(args[0]) == null && call is CallExpression rc && _p.BundledId(rc, scope) == null:
                return new Sink("code", name + " (computed)", [0], null);
        }
        return null;
    }

    /// <summary>The constructor a receiver was made with (x = new WebSocket(...)), by name.</summary>
    private string? Constructed(Node expr)
    {
        expr = JsProgram.Unwrap(expr);
        if (expr is Identifier id && ScopeOf(expr).Lookup(id.Name) is { Sources: [{ Path.Length: 0 } src] }) expr = JsProgram.Unwrap(src.Expr);
        return expr is NewExpression ne ? JsProgram.Chain(ne.Callee)?.Split('.')[^1] : null;
    }

    private Dictionary<string, JsEndpoint> Endpoints()
    {
        if (_endpoints != null) return _endpoints;
        _endpoints = new Dictionary<string, JsEndpoint>(StringComparer.Ordinal);
        var rows = new List<Corvus.Services.Analysis.Endpoints.CodeEndpoint>();
        Corvus.Services.Analysis.Endpoints.JsEndpoints.Scan(_p, _p.Path, rows, default);
        foreach (var e in rows)
            if (e.Location is { } at)
                _endpoints.TryAdd(at, JsAnalysis.Endpoint(e, _map));
        return _endpoints;
    }

    /// <summary>The Electron graph's pairing of an IPC call, over the scripts of the app the file belongs to.</summary>
    private string? IpcLink(Node call)
    {
        if (_fullPath == null) return null;
        if (_ipc == null) (_ipcFile, _ipc) = JsFlowIpc.Links(_fullPath, default);
        if (_ipc.GetValueOrDefault($"{_ipcFile}:{Line(call)}") is { } link) return link;
        // a channel forwarded by a wrapper: the graph's row is at the wrapper's call site, an earlier step
        for (int i = _current, n = 0; i >= 0 && n < 16; i = _steps[i].From, n++)
            if (_ipc.GetValueOrDefault($"{_ipcFile}:{Line(_steps[i].At)}") is { } wrapped) return wrapped;
        return null;
    }

    /// <summary>A network sink's endpoint row: at the call, or (a URL wrapper) at the caller's site an earlier step names.</summary>
    private JsEndpoint? EndpointOf(Sink sink)
    {
        if (sink.Endpoint != null || sink.Category != "network") return sink.Endpoint;
        for (int i = _current, n = 0; i >= 0 && n < 16; i = _steps[i].From, n++)
            if (Endpoints().GetValueOrDefault(Line(_steps[i].At)) is { } e && e.Client.Contains(" via ", StringComparison.Ordinal)) return e;
        return null;
    }

    // ---- walks ----

    private readonly List<Step> _steps = [];
    private readonly Queue<(object State, int Step)> _queue = new();
    private readonly HashSet<object> _seen = [];
    private int _current = -1;

    /// <summary>Walks from the seeds of <paramref name="query"/> (or the expression at line:column) and returns the flows, sinks and origins first; the index serves any number of walks.</summary>
    public JsFlowResult Run(string? query, int line, int column, bool back, int limit, Budget budget, CancellationToken ct)
    {
        _steps.Clear();
        _queue.Clear();
        _seen.Clear();
        _current = -1;
        var seeds = Seeds(query, line, column, back);
        if (seeds.Count == 0)
            throw new ToolError(ErrorCode.NotFound, $"nothing in {_p.Path} matches '{query ?? $"{line}:{column}"}'.",
                "query takes a name, \"literal\", sinks, sink:<kind>, module:<id>, or pass line and column");
        foreach (var (state, kind, text, at, endpoint, link) in seeds)
            if (_seen.Add(state)) _queue.Enqueue((state, AddStep(kind, text, at, -1, null, endpoint, link)));
        var clock = Stopwatch.StartNew();
        long allocated = GC.GetAllocatedBytesForCurrentThread();
        string? partial = null;
        int expanded = 0;
        while (_queue.Count > 0)
        {
            if ((++expanded & 0xFF) == 0)
            {
                ct.ThrowIfCancellationRequested();
                if (clock.Elapsed > budget.Time) partial = $"time budget ({budget.Time.TotalSeconds:0} s)";
                else if (GC.GetAllocatedBytesForCurrentThread() - allocated > budget.Bytes) partial = $"allocation budget ({budget.Bytes / 1048576} MB)";
            }
            if (_steps.Count >= budget.Steps) partial = $"step budget ({budget.Steps:N0})";
            if (partial != null) break;
            var (state, step) = _queue.Dequeue();
            _current = step;
            if (back) Back(state); else Forward(state);
        }
        if (partial != null) partial += $"; {_queue.Count:N0} state(s) not followed";
        return Result(query ?? $"{line}:{column}", seeds.Count, limit, partial);
    }

    private JsFlowResult Result(string query, int seeds, int limit, string? partial)
    {
        var leaves = _steps.Select((s, i) => (s, i)).Where(x => x.s.End != null).ToList();
        int Rank(string end) => end switch { "sink" => 0, "origin" => 1, "unknown" => 2, _ => 3 };
        var ordered = leaves.OrderBy(x => Rank(x.s.End!)).ThenBy(x => x.i).ToList();
        var flows = new List<JsFlowPath>();
        foreach (var (leaf, index) in ordered.Take(Math.Max(1, limit)))
        {
            var chain = new List<JsFlowStep>();
            for (int i = index; i >= 0; i = _steps[i].From) chain.Add(Public(_steps[i]));
            chain.Reverse();
            flows.Add(new JsFlowPath(leaf.End!, chain));
        }
        return new JsFlowResult(query, seeds, _steps.Count, leaves.Count(x => x.s.End == "sink"),
            leaves.Count(x => x.s.End == "unknown"), leaves.Count(x => x.s.End == "origin"), leaves.Count, partial, flows);
    }

    private JsFlowStep Public(Step s)
    {
        var loc = s.At.Location.Start;
        return new JsFlowStep(s.Kind, s.Text, $"{loc.Line}:{loc.Column + 1}")
        {
            Module = ModuleAt(s.At.Start),
            Original = JsAnalysis.Original(_map, loc.Line, loc.Column + 1),
            Endpoint = s.Endpoint,
            Link = s.Link,
        };
    }

    private string? ModuleAt(int pos)
    {
        int lo = 0, hi = _modules.Length - 1, found = -1;
        while (lo <= hi)
        {
            int mid = (lo + hi) >> 1;
            if (_modules[mid].Start <= pos) { found = mid; lo = mid + 1; } else hi = mid - 1;
        }
        for (int i = found; i >= 0 && i > found - 8; i--)
            if (_modules[i].End >= pos) return _modules[i].Name != null && _modules[i].Name != _modules[i].Id ? $"{_modules[i].Id} ({_modules[i].Name})" : _modules[i].Id;
        return null;
    }

    private int AddStep(string kind, string text, Node at, int from, string? end, JsEndpoint? endpoint = null, string? link = null)
    {
        _steps.Add(new Step(kind, text, at, from, end) { Endpoint = endpoint, Link = link });
        return _steps.Count - 1;
    }

    /// <summary>Moves to a new state; with a kind it records a step there, else the state continues the current step.</summary>
    private void Go(object state, string? kind, string text, Node at)
    {
        if (!_seen.Add(state)) return;
        _queue.Enqueue((state, kind == null ? _current : AddStep(kind, text, at, _current, null)));
    }

    private void Leaf(string end, string kind, string text, Node at, JsEndpoint? endpoint = null, string? link = null)
    {
        if (_seen.Add((end, kind, text, at))) AddStep(kind, text, at, _current, end, endpoint, link);
    }

    // ---- seeds ----

    private List<(object State, string Kind, string Text, Node At, JsEndpoint? Endpoint, string? Link)> Seeds(string? query, int line, int column, bool back)
    {
        var seeds = new List<(object, string, string, Node, JsEndpoint?, string?)>();
        if (line > 0 && column > 0)
        {
            if (At(line, column) is { } node) seeds.Add((node, "seed", "expression " + Snip(node), node, null, null));
            return seeds;
        }
        var q = query?.Trim() ?? "";
        if (q.Length == 0) return seeds;
        if (q is "sinks" or "sink" || q.StartsWith("sink:", StringComparison.Ordinal))
        {
            var filter = q.StartsWith("sink:", StringComparison.Ordinal) ? q[5..] : null;
            foreach (var call in _calls)
            {
                if (SinkOf(call) is not { } s || filter != null && !s.Category.StartsWith(filter, StringComparison.OrdinalIgnoreCase)
                    && !s.Call.Contains(filter, StringComparison.OrdinalIgnoreCase)) continue;
                var args = Args(call);
                if (back)
                    for (int i = 0; i < args.Count; i++)
                    {
                        if (s.Args != null && !s.Args.Contains(i)) continue;
                        var arg = args[i] is SpreadElement sp ? sp.Argument : args[i];
                        seeds.Add((arg, "sink", $"{s.Call} argument {i + 1} ({s.Category})", arg, s.Endpoint, s.Category == "ipc" ? IpcLink(call) : null));
                    }
                else seeds.Add((call, "sink", $"{s.Call} result ({s.Category})", call, s.Endpoint, s.Category == "ipc" ? IpcLink(call) : null));
            }
            return seeds;
        }
        if (q.StartsWith("module:", StringComparison.Ordinal))
        {
            var id = q[7..].Trim();
            var m = _p.Modules.FirstOrDefault(x => x.Id == id || x.Name == id);
            if (m == null) return seeds;
            if (back)
                foreach (var (key, expr) in _exports.GetValueOrDefault(m.Id) ?? [])
                    seeds.Add((expr, "seed", $"export {(key.Length == 0 ? "module.exports" : key)} of module {m.Id}", expr, null, null));
            else
                foreach (var call in _requires.GetValueOrDefault(m.Id) ?? [])
                    seeds.Add((call, "seed", $"require of module {m.Id}", call, null, null));
            return seeds;
        }
        if (q.Length >= 2 && q[0] is '"' or '\'' or '`' && q[^1] == q[0])
        {
            var text = q[1..^1];
            foreach (var n in _parent.Keys)
            {
                var value = n switch
                {
                    StringLiteral s => s.Value,
                    TemplateLiteral t when _parent.GetValueOrDefault(t) is not TaggedTemplateExpression => string.Concat(t.Quasis.Select(x => x.Value.Cooked ?? x.Value.Raw)),
                    _ => null,
                };
                if (value != null && value.Contains(text, StringComparison.Ordinal) && _parent.GetValueOrDefault(n) is not (Property { Computed: false } or ImportDeclaration or ExportNamedDeclaration or ExportAllDeclaration))
                    seeds.Add((n, "seed", "literal " + Snip(n), n, null, null));
                if (seeds.Count >= 500) break;
            }
            return [.. seeds.OrderBy(s => s.Item4.Start)];
        }
        // a name: variables and parameters, functions and methods (Class.method)
        var functions = new HashSet<IFunction>();
        foreach (var b in _bindings.GetValueOrDefault(q) ?? [])
        {
            var fn = (b.Fixed as JsFunction)?.Node ?? (b.Sources is [{ Expr: IFunction sf, Path.Length: 0 }] ? sf : null);
            if (fn != null) functions.Add(fn);
            else seeds.Add((b, "seed", (b.ParamOf != null ? "parameter " : "variable ") + b.Name, Declaration(b), null, null));
        }
        foreach (var n in _parent.Keys)
            if (n is IFunction f && !functions.Contains(f) && FnName(f) is var name && (name == q || name.EndsWith("." + q, StringComparison.Ordinal) && !q.Contains('.')))
                functions.Add(f);
        foreach (var f in functions.OrderBy(f => ((Node)f).Start))
        {
            if (!back) seeds.Add((new Ret(f), "seed", "returns of " + FnName(f), (Node)f, null, null));
            else
            {
                var fs = (JsScope?)((Node)f).UserData;
                foreach (var p in f.Params)
                    foreach (var pid in PatternNames(p))
                        if (fs?.Lookup(pid.Name) is { } pb) seeds.Add((pb, "seed", $"parameter {pid.Name} of {FnName(f)}", pid, null, null));
            }
        }
        return seeds;
    }

    private Node Declaration(JsBinding b) =>
        _declared.GetValueOrDefault(b) ?? _reads.GetValueOrDefault(b)?.FirstOrDefault() as Node ?? b.Sources.FirstOrDefault().Expr ?? b.Scope.Owner;

    /// <summary>The innermost expression at a 1-based generated line and column.</summary>
    private Node? At(int line, int column)
    {
        Node? best = null;
        foreach (var n in _parent.Keys)
        {
            if (n is not (Expression or Identifier)) continue;
            var (s, e) = (n.Location.Start, n.Location.End);
            bool after = s.Line < line || s.Line == line && s.Column <= column - 1;
            bool before = e.Line > line || e.Line == line && e.Column > column - 1;
            if (after && before && (best == null || n.End - n.Start < best.End - best.Start)) best = n;
        }
        return best;
    }

    private static IEnumerable<Identifier> PatternNames(Node pattern)
    {
        switch (pattern)
        {
            case Identifier id: yield return id; break;
            case AssignmentPattern ap: foreach (var i in PatternNames(ap.Left)) yield return i; break;
            case RestElement r: foreach (var i in PatternNames(r.Argument)) yield return i; break;
            case ArrayPattern a:
                foreach (var e in a.Elements)
                    if (e != null) foreach (var i in PatternNames(e)) yield return i;
                break;
            case ObjectPattern o:
                foreach (var p in o.Properties)
                    foreach (var i in PatternNames(p is Property prop ? prop.Value : p)) yield return i;
                break;
        }
    }

    // ---- forward ----

    private void Forward(object state)
    {
        switch (state)
        {
            case JsBinding b: Reads(b); break;
            case Ret r: Returned(r.Function); break;
            case Slot s: Loads(s); break;
            case Node e: Expr(e); break;
        }
    }

    private void Reads(JsBinding b)
    {
        var reads = _reads.GetValueOrDefault(b);
        if (reads == null || reads.Count == 0)
        {
            Leaf("end", "end", $"{b.Name} is never read", Declaration(b));
            return;
        }
        var home = b.Scope.FunctionScope.Owner;
        foreach (var r in reads)
        {
            var fn = FunctionOf(r);
            if (fn != null && !ReferenceEquals(fn, home)) Go(r, "closure", $"{b.Name} read inside {FnName(fn)}", r);
            else Go(r, null, "", r);
        }
    }

    private void Returned(IFunction f)
    {
        bool any = false;
        foreach (var (call, _) in _callers.GetValueOrDefault(f) ?? [])
        {
            any = true;
            Go(call, "return", $"from {FnName(f)} to {Snip(call)}", call);
        }
        if (_thenOf.TryGetValue(f, out var then))
        {
            any = true;
            Go(then, "promise", $"then callback result of {Snip(then)}", then);
        }
        var node = (Node)f;
        var up = _parent.GetValueOrDefault(node);
        if (up is MethodDefinition { Kind: PropertyKind.Get } getter && ElementKey(getter.Key) is { } gk && ThisOwnerOfMethod(getter) is { } cls)
        {
            any = true;
            Go(new Slot(cls, gk), "property", $"getter {OwnerName(cls)}.{gk}", node);
        }
        foreach (var (module, key) in ExportsOf(f))
        {
            any = true;
            Go(new Slot("module:" + module, key), "export", $"{key} of module {module}", node);
        }
        if (up is CallExpression or NewExpression && !any)
        {
            Leaf("unknown", "unknown", $"returned from a callback passed to {Snip(up)}", node, link: "the caller is not in the tree");
            return;
        }
        if (!any) Leaf("unknown", "unknown", $"returned from {FnName(f)}: no resolved caller", node, link: "called dynamically, exported or an event handler");
    }

    private IEnumerable<(string, string)> ExportsOf(IFunction f)
    {
        // a webpack getter (key: () => value) is its result's export
        foreach (var r in Returns(f))
            if (_exportExprs.TryGetValue(r, out var e) && _parent.GetValueOrDefault((Node)f) is Property) yield return e;
    }

    private Node? ThisOwnerOfMethod(MethodDefinition md) => Up(Up(md));

    private void Loads(Slot s)
    {
        bool any = false;
        if (s.Owner is string module && s.Key.Length == 0)
            foreach (var call in _requires.GetValueOrDefault(module[7..]) ?? [])
            {
                any = true;
                Go(call, "import", $"module {module[7..]} required", call);
            }
        foreach (var m in _members.GetValueOrDefault(s.Key) ?? [])
        {
            if (_parent.GetValueOrDefault(m) is AssignmentExpression { Operator: Operator.Assignment } a && ReferenceEquals(a.Left, m)) continue;
            var owner = OwnerOf(m.Object);
            if (owner == null || !owner.Equals(s.Owner)) continue;
            any = true;
            Go(m, "property", $"read {Snip(m)}", m);
        }
        if (s.Owner is string mod && s.Key.Length > 0)
            foreach (var call in _requires.GetValueOrDefault(mod[7..]) ?? [])
                if (_parent.GetValueOrDefault(call) is not MemberExpression)
                {
                    any = true;
                    Go(call, "import", $"module {mod[7..]} required (export {s.Key} inside)", call);
                }
        // an object literal's own flow continues past it; only named objects and classes end here
        if (!any && s.Owner is not ObjectExpression) Leaf("end", "end", $"{OwnerName(s.Owner)}.{s.Key} is never read where the tree resolves the object", AnyNode(s));
    }

    private Node AnyNode(Slot s) => s.Owner as Node ?? _p.Tree;

    private void Expr(Node e)
    {
        if (_exportExprs.TryGetValue(e, out var export) && _parent.GetValueOrDefault(e) is not AssignmentExpression)
            Go(new Slot("module:" + export.Module, export.Key), "export", $"{(export.Key.Length == 0 ? "module.exports" : export.Key)} of module {export.Module}", e);
        if (!_parent.TryGetValue(e, out var up))
        {
            Leaf("end", "end", "top level", e);
            return;
        }
        switch (up)
        {
            case ParenthesizedExpression or ChainExpression or SpreadElement:
                Go(up, null, "", up);
                return;
            case SequenceExpression seq:
                if (ReferenceEquals(seq.Expressions[^1], e)) Go(up, null, "", up);
                else Leaf("end", "end", "discarded in a sequence", e);
                return;
            case ConditionalExpression ce when !ReferenceEquals(ce.Test, e):
            case LogicalExpression:
                Go(up, null, "", up);
                return;
            case AwaitExpression:
                Go(up, "promise", "awaited", up);
                return;
            case TemplateLiteral t when _parent.GetValueOrDefault(t) is TaggedTemplateExpression tt:
                Leaf("unknown", "unknown", $"passed to the tag {Snip(tt.Tag)}", up);
                return;
            case TemplateLiteral:
                Go(up, "through", "template " + Snip(up), up);
                return;
            case BinaryExpression { Operator: Operator.Addition }:
                Go(up, "through", "concatenated " + Snip(up), up);
                return;
            case ArrayExpression:
                Go(up, "through", "array element", up);
                return;
            case Property { Computed: false } prop when ReferenceEquals(prop.Value, e) && _parent.GetValueOrDefault(prop) is ObjectExpression o && JsProgram.KeyName(prop.Key) is { } key:
                Go(new Slot(o, key), "property", $"stored as {key} in the object at {Line(o)}", prop);
                Go(o, "through", $"in the object as {key}", prop);
                return;
            case VariableDeclarator d when ReferenceEquals(d.Init, e):
                Bind(d.Id, e, "assign");
                return;
            case AssignmentExpression a when ReferenceEquals(a.Right, e):
                Assign(a.Left, e);
                if (_parent.GetValueOrDefault(a) is not ExpressionStatement) Go(a, null, "", a);
                return;
            case AssignmentPattern ap when ReferenceEquals(ap.Right, e):
                Bind(ap.Left, e, "default");
                return;
            case CallExpression c when !ReferenceEquals(JsProgram.Unwrap(c.Callee), e) && !ReferenceEquals(c.Callee, e):
                Argument(c, Index(c.Arguments, e));
                return;
            case NewExpression n when !ReferenceEquals(n.Callee, e):
                Argument(n, Index(n.Arguments, e));
                return;
            case CallExpression or NewExpression:
                Leaf("end", "end", "called as a function", up);
                return;
            case MemberExpression m when ReferenceEquals(m.Object, e):
                Receiver(m);
                return;
            case MemberExpression:
                Leaf("end", "end", "used as a property key", up);
                return;
            case ReturnStatement:
                if (FunctionOf(up) is { } f) Go(new Ret(f), "return", "returned from " + FnName(f), up);
                return;
            case ArrowFunctionExpression af when ReferenceEquals(af.Body, e):
                Go(new Ret(af), "return", "returned from " + FnName(af), e);
                return;
            case ForOfStatement fo when ReferenceEquals(fo.Right, e):
                if (fo.Left is VariableDeclaration { Declarations: [var fd] }) Bind(fd.Id, e, "iterated");
                else Assign(fo.Left, e);
                return;
            case ExportDefaultDeclaration or ExportSpecifier or ExportNamedDeclaration:
                Leaf("unknown", "unknown", "exported from the file", up, link: "the importer is outside this file");
                return;
            case YieldExpression:
                Leaf("unknown", "unknown", "yielded from a generator", up, link: "the consumer is not resolved");
                return;
            case ThrowStatement:
                Leaf("unknown", "unknown", "thrown", up, link: "the catch site is not resolved");
                return;
            case ImportExpression:
                Leaf("sink", "sink", "import() (code)", up);
                return;
            case UnaryExpression { Operator: Operator.TypeOf or Operator.LogicalNot or Operator.Void or Operator.Delete }:
            case BinaryExpression:
                Leaf("end", "end", "compared or computed in " + Snip(up), up);
                return;
            case UnaryExpression:
                Go(up, "through", Snip(up), up);
                return;
            case IfStatement or WhileStatement or DoWhileStatement or ForStatement or SwitchStatement or SwitchCase or ConditionalExpression:
                Leaf("end", "end", "tested in a condition", up);
                return;
            case ExpressionStatement:
                Leaf("end", "end", "discarded", e);
                return;
            default:
                Leaf("end", "end", "used in " + up.Type, up);
                return;
        }
    }

    private static int Index(in NodeList<Expression> args, Node e)
    {
        for (int i = 0; i < args.Count; i++)
            if (ReferenceEquals(args[i], e)) return i;
        return -1;
    }

    private void Bind(Node pattern, Node from, string how)
    {
        var scope = ScopeOf(pattern);
        foreach (var id in PatternNames(pattern))
            if (scope.Lookup(id.Name) is { } b)
                Go(b, how, pattern is Identifier ? id.Name : id.Name + " (destructured)", id);
    }

    private void Assign(Node left, Node from)
    {
        left = JsProgram.Unwrap(left);
        switch (left)
        {
            case Identifier id:
                if (ScopeOf(left).Lookup(id.Name) is { } b) Go(b, "assign", id.Name, left);
                else Leaf("unknown", "unknown", $"stored in the global {id.Name}", left, link: "globals are read outside the tree");
                return;
            case MemberExpression m:
                Store(m);
                return;
            default:
                Bind(left, from, "assign");
                return;
        }
    }

    private void Store(MemberExpression m)
    {
        var key = Key(m);
        if (key is "innerHTML" or "outerHTML" or "srcdoc")
        {
            Leaf("sink", "sink", $"{Snip(m)} (dom)", m);
            return;
        }
        if (key is "href" && JsProgram.Chain(m.Object) is "location" or "window.location" or "document.location")
        {
            Leaf("sink", "sink", $"{Snip(m)} (navigation)", m);
            return;
        }
        if (key == null)
        {
            Leaf("unknown", "unknown", $"stored under a computed key {Snip(m)}", m, link: "dynamic property");
            return;
        }
        if (_p.ExportKey(m, ScopeOf(m)) is { } export)
        {
            Go(new Slot("module:" + export.Module, export.Key), "export", $"{(export.Key.Length == 0 ? "module.exports" : export.Key)} of module {export.Module}", m);
            return;
        }
        if (OwnerOf(m.Object) is { } owner) Go(new Slot(owner, key), "property", $"stored in {OwnerName(owner)}.{key}", m);
        else Leaf("unknown", "unknown", $"stored in {Snip(m)}", m, link: "the object is not resolved");
    }

    private void Argument(Node call, int index)
    {
        if (index < 0) return;
        var args = Args(call);
        if (SinkOf(call) is { } sink && (sink.Args == null || sink.Args.Contains(index)))
        {
            Leaf("sink", "sink", $"{sink.Call} argument {index + 1} ({sink.Category})", call, EndpointOf(sink), sink.Category == "ipc" ? IpcLink(call) : null);
            return;
        }
        var callee = JsProgram.Unwrap(call is CallExpression c ? c.Callee : ((NewExpression)call).Callee);
        // new Promise((resolve) => resolve(v)): v is the promise's value
        if (callee is Identifier rid && ScopeOf(call).Lookup(rid.Name) is { ParamIndex: 0, ParamOf: { } exec } && _executors.TryGetValue(exec, out var promise))
        {
            Go(promise, "promise", "resolves " + Snip(promise), call);
            return;
        }
        var t = TargetOf(call);
        var functions = t.Functions.Count > 0 ? t.Functions : Passed(call);
        if (functions.Count > 0)
        {
            foreach (var f in functions)
            {
                int p = t.Shift == int.MaxValue ? -1 : index - (t.Functions.Count > 0 ? t.Shift : 0);
                if (t.Shift == int.MaxValue)
                {
                    Leaf("unknown", "unknown", $"passed through {Snip(callee)} (apply)", call, link: "arguments array");
                    continue;
                }
                if (p < 0) { Leaf("end", "end", "passed as this", call); continue; }
                Param(f, p, call);
            }
            return;
        }
        var chain = t.Ref != null ? (t.Ref.Module.Length == 0 ? t.Ref.Path : t.Ref.Module + "." + t.Ref.Path) : JsProgram.Chain(callee);
        var method = callee is MemberExpression { Property: Identifier mp, Computed: false } ? mp.Name : null;
        if (chain != null && (PassCalls.Contains(chain) || t.Ref != null && PassModules.Contains(t.Ref.Module) || method != null && ArgPass.Contains(method)))
        {
            Go(call, "through", $"{Snip(callee)}()", call);
            return;
        }
        if (method != null && AddTo.Contains(method) && callee is MemberExpression am)
        {
            Container(am.Object, $"added by .{method}()", call);
            return;
        }
        if (t.Ref is { Module.Length: > 0 } ext && !ext.Module.StartsWith('#'))
            Leaf("unknown", "unknown", $"argument {index + 1} of {ext.Module}.{ext.Path} (external module)", call, link: "the module is not in this file");
        else if (t.Ref != null)
            Leaf("unknown", "unknown", $"argument {index + 1} of {chain}() (not defined in this file)", call, link: "a global or host function");
        else
            Leaf("unknown", "unknown", $"argument {index + 1} of {Snip(callee)}()", call, link: t.Why ?? "callee not resolved");
    }

    /// <summary>A value put into a container (list.push(v), map.set(k, v)): the container's reads carry it.</summary>
    private void Container(Node receiver, string how, Node at)
    {
        receiver = JsProgram.Unwrap(receiver);
        if (receiver is Identifier id && ScopeOf(receiver).Lookup(id.Name) is { } b) Go(b, "property", $"{how} {id.Name}", at);
        else if (receiver is MemberExpression rm && Key(rm) is { } key && OwnerOf(rm.Object) is { } owner)
            Go(new Slot(owner, key), "property", $"{how} {OwnerName(owner)}.{key}", at);
        else Leaf("unknown", "unknown", $"{how} {Snip(receiver)}", at, link: "the container is not resolved");
    }

    private void Param(IFunction f, int index, Node call)
    {
        var fs = (JsScope?)((Node)f).UserData;
        Node? p = null;
        for (int i = 0; i < f.Params.Count; i++)
        {
            if (f.Params[i] is RestElement && i <= index) { p = f.Params[i]; break; }
            if (i == index) { p = f.Params[i]; break; }
        }
        if (p == null || fs == null)
        {
            Leaf("end", "end", $"argument {index + 1} of {FnName(f)}: no such parameter", call);
            return;
        }
        foreach (var id in PatternNames(p))
            if (fs.Lookup(id.Name) is { } b)
                Go(b, "argument", $"{index + 1} to parameter {id.Name} of {FnName(f)}" + (TargetOf(call).ByName ? " (method matched by name)" : ""), call);
    }

    private void Receiver(MemberExpression m)
    {
        var key = Key(m);
        var up = _parent.GetValueOrDefault(m);
        while (up is ParenthesizedExpression or ChainExpression) up = _parent.GetValueOrDefault(up);
        if (up is CallExpression c && ReferenceEquals(JsProgram.Unwrap(c.Callee), m))
        {
            if (key == "then" && c.Arguments.Count > 0)
            {
                foreach (var cb in c.Arguments.Take(1))
                    if (FunctionValue(cb, ScopeOf(c)) is { } f && f.Params.Count > 0) Param(f, 0, c);
                    else Leaf("unknown", "unknown", $"then callback {Snip(cb)}", c, link: "callback not resolved");
                return;
            }
            if (key != null && Each.Contains(key) && c.Arguments.Count > 0)
            {
                if (FunctionValue(c.Arguments[0], ScopeOf(c)) is { } each && each.Params.Count > 0) Param(each, 0, c);
                else Leaf("unknown", "unknown", $".{key} callback {Snip(c.Arguments[0])}", c, link: "callback not resolved");
                if (key is "map" or "filter" or "flatMap" or "find" or "findLast") Go(c, "through", $".{key}()", c);
                return;
            }
            if (key != null && (AddTo.Contains(key) || key is "has" or "includes" or "indexOf" or "delete" or "clear" or "keys" or "forEach"))
            {
                Leaf("end", "end", $"container method .{key}()", c);
                return;
            }
            if (key != null && ReceiverPass.Contains(key))
            {
                Go(c, "through", $".{key}()", c);
                return;
            }
            if (SinkOf(c) is { } sink)
            {
                Leaf("sink", "sink", $"{sink.Call} on the value ({sink.Category})", c, sink.Endpoint);
                return;
            }
            var t = TargetOf(c);
            if (t.Functions.Count > 0) Leaf("end", "end", $"this of {string.Join(", ", t.Functions.Take(3).Select(FnName))}", c);
            else Leaf("unknown", "unknown", $"method {Snip(c.Callee)}() called on the value", c, link: t.Why ?? "method not resolved");
            return;
        }
        if (_parent.GetValueOrDefault(m) is AssignmentExpression { Operator: Operator.Assignment } a && ReferenceEquals(a.Left, m))
        {
            Leaf("end", "end", $"property {key ?? "[computed]"} written", m);
            return;
        }
        Go(m, "property", key == null ? $"computed property {Snip(m)}" : $"property .{key}", m);
    }

    // ---- back ----

    private void Back(object state)
    {
        switch (state)
        {
            case JsBinding b: Sources(b, b.Scope.Owner); break;
            case Ret r: ReturnsOf(r.Function); break;
            case Slot s: Stores(s); break;
            case Node e: From(e); break;
        }
    }

    private void Sources(JsBinding b, Node at)
    {
        if (b.Fixed is JsFunction jf)
        {
            Leaf("origin", "origin", "function " + FnName(jf.Node), (Node)jf.Node);
            return;
        }
        if (b.Fixed is JsRef r)
        {
            Leaf("unknown", "unknown", $"imported {(r.Path.Length > 0 ? r.Path + " " : "")}from '{r.Module}'", at, link: "the module is outside this file");
            return;
        }
        bool any = false;
        foreach (var (expr, _, path) in b.Sources)
        {
            any = true;
            Go(expr, "assign", path.Length > 0 ? $"{b.Name} from {string.Join(".", path)} of {Snip(expr)}" : $"{b.Name} = {Snip(expr)}", expr);
        }
        if (_iterated.TryGetValue(b, out var iterable))
        {
            any = true;
            Go(iterable, "through", $"{b.Name} iterates {Snip(iterable)}", iterable);
        }
        if (b.ParamOf is { } f)
        {
            any = true;
            Callers(f, b.ParamIndex, b.Name);
        }
        else if (b.Scope.Owner is CatchClause cc)
        {
            any = true;
            Leaf("unknown", "unknown", $"{b.Name}: a caught exception", cc, link: "the throw site is not resolved");
        }
        else if (!any && b.Scope.Owner is IFunction pf)
        {
            // a destructured parameter: the whole argument
            for (int i = 0; i < pf.Params.Count; i++)
                if (PatternNames(pf.Params[i]).Any(id => id.Name == b.Name))
                {
                    any = true;
                    Callers(pf, i, b.Name);
                }
        }
        if (!any) Leaf("origin", "origin", $"{b.Name} declared without a value", Declaration(b));
    }

    private void Callers(IFunction f, int index, string name)
    {
        bool any = false;
        foreach (var (call, shift) in _callers.GetValueOrDefault(f) ?? [])
        {
            any = true;
            var args = Args(call);
            if (shift == int.MaxValue) Leaf("unknown", "unknown", $"parameter {name}: arguments array of {Snip(call)}", call, link: "apply");
            else if (index + shift < args.Count)
                Go(args[index + shift], "argument", $"parameter {name} of {FnName(f)} from {Snip(call)}" + (TargetOf(call).ByName ? " (method matched by name)" : ""), args[index + shift]);
            else Leaf("origin", "origin", $"parameter {name} of {FnName(f)}: no argument at {Snip(call)} (undefined or default)", call);
        }
        if (_thenOf.TryGetValue(f, out var then) && index == 0 && then is CallExpression { Callee: MemberExpression { Property: Identifier { Name: "then" } } tm })
        {
            any = true;
            Go(tm.Object, "promise", $"then of {Snip(tm.Object)}", tm.Object);
        }
        // arr.forEach(x => ...): the element comes from the receiver
        if (!any && index == 0 && _parent.GetValueOrDefault((Node)f) is CallExpression { Callee: MemberExpression em } ec && Key(em) is { } ek && Each.Contains(ek)
            && ReferenceEquals(ec.Arguments[0], f))
        {
            any = true;
            Go(em.Object, "through", $"element of {Snip(em.Object)} (.{ek})", em.Object);
        }
        if (!any && _parent.GetValueOrDefault((Node)f) is CallExpression or NewExpression)
        {
            var site = _parent[(Node)f];
            Leaf("unknown", "unknown", $"parameter {name} of a callback passed to {Snip(site)}", site, link: "the caller is not in the tree");
        }
        else if (!any) Leaf("unknown", "unknown", $"parameter {name} of {FnName(f)}: no resolved caller", (Node)f, link: "called dynamically, exported or an event handler");
    }

    private void ReturnsOf(IFunction f)
    {
        var rets = Returns(f);
        if (rets.Count == 0) Leaf("origin", "origin", $"{FnName(f)} returns nothing", (Node)f);
        foreach (var r in rets) Go(r, "return", $"returned by {FnName(f)}", r);
    }

    private void Stores(Slot s)
    {
        bool any = false;
        if (s.Owner is string module)
        {
            foreach (var (key, expr) in _exports.GetValueOrDefault(module[7..]) ?? [])
                if (key == s.Key || s.Key.Length == 0)
                {
                    any = true;
                    Go(expr, "export", $"{(key.Length == 0 ? "module.exports" : key)} of module {module[7..]}", expr);
                }
        }
        else if (s.Owner is ObjectExpression o && PropertyValue(o, s.Key) is { } pv)
        {
            any = true;
            Go(pv, "property", $"{s.Key} in the object at {Line(o)}", pv);
        }
        else if (s.Owner is IClass cls)
        {
            foreach (var e in cls.Body.Body)
                if (e is PropertyDefinition { Computed: false, Value: { } v } pd && ElementKey(pd.Key) == s.Key)
                {
                    any = true;
                    Go(v, "property", $"field {OwnerName(cls)}.{s.Key}", v);
                }
                else if (e is MethodDefinition { Kind: PropertyKind.Get, Computed: false } g && ElementKey(g.Key) == s.Key)
                {
                    any = true;
                    Go(new Ret(g.Value), "property", $"getter {OwnerName(cls)}.{s.Key}", g);
                }
        }
        foreach (var m in _members.GetValueOrDefault(s.Key) ?? [])
        {
            if (_parent.GetValueOrDefault(m) is not AssignmentExpression { Operator: Operator.Assignment } a || !ReferenceEquals(a.Left, m)) continue;
            var owner = OwnerOf(m.Object);
            if (owner == null || !owner.Equals(s.Owner)) continue;
            any = true;
            Go(a.Right, "property", $"{Snip(m)} = {Snip(a.Right)}", a.Right);
        }
        if (!any) Leaf("unknown", "unknown", $"{OwnerName(s.Owner)}.{s.Key}: no store the tree resolves", AnyNode(s), link: "set dynamically or outside the file");
    }

    private void From(Node e)
    {
        var scope = ScopeOf(e);
        switch (e)
        {
            case Literal:
                Leaf("origin", "origin", "literal " + Snip(e), e);
                return;
            case TemplateLiteral t:
                if (t.Expressions.Count == 0) Leaf("origin", "origin", "literal " + Snip(e), e);
                foreach (var x in t.Expressions) Go(x, "through", "part of " + Snip(t), x);
                return;
            case LogicalExpression l:
                Go(l.Left, null, "", l.Left);
                Go(l.Right, null, "", l.Right);
                return;
            case BinaryExpression b:
                Go(b.Left, "through", "operand of " + Snip(b), b.Left);
                Go(b.Right, "through", "operand of " + Snip(b), b.Right);
                return;
            case ConditionalExpression c:
                Go(c.Consequent, null, "", c.Consequent);
                Go(c.Alternate, null, "", c.Alternate);
                return;
            case UnaryExpression u:
                Go(u.Argument, "through", Snip(u), u.Argument);
                return;
            case ParenthesizedExpression p:
                Go(p.Expression, null, "", p.Expression);
                return;
            case ChainExpression ch:
                Go(ch.Expression, null, "", ch.Expression);
                return;
            case SequenceExpression s:
                Go(s.Expressions[^1], null, "", s.Expressions[^1]);
                return;
            case AssignmentExpression a:
                Go(a.Right, null, "", a.Right);
                return;
            case AwaitExpression aw:
                Go(aw.Argument, "promise", "awaits " + Snip(aw.Argument), aw.Argument);
                return;
            case SpreadElement sp:
                Go(sp.Argument, null, "", sp.Argument);
                return;
            case Identifier id:
                if (id.Name == "undefined" && scope.Lookup("undefined") == null)
                {
                    Leaf("origin", "origin", "undefined", e);
                    return;
                }
                if (scope.Lookup(id.Name) is not { } bound)
                {
                    Leaf("unknown", "unknown", $"the global {id.Name}", e, link: "not defined in this file");
                    return;
                }
                var fn = FunctionOf(e);
                if (fn != null && !ReferenceEquals(fn, bound.Scope.FunctionScope.Owner)) Go(bound, "closure", $"{id.Name} captured from {FnOwner(bound)}", e);
                else Go(bound, null, "", e);
                return;
            case MemberExpression m:
                Member(m);
                return;
            case CallExpression c:
                CallResult(c);
                return;
            case NewExpression n:
                if (n.Callee is Identifier { Name: "Promise" } && n.Arguments.Count > 0 && FunctionValue(n.Arguments[0], scope) is { } exec)
                {
                    Resolves(exec, n);
                    return;
                }
                var ctor = JsProgram.Chain(n.Callee)?.Split('.')[^1];
                if (ctor != null && PassCalls.Contains(ctor) && n.Arguments.Count > 0)
                {
                    foreach (var a in n.Arguments) Go(a, "through", $"new {ctor}()", a);
                    return;
                }
                Leaf("origin", "origin", "object " + Snip(n), n);
                return;
            case ImportExpression ie:
                Leaf("unknown", "unknown", "dynamic import " + Snip(ie.Source), e, link: "the module is outside this file");
                return;
            case ThisExpression:
                Leaf("origin", "origin", ThisOwner(e) is { } owner ? $"this ({OwnerName(owner)})" : "this", e);
                return;
            case IFunction f:
                Leaf("origin", "origin", "function " + FnName(f), e);
                return;
            case ObjectExpression or ArrayExpression or ClassExpression:
                Leaf("origin", "origin", (e is ArrayExpression ? "array " : e is ObjectExpression ? "object " : "class ") + Snip(e), e);
                return;
            default:
                Leaf("origin", "origin", e.Type + " " + Snip(e), e);
                return;
        }
    }

    private string FnOwner(JsBinding b) => b.Scope.FunctionScope.Owner is IFunction f ? FnName(f) : "the top level";

    /// <summary>The resolve(v) calls of a promise executor: each v is the promise's value.</summary>
    private void Resolves(IFunction exec, NewExpression promise)
    {
        bool any = false;
        if (exec.Params.Count > 0 && exec.Params[0] is Identifier rp && ((JsScope?)((Node)exec).UserData)?.Lookup(rp.Name) is { } resolve)
            foreach (var r in _reads.GetValueOrDefault(resolve) ?? [])
                if (_parent.GetValueOrDefault(r) is CallExpression { Arguments.Count: > 0 } call && ReferenceEquals(call.Callee, r))
                {
                    any = true;
                    Go(call.Arguments[0], "promise", $"{rp.Name}({Snip(call.Arguments[0])})", call.Arguments[0]);
                }
                else if (_parent.GetValueOrDefault(r) is not CallExpression)
                {
                    any = true;
                    Leaf("unknown", "unknown", $"{rp.Name} handed on at {Line(r)}", r, link: "resolve escapes the executor");
                }
        if (!any) Leaf("origin", "origin", "promise " + Snip(promise), promise);
    }

    private void Member(MemberExpression m)
    {
        var scope = ScopeOf(m);
        var key = Key(m);
        if (key == null)
        {
            Leaf("unknown", "unknown", $"computed property {Snip(m)}", m, link: "dynamic property");
            return;
        }
        if (OwnerOf(m.Object) is { } owner)
        {
            Go(new Slot(owner, key), "property", $"{OwnerName(owner)}.{key}", m);
            return;
        }
        if (_p.Eval(m, scope) is JsRef r && JsProgram.Unwrap(m.Object) is not ThisExpression)
        {
            if (r.Module.Length > 0 && !r.Module.StartsWith('#')) Leaf("unknown", "unknown", $"{r.Path} of '{r.Module}' (external module)", m, link: "the module is outside this file");
            else if (r.Module.Length == 0) Leaf("unknown", "unknown", $"the global {r.Path}", m, link: "not defined in this file");
            else Leaf("unknown", "unknown", $"{r.Path} of module {r.Module[1..]}", m, link: "export not resolved");
            return;
        }
        Go(m.Object, "property", $".{key} of {Snip(m.Object)}", m.Object);
    }

    private void CallResult(CallExpression c)
    {
        var scope = ScopeOf(c);
        if (_p.BundledId(c, scope) is { } id)
        {
            Go(new Slot("module:" + id, ""), "import", $"module {id}", c);
            return;
        }
        var callee = JsProgram.Unwrap(c.Callee);
        var method = callee is MemberExpression { Property: Identifier mp, Computed: false } cm ? mp.Name : null;
        if (method is "then" or "catch" or "finally" && callee is MemberExpression pm)
        {
            if (method != "then") Go(pm.Object, "promise", $"settles {Snip(pm.Object)}", pm.Object);
            foreach (var a in c.Arguments)
                if (FunctionValue(a, scope) is { } cb) Go(new Ret(cb), "promise", $"result of the {method} callback", a);
            return;
        }
        var t = TargetOf(c);
        var functions = t.Functions.Count > 0 ? t.Functions : Passed(c);
        if (functions.Count > 0)
        {
            foreach (var f in functions) Go(new Ret(f), "return", $"result of {FnName(f)}", c);
            return;
        }
        var chain = t.Ref != null ? (t.Ref.Module.Length == 0 ? t.Ref.Path : t.Ref.Module + "." + t.Ref.Path) : JsProgram.Chain(callee);
        if (chain != null && (PassCalls.Contains(chain) || t.Ref != null && PassModules.Contains(t.Ref.Module)) || method != null && ArgPass.Contains(method) && t.Ref == null)
        {
            foreach (var a in c.Arguments) Go(a, "through", $"{Snip(callee)}()", a);
            if (method != null && callee is MemberExpression am2 && t.Ref == null) Go(am2.Object, "through", $"receiver of .{method}()", am2.Object);
            return;
        }
        if (method != null && ReceiverPass.Contains(method) && callee is MemberExpression rm && t.Ref == null)
        {
            Go(rm.Object, "through", $"receiver of .{method}()", rm.Object);
            return;
        }
        if (SinkOf(c) is { } sink)
        {
            Leaf("origin", "origin", $"result of {sink.Call} ({sink.Category})", c, sink.Endpoint);
            return;
        }
        if (t.Ref is { Module.Length: > 0 } ext && !ext.Module.StartsWith('#'))
            Leaf("unknown", "unknown", $"result of {ext.Module}.{ext.Path} (external module)", c, link: "the module is not in this file");
        else if (t.Ref != null)
            Leaf("unknown", "unknown", $"result of {chain}() (not defined in this file)", c, link: "a global or host function");
        else
            Leaf("unknown", "unknown", $"result of {Snip(callee)}()", c, link: t.Why ?? "callee not resolved");
    }

    // ---- text ----

    private string Snip(Node n)
    {
        if (n.Start < 0 || n.End > _p.Text.Length || n.End < n.Start) return n.Type.ToString();
        var span = _p.Text.AsSpan(n.Start, Math.Min(n.End - n.Start, 200));
        var s = string.Join(' ', span.ToString().Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries));
        return s.Length > 60 || n.End - n.Start > 200 ? s[..Math.Min(s.Length, 57)] + "..." : s;
    }

    private static string Line(Node n) => $"{n.Location.Start.Line}:{n.Location.Start.Column + 1}";
}

/// <summary>IPC pairings for a flow: the Electron graph over the scripts of the app a file belongs to (the nearest folder with a package.json).</summary>
internal static class JsFlowIpc
{
    private const int MaxFiles = 400;
    private const long MaxBytes = 64L * 1024 * 1024;

    /// <summary>The file's app-relative name and each IPC call's pairing by "file:line:column".</summary>
    public static (string File, Dictionary<string, string> Links) Links(string path, CancellationToken ct)
    {
        var full = Path.GetFullPath(path);
        var root = Path.GetDirectoryName(full)!;
        int depth = 0;
        for (var d = root; d != null && depth < 4; d = Path.GetDirectoryName(d), depth++)
            if (File.Exists(Path.Combine(d, "package.json"))) { root = d; break; }
        string Rel(string f) => Path.GetRelativePath(root, f).Replace('\\', '/');
        var graph = new Corvus.Services.Analysis.ElectronGraph();
        var links = new Dictionary<string, string>(StringComparer.Ordinal);
        try
        {
            graph.Add(Rel(full), File.ReadAllText(full), ct);
            long bytes = new FileInfo(full).Length;
            int files = 1;
            var dirs = new Queue<(string Dir, int Depth)>();
            dirs.Enqueue((root, 0));
            while (dirs.Count > 0 && files < MaxFiles && bytes < MaxBytes)
            {
                var (dir, level) = dirs.Dequeue();
                foreach (var f in Directory.EnumerateFiles(dir))
                {
                    if (Path.GetExtension(f) is not (".js" or ".mjs" or ".cjs") || string.Equals(f, full, StringComparison.OrdinalIgnoreCase)) continue;
                    if (++files > MaxFiles || (bytes += new FileInfo(f).Length) > MaxBytes) break;
                    graph.Add(Rel(f), File.ReadAllText(f), ct);
                }
                if (level < 6)
                    foreach (var sub in Directory.EnumerateDirectories(dir))
                        if (Path.GetFileName(sub) is not ("node_modules" or ".git") && !new DirectoryInfo(sub).Attributes.HasFlag(FileAttributes.ReparsePoint))
                            dirs.Enqueue((sub, level + 1));
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
        foreach (var r in graph.Finish())
            if (r.Kind is "ipc-main" or "ipc-renderer" && r.Link != null) links.TryAdd(r.Site, $"{r.Call} {r.Value}: {r.Link}");
        return (Rel(full), links);
    }
}
