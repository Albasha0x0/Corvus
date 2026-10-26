using System.Text;
using System.Text.RegularExpressions;
using Acornima;
using Acornima.Ast;

namespace Corvus.Services.Web;

/// <summary>
/// Lexical scopes of one parsed script or module and every binding's declaration and reference sites, for renaming a
/// binding everywhere it is used and nowhere else. A rename is refused when the new name would shadow or capture another
/// name, and bindings that code outside the file or a direct eval / with can reach (script globals, exports) stay fixed.
/// Suggested names for minified bindings come from evidence: a require or import source, a constructor, a getter call,
/// a destructured key, a callback position, a catch parameter, a loop counter.
/// </summary>
internal sealed partial class JsNames
{
    /// <summary>A reference or declaration site: the identifier's start, and how it is written when renamed.</summary>
    public enum SiteKind { Plain, ShorthandProperty, ShorthandImport, ShorthandExport }

    public sealed class Scope(Scope? parent, bool function, int start, int end)
    {
        public Scope? Parent { get; } = parent;
        public bool Function { get; } = function;
        public int Start { get; } = start;
        public int End { get; } = end;
        public readonly Dictionary<string, Binding> Names = new(StringComparer.Ordinal);
        // Names referenced inside this scope's subtree that resolve outside it, with their reference counts.
        public readonly Dictionary<string, int> Through = new(StringComparer.Ordinal);
        public bool Dynamic, Loop;

        public Scope VarScope
        {
            get
            {
                var s = this;
                while (!s.Function && s.Parent != null) s = s.Parent;
                return s;
            }
        }
    }

    public sealed class Binding(string name, Scope scope, int declared)
    {
        public string Name { get; set; } = name;
        public string Original { get; } = name;
        public Scope Scope { get; } = scope;
        public int Declared { get; } = declared;
        public readonly List<(int Start, SiteKind Kind, Scope From)> Sites = [];
        public string? Fixed;
        public string? Suggested, Reason;
    }

    /// <summary>A rename applied: the binding's original and new name, where it is declared, and why the name was chosen.</summary>
    public sealed record Rename(string From, string To, int Declared, string Reason);

    private static readonly HashSet<string> Reserved = new(StringComparer.Ordinal)
    {
        "break", "case", "catch", "class", "const", "continue", "debugger", "default", "delete", "do", "else", "enum", "export", "extends",
        "false", "finally", "for", "function", "if", "import", "in", "instanceof", "new", "null", "return", "super", "switch", "this",
        "throw", "true", "try", "typeof", "var", "void", "while", "with", "yield", "let", "static", "implements", "interface", "package",
        "private", "protected", "public", "await", "arguments", "eval", "undefined", "NaN", "Infinity", "async", "of", "get", "set",
    };

    private readonly List<(string Name, Scope From, int Start, SiteKind Kind)> _references = [];
    private readonly List<Scope> _scopes = [];
    private readonly Dictionary<Node, Scope> _scopeOf = [];
    private readonly bool _module;
    private bool _strict;

    public Scope Root { get; }
    public List<Binding> Bindings { get; } = [];
    public List<string> Notes { get; } = [];

    /// <summary>Resolves every scope and reference of <paramref name="tree"/>; deep trees need a large stack (callers use a thread of their own).</summary>
    public JsNames(Acornima.Ast.Program tree)
    {
        _module = tree is Acornima.Ast.Module;
        _strict = tree.Strict || _module;
        Root = NewScope(null, true, tree);
        Walk(tree, Root);
        Resolve();
    }

    private Scope NewScope(Scope? parent, bool function, Node owner)
    {
        var s = new Scope(parent, function, owner.Start, owner.End);
        _scopes.Add(s);
        _scopeOf[owner] = s;
        return s;
    }

    private Binding Declare(Scope scope, Identifier id, SiteKind kind = SiteKind.Plain)
    {
        if (!scope.Names.TryGetValue(id.Name, out var b))
        {
            scope.Names[id.Name] = b = new Binding(id.Name, scope, id.Start);
            Bindings.Add(b);
            // Top-level declarations of a script are properties of the global object, visible to other scripts.
            if (scope == Root && !_module) b.Fixed = "a global of the script";
        }
        b.Sites.Add((id.Start, kind, scope));
        return b;
    }

    private void Reference(Identifier id, Scope from, SiteKind kind = SiteKind.Plain) => _references.Add((id.Name, from, id.Start, kind));

    // Declares the names a pattern binds; default values and computed keys are walked as expressions in valueScope.
    private void Pattern(Node? node, Scope target, Scope valueScope, List<Binding>? declared = null)
    {
        switch (node)
        {
            case null: return;
            case Identifier id:
            {
                var b = Declare(target, id);
                declared?.Add(b);
                return;
            }
            case AssignmentPattern ap:
                Pattern(ap.Left, target, valueScope, declared);
                Walk(ap.Right, valueScope);
                return;
            case RestElement r: Pattern(r.Argument, target, valueScope, declared); return;
            case ArrayPattern arr:
                foreach (var e in arr.Elements) Pattern(e, target, valueScope, declared);
                return;
            case ObjectPattern obj:
                foreach (var p in obj.Properties)
                {
                    if (p is RestElement rest) { Pattern(rest.Argument, target, valueScope, declared); continue; }
                    var prop = (Property)p;
                    if (prop.Computed) Walk(prop.Key, valueScope);
                    if (prop.Shorthand && (prop.Value as Identifier ?? (prop.Value as AssignmentPattern)?.Left as Identifier) is { } sid)
                    {
                        var b = Declare(target, sid, SiteKind.ShorthandProperty);
                        declared?.Add(b);
                        if (prop.Value is AssignmentPattern def) Walk(def.Right, valueScope);
                    }
                    else Pattern(prop.Value, target, valueScope, declared);
                }
                return;
            case MemberExpression m: Walk(m, valueScope); return;
            default: Walk(node, valueScope); return;
        }
    }

    private void Walk(Node? node, Scope scope)
    {
        switch (node)
        {
            case null: return;
            case Identifier id: Reference(id, scope); return;
            case Acornima.Ast.Program p:
                foreach (var s in p.Body) Walk(s, scope);
                return;
            case VariableDeclaration v:
            {
                var target = v.Kind == VariableDeclarationKind.Var ? scope.VarScope : scope;
                foreach (var d in v.Declarations)
                {
                    var names = new List<Binding>();
                    Pattern(d.Id, target, scope, names);
                    Walk(d.Init, scope);
                    if (d.Id is Identifier && names.Count == 1 && d.Init != null) Evidence(names[0], d.Init);
                }
                return;
            }
            case FunctionDeclaration f:
            {
                // Sloppy-mode block functions are also var-scoped (ECMA-262 Annex B.3.3): declare them where both are seen.
                if (f.Id != null) Declare(_strict ? scope : scope.VarScope, f.Id);
                Function(f, f.Params, f.Body, scope);
                return;
            }
            case FunctionExpression fe:
            {
                var outer = scope;
                if (fe.Id != null)
                {
                    outer = NewScope(scope, false, fe);
                    Declare(outer, fe.Id);
                }
                Function(fe, fe.Params, fe.Body, outer, named: fe.Id != null);
                return;
            }
            case ArrowFunctionExpression a: Function(a, a.Params, a.Body, scope); return;
            case ClassDeclaration c:
                if (c.Id != null) Declare(scope, c.Id);
                Class(c, c.Id, c.SuperClass, c.Body, c.Decorators, scope, expression: false);
                return;
            case ClassExpression ce: Class(ce, ce.Id, ce.SuperClass, ce.Body, ce.Decorators, scope, expression: true); return;
            case BlockStatement b:
            {
                var inner = b is StaticBlock ? NewScope(scope, true, b) : NewScope(scope, false, b);
                foreach (var s in b.Body) Walk(s, inner);
                return;
            }
            case CatchClause cc:
            {
                var inner = NewScope(scope, false, cc);
                if (cc.Param != null)
                {
                    var names = new List<Binding>();
                    Pattern(cc.Param, inner, inner, names);
                    if (cc.Param is Identifier && names.Count == 1) Suggest(names[0], "error", "catch parameter");
                }
                foreach (var s in cc.Body.Body) Walk(s, inner);
                return;
            }
            case ForStatement fs:
            {
                var inner = NewScope(scope, false, fs);
                inner.Loop = true;
                Walk(fs.Init, inner);
                Walk(fs.Test, inner);
                Walk(fs.Update, inner);
                if (fs.Init is VariableDeclaration { Declarations: [{ Id: Identifier counter, Init: Literal }] } && fs.Update is UpdateExpression { Argument: Identifier u } && u.Name == counter.Name
                    && (inner.Names.GetValueOrDefault(counter.Name) ?? scope.VarScope.Names.GetValueOrDefault(counter.Name)) is { } b)
                    Suggest(b, Counter(scope), "loop counter");
                Walk(fs.Body, inner);
                return;
            }
            case ForInStatement or ForOfStatement:
            {
                var (left, right, body) = node is ForInStatement fi ? (fi.Left, fi.Right, fi.Body) : (((ForOfStatement)node).Left, ((ForOfStatement)node).Right, ((ForOfStatement)node).Body);
                var inner = NewScope(scope, false, node);
                Walk(right, scope);
                if (left is VariableDeclaration { Declarations: [{ Id: Identifier one }] } lv)
                {
                    var target = lv.Kind == VariableDeclarationKind.Var ? scope.VarScope : inner;
                    Suggest(Declare(target, one), node is ForInStatement ? "key" : "item", node is ForInStatement ? "for-in key" : "for-of item");
                }
                else Walk(left, inner);
                Walk(body, inner);
                return;
            }
            case SwitchStatement sw:
            {
                Walk(sw.Discriminant, scope);
                var inner = NewScope(scope, false, sw);
                foreach (var c in sw.Cases)
                {
                    Walk(c.Test, inner);
                    foreach (var s in c.Consequent) Walk(s, inner);
                }
                return;
            }
            case MemberExpression m:
                Walk(m.Object, scope);
                if (m.Computed) Walk(m.Property, scope);
                return;
            case Property prop:
                if (prop.Computed) Walk(prop.Key, scope);
                if (prop.Shorthand && prop.Value is Identifier sv) Reference(sv, scope, SiteKind.ShorthandProperty);
                else if (prop.Shorthand && prop.Value is AssignmentPattern { Left: Identifier dv } def)
                {
                    Reference(dv, scope, SiteKind.ShorthandProperty);
                    Walk(def.Right, scope);
                }
                else Walk(prop.Value, scope);
                return;
            case LabeledStatement l: Walk(l.Body, scope); return;
            case BreakStatement or ContinueStatement or MetaProperty: return;
            case WithStatement w:
            {
                Walk(w.Object, scope);
                var inner = NewScope(scope, false, w);
                inner.Dynamic = true;
                Walk(w.Body, inner);
                return;
            }
            case CallExpression { Callee: Identifier { Name: "eval" } } call:
            {
                // A direct eval sees every name in scope.
                for (var s = scope; s != null; s = s.Parent) s.Dynamic = true;
                Notes.Add("a direct eval keeps the names it can reach");
                Walk(call.Callee, scope);
                foreach (var a in call.Arguments) Walk(a, scope);
                return;
            }
            case CallExpression call:
                Walk(call.Callee, scope);
                foreach (var a in call.Arguments) Walk(a, scope);
                Callbacks(call);
                return;
            case NewExpression ne:
                Walk(ne.Callee, scope);
                foreach (var a in ne.Arguments) Walk(a, scope);
                if (ne.Callee is Identifier { Name: "Promise" } && ne.Arguments is [IFunction executor]) _callbacks.Add(((Node)executor, ["resolve", "reject"], "Promise executor"));
                return;
            case ImportDeclaration imp:
                foreach (var spec in imp.Specifiers)
                {
                    var shorthand = spec is ImportSpecifier { Imported: Identifier imported } && imported.Start == spec.Local.Start;
                    var b = Declare(scope, spec.Local, shorthand ? SiteKind.ShorthandImport : SiteKind.Plain);
                    if (spec is ImportDefaultSpecifier or ImportNamespaceSpecifier && imp.Source.Value is string source) Suggest(b, FromModule(source), $"import from \"{source}\"");
                }
                return;
            case ExportNamedDeclaration ex:
                if (ex.Declaration != null)
                {
                    int before = Bindings.Count;
                    Walk(ex.Declaration, scope);
                    foreach (var b in Bindings.Skip(before)) b.Fixed ??= "exported";
                }
                if (ex.Source == null)
                    foreach (var spec in ex.Specifiers)
                        if (spec.Local is Identifier local)
                            Reference(local, scope, spec.Exported is Identifier e && e.Start == local.Start ? SiteKind.ShorthandExport : SiteKind.Plain);
                return;
            case ExportAllDeclaration: return;
            case ExportDefaultDeclaration ed: Walk(ed.Declaration, scope); return;
            case ClassProperty cp:
                foreach (var d in cp.ChildNodes.OfType<Decorator>()) Walk(d, scope);
                if (cp.Computed) Walk(cp.Key, scope);
                Walk(cp.Value, scope);
                return;
            default:
                foreach (var child in node.ChildNodes) Walk(child, scope);
                return;
        }
    }

    private void Function(Node owner, in NodeList<Node> parameters, Node body, Scope scope, bool named = false)
    {
        bool strict = _strict;
        if (body is FunctionBody { Strict: true }) _strict = true;
        var inner = NewScope(scope, true, owner);
        foreach (var p in parameters) Pattern(p, inner, inner);
        if (body is FunctionBody fb)
            foreach (var s in fb.Body) Walk(s, inner);
        else Walk(body, inner);
        _strict = strict;
    }

    private void Class(Node owner, Identifier? id, Expression? superClass, ClassBody body, in NodeList<Decorator> decorators, Scope scope, bool expression)
    {
        foreach (var d in decorators) Walk(d, scope);
        bool strict = _strict;
        _strict = true;
        var inner = NewScope(scope, false, owner);
        if (id != null && expression) Declare(inner, id);
        Walk(superClass, inner);
        foreach (var e in body.Body) Walk(e, inner);
        _strict = strict;
    }

    private void Resolve()
    {
        foreach (var (name, from, start, kind) in _references)
        {
            Scope? at = from;
            Binding? b = null;
            for (; at != null; at = at.Parent)
                if (at.Names.TryGetValue(name, out b)) break;
            for (Scope? s = from; s != null && s != at; s = s.Parent) s.Through[name] = s.Through.GetValueOrDefault(name) + 1;
            if (b != null) b.Sites.Add((start, kind, from));
        }
        foreach (var b in Bindings)
        {
            if (b.Fixed != null) continue;
            if (b.Scope.Dynamic || b.Sites.Any(s => InDynamic(s.From, b.Scope))) b.Fixed = "reachable by a direct eval or with";
        }
    }

    private static bool InDynamic(Scope from, Scope until)
    {
        for (var s = from; s != null; s = s.Parent)
        {
            if (s.Dynamic) return true;
            if (s == until) return false;
        }
        return false;
    }

    /// <summary>Null when <paramref name="b"/> can take <paramref name="name"/>, otherwise why not.</summary>
    public string? Refuse(Binding b, string name)
    {
        if (b.Fixed != null) return b.Fixed;
        if (!IsIdentifier(name) || Reserved.Contains(name)) return $"'{name}' is not a usable identifier";
        if (name == b.Name) return null;
        if (b.Scope.Names.ContainsKey(name)) return $"'{name}' is already declared in the same scope";
        if (b.Scope.Through.ContainsKey(name)) return $"'{name}' is used inside the scope for an outer name it would hide";
        foreach (var (_, _, from) in b.Sites)
            for (var s = from; s != null && s != b.Scope; s = s.Parent)
                if (s.Names.ContainsKey(name)) return $"'{name}' is declared in an inner scope that uses the binding";
        return null;
    }

    /// <summary>Renames <paramref name="b"/>, keeping scope tables current for later checks; call only after <see cref="Refuse"/> returned null.</summary>
    public void Apply(Binding b, string name)
    {
        if (name == b.Name) return;
        b.Scope.Names.Remove(b.Name);
        b.Scope.Names[name] = b;
        foreach (var (_, _, from) in b.Sites)
            for (var s = from; s != null && s != b.Scope; s = s.Parent)
            {
                if (s.Through.TryGetValue(b.Name, out var n)) { if (n <= 1) s.Through.Remove(b.Name); else s.Through[b.Name] = n - 1; }
                s.Through[name] = s.Through.GetValueOrDefault(name) + 1;
            }
        b.Name = name;
    }

    /// <summary>True for a name a minifier or obfuscator produced: one or two characters, or _0x followed by hex digits.</summary>
    public static bool Minified(string name) => name.Length <= 2 || HexName().IsMatch(name);

    [GeneratedRegex("^_0x[0-9a-f]{3,}$")]
    private static partial Regex HexName();

    public static bool IsIdentifier(string s)
    {
        if (s.Length == 0 || char.IsDigit(s[0])) return false;
        foreach (char c in s) if (!(char.IsLetterOrDigit(c) || c is '_' or '$')) return false;
        return true;
    }

    private static void Suggest(Binding b, string? name, string reason)
    {
        if (b.Suggested != null || name == null || !Minified(b.Original)) return;
        b.Suggested = name;
        b.Reason = reason;
    }

    // Callback functions and the names their parameters take by position; applied once the function scopes exist.
    private readonly List<(Node Function, string[] Names, string Reason)> _callbacks = [];

    private void Callbacks(CallExpression call)
    {
        if (call.Callee is not MemberExpression { Computed: false, Property: Identifier method }) return;
        string[]? names = method.Name switch
        {
            "then" => ["result"],
            "catch" => ["error"],
            "forEach" or "map" or "filter" or "find" or "findIndex" or "some" or "every" or "flatMap" or "findLast" or "findLastIndex" => ["item", "index"],
            "reduce" or "reduceRight" => ["accumulator", "item", "index"],
            _ => null,
        };
        if (method.Name is "addEventListener" && call.Arguments is [_, IFunction listener, ..]) _callbacks.Add(((Node)listener, ["event"], "event listener"));
        else if (names != null && call.Arguments is [IFunction f, ..]) _callbacks.Add(((Node)f, names, $".{method.Name} callback"));
    }

    // i, j, k by how many counting loops enclose this one within its function.
    private static string Counter(Scope scope)
    {
        int depth = 0;
        for (var s = scope; s != null && !s.Function; s = s.Parent) if (s.Loop) depth++;
        return depth switch { 0 => "i", 1 => "j", 2 => "k", _ => "n" };
    }

    // A name from a variable's initializer.
    private static void Evidence(Binding b, Expression init)
    {
        var (name, reason) = FromValue(init);
        Suggest(b, name, reason);
    }

    private static (string? Name, string Reason) FromValue(Expression e)
    {
        switch (e)
        {
            case AwaitExpression aw: return FromValue(aw.Argument);
            case ThisExpression: return ("self", "this alias");
            case CallExpression { Callee: Identifier { Name: "require" or "__require" }, Arguments: [StringLiteral s] }:
                return (FromModule(s.Value), $"require(\"{s.Value}\")");
            case CallExpression { Callee: Identifier { Name: "fetch" } }: return ("response", "fetch result");
            case CallExpression { Callee: MemberExpression { Object: Identifier { Name: "JSON" }, Property: Identifier { Name: "parse" } } }: return ("data", "JSON.parse result");
            case CallExpression { Callee: MemberExpression { Object: Identifier { Name: "JSON" }, Property: Identifier { Name: "stringify" } } }: return ("json", "JSON.stringify result");
            case CallExpression { Callee: MemberExpression { Computed: false, Property: Identifier m } }:
            {
                if (m.Name is "getElementById" or "querySelector" or "createElement" or "closest") return ("element", $".{m.Name} result");
                if (m.Name is "querySelectorAll" or "getElementsByClassName" or "getElementsByTagName") return ("elements", $".{m.Name} result");
                var word = Regex.Match(m.Name, "^(?:get|create|load|read|find|build|make|fetch|open|parse)([A-Z][A-Za-z0-9]*)$");
                if (word.Success) return (Lower(word.Groups[1].Value), $".{m.Name} result");
                return (null, "");
            }
            case NewExpression { Callee: var callee }:
            {
                var type = callee switch { Identifier i => i.Name, MemberExpression { Computed: false, Property: Identifier p } => p.Name, _ => null };
                return type != null && !Minified(type) ? (Lower(type), $"new {type}") : (null, "");
            }
            case MemberExpression { Computed: false, Property: Identifier p } when !Minified(p.Name) && p.Name is not ("default" or "prototype" or "call" or "apply" or "bind"):
                return (p.Name, $".{p.Name} value");
            case FunctionExpression { Id: { } id } when !Minified(id.Name): return (id.Name, "function name");
            case ClassExpression { Id: { } cid } when !Minified(cid.Name): return (Lower(cid.Name), "class name");
            default: return (null, "");
        }
    }

    // A camelCase identifier from a module specifier's last path segment: "lodash/debounce" gives debounce, "react-dom" reactDom.
    private static string? FromModule(string source)
    {
        var last = source.TrimEnd('/').Split('/', ':')[^1];
        int dot = last.LastIndexOf('.');
        if (dot > 0) last = last[..dot];
        var sb = new StringBuilder();
        bool upper = false;
        foreach (char c in last)
        {
            if (char.IsLetterOrDigit(c)) { sb.Append(upper && sb.Length > 0 ? char.ToUpperInvariant(c) : c); upper = false; }
            else upper = true;
        }
        var name = sb.ToString();
        return name.Length == 0 || char.IsDigit(name[0]) ? null : name;
    }

    // camelCase of a type name: a leading acronym is lowered whole, "XMLHttpRequest" gives xmlHttpRequest, "URL" url.
    private static string Lower(string s)
    {
        int n = 0;
        while (n < s.Length && char.IsUpper(s[n])) n++;
        if (n > 1 && n < s.Length && char.IsLower(s[n])) n--;
        return n == 0 ? s : s[..Math.Max(1, n)].ToLowerInvariant() + s[Math.Max(1, n)..];
    }

    /// <summary>
    /// Applies <paramref name="requested"/> (name=new or name@line:column=new, comma-separated) and, with
    /// <paramref name="auto"/>, the suggested names of minified bindings; returns the renames applied and notes for the
    /// ones refused. A requested name that names no binding, or more than one without a position, is refused with the
    /// positions to choose from.
    /// </summary>
    public List<Rename> Plan(string? requested, bool auto, Func<int, (int Line, int Column)> position, List<string> refused)
    {
        var applied = new List<Rename>();
        foreach (var (function, names, reason) in _callbacks)
            if (_scopeOf.TryGetValue(function, out var fs) && function is IFunction f)
                for (int i = 0; i < Math.Min(names.Length, f.Params.Count); i++)
                    if (f.Params[i] is Identifier p && fs.Names.TryGetValue(p.Name, out var pb) && pb.Declared == p.Start) Suggest(pb, names[i], reason);
        foreach (var part in (requested ?? "").Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var m = Regex.Match(part, @"^([\p{L}\p{Nl}_$][\p{L}\p{Nl}\p{Nd}_$]*)(?:@(\d+):(\d+))?=(.+)$");
            if (!m.Success) { refused.Add($"'{part}': expected name=new or name@line:column=new"); continue; }
            string from = m.Groups[1].Value, to = m.Groups[4].Value.Trim();
            var candidates = Bindings.Where(b => b.Original == from).ToList();
            if (m.Groups[2].Success)
            {
                int line = int.Parse(m.Groups[2].Value, System.Globalization.CultureInfo.InvariantCulture), column = int.Parse(m.Groups[3].Value, System.Globalization.CultureInfo.InvariantCulture);
                candidates = [.. candidates.Where(b => b.Sites.Any(s => position(s.Start) == (line, column)))];
            }
            if (candidates.Count != 1)
            {
                var at = Bindings.Where(b => b.Original == from).Take(10).Select(b => { var (l, c) = position(b.Declared); return $"{from}@{l}:{c}"; }).ToList();
                refused.Add(candidates.Count == 0
                    ? $"'{part}': no binding named {from}{(at.Count > 0 ? " there; declared at " + string.Join(", ", at) : (Root.Through.ContainsKey(from) ? " (it is a global)" : ""))}"
                    : $"'{part}': {candidates.Count} bindings named {from}; pick one: {string.Join(", ", at)}");
                continue;
            }
            var target = candidates[0];
            if (Refuse(target, to) is { } why) { refused.Add($"'{part}': {why}"); continue; }
            applied.Add(new Rename(target.Name, to, target.Declared, "requested"));
            Apply(target, to);
        }
        if (auto)
            foreach (var b in Bindings.Where(b => b.Suggested != null && b.Name == b.Original && b.Fixed == null).OrderBy(b => b.Declared))
            {
                for (int n = 1; n <= 20; n++)
                {
                    var name = n == 1 ? b.Suggested! : b.Suggested + n.ToString(System.Globalization.CultureInfo.InvariantCulture);
                    if (Refuse(b, name) != null) continue;
                    applied.Add(new Rename(b.Name, name, b.Declared, b.Reason!));
                    Apply(b, name);
                    break;
                }
            }
        return applied;
    }

    /// <summary>The new text of every renamed site, by the identifier's start offset.</summary>
    public Dictionary<int, string> Sites()
    {
        var map = new Dictionary<int, string>();
        foreach (var b in Bindings)
        {
            if (b.Name == b.Original) continue;
            foreach (var (start, kind, _) in b.Sites)
                map[start] = kind switch
                {
                    SiteKind.ShorthandProperty => $"{b.Original}: {b.Name}",
                    SiteKind.ShorthandImport => $"{b.Original} as {b.Name}",
                    SiteKind.ShorthandExport => $"{b.Name} as {b.Original}",
                    _ => b.Name,
                };
        }
        return map;
    }
}
