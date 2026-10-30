using System.Text;
using System.Text.RegularExpressions;
using Acornima;
using Acornima.Ast;

namespace Corvus.Services.Web.Scripts;

/// <summary>Restores transformed JavaScript pass by pass; each rewrite replaces one node's span, so the rest stays as written.</summary>
internal static class JsLayers
{
    private const int MaxPasses = 12, MaxChars = 8 << 20;

    public static string Read(string text, ScriptContext ctx, int depth)
    {
        var current = text;
        for (int pass = 0; pass < MaxPasses; pass++)
        {
            if (ctx.Budget.Exhausted) break;
            if (current.Length > MaxChars) { ctx.Note($"Over {MaxChars:N0} characters: read as written."); break; }
            var program = Parse(current);
            if (program == null)
            {
                if (pass == 0) ctx.Note("The script does not parse as JavaScript: shown as written.");
                break;
            }
            var next = new JsPass(current, program, ctx, depth).Run();
            if (next == current) break;
            if (Parse(next) == null)
            {
                ctx.Note($"Pass {pass + 1} produced text that does not parse; the text before it is shown.");
                break;
            }
            current = next;
            if (pass == MaxPasses - 1) ctx.Note($"Stopped after {MaxPasses} passes.");
        }
        // A pass that ran out of steps can leave the text unchanged, so the note follows the loop.
        if (ctx.Budget.Exhausted)
        {
            if (!ctx.Incomplete) ctx.Note("The evaluation budget ran out: later passes are not shown.");
            ctx.Incomplete = true;
        }
        return Layout(current);
    }

    internal static Acornima.Ast.Program? Parse(string text)
    {
        var parser = new Parser(new ParserOptions { Tolerant = true, AllowReturnOutsideFunction = true });
        try { return parser.ParseScript(text); }
        catch (ParseErrorException)
        {
            try { return parser.ParseModule(text); }
            catch (ParseErrorException) { return null; }
        }
    }

    /// <summary>Minified text (long lines) laid out one statement per line by the tree; other text is kept as written.</summary>
    internal static string Layout(string text)
    {
        int lines = 1;
        foreach (var c in text) if (c == '\n') lines++;
        if (text.Length / lines < 200 || text.Length > 2 << 20) return text;
        var program = Parse(text);
        if (program == null) return text;
        var sb = new StringBuilder(text.Length + text.Length / 8);
        foreach (var st in program.Body) Statement(text, st, 0, sb);
        return sb.ToString();
    }

    private static void Statement(string text, Node st, int indent, StringBuilder sb)
    {
        sb.Append(' ', indent * 2);
        Inline(text, st, indent, sb);
        sb.Append('\n');
    }

    /// <summary>The node's text with every block inside it (function bodies, statement blocks, switch bodies) laid out.</summary>
    private static void Inline(string text, Node node, int indent, StringBuilder sb)
    {
        var blocks = new List<Node>();
        var stack = new Stack<Node>();
        foreach (var c in node.ChildNodes) stack.Push(c);
        while (stack.Count > 0)
        {
            var n = stack.Pop();
            if (n is BlockStatement { Body.Count: > 0 } || n is SwitchStatement) { blocks.Add(n); continue; }
            foreach (var c in n.ChildNodes) stack.Push(c);
        }
        if (node is BlockStatement or SwitchStatement) blocks = [node];
        blocks.Sort((a, b) => a.Start.CompareTo(b.Start));
        int at = node.Start;
        foreach (var b in blocks)
        {
            if (b.Start < at) continue;
            sb.Append(text, at, b.Start - at);
            if (b is BlockStatement block)
            {
                sb.Append("{\n");
                foreach (var s in block.Body) Statement(text, s, indent + 1, sb);
                sb.Append(' ', indent * 2).Append('}');
            }
            else
            {
                var sw = (SwitchStatement)b;
                sb.Append("switch (").Append(text, sw.Discriminant.Start, sw.Discriminant.End - sw.Discriminant.Start).Append(") {\n");
                foreach (var c in sw.Cases)
                {
                    sb.Append(' ', (indent + 1) * 2).Append(c.Test != null ? "case " + text[c.Test.Start..c.Test.End] + ":" : "default:").Append('\n');
                    foreach (var s in c.Consequent) Statement(text, s, indent + 2, sb);
                }
                sb.Append(' ', indent * 2).Append('}');
            }
            at = b.End;
        }
        sb.Append(text, at, node.End - at);
    }
}

/// <summary>One pass of rewrites over a parsed text.</summary>
internal sealed class JsPass
{
    private const string Base64Alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/=";

    private readonly string _text;
    private readonly Acornima.Ast.Program _program;
    private readonly ScriptContext _ctx;
    private readonly int _depth;
    private readonly TextEdits _edits;
    private readonly JsConstants _eval;
    private readonly List<(Node Node, Node? Parent)> _nodes = [];
    private readonly Dictionary<string, List<Node>> _declarations = new(StringComparer.Ordinal);
    private readonly HashSet<string> _assigned = new(StringComparer.Ordinal);
    private readonly Dictionary<string, Dictionary<string, object?>> _constantObjects = new(StringComparer.Ordinal);
    /// <summary>Objects whose members are set once (in the literal or by one assignment each) and never changed otherwise, by name and alias.</summary>
    private readonly Dictionary<string, Dictionary<string, (Node Value, int SetAt)>> _objects = new(StringComparer.Ordinal);
    private readonly List<(AssignmentExpression Node, string Owner, string? Key)> _memberWrites = [];
    private readonly HashSet<string> _dirtyObjects = new(StringComparer.Ordinal);
    private readonly Dictionary<Node, Node?> _parents = [];

    public JsPass(string text, Acornima.Ast.Program program, ScriptContext ctx, int depth)
    {
        _text = text;
        _program = program;
        _ctx = ctx;
        _depth = depth;
        _edits = new TextEdits(text);
        _eval = new JsConstants(ctx.Budget);
    }

    private string Src(Node n) => _text[n.Start..n.End];

    public string Run()
    {
        Index();
        _eval.Names = ConstantName;
        StringArrays();
        ProxyObjects();
        Flattening();
        DeadBranches();
        Layers();
        Calls();
        Clipboard();
        Fold();
        _ctx.Folded += _edits.Count;
        return _edits.Render();
    }

    // --- index ---

    private void Index()
    {
        var stack = new Stack<(Node, Node?)>();
        stack.Push((_program, null));
        while (stack.Count > 0)
        {
            var (n, parent) = stack.Pop();
            if (!_ctx.Budget.Step()) break;
            _nodes.Add((n, parent));
            _parents[n] = parent;
            switch (n)
            {
                case VariableDeclarator { Id: Identifier id } d: Declare(id.Name, d); break;
                case FunctionDeclaration { Id: { } fid } f: Declare(fid.Name, f); break;
                case AssignmentExpression { Left: Identifier target }: _assigned.Add(target.Name); break;
                case AssignmentExpression { Left: MemberExpression { Object: Identifier owner } member } write:
                    _assigned.Add(owner.Name + "[]");
                    var memberKey = MemberKey(member);
                    if (write.Operator != Operator.Assignment || memberKey == null) _dirtyObjects.Add(owner.Name);
                    else _memberWrites.Add((write, owner.Name, memberKey));
                    break;
                case UpdateExpression { Argument: Identifier updated }: _assigned.Add(updated.Name); break;
                case UpdateExpression { Argument: MemberExpression { Object: Identifier updatedOwner } }: _dirtyObjects.Add(updatedOwner.Name); break;
                case UnaryExpression { Operator: Operator.Delete, Argument: MemberExpression { Object: Identifier deletedOwner } }: _dirtyObjects.Add(deletedOwner.Name); break;
            }
            var children = n.ChildNodes.ToList();
            for (int i = children.Count - 1; i >= 0; i--) stack.Push((children[i], n));
        }
        _nodes.Reverse();
        _nodes.Sort((a, b) => a.Node.Start != b.Node.Start ? a.Node.Start.CompareTo(b.Node.Start) : b.Node.End.CompareTo(a.Node.End));
        Objects();
        // Constant members let member reads fold.
        foreach (var (name, members) in _objects)
        {
            var map = new Dictionary<string, object?>(StringComparer.Ordinal);
            foreach (var (key, (value, _)) in members)
                if (value is not (FunctionExpression or ArrowFunctionExpression) && _eval.Eval(value) is var v && v is string or double or bool) map[key] = v;
            if (map.Count > 0) _constantObjects[name] = map;
        }
    }

    private static string? MemberKey(MemberExpression m) => m.Computed
        ? m.Property switch { StringLiteral s => s.Value, NumericLiteral n => JsConstants.NumberToString(n.Value), _ => null }
        : (m.Property as Identifier)?.Name;

    /// <summary>Objects built from a literal and single assignments per member, never changed otherwise, with their aliases.</summary>
    private void Objects()
    {
        foreach (var (name, decls) in _declarations)
        {
            if (decls is not [VariableDeclarator { Init: ObjectExpression obj }] || _assigned.Contains(name) || _dirtyObjects.Contains(name)) continue;
            var members = new Dictionary<string, (Node, int)>(StringComparer.Ordinal);
            bool ok = true;
            foreach (var p in obj.Properties)
            {
                if (p is not Property { Computed: false, Kind: PropertyKind.Init } prop || Key(prop) is not { } key || members.ContainsKey(key)) { ok = false; break; }
                members[key] = (prop.Value, obj.Start);
            }
            if (!ok) continue;
            _objects[name] = members;
        }
        var conflicts = new HashSet<(string, string)>();
        foreach (var (write, owner, key) in _memberWrites)
        {
            if (!_objects.TryGetValue(owner, out var members)) continue;
            if (members.ContainsKey(key!)) conflicts.Add((owner, key!));
            else members[key!] = (write.Right, write.Start);
        }
        foreach (var (owner, key) in conflicts) _objects[owner].Remove(key);
        // var b = a: an alias of the same object.
        foreach (var (name, decls) in _declarations)
            if (decls is [VariableDeclarator { Init: Identifier source }] && !_assigned.Contains(name) && !_dirtyObjects.Contains(name)
                && !_memberWrites.Any(w => w.Owner == name) && _objects.TryGetValue(source.Name, out var shared))
                _objects.TryAdd(name, shared);
    }

    private void Declare(string name, Node n)
    {
        if (!_declarations.TryGetValue(name, out var list)) _declarations[name] = list = [];
        list.Add(n);
    }

    private static string? Key(Property p) => p.Key switch
    {
        Identifier i => i.Name,
        StringLiteral s => s.Value,
        NumericLiteral n => JsConstants.NumberToString(n.Value),
        _ => null,
    };

    private object? ConstantName(string name) =>
        _constantObjects.TryGetValue(name, out var map) ? map : JsUnknown.Value;

    // --- obfuscator.io string arrays ---

    private sealed class StringArray
    {
        public required string Name { get; init; }
        public required Node Declaration { get; init; }
        public required List<string> Items { get; init; }
        public Node? Decoder { get; set; }
        public string? DecoderName { get; set; }
        public double Offset { get; set; }
        public string Encoding { get; set; } = "none";
        public Node? Rotation { get; set; }
        public Dictionary<string, string> Rc4Cache { get; } = [];
    }

    private void StringArrays()
    {
        foreach (var array in FindArrays())
        {
            if (!FindDecoder(array)) continue;
            // Tries the decoder's apparent encoding first; the one whose rotation reaches the checksum is right.
            var original = array.Items.ToList();
            bool? matched = null;
            foreach (var encoding in new[] { array.Encoding }.Concat(new[] { "base64", "rc4", "none" }.Where(e => e != array.Encoding)))
            {
                array.Encoding = encoding;
                array.Items.Clear();
                array.Items.AddRange(original);
                matched = Rotate(array);
                if (matched != false) break;
            }
            if (matched == false)
            {
                _ctx.Note("A string-array rotation did not reach its checksum: its strings are left as written.");
                continue;
            }
            InlineDecoded(array);
        }
    }

    private IEnumerable<StringArray> FindArrays()
    {
        foreach (var (node, parent) in _nodes)
        {
            // function _0x1(){var a=['..',..];_0x1=function(){return a;};return _0x1();}
            if (node is FunctionDeclaration { Id: { } fid, Body.Body: [VariableDeclaration { Declarations: [{ Init: ArrayExpression arr }] }, ..] } fn && Strings(arr) is { Count: >= 2 } items)
                yield return new StringArray { Name = fid.Name, Declaration = fn, Items = items };
            // var _0x1 = ['..', ..] used inside a decoder (older releases).
            else if (node is VariableDeclarator { Id: Identifier vid, Init: ArrayExpression varr } && Strings(varr) is { Count: >= 3 } vitems
                     && Regex.IsMatch(vid.Name, @"^_0x[0-9a-f]+$|^a\d+_0x[0-9a-f]+$") && parent is VariableDeclaration { Declarations.Count: 1 } decl)
                yield return new StringArray { Name = vid.Name, Declaration = decl, Items = vitems };
        }
    }

    private static List<string>? Strings(ArrayExpression arr)
    {
        var list = new List<string>(arr.Elements.Count);
        foreach (var e in arr.Elements)
        {
            if (e is not StringLiteral s) return null;
            list.Add(s.Value);
        }
        return list;
    }

    private bool FindDecoder(StringArray array)
    {
        foreach (var (node, _) in _nodes)
        {
            IFunction? fn = null;
            Node? decl = null;
            string? name = null;
            if (node is FunctionDeclaration { Id: { } id } f && f != array.Declaration) (fn, decl, name) = (f, f, id.Name);
            else if (node is VariableDeclarator { Id: Identifier vid, Init: FunctionExpression fe }) (fn, decl, name) = (fe, node, vid.Name);
            if (fn == null || fn.Params.Count is 0 or > 3 || fn.Params[0] is not Identifier) continue;
            var body = Src((Node)fn);
            if (!Regex.IsMatch(body, @"\b" + Regex.Escape(array.Name) + @"\b")) continue;
            array.Decoder = decl;
            array.DecoderName = name;
            // The index shift: p = p - N or p -= N on a parameter of the decoder or its replacement.
            var parameters = Inside((Node)fn).Select(n => n.Node).OfType<IFunction>().Append(fn)
                .SelectMany(f => f.Params.OfType<Identifier>().Select(p => p.Name)).ToHashSet(StringComparer.Ordinal);
            foreach (var (inner, _) in Inside((Node)fn))
            {
                if (inner is AssignmentExpression { Left: Identifier l } a && parameters.Contains(l.Name))
                {
                    var p0Name = l.Name;
                    if (a.Operator == Operator.SubtractionAssignment && _eval.Eval(a.Right) is double d1) { array.Offset = d1; break; }
                    if (a.Right is BinaryExpression { Operator: Operator.Subtraction or Operator.Addition, Left: Identifier bl } b && bl.Name == p0Name && _eval.Eval(b.Right) is double d2)
                    {
                        array.Offset = b.Operator == Operator.Subtraction ? d2 : -d2;
                        break;
                    }
                }
            }
            if (body.Contains(Base64Alphabet, StringComparison.Ordinal))
                array.Encoding = fn.Params.Count >= 2 && Regex.IsMatch(body, @"0x100\b|\b256\b") ? "rc4" : "base64";
            return true;
        }
        return false;
    }

    /// <summary>The nodes within <paramref name="outer"/>'s span, in source order, without <paramref name="outer"/>.</summary>
    private IEnumerable<(Node Node, Node? Parent)> Inside(Node outer)
    {
        // The index is sorted by start, so only nodes starting in the span are read.
        int lo = 0, hi = _nodes.Count;
        while (lo < hi)
        {
            int mid = (lo + hi) >>> 1;
            if (_nodes[mid].Node.Start < outer.Start) lo = mid + 1; else hi = mid;
        }
        for (int i = lo; i < _nodes.Count && _nodes[i].Node.Start <= outer.End; i++)
            if (_nodes[i].Node.End <= outer.End && _nodes[i].Node != outer) yield return _nodes[i];
    }

    /// <summary>The rotation call: push(shift) until the checksum expression equals its target, or a fixed count (older releases).</summary>
    /// <returns>True when the checksum was reached, false when it was not, null when there is no checksum.</returns>
    private bool? Rotate(StringArray array)
    {
        foreach (var (node, parent) in _nodes)
        {
            if (node is not CallExpression { Callee: var callee } call || Unwrap(callee) is not FunctionExpression fn || call.Arguments.Count < 2) continue;
            if (call.Arguments[0] is not Identifier first || first.Name != array.Name) continue;
            if (_eval.Eval(call.Arguments[1]) is not double target) continue;
            array.Rotation = Statement(call);
            var items = array.Items;
            // The checksum is the declarator whose init calls parseInt.
            var checksum = Inside(fn).Select(n => n.Node).OfType<VariableDeclarator>().FirstOrDefault(d => d.Init != null && Src(d.Init).Contains("parseInt", StringComparison.Ordinal))?.Init;
            if (checksum == null)
            {
                // Older releases: while (--n) { arr.push(arr.shift()) } called with ++count.
                if (Src(fn).Contains("push", StringComparison.Ordinal) && items.Count > 0)
                    RotateLeft(items, (int)((long)target % items.Count));
                return null;
            }
            var aliases = Aliases(array);
            var wrappers = Wrappers(aliases);
            for (int i = 0; i <= items.Count; i++)
            {
                if (!_ctx.Budget.Step(8)) return false;
                var saved = _eval.Calls;
                _eval.Calls = c => c.Callee is Identifier ci && (aliases.Contains(ci.Name) || wrappers.ContainsKey(ci.Name)) ? Resolve(array, aliases, wrappers, c, [], 0) : null;
                var value = _eval.Eval(checksum);
                _eval.Calls = saved;
                if (value is double v && v == target) return true;
                RotateLeft(items, 1);
            }
            return false;
        }
        return null;
    }

    private static void RotateLeft(List<string> items, int n)
    {
        if (items.Count == 0) return;
        n %= items.Count;
        if (n == 0) return;
        var head = items.GetRange(0, n);
        items.RemoveRange(0, n);
        items.AddRange(head);
    }

    private static Node Unwrap(Node n) => n is ParenthesizedExpression p ? Unwrap(p.Expression) : n;

    /// <summary>The statement holding an expression (an IIFE's ExpressionStatement), or the expression itself.</summary>
    private Node Statement(Node n)
    {
        var cur = n;
        while (_parents.GetValueOrDefault(cur) is { } parent && parent is ParenthesizedExpression or UnaryExpression or SequenceExpression { Expressions.Count: 1 }) cur = parent;
        return _parents.GetValueOrDefault(cur) is ExpressionStatement st ? st : cur;
    }

    /// <summary>The decoder's name and every variable that holds it (var x = decoder), within <paramref name="scope"/> or the whole text.</summary>
    private HashSet<string> Aliases(StringArray array, Node? scope = null)
    {
        var set = new HashSet<string>(StringComparer.Ordinal) { array.DecoderName! };
        bool grew = true;
        while (grew)
        {
            grew = false;
            foreach (var (node, _) in scope != null ? Inside(scope) : _nodes)
                if (node is VariableDeclarator { Id: Identifier id, Init: Identifier init } && set.Contains(init.Name) && set.Add(id.Name)) grew = true;
                else if (node is AssignmentExpression { Left: Identifier left, Right: Identifier right } && set.Contains(right.Name) && set.Add(left.Name)) grew = true;
        }
        return set;
    }

    /// <summary>A decoder call's string: arguments evaluated (with <paramref name="bound"/> parameters), decoded from the array.</summary>
    private object? DecodeCall(StringArray array, CallExpression call, Dictionary<string, object?> bound)
    {
        if (call.Arguments.Count == 0) return JsUnknown.Value;
        var saved = _eval.Names;
        _eval.Names = n => bound.TryGetValue(n, out var v) ? v : ConstantName(n);
        try
        {
            var index = _eval.Eval(call.Arguments[0]);
            var key = call.Arguments.Count > 1 ? _eval.Eval(call.Arguments[1]) : JsUndefined.Value;
            if (!JsConstants.Known(index) || !JsConstants.Known(key)) return JsUnknown.Value;
            return Decode(array, JsConstants.ToNumber(index), key as string);
        }
        finally { _eval.Names = saved; }
    }

    private object? Decode(StringArray array, double index, string? key)
    {
        double i = index - array.Offset;
        if (double.IsNaN(i) || i < 0 || i >= array.Items.Count || i != Math.Floor(i)) return JsUnknown.Value;
        var s = array.Items[(int)i];
        switch (array.Encoding)
        {
            case "base64": return ObfuscatorBase64(s) ?? (object)JsUnknown.Value;
            case "rc4":
                if (key == null || ObfuscatorBase64(s) is not { } bin) return JsUnknown.Value;
                return Rc4(bin, key);
        }
        return s;
    }

    /// <summary>The obfuscator's base64 (lowercase alphabet first), then its percent-encoding round trip (UTF-8).</summary>
    internal static string? ObfuscatorBase64(string s)
    {
        var raw = new StringBuilder();
        int bc = 0, bs = 0;
        foreach (var ch in s)
        {
            int idx = Base64Alphabet.IndexOf(ch);
            if (idx < 0) continue;
            bc = bs % 4 != 0 ? bc * 64 + idx : idx;
            if (bs++ % 4 != 0) raw.Append((char)(0xFF & bc >> ((-2 * bs) & 6)));
        }
        var bytes = raw.ToString().Select(c => (byte)c).ToArray();
        try { return new UTF8Encoding(false, true).GetString(bytes); }
        catch (DecoderFallbackException) { return null; }
    }

    internal static string Rc4(string data, string key)
    {
        var s = new int[256];
        for (int i = 0; i < 256; i++) s[i] = i;
        int j = 0;
        for (int i = 0; i < 256; i++)
        {
            j = (j + s[i] + key[i % key.Length]) % 256;
            (s[i], s[j]) = (s[j], s[i]);
        }
        var sb = new StringBuilder(data.Length);
        int x = 0;
        j = 0;
        foreach (var c in data)
        {
            x = (x + 1) % 256;
            j = (j + s[x]) % 256;
            (s[x], s[j]) = (s[j], s[x]);
            sb.Append((char)(c ^ s[(s[x] + s[j]) % 256]));
        }
        return sb.ToString();
    }

    /// <summary>Replaces every decoder call (through aliases and wrapper functions) whose arguments are constant with its string.</summary>
    private void InlineDecoded(StringArray array)
    {
        if (array.Items.Count == 0) return;
        var aliases = Aliases(array);
        var wrappers = Wrappers(aliases);
        int total = 0, done = 0;
        foreach (var (node, _) in _nodes)
        {
            if (node is not CallExpression { Callee: Identifier callee } call) continue;
            if (!aliases.Contains(callee.Name) && !wrappers.ContainsKey(callee.Name)) continue;
            if (Inside(array.Decoder!).Any(n => n.Node == call) || array.Rotation != null && call.Start >= array.Rotation.Start && call.End <= array.Rotation.End) continue;
            // Skips a wrapper's own forwarding call.
            if (wrappers.Values.Any(w => w.Inner == call)) continue;
            total++;
            var value = Resolve(array, aliases, wrappers, call, [], 0);
            if (value is string s)
            {
                _edits.Set(call.Start, call.End, JsConstants.Literal(s));
                done++;
            }
        }
        if (total == 0 || done < total)
        {
            if (total > 0) _ctx.Note($"{total - done} of {total} string-array calls left as written (arguments not constant).");
            return;
        }
        // Every call decoded, so the array, decoder, rotation, wrappers and aliases are unused.
        Remove(array.Declaration);
        Remove(array.Decoder is VariableDeclarator vd ? _parents.GetValueOrDefault(vd) ?? vd : array.Decoder!);
        if (array.Rotation != null) Remove(array.Rotation);
        foreach (var w in wrappers.Values) Remove(w.Function is FunctionDeclaration ? w.Function : _parents.GetValueOrDefault(w.Function) is VariableDeclarator d ? _parents.GetValueOrDefault(d) ?? d : w.Function);
        foreach (var (node, parent) in _nodes)
            if (node is VariableDeclarator { Id: Identifier id, Init: Identifier init } alias && aliases.Contains(id.Name) && aliases.Contains(init.Name))
                RemoveDeclarator(alias);
        _ctx.Note($"obfuscator.io string array of {array.Items.Count} strings decoded ({array.Encoding}), {done} calls inlined.");
        _ctx.Recovered.Add("obfuscator.io string array");
    }

    private void Remove(Node n)
    {
        if (n is VariableDeclaration { Declarations.Count: > 1 }) return;
        _edits.Set(n.Start, n.End, "");
    }

    /// <summary>Removes one declarator with its comma; a declaration of one declarator goes whole.</summary>
    private void RemoveDeclarator(VariableDeclarator d)
    {
        if (_parents.GetValueOrDefault(d) is not VariableDeclaration decl) return;
        var list = decl.Declarations;
        int i = 0;
        while (i < list.Count && list[i] != d) i++;
        if (list.Count == 1) Remove(decl);
        else if (i >= 0 && i < list.Count - 1) _edits.Set(d.Start, list[i + 1].Start, "");
        else if (i > 0) _edits.Set(list[i - 1].End, d.End, "");
    }

    private sealed record Wrapper(Node Function, List<string> Params, CallExpression Inner);

    /// <summary>Functions whose body is one return of a decoder or wrapper call: function w(a, b, c) { return d(c - 0x12, a); }.</summary>
    private Dictionary<string, Wrapper> Wrappers(HashSet<string> aliases)
    {
        var map = new Dictionary<string, Wrapper>(StringComparer.Ordinal);
        bool grew = true;
        while (grew)
        {
            grew = false;
            foreach (var (node, parent) in _nodes)
            {
                (IFunction? fn, string? name) = node switch
                {
                    FunctionDeclaration { Id: { } id } f => ((IFunction?)f, id.Name),
                    FunctionExpression fe when parent is VariableDeclarator { Id: Identifier vid } => (fe, vid.Name),
                    _ => (null, null),
                };
                if (fn == null || name == null || map.ContainsKey(name) || aliases.Contains(name)) continue;
                if (fn.Body is not FunctionBody { Body: [ReturnStatement { Argument: CallExpression { Callee: Identifier inner } call }] }) continue;
                if (!aliases.Contains(inner.Name) && !map.ContainsKey(inner.Name)) continue;
                var ps = fn.Params.OfType<Identifier>().Select(p => p.Name).ToList();
                if (ps.Count != fn.Params.Count) continue;
                map[name] = new Wrapper((Node)fn, ps, call);
                grew = true;
            }
        }
        return map;
    }

    private object? Resolve(StringArray array, HashSet<string> aliases, Dictionary<string, Wrapper> wrappers, CallExpression call, Dictionary<string, object?> bound, int depth)
    {
        if (depth > 16 || call.Callee is not Identifier callee) return JsUnknown.Value;
        if (aliases.Contains(callee.Name)) return DecodeCall(array, call, bound);
        if (!wrappers.TryGetValue(callee.Name, out var w)) return JsUnknown.Value;
        var saved = _eval.Names;
        _eval.Names = n => bound.TryGetValue(n, out var v) ? v : ConstantName(n);
        var args = new Dictionary<string, object?>(StringComparer.Ordinal);
        try
        {
            for (int i = 0; i < w.Params.Count; i++)
                args[w.Params[i]] = i < call.Arguments.Count ? _eval.Eval(call.Arguments[i]) : JsUndefined.Value;
        }
        finally { _eval.Names = saved; }
        return Resolve(array, aliases, wrappers, w.Inner, args, depth + 1);
    }

    // --- proxy objects ---

    /// <summary>Objects of string constants and one-line functions (control-flow storage): members inlined where read.</summary>
    private void ProxyObjects()
    {
        foreach (var (name, all) in _objects)
        {
            var members = all.Where(m => m.Value.Value is StringLiteral or NumericLiteral || m.Value.Value is FunctionExpression { Body.Body: [ReturnStatement { Argument: not null }] })
                .ToDictionary(m => m.Key, m => m.Value, StringComparer.Ordinal);
            if (members.Count == 0) continue;
            var decl = (VariableDeclarator)_declarations[name][0];
            int uses = 0, inlined = 0;
            foreach (var (node, parent) in _nodes)
            {
                if (node is not Identifier id || id.Name != name || node == decl.Id) continue;
                uses++;
                if (parent is not MemberExpression m || m.Object != node) continue;
                if (_parents.GetValueOrDefault(m) is AssignmentExpression assign && assign.Left == m) continue;
                var key = MemberKey(m);
                if (key == null || !members.TryGetValue(key, out var set) || set.SetAt > m.Start) continue;
                var value = set.Value;
                var outer = _parents.GetValueOrDefault(m);
                if (value is FunctionExpression fn)
                {
                    if (outer is not CallExpression call || call.Callee != m) continue;
                    if (Inline(fn, call) is { } text) { _edits.Set(call.Start, call.End, text); inlined++; _ctx.Recovered.Add("proxy objects"); }
                }
                else if (!(outer is CallExpression c2 && c2.Callee == m))
                {
                    _edits.Set(m.Start, m.End, Src(value));
                    inlined++;
                }
            }
            // Removed in a later pass, since an inlined function body can name the object again.
            if (uses == 0 && decl.Init is ObjectExpression && !_memberWrites.Any(w => w.Owner == name)) RemoveDeclarator(decl);
        }
    }

    /// <summary>A proxy function's return expression with its parameters replaced by the call's arguments, or null.</summary>
    private string? Inline(FunctionExpression fn, CallExpression call)
    {
        var ret = ((ReturnStatement)fn.Body.Body[0]).Argument!;
        var ps = fn.Params.OfType<Identifier>().Select(p => p.Name).ToList();
        if (ps.Count != fn.Params.Count || call.Arguments.Count != ps.Count || call.Arguments.Any(a => a is SpreadElement)) return null;
        var uses = Inside(ret).Select(n => n.Node).Append(ret).OfType<Identifier>().Where(i => ps.Contains(i.Name)).OrderBy(i => i.Start).ToList();
        foreach (var p in ps)
            if (uses.Count(u => u.Name == p) > 1 && !Simple(call.Arguments[ps.IndexOf(p)])) return null;
        var sb = new StringBuilder();
        int at = ret.Start;
        foreach (var u in uses)
        {
            sb.Append(_text, at, u.Start - at);
            var arg = call.Arguments[ps.IndexOf(u.Name)];
            sb.Append(Simple(arg) ? Src(arg) : "(" + Src(arg) + ")");
            at = u.End;
        }
        sb.Append(_text, at, ret.End - at);
        var body = sb.ToString();
        return ret is CallExpression or MemberExpression or Identifier or Literal ? body : "(" + body + ")";
    }

    private static bool Simple(Node n) => n is Identifier or Literal or MemberExpression { Object: Identifier, Computed: false } or CallExpression or ParenthesizedExpression;

    // --- control-flow flattening ---

    /// <summary>while (!![]) { switch (order[i++]) { case '1': ...; continue; ... } break; } put back as the statements in order.</summary>
    private void Flattening()
    {
        foreach (var (node, _) in _nodes)
        {
            if (node is not WhileStatement { Body: BlockStatement { Body: [SwitchStatement sw, BreakStatement { Label: null }] } } loop) continue;
            if (_eval.Eval(loop.Test) is not true) continue;
            if (sw.Discriminant is not MemberExpression { Computed: true, Object: Identifier seq, Property: UpdateExpression { Argument: Identifier counter } }) continue;
            if (Declarator(seq.Name) is not { Init: { } seqInit } seqDecl || _eval.Eval(seqInit) is not object[] order) continue;
            if (Declarator(counter.Name, updated: true) is not { Init: { } counterInit } counterDecl || _eval.Eval(counterInit) is not double start) continue;
            var cases = new Dictionary<string, SwitchCase>(StringComparer.Ordinal);
            foreach (var c in sw.Cases)
                if (c.Test != null && _eval.Eval(c.Test) is { } k && JsConstants.Known(k)) cases[JsConstants.ToStr(k)] = c;
            var sb = new StringBuilder();
            bool ok = true;
            foreach (var key in order.Skip((int)start))
            {
                if (!cases.TryGetValue(JsConstants.ToStr(key), out var c)) { ok = false; break; }
                var stmts = c.Consequent.Where(s => s is not ContinueStatement { Label: null }).ToList();
                if (stmts.Count == 0) continue;
                if (sb.Length > 0) sb.Append('\n');
                sb.Append(_text, stmts[0].Start, stmts[^1].End - stmts[0].Start);
            }
            if (!ok) continue;
            _edits.Set(loop.Start, loop.End, sb.ToString());
            _ctx.Recovered.Add("control-flow flattening");
            var a = _parents.GetValueOrDefault(seqDecl);
            if (a == _parents.GetValueOrDefault(counterDecl) && a is VariableDeclaration { Declarations.Count: 2 } both) _edits.Set(both.Start, both.End, "");
            else
            {
                RemoveDeclarator(seqDecl);
                RemoveDeclarator(counterDecl);
            }
        }
    }

    /// <param name="updated">The loop counter: only its start value is read, so i++ is allowed.</param>
    private VariableDeclarator? Declarator(string name, bool updated = false) =>
        _declarations.TryGetValue(name, out var list) && list is [VariableDeclarator d] && (updated || !_assigned.Contains(name)) ? d : null;

    // --- dead branches ---

    private void DeadBranches()
    {
        foreach (var (node, parent) in _nodes)
        {
            if (node is IfStatement s && Pure(s.Test) && _eval.Eval(s.Test) is { } test && JsConstants.Known(test))
            {
                var taken = JsConstants.Truthy(test) ? s.Consequent : s.Alternate;
                _edits.Set(s.Start, s.End, taken == null ? "" : taken is BlockStatement b ? Body(b) : Src(taken));
                _ctx.Recovered.Add("dead branches");
            }
            else if (node is ConditionalExpression c && Pure(c.Test) && _eval.Eval(c.Test) is { } ct && JsConstants.Known(ct))
            {
                var taken = JsConstants.Truthy(ct) ? c.Consequent : c.Alternate;
                _edits.Set(c.Start, c.End, "(" + Src(taken) + ")");
            }
        }
    }

    private string Body(BlockStatement b) => b.Body.Count == 0 ? "" : _text[b.Body[0].Start..b.Body[^1].End];

    /// <summary>A test built from literals only (string, number and boolean comparisons), not a variable's value.</summary>
    private bool Pure(Node test) => test is not Literal && Inside(test).All(n => n.Node is Literal or BinaryExpression or UnaryExpression or ParenthesizedExpression or ArrayExpression);

    // --- eval layers ---

    private void Layers()
    {
        foreach (var (node, parent) in _nodes)
        {
            if (node is not (CallExpression or NewExpression)) continue;
            var (callee, args) = node switch
            {
                CallExpression c => (c.Callee, c.Arguments),
                NewExpression n => (n.Callee, n.Arguments),
                _ => throw new InvalidOperationException(),
            };
            var name = CalleeName(callee);
            if (name is not ("eval" or "Function" or "setTimeout" or "setInterval" or "execScript") || args.Count == 0) continue;
            // With parameters, the body is a function, not a layer.
            if (name == "Function" && args.Count > 1) continue;
            var arg = name == "Function" ? args[^1] : args[0];
            _eval.Steps.Clear();
            string? code = Packed(arg) ?? (_eval.Eval(arg) is string s ? s : null);
            if (code == null || arg is StringLiteral && name is "setTimeout" or "setInterval" && code.Length < 4) continue;
            var via = _eval.Steps.Count > 0 ? $"{name} of {string.Join(" > ", _eval.Steps)}" : name;
            if (Packed(arg) != null) via = name + " of a packer";
            var site = node;
            // Function(code)() runs the body, so the outer call is the site.
            if (name == "Function" && parent is CallExpression outer && outer.Callee == node) site = outer;
            if (_ctx.Peel("javascript", code, via, _depth + 1) is not { } plain) continue;
            // A statement takes the layer's text; inside an expression the call stays and the layer is listed.
            if (_parents.GetValueOrDefault(site) is ExpressionStatement statement && statement.Expression == site)
                _edits.Set(statement.Start, statement.End, plain.Trim());
        }
    }

    private static string? CalleeName(Node callee) => Unwrap(callee) switch
    {
        Identifier i => i.Name,
        MemberExpression { Object: Identifier { Name: "window" or "self" or "globalThis" or "this" }, Property: Identifier p, Computed: false } => p.Name,
        MemberExpression { Object: Identifier { Name: "window" or "self" or "globalThis" }, Property: StringLiteral s, Computed: true } => s.Value,
        _ => null,
    };

    /// <summary>Dean Edwards' packer: function(p,a,c,k,e,d){...}('payload', radix, count, 'words'.split('|'), ...) unpacked.</summary>
    private string? Packed(Node arg)
    {
        if (Unwrap(arg) is not CallExpression { Callee: var callee } call || Unwrap(callee) is not FunctionExpression { Params.Count: >= 4 } || call.Arguments.Count < 4) return null;
        if (_eval.Eval(call.Arguments[0]) is not string p || _eval.Eval(call.Arguments[1]) is not double a || _eval.Eval(call.Arguments[2]) is not double c) return null;
        if (_eval.Eval(call.Arguments[3]) is not object[] k) return null;
        int radix = (int)a, count = (int)c;
        if (radix is < 2 or > 95 || count < 0 || count > 1_000_000) return null;
        var words = new Dictionary<string, string>(StringComparer.Ordinal);
        for (int i = count - 1; i >= 0; i--)
        {
            var key = Encode(i, radix);
            words[key] = i < k.Length && k[i] is string w && w.Length > 0 ? w : key;
        }
        return PackedWord.Replace(p, m => words.TryGetValue(m.Value, out var w) ? w : m.Value);
    }

    // NonBacktracking matches in linear time, so no match timeout.
    private static readonly Regex PackedWord = new(@"\b\w+\b", RegexOptions.NonBacktracking);

    private static string Encode(int c, int a) => (c < a ? "" : Encode(c / a, a)) + ((c % a) > 35 ? ((char)(c % a + 29)).ToString() : JsConstants.ToRadix(c % a, 36));

    // --- calls worth reviewing ---

    private static readonly HashSet<string> Noteworthy = new(StringComparer.Ordinal)
    {
        "eval", "Function", "fetch", "XMLHttpRequest", "ActiveXObject", "require", "exec", "execSync", "spawn", "spawnSync", "execFile", "execFileSync",
        "WebSocket", "importScripts", "sendBeacon", "Run", "Exec", "ShellExecute", "write", "writeFileSync", "open", "GetObject",
    };

    private void Calls()
    {
        foreach (var (node, _) in _nodes)
        {
            Node callee;
            NodeList<Expression> args;
            bool isNew;
            if (node is CallExpression c) (callee, args, isNew) = (c.Callee, c.Arguments, false);
            else if (node is NewExpression n) (callee, args, isNew) = (n.Callee, n.Arguments, true);
            else continue;
            var name = Unwrap(callee) switch
            {
                Identifier i => i.Name,
                MemberExpression { Computed: false, Property: Identifier p } => p.Name,
                MemberExpression { Computed: true, Property: StringLiteral s } => s.Value,
                _ => null,
            };
            if (name == null || !Noteworthy.Contains(name)) continue;
            if (name is "write" && !Src(callee).StartsWith("document", StringComparison.Ordinal)) continue;
            if (name is "open" && !Regex.IsMatch(Src(callee), @"\.(open)$") || name == "open" && args.Count < 2) continue;
            var first = args.Count > 0 ? _eval.Eval(args[0]) : null;
            var shown = first is string s1 ? JsConstants.Literal(s1.Length > 160 ? s1[..160] + "…" : s1) : args.Count > 0 ? "…" : "";
            if (name is "open" && args.Count > 1 && _eval.Eval(args[1]) is string url) shown += ", " + JsConstants.Literal(url);
            var callText = $"{(isNew ? "new " : "")}{name}({shown})";
            if (_ctx.Calls.Count < 200) _ctx.Calls.Add(callText);
            // A command line that starts a script host is read as a batch layer.
            if (name is "Run" or "Exec" or "exec" or "execSync" or "ShellExecute" && first is string command
                && Regex.IsMatch(command, @"^\s*(cmd|powershell|pwsh|mshta)(\.exe)?\b", RegexOptions.IgnoreCase)
                && _ctx.Peel("cmd", command, name == "ShellExecute" ? "Shell.Application.ShellExecute" : name is "Run" or "Exec" ? "WScript.Shell." + name : "child_process." + name, _depth + 1) is { } plain
                && plain.Trim() != command.Trim() && _parents.GetValueOrDefault(node) is ExpressionStatement statement
                && !_text.AsSpan(statement.End).TrimStart().StartsWith("/* runs:", StringComparison.Ordinal))
                // The call stays; what it runs follows as a comment on the last character, apart from inner edits.
                _edits.Set(statement.End - 1, statement.End, _text[statement.End - 1] + " /* runs: " + plain.Trim().Replace("*/", "* /") + " */");
        }
    }

    // --- clipboard writes ---

    // NonBacktracking matches in linear time, so no match timeout.
    private static readonly Regex ShellCommand = new(
        @"^\s*""?(?:[a-z]:\\[^""]*\\)?(?:cmd|powershell|pwsh|mshta|curl|wget|msiexec|rundll32|regsvr32|certutil|bitsadmin|wscript|cscript|conhost|forfiles|bash)(?:\.exe)?\b|\|\s*(?:iex|invoke-expression)\b",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.NonBacktracking);

    private static readonly HashSet<string> CopiedProperties = new(StringComparer.Ordinal) { "value", "textContent", "innerText" };

    /// <summary>
    /// Shell commands written by clipboard.writeText, clipboardData.setData or
    /// execCommand('copy') of a field's text.
    /// </summary>
    private void Clipboard()
    {
        foreach (var (node, _) in _nodes)
        {
            if (node is not CallExpression { Callee: var callee } call || Unwrap(callee) is not MemberExpression { Computed: false, Property: Identifier property } member) continue;
            var (text, via) = property.Name switch
            {
                "writeText" when call.Arguments.Count > 0 && Src(member.Object).EndsWith("clipboard", StringComparison.Ordinal) => (Constant(call.Arguments[0]), "navigator.clipboard.writeText"),
                "setData" when call.Arguments.Count > 1 && Src(member.Object).EndsWith("clipboardData", StringComparison.Ordinal) => (Constant(call.Arguments[1]), "clipboardData.setData"),
                "execCommand" when call.Arguments.Count > 0 && Constant(call.Arguments[0]) == "copy" => (Selected(call.Start), "document.execCommand('copy')"),
                _ => (null, ""),
            };
            if (text == null || !ShellCommand.IsMatch(text) || _ctx.Copied.Any(c => c.Text == text)) continue;
            _ctx.Clipboard = text;
            var plain = _ctx.Peel("cmd", text, "clipboard via " + via, _depth + 1) ?? text;
            _ctx.Copied.Add(new ClipboardCommand(via, text, plain.Trim()));
        }
    }

    /// <summary>
    /// The text last set on a field (value, textContent, innerText) before
    /// <paramref name="before"/>; null when none is constant.
    /// </summary>
    private string? Selected(int before)
    {
        AssignmentExpression? last = null;
        foreach (var (node, _) in _nodes)
            if (node is AssignmentExpression { Left: MemberExpression { Computed: false, Property: Identifier p } } a && a.End <= before
                && CopiedProperties.Contains(p.Name) && (last == null || a.Start > last.Start))
                last = a;
        return last == null ? null : Constant(last.Right);
    }

    /// <summary>
    /// The string an expression builds, reading variables declared once and
    /// never assigned; null when it is not constant.
    /// </summary>
    private string? Constant(Node n)
    {
        var saved = _eval.Names;
        var open = new HashSet<string>(StringComparer.Ordinal);
        object? Name(string name)
        {
            // A name being read already refers to itself; it stays unknown.
            if (Declarator(name) is not { Init: { } init } || !open.Add(name)) return saved?.Invoke(name);
            try { return _eval.Eval(init); }
            finally { open.Remove(name); }
        }
        _eval.Names = Name;
        try { return _eval.Eval(n) as string; }
        finally { _eval.Names = saved; }
    }

    // --- constant folding ---

    private void Fold()
    {
        foreach (var (node, parent) in _nodes)
        {
            if (!_ctx.Budget.Step()) break;
            switch (node)
            {
                case StringLiteral s when s.Raw is { } raw && raw.Length > 2 && (raw.Contains("\\x", StringComparison.Ordinal) || raw.Contains("\\u", StringComparison.Ordinal)):
                    if (parent is not (Property { Computed: false } or ImportDeclaration or ExportAllDeclaration or ExportNamedDeclaration) && ScriptText.Printable(s.Value))
                        _edits.Set(s.Start, s.End, JsConstants.Literal(s.Value), weak: true);
                    break;
                case NumericLiteral n when n.Raw is { } nraw && nraw.StartsWith("0x", StringComparison.OrdinalIgnoreCase):
                    _edits.Set(n.Start, n.End, JsConstants.NumberToString(n.Value), weak: true);
                    break;
                case BinaryExpression or UnaryExpression { Operator: not Operator.TypeOf } or TemplateLiteral or CallExpression when Pure2(node):
                {
                    var v = _eval.Eval(node);
                    if (v is string str && str.Length > 4096 || !JsConstants.Known(v)) break;
                    if (JsConstants.Source(v) is { } text && text != Src(node) && !(v is double d && (double.IsNaN(d) || d != Math.Floor(d))))
                        _edits.Set(node.Start, node.End, text, weak: true);
                    break;
                }
                case MemberExpression { Computed: true, Property: StringLiteral key, Optional: false } m
                    when Regex.IsMatch(key.Value, @"^[A-Za-z_$][\w$]*$") && m.Object is not NumericLiteral && !Reserved.Contains(key.Value):
                {
                    // From the bracket: the object may end before a parenthesis the tree does not hold.
                    int bracket = _text.LastIndexOf('[', key.Start);
                    if (bracket >= m.Object.End) _edits.Set(bracket, m.End, "." + key.Value, weak: true);
                }
                    break;
            }
        }
    }

    /// <summary>An expression of literals and constant method calls only (no names but String, Math and atob-like globals).</summary>
    private bool Pure2(Node node)
    {
        foreach (var (n, _) in Inside(node))
        {
            if (!_ctx.Budget.Step()) return false;
            switch (n)
            {
                case Literal or BinaryExpression or UnaryExpression or ParenthesizedExpression or ArrayExpression or TemplateLiteral or TemplateElement or CallExpression or MemberExpression:
                    continue;
                case Identifier i when i.Name is "String" or "fromCharCode" or "atob" or "unescape" or "decodeURIComponent" or "parseInt" or "length"
                    or "split" or "reverse" or "join" or "replace" or "charAt" or "charCodeAt" or "substr" or "substring" or "slice" or "toString" or "concat"
                    or "toUpperCase" or "toLowerCase" or "undefined":
                    continue;
                default:
                    return false;
            }
        }
        return node is not CallExpression || Src(node).Length < 20_000;
    }

    private static readonly HashSet<string> Reserved = new(StringComparer.Ordinal)
    {
        "break", "case", "catch", "class", "const", "continue", "debugger", "default", "delete", "do", "else", "export", "extends", "finally", "for",
        "function", "if", "import", "in", "instanceof", "new", "return", "super", "switch", "this", "throw", "try", "typeof", "var", "void", "while", "with", "yield",
    };
}
