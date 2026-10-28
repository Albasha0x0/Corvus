using Acornima;
using Acornima.Ast;
using Corvus.Core;

namespace Corvus.Services.Web;

/// <summary>A module recovered from a bundle: its id, the name and where the name came from, its byte range and what it requires.</summary>
/// <remarks>Provenance: bundler_key (esbuild / Metro paths), dependency_map (Browserify) or module_table (an id only).</remarks>
public sealed record JsModule(string Id, string? Name, string Provenance, string Family, int Start, int End, IReadOnlyList<string> Requires);

/// <summary>The module table of a bundle, found on its syntax tree.</summary>
public static class JsModules
{
    /// <summary>Largest file parsed whole; larger ones report no modules.</summary>
    public const int MaxParseBytes = 64 * 1024 * 1024;

    /// <summary>The syntax tree, or null with the reason in <paramref name="notes"/> (over the budget, or a parse error).</summary>
    public static Acornima.Ast.Program? Parse(string text, List<string> notes)
    {
        if (text.Length > MaxParseBytes)
        {
            notes.Add($"not parsed: {text.Length:N0} characters, over the {MaxParseBytes:N0} parse budget");
            return null;
        }
        // A deep tree must not overflow the server's stack, so the parse runs on a thread with a large stack.
        Acornima.Ast.Program? parsed = null;
        Exception? error = null;
        var thread = new Thread(() =>
        {
            var parser = new Parser(new ParserOptions { Tolerant = true });
            // A script first; import / export make it a module (Rollup and Vite chunks).
            try { parsed = parser.ParseScript(text); }
            catch (ParseErrorException)
            {
                try { parsed = parser.ParseModule(text); }
                catch (Exception ex) { error = ex; }
            }
            catch (Exception ex) { error = ex; }
        }, 256 * 1024 * 1024);
        thread.Start();
        thread.Join();
        if (error is ParseErrorException parse) { notes.Add($"parse error: {parse.Message}"); return null; }
        // Acornima 1.8.0 stops near a nesting depth of 1,000,000 on this stack.
        if (error is InsufficientExecutionStackException) { notes.Add("not parsed: nested too deep"); return null; }
        if (error != null) throw error;
        return parsed;
    }

    /// <summary>
    /// The syntax tree of a script cut short, cut again at the last separator that
    /// parses once its open brackets are closed; the tree and the text it was parsed
    /// from, or null when no cut parses.
    /// </summary>
    public static (Acornima.Ast.Program Tree, string Text)? ParseCut(string text, CancellationToken ct)
    {
        // Deepest first: a cut inside the last module keeps every module before it.
        foreach (var (at, closers) in PrefixCuts(text, ct))
        {
            ct.ThrowIfCancellationRequested();
            var repaired = string.Concat(text.AsSpan(0, at), closers);
            if (Parse(repaired, []) is { } tree) return (tree, repaired);
        }
        return null;
    }

    /// <summary>
    /// Cuts tried per script, the deepest bracket depths that hold one.
    /// </summary>
    private const int MaxCuts = 4;

    /// <summary>
    /// The last cut at each of the <see cref="MaxCuts"/> deepest bracket depths
    /// that hold one, deepest first, with the closers that depth needs.
    /// </summary>
    private static List<(int At, string Closers)> PrefixCuts(ReadOnlySpan<char> text, CancellationToken ct)
    {
        var open = new List<char>();
        // At depth d: the last cut, cleared when the bracket holding it closes.
        var last = new List<int> { 0 };
        char previous = '\0';
        int check = 0;
        for (int i = 0; i < text.Length; i++)
        {
            if (i >= check)
            {
                ct.ThrowIfCancellationRequested();
                check = i + 64 * 1024;
            }
            char c = text[i];
            if (open.Count > 0 && open[^1] == '`')
            {
                if (c == '\\') i++;
                else if (c == '`') Pop(open, last);
                else if (c == '$' && i + 1 < text.Length && text[i + 1] == '{') { Push(open, last, '$'); i++; }
                continue;
            }
            if (char.IsWhiteSpace(c)) continue;
            if (char.IsLetter(c) || c is '_' or '$')
            {
                int start = i;
                while (i + 1 < text.Length && (char.IsLetterOrDigit(text[i + 1]) || text[i + 1] is '_' or '$')) i++;
                // After a keyword that takes an expression, a slash starts a
                // regular expression, as at the start of the text.
                previous = RegexKeywords.Contains(text[start..(i + 1)]) ? '\0' : c;
                continue;
            }
            switch (c)
            {
                // After ++ or --, a slash divides.
                case '+' or '-' when i + 1 < text.Length && text[i + 1] == c:
                    i++;
                    previous = ')';
                    continue;
                case '"' or '\'':
                    for (i++; i < text.Length && text[i] != c && text[i] != '\n'; i++)
                        if (text[i] == '\\') i++;
                    break;
                case '`': Push(open, last, '`'); break;
                case '/' when i + 1 < text.Length && text[i + 1] == '/':
                    while (i < text.Length && text[i] != '\n') i++;
                    continue;
                case '/' when i + 1 < text.Length && text[i + 1] == '*':
                    int end = text[(i + 2)..].IndexOf("*/");
                    i = end < 0 ? text.Length : i + 3 + end;
                    continue;
                // A slash after an operator or a bracket starts a regular expression.
                case '/' when previous is '\0' or '(' or ',' or '=' or ':' or '[' or '!' or '&' or '|' or '?' or '{' or '}' or ';'
                    or '+' or '-' or '*' or '%' or '<' or '>' or '~' or '^':
                    bool inClass = false;
                    for (i++; i < text.Length && text[i] != '\n' && (inClass || text[i] != '/'); i++)
                        if (text[i] == '\\') i++;
                        else if (text[i] == '[') inClass = true;
                        else if (text[i] == ']') inClass = false;
                    break;
                case '(' or '[' or '{': Push(open, last, c); break;
                case ')' or ']' or '}':
                    Pop(open, last);
                    if (c == '}') last[open.Count] = i + 1;
                    break;
                case ',': last[open.Count] = i; break;
                case ';': last[open.Count] = i + 1; break;
            }
            previous = c;
        }
        var cuts = new List<(int, string)>();
        for (int d = open.Count; d >= 0 && cuts.Count < MaxCuts; d--)
            if (last[d] > 0)
                cuts.Add((last[d], Closers(open, d)));
        return cuts;
    }

    private static readonly HashSet<string>.AlternateLookup<ReadOnlySpan<char>> RegexKeywords = new HashSet<string>(
        ["return", "typeof", "case", "in", "of", "delete", "void", "throw", "new", "else", "yield", "await", "instanceof", "do"],
        StringComparer.Ordinal).GetAlternateLookup<ReadOnlySpan<char>>();

    private static string Closers(List<char> open, int depth) => string.Create(depth, open, (span, brackets) =>
    {
        for (int k = 0; k < span.Length; k++)
            span[k] = brackets[depth - 1 - k] switch { '(' => ')', '[' => ']', '`' => '`', _ => '}' };
    });

    private static void Push(List<char> open, List<int> last, char bracket)
    {
        open.Add(bracket);
        if (last.Count <= open.Count) last.Add(0);
        else last[open.Count] = 0;
    }

    // An unbalanced closer is ignored; the parse of the cut decides.
    private static void Pop(List<char> open, List<int> last)
    {
        if (open.Count == 0) return;
        last[open.Count] = 0;
        open.RemoveAt(open.Count - 1);
    }

    // Module tables of the last files read, by path, size and write time, so a large bundle is parsed once.
    private static readonly List<((string Path, long Size, DateTime Written) Key, List<JsModule> Modules, List<string> Notes)> Recent = [];

    /// <summary>The module table of the file at <paramref name="path"/>, from the recent cache when the file is unchanged.</summary>
    public static (List<JsModule> Modules, List<string> Notes) Of(string path, CancellationToken ct)
    {
        var info = new FileInfo(InputFiles.RequireRegularFile(path, "JavaScript file"));
        var key = (info.FullName, info.Exists ? info.Length : -1, info.Exists ? info.LastWriteTimeUtc : default);
        lock (Recent)
            if (Recent.FirstOrDefault(r => r.Key == key) is { Modules: not null } hit) return (hit.Modules, hit.Notes);
        var found = Find(System.Text.Encoding.UTF8.GetString(JsAnalysis.Read(path)), ct);
        lock (Recent)
        {
            Recent.Insert(0, (key, found.Modules, found.Notes));
            if (Recent.Count > 4) Recent.RemoveAt(Recent.Count - 1);
        }
        return found;
    }

    public static (List<JsModule> Modules, List<string> Notes) Find(string text, CancellationToken ct)
    {
        var notes = new List<string>();
        var modules = new List<JsModule>();
        if (Parse(text, notes) is not { } script) return (modules, notes);
        return (Find(text, script, ct), notes);
    }

    public static List<JsModule> Find(string text, Acornima.Ast.Program script, CancellationToken ct)
    {
        var modules = new List<JsModule>();
        var stack = new Stack<Node>();
        stack.Push(script);
        var seen = new HashSet<Node>();
        while (stack.Count > 0)
        {
            ct.ThrowIfCancellationRequested();
            var node = stack.Pop();
            switch (node)
            {
                case CallExpression { Callee: Identifier { Name: "__commonJS" or "__esm" }, Arguments: [ObjectExpression table, ..] }:
                    foreach (var p in table.Properties.OfType<Property>())
                        if (p.Value is Node body && Key(p) is { } key && seen.Add(p))
                            modules.Add(Module(text, key, key, "bundler_key", "esbuild", body, null));
                    break;
                // AMD: define("name", ["dep"], factory)
                case CallExpression { Callee: Identifier { Name: "define" }, Arguments: [StringLiteral name, ArrayExpression amdDeps, Node factory, ..] }:
                    modules.Add(new JsModule(name.Value, name.Value, "bundler_key", "amd", factory.Start, factory.End, Strings(amdDeps)));
                    break;
                // SystemJS: System.register(["dep"], function(_export, _context) {...})
                case CallExpression { Callee: MemberExpression { Object: Identifier { Name: "System" }, Property: Identifier { Name: "register" } }, Arguments: [.., ArrayExpression systemDeps, Node factory] } system:
                    var systemName = system.Arguments.Count == 3 && system.Arguments[0] is StringLiteral sn ? sn.Value : null;
                    modules.Add(new JsModule(systemName ?? $"@{system.Start}", systemName, systemName != null ? "bundler_key" : "module_table", "systemjs", factory.Start, factory.End, Strings(systemDeps)));
                    break;
                // Parcel 2: parcelRegister("id", function(module, exports) {...})
                case CallExpression { Callee: Identifier { Name: "parcelRegister" }, Arguments: [StringLiteral parcelId, Node factory, ..] }:
                    modules.Add(new JsModule(parcelId.Value, null, "module_table", "parcel", factory.Start, factory.End, []));
                    break;
                case CallExpression { Callee: Identifier { Name: "__d" }, Arguments: [FunctionExpression fn, var id, ..] } metro:
                    string? path = metro.Arguments.Count > 3 && metro.Arguments[3] is StringLiteral s ? s.Value : null;
                    var deps = metro.Arguments.Count > 2 && metro.Arguments[2] is ArrayExpression a ? a.Elements.Select(e => e is NumericLiteral n ? n.Raw : null).OfType<string>().ToList() : [];
                    modules.Add(new JsModule(Raw(text, id), path, path != null ? "bundler_key" : "module_table", "metro", fn.Start, fn.End, deps));
                    break;
                case ObjectExpression obj when IsModuleTable(obj.Properties.OfType<Property>().Select(p => (Node?)p.Value).ToList()):
                    foreach (var p in obj.Properties.OfType<Property>())
                        if (Key(p) is { } id && seen.Add(p))
                        {
                            // Browserify and Parcel 1: [factory, {"./dep": id}]
                            if (p.Value is ArrayExpression { Elements: [Node f, ObjectExpression map, ..] })
                                modules.Add(Module(text, id, null, "dependency_map", "browserify", f,
                                    map.Properties.OfType<Property>().Select(d => $"{Key(d)} -> {Raw(text, d.Value)}").ToList()));
                            else modules.Add(Module(text, id, id.Contains('/') ? id : null, id.Contains('/') ? "bundler_key" : "module_table", "webpack", p.Value, null));
                        }
                    break;
                case ArrayExpression arr when IsModuleTable(arr.Elements.Select(e => (Node?)e).ToList()):
                    for (int i = 0; i < arr.Elements.Count; i++)
                        if (arr.Elements[i] is Node f) modules.Add(Module(text, i.ToString(System.Globalization.CultureInfo.InvariantCulture), null, "module_table", "webpack", f, null));
                    break;
            }
            foreach (var child in node.ChildNodes)
                if (child != null) stack.Push(child);
        }
        // An ES module (Rollup or Vite chunk) is one module whose imports are its requires.
        if (modules.Count == 0 && script.Body.Any(s => s is ImportDeclaration or ExportNamedDeclaration or ExportAllDeclaration))
        {
            var imports = script.Body.Select(s => s switch
            {
                ImportDeclaration i => i.Source.Value,
                ExportNamedDeclaration { Source: { } from } => from.Value,
                ExportAllDeclaration a => a.Source.Value,
                _ => null,
            }).OfType<string>().Distinct().ToList();
            modules.Add(new JsModule("(file)", null, "module_table", "esm", 0, text.Length, imports));
        }
        modules.Sort((x, y) => x.Start.CompareTo(y.Start));
        return modules;
    }

    /// <summary>At least two entries, every one a function of up to three parameters (or [function, deps]).</summary>
    private static bool IsModuleTable(List<Node?> values) =>
        values.Count >= 2 && values.All(v => v switch
        {
            FunctionExpression f => f.Params.Count <= 3,
            ArrowFunctionExpression f => f.Params.Count <= 3,
            ArrayExpression { Elements: [FunctionExpression, ObjectExpression, ..] } => true,
            _ => false,
        });

    private static JsModule Module(string text, string id, string? name, string provenance, string family, Node factory, List<string>? deps) =>
        new(id, name, provenance, family, factory.Start, factory.End, deps ?? Requires(factory));

    /// <summary>Calls of the factory's require parameter (the third, or the only one named require) with a literal argument.</summary>
    private static List<string> Requires(Node factory)
    {
        var (parameters, body) = factory switch
        {
            FunctionExpression f => (f.Params, (Node)f.Body),
            ArrowFunctionExpression f => (f.Params, f.Body),
            _ => (default(NodeList<Node>), factory),
        };
        string? require = parameters.Count >= 3 && parameters[2] is Identifier r ? r.Name
            : parameters.FirstOrDefault(p => p is Identifier { Name: "require" }) is Identifier named ? named.Name : null;
        var found = new List<string>();
        if (require == null) return found;
        var stack = new Stack<Node>();
        stack.Push(body);
        while (stack.Count > 0 && found.Count < 500)
        {
            var node = stack.Pop();
            if (node is CallExpression { Callee: Identifier callee, Arguments: [Literal arg, ..] } && callee.Name == require)
                found.Add(arg is StringLiteral s ? s.Value : arg.Raw);
            foreach (var child in node.ChildNodes)
                if (child != null) stack.Push(child);
        }
        return found.Distinct().ToList();
    }

    /// <summary>Offsets where each line starts.</summary>
    internal static List<int> LineStarts(string text)
    {
        var starts = new List<int> { 0 };
        for (int i = 0; i < text.Length; i++)
            if (text[i] == '\n') starts.Add(i + 1);
        return starts;
    }

    /// <summary>The original source most of three probes inside the module map to (at a quarter, half and three quarters of it).</summary>
    internal static string? OriginalSource(SourceMap map, List<int> lines, JsModule m)
    {
        var votes = new List<string>();
        foreach (var fraction in new[] { 0.25, 0.5, 0.75 })
        {
            int offset = m.Start + (int)((m.End - m.Start) * fraction);
            int line = lines.BinarySearch(offset);
            if (line < 0) line = ~line - 1;
            if (map.Find(line, offset - lines[line]) is { Source: >= 0 } seg && seg.Source < map.Sources.Count) votes.Add(map.Sources[seg.Source]);
        }
        return votes.GroupBy(v => v).OrderByDescending(g => g.Count()).FirstOrDefault()?.Key;
    }

    private static List<string> Strings(ArrayExpression a) => a.Elements.OfType<StringLiteral>().Select(s => s.Value).ToList();

    private static string? Key(Property p) => p.Key switch
    {
        Identifier i => i.Name,
        StringLiteral s => s.Value,
        NumericLiteral n => n.Raw,
        _ => null,
    };

    private static string Raw(string text, Node? node) =>
        node == null ? "" : node.End - node.Start > 80 ? text[node.Start..(node.Start + 77)] + "..." : text[node.Start..node.End];
}
