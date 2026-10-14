using Acornima;
using Acornima.Ast;
using Corvus.Core;

namespace Corvus.Services.Web;

/// <summary>A module recovered from a bundle: its id, the name and where the name came from, its byte range and what it requires.</summary>
/// <see cref="Provenance"/>: bundler_key (esbuild / Metro paths), dependency_map (Browserify) or module_table (an id only).
public sealed record JsModule(string Id, string? Name, string Provenance, string Family, int Start, int End, IReadOnlyList<string> Requires);

/// <summary>The module table of a bundle, found on its syntax tree (the design's L3 recognizers).</summary>
public static class JsModules
{
    /// <summary>Largest file parsed whole; larger ones report no modules (a tokenizer split is the design's fallback).</summary>
    public const int MaxParseBytes = 64 * 1024 * 1024;

    /// <summary>The syntax tree, or null with the reason in <paramref name="notes"/> (over the budget, or a parse error).</summary>
    public static Acornima.Ast.Program? Parse(string text, List<string> notes)
    {
        if (text.Length > MaxParseBytes)
        {
            notes.Add($"not parsed: {text.Length:N0} characters, over the {MaxParseBytes:N0} parse budget");
            return null;
        }
        // a deep tree must not overflow the server's stack: a thread of its own with a large stack
        Acornima.Ast.Program? parsed = null;
        Exception? error = null;
        var thread = new Thread(() =>
        {
            var parser = new Parser(new ParserOptions { Tolerant = true });
            // a script first; import / export make it a module (Rollup and Vite chunks)
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
        if (error != null) throw error;
        return parsed;
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
        // an ES module (a Rollup or Vite chunk): the file is one module and its imports are its requires
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
