using System.Text;
using System.Text.RegularExpressions;

namespace Corvus.Native;

/// <summary>A named script runtime; Version is null when no marker states one, Binding is empty when no registration call is present.</summary>
public sealed record ScriptRuntimeFinding(string Name, string? Version, string Evidence, IReadOnlyList<string> Binding);

/// <summary>Names the script runtimes an image embeds from API names and string markers; nothing is executed.</summary>
public static partial class ScriptRuntimeDetection
{
    // Markers name a runtime alone; WeakMarkers are common text and need an API name too.
    private sealed record Rule(string Name, string[] NamePrefixes, string[] Contains, string[] Markers, string[] WeakMarkers, string[] Binding);

    private const int MaxNames = 8;
    [GeneratedRegex(@"^(lib)?python3?\d*\.")]
    private static partial Regex PythonModule();

    private static readonly Rule[] Rules =
    [
        new("LuaJIT", ["luaJIT_"], [], ["LuaJIT "], [],
            ["lua_pushcclosure", "luaL_register", "luaL_setfuncs"]),
        new("Lua", ["lua_", "luaL_", "luaopen_"], [], ["Lua 5."], [],
            ["lua_pushcclosure", "lua_pushcfunction", "luaL_register", "luaL_setfuncs", "luaL_newlib"]),
        new("QuickJS", ["JS_NewRuntime", "JS_NewCFunction", "JS_SetPropertyFunctionList", "js_std_"], [], [], ["QuickJS"],
            ["JS_NewCFunction", "JS_SetPropertyFunctionList", "JS_NewCModule"]),
        new("V8", [], ["@V8@v8@@", "@v8@@", "_ZN2v8"], ["V8 version "], [],
            ["?New@FunctionTemplate@v8@@", "?SetMethod@", "_ZN2v816FunctionTemplate3New"]),
        new("Python", ["Py_Initialize", "PyRun_", "PyImport_", "PyEval_", "PyModule_", "Py_Main", "Py_BytesMain"], [], [], ["Python 3.", "Python 2."],
            ["PyModule_AddFunctions", "PyModule_Create2", "Py_InitModule4", "PyCFunction_NewEx"]),
        new("mruby", ["mrb_"], [], [], ["mruby "],
            ["mrb_define_method", "mrb_define_class_method", "mrb_define_module_function", "mrb_define_class"]),
    ];

    /// <summary>Returns the runtimes the image shows; empty when none. One API name alone does not count.</summary>
    public static IReadOnlyList<ScriptRuntimeFinding> Detect(INativeImage image, ReadOnlySpan<byte> file)
    {
        var names = new HashSet<string>(StringComparer.Ordinal);
        foreach (var e in image.Exports) if (e.Name != null) names.Add(e.Name);
        foreach (var i in image.Imports) if (i.Name != null) names.Add(i.Name);
        foreach (var s in image.Symbols) if (s.Name != null) names.Add(s.Name);
        var modules = image.Imports.Select(i => i.Module).Concat(image.Dependencies).ToList();
        return Detect(names, modules, file);
    }

    /// <summary>Returns the runtimes shown by API names, module names and file bytes; LuaJIT hides a Lua match of the same API.</summary>
    public static IReadOnlyList<ScriptRuntimeFinding> Detect(IReadOnlyCollection<string> names, IReadOnlyCollection<string> modules, ReadOnlySpan<byte> file)
    {
        var result = new List<ScriptRuntimeFinding>();
        foreach (var rule in Rules)
        {
            if (rule.Name == "Python" && IsPythonExtension(names)) continue;
            var hits = names.Where(n => rule.NamePrefixes.Any(p => n.StartsWith(p, StringComparison.Ordinal)) || rule.Contains.Any(c => n.Contains(c, StringComparison.Ordinal)))
                .Order(StringComparer.Ordinal).ToList();
            var module = modules.FirstOrDefault(m => ModuleMatches(rule.Name, m));
            string? version = null, marker = null;
            bool weak = false;
            foreach (var m in rule.Markers.Concat(rule.WeakMarkers))
            {
                var (found, v) = Scan(file, m);
                if (!found) continue;
                marker = m;
                version = v;
                weak = Array.IndexOf(rule.WeakMarkers, m) >= 0;
                break;
            }
            // A weak marker is common text, so it counts only beside an API name.
            bool marked = marker != null && (!weak || hits.Count > 0);
            if (rule.Name == "Lua" && result.Any(r => r.Name == "LuaJIT") && !marked) continue;
            // Prefixes such as "lua_" and "mrb_" match unrelated names, so one hit alone names nothing.
            if (!marked && hits.Count < 2 && module == null) continue;
            var evidence = new List<string>();
            if (module != null) evidence.Add($"module {module}");
            if (hits.Count > 0)
                evidence.Add($"{(hits.Count == 1 ? "1 API name" : $"{hits.Count} API names")} ({string.Join(", ", hits.Take(MaxNames))}{(hits.Count > MaxNames ? ", ..." : "")})");
            if (marked) evidence.Add($"string \"{marker!.Trim()}\"");
            var binding = names.Where(n => rule.Binding.Any(b => n.StartsWith(b, StringComparison.Ordinal)))
                .Order(StringComparer.Ordinal).Take(MaxNames).ToList();
            result.Add(new ScriptRuntimeFinding(rule.Name, marked ? version : null, string.Join("; ", evidence), binding));
        }
        return result;
    }

    // A module that exports PyInit_ extends Python and embeds no interpreter.
    private static bool IsPythonExtension(IReadOnlyCollection<string> names) =>
        names.Any(n => n.StartsWith("PyInit_", StringComparison.Ordinal))
        && !names.Any(n => n.StartsWith("Py_Initialize", StringComparison.Ordinal) || n.StartsWith("Py_Main", StringComparison.Ordinal) || n.StartsWith("Py_BytesMain", StringComparison.Ordinal));

    private static bool ModuleMatches(string runtime, string module)
    {
        var m = module.ToLowerInvariant();
        return runtime switch
        {
            "LuaJIT" => m.StartsWith("luajit", StringComparison.Ordinal),
            "Lua" => m.StartsWith("lua5", StringComparison.Ordinal) || m.StartsWith("liblua", StringComparison.Ordinal) || m.StartsWith("lua.", StringComparison.Ordinal),
            "QuickJS" => m.StartsWith("quickjs", StringComparison.Ordinal),
            "V8" => m.StartsWith("v8.", StringComparison.Ordinal) || m.StartsWith("libv8", StringComparison.Ordinal),
            "Python" => PythonModule().IsMatch(m),
            "mruby" => m.StartsWith("mruby", StringComparison.Ordinal) || m.StartsWith("libmruby", StringComparison.Ordinal),
            _ => false,
        };
    }

    // A marker ending in a dot counts only when a version tail follows it.
    private static (bool Found, string? Version) Scan(ReadOnlySpan<byte> file, string marker)
    {
        var bytes = Encoding.ASCII.GetBytes(marker);
        bool any = false;
        int from = 0;
        while (from <= file.Length - bytes.Length)
        {
            int at = file[from..].IndexOf(bytes);
            if (at < 0) break;
            at += from;
            any = true;
            if (Version(file, at + bytes.Length, marker) is { } v) return (true, v);
            from = at + 1;
        }
        return (any && !marker.EndsWith('.'), null);
    }

    // Marker text ending in a dot ("Lua 5.") is rejoined with the digits that follow it.
    private static string? Version(ReadOnlySpan<byte> file, int start, string marker)
    {
        int end = start;
        while (end < file.Length && end - start < 16 && (file[end] is >= (byte)'0' and <= (byte)'9' || file[end] == (byte)'.')) end++;
        var tail = Encoding.ASCII.GetString(file[start..end]).TrimEnd('.');
        if (tail.Length == 0) return null;
        var head = marker.EndsWith('.') ? marker.TrimEnd().Split(' ').Last() : "";
        return head + tail;
    }
}
