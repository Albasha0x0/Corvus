using System.Text.RegularExpressions;

namespace Corvus.Core.WebAssembly;

/// <summary>One module import and the JS that provides it: the binding's text and its line:column, or null when the glue does not name it.</summary>
public sealed record WasmGlueBinding(string Module, string Name, string? Value, string? At, string How);

/// <summary>
/// A module joined to its JS glue: the toolchain the glue is, the import object (module keys and what they point at), the
/// instantiate calls, each import's provider, and the exports the glue reads.
/// </summary>
public sealed record WasmGlueLink(string File, string Toolchain, IReadOnlyList<string> ImportObject, IReadOnlyList<string> Instantiate,
    int Matched, int Total, IReadOnlyList<WasmGlueBinding> Imports, int ExportsUsed, IReadOnlyList<string> ExportsUnused);

/// <summary>
/// Joins a module's imports to JS glue by name: Emscripten (an import object such as info = { env: wasmImports } with
/// wasmImports = { name: impl }), wasm-bindgen (imports.wbg.name = function, or the exported functions of an ES module
/// the wasm imports from), Go (importObject = { gojs: { "runtime.wasmExit": … } }) and any object literal or assignment of
/// the same shape. Strings and comments are skipped; nothing is executed.
/// </summary>
public static partial class WasmGlue
{
    private const int MaxSource = 32 << 20;

    private sealed record Entry(string Key, string Value, int At, string? Owner, int OwnerAt);

    public static WasmGlueLink Link(WasmBinary m, string file, string js)
    {
        if (js.Length > MaxSource) js = js[..MaxSource];
        var lines = LineStarts(js);
        string Pos(int at)
        {
            int line = Array.BinarySearch(lines, at);
            if (line < 0) line = ~line - 1;
            return $"{line + 1}:{at - lines[line] + 1}";
        }
        var entries = ObjectEntries(js);
        // module keys: "env": wasmImports, gojs: { … }, imports.wbg = {}
        var moduleTargets = new Dictionary<string, HashSet<string>>(StringComparer.Ordinal);
        var importObject = new List<string>();
        var modules = m.Imports.Select(i => i.Module).Distinct().ToList();
        foreach (var e in entries)
            if (modules.Contains(e.Key) && e.Value.Length > 0)
            {
                if (!moduleTargets.TryGetValue(e.Key, out var set)) moduleTargets[e.Key] = set = [];
                set.Add(e.Value == "{" ? $"{{{e.At}}}" : e.Value);
                if (importObject.Count < 20) importObject.Add($"{e.Key} -> {(e.Value == "{" ? "{…}" : e.Value)} ({Pos(e.At)})");
            }
        var byKey = entries.GroupBy(e => e.Key, StringComparer.Ordinal).ToDictionary(g => g.Key, g => g.ToList(), StringComparer.Ordinal);
        var assignments = Assignments(js);
        var exportedFunctions = ExportedFunctions(js);
        var bindings = new List<WasmGlueBinding>();
        foreach (var i in m.Imports)
        {
            WasmGlueBinding? found = null;
            var owners = moduleTargets.GetValueOrDefault(i.Module);
            if (byKey.TryGetValue(i.Name, out var candidates))
            {
                // an entry of the object the module key points at (by name, or the literal nested under the key), else any entry of that name
                bool Owned(Entry c) => owners != null && (c.Owner != null && owners.Contains(c.Owner) || owners.Contains($"{{{c.OwnerAt}}}"));
                var owned = candidates.FirstOrDefault(Owned);
                var best = owned ?? candidates.FirstOrDefault(c => c.Value.Length > 0 && c.Value != "{");
                if (best != null) found = new WasmGlueBinding(i.Module, i.Name, best.Value, Pos(best.At), owned != null ? "import object" : "name only");
            }
            if (found == null && assignments.TryGetValue((i.Module, i.Name), out var assigned))
                found = new WasmGlueBinding(i.Module, i.Name, assigned.Value, Pos(assigned.At), "assignment");
            if (found == null && exportedFunctions.TryGetValue(i.Name, out var exported) && i.Module.Contains(".js", StringComparison.Ordinal))
                found = new WasmGlueBinding(i.Module, i.Name, "export function " + i.Name, Pos(exported), "ES module export");
            bindings.Add(found ?? new WasmGlueBinding(i.Module, i.Name, null, null, "not found"));
        }
        var instantiate = Instantiate().Matches(js).Take(20).Select(x => $"{x.Value.TrimEnd('(')} at {Pos(x.Index)}").ToList();
        // exports the glue reads: as .name or as a quoted "name"
        var referenced = new HashSet<string>(StringComparer.Ordinal);
        foreach (Match x in MemberOrString().Matches(js)) referenced.Add(x.Groups["n"].Value);
        int used = 0;
        var unused = new List<string>();
        foreach (var e in m.Exports)
        {
            if (referenced.Contains(e.Name)) used++;
            else if (unused.Count < 50) unused.Add(e.Name);
        }
        return new WasmGlueLink(file, Toolchain(js, m), importObject, instantiate, bindings.Count(b => b.Value != null), bindings.Count, bindings, used, unused);
    }

    /// <summary>The JS files beside a module (same folder, .js / .mjs / .cjs, at most 50 of up to 32 MB), the best match first; null when none names an import.</summary>
    public static WasmGlueLink? Beside(WasmBinary m, string path, CancellationToken ct)
    {
        if (m.Imports.Count == 0 || Path.GetDirectoryName(Path.GetFullPath(path)) is not { } dir || !Directory.Exists(dir)) return null;
        string stem = Path.GetFileNameWithoutExtension(path);
        WasmGlueLink? best = null;
        IEnumerable<string> files;
        try
        {
            files = Directory.EnumerateFiles(dir).Where(f => Path.GetExtension(f).ToLowerInvariant() is ".js" or ".mjs" or ".cjs")
                // the glue named after the module first ("x.wasm" with "x.js" or "x_bg.js"), then the rest
                .OrderBy(f => Path.GetFileNameWithoutExtension(f).StartsWith(stem.Replace("_bg", ""), StringComparison.OrdinalIgnoreCase) ? 0 : 1)
                .ThenBy(f => f, StringComparer.Ordinal).Take(50).ToList();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return null; }
        foreach (var f in files)
        {
            ct.ThrowIfCancellationRequested();
            string js;
            try
            {
                if (new FileInfo(f).Length > MaxSource) continue;
                js = File.ReadAllText(f);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { continue; }
            var link = Link(m, Path.GetFileName(f), js);
            if (link.Matched > 0 && (best == null || link.Matched > best.Matched)) best = link;
        }
        return best;
    }

    private static string Toolchain(string js, WasmBinary m)
    {
        if (js.Contains("__wbindgen", StringComparison.Ordinal) || js.Contains("imports.wbg", StringComparison.Ordinal)) return "wasm-bindgen";
        if (js.Contains("runtime.wasmExit", StringComparison.Ordinal) || js.Contains("\"gojs\"", StringComparison.Ordinal) || js.Contains("gojs:", StringComparison.Ordinal)) return "Go (wasm_exec.js)";
        if (js.Contains("wasmImports", StringComparison.Ordinal) || js.Contains("asmLibraryArg", StringComparison.Ordinal) || js.Contains("_emscripten_", StringComparison.Ordinal))
            return "Emscripten";
        return m.Imports.Any(i => i.Module.StartsWith("wasi", StringComparison.Ordinal)) ? "WASI host" : "unknown";
    }

    private static int[] LineStarts(string s)
    {
        var starts = new List<int> { 0 };
        for (int i = 0; i < s.Length; i++) if (s[i] == '\n') starts.Add(i + 1);
        return [.. starts];
    }

    /// <summary>
    /// Every "key: value" of every object literal: the key (identifier, string or number), the value's first token (an
    /// identifier path, "function", "{" for a nested literal…), where it is, and the literal's owner (the name it is assigned to) and start.
    /// </summary>
    private static List<Entry> ObjectEntries(string js)
    {
        var entries = new List<Entry>();
        var stack = new Stack<(int Start, string? Owner, bool Object)>();
        for (int i = 0; i < js.Length; i++)
        {
            char c = js[i];
            if (Skip(js, ref i)) continue;
            if (c == '{')
            {
                // an object literal follows "=", ":", "(", ",", "[" or "return"; a block follows ")" or a keyword
                int p = Back(js, i - 1);
                bool literal = p < 0 || js[p] is '=' or ':' or '(' or ',' or '[' or '?' or '|' or '&' || EndsWithWord(js, p, "return");
                string? owner = literal && p >= 0 && js[p] is '=' or ':' ? NameBefore(js, p) : null;
                stack.Push((i, owner, literal));
                if (literal) ReadEntries(js, i, owner, entries);
            }
            else if (c == '}' && stack.Count > 0) stack.Pop();
        }
        return entries;
    }

    /// <summary>The keys of the object literal at <paramref name="open"/> at its own depth.</summary>
    private static void ReadEntries(string js, int open, string? owner, List<Entry> entries)
    {
        int depth = 0;
        bool expectKey = true;
        for (int i = open + 1; i < js.Length; i++)
        {
            char c = js[i];
            if (c is '"' or '\'' or '`' && depth == 0 && expectKey)
            {
                int end = StringEnd(js, i);
                int colon = Forward(js, end + 1);
                if (colon < js.Length && js[colon] == ':')
                {
                    entries.Add(new Entry(Unescape(js[(i + 1)..end]), Value(js, colon + 1, out int at), at, owner, open));
                    i = colon;
                    expectKey = false;
                    continue;
                }
                i = end;
                continue;
            }
            if (Skip(js, ref i)) continue;
            if (c is '{' or '[' or '(') { depth++; continue; }
            if (c is '}' or ']' or ')')
            {
                if (depth == 0) return;
                depth--;
                continue;
            }
            if (depth != 0) continue;
            if (c == ',') { expectKey = true; continue; }
            if (expectKey && (char.IsLetter(c) || c is '_' or '$' || char.IsDigit(c)))
            {
                int start = i;
                while (i < js.Length && (char.IsLetterOrDigit(js[i]) || js[i] is '_' or '$')) i++;
                string key = js[start..i];
                int colon = Forward(js, i);
                if (colon < js.Length && js[colon] == ':')
                {
                    entries.Add(new Entry(key, Value(js, colon + 1, out int at), at, owner, open));
                    i = colon;
                    expectKey = false;
                }
                else if (colon < js.Length && js[colon] is ',' or '}')
                {
                    entries.Add(new Entry(key, key, start, owner, open)); // shorthand { name }
                    i = colon - 1;
                    expectKey = false;
                }
                else i--;
                continue;
            }
            if (!char.IsWhiteSpace(c)) expectKey = false;
        }
    }

    /// <summary>The value's first token: an identifier path, a keyword (function, async), "{" or "(" and so on, clipped.</summary>
    private static string Value(string js, int from, out int at)
    {
        at = Forward(js, from);
        if (at >= js.Length) return "";
        if (js[at] is '{') return "{";
        int i = at;
        while (i < js.Length && (char.IsLetterOrDigit(js[i]) || js[i] is '_' or '$' or '.')) i++;
        if (i > at) return js[at..i];
        int end = Math.Min(js.Length, at + 40);
        int stop = js.IndexOfAny([',', '\n', '}'], at, end - at);
        return js[at..(stop < 0 ? end : stop)].Trim();
    }

    /// <summary>"a.module.name = value" and "a["module"]["name"] = value" assignments by (module, name).</summary>
    private static Dictionary<(string, string), (string Value, int At)> Assignments(string js)
    {
        var result = new Dictionary<(string, string), (string, int)>();
        foreach (Match x in Assignment().Matches(js))
        {
            var key = (x.Groups["m"].Value, x.Groups["n"].Value);
            if (!result.ContainsKey(key)) result[key] = (Value(js, x.Index + x.Length, out _), x.Index);
        }
        return result;
    }

    private static Dictionary<string, int> ExportedFunctions(string js)
    {
        var result = new Dictionary<string, int>(StringComparer.Ordinal);
        foreach (Match x in ExportFunction().Matches(js)) result.TryAdd(x.Groups["n"].Value, x.Index);
        return result;
    }

    // ---- scanning ----

    /// <summary>Steps over a string, template literal or comment starting at <paramref name="i"/>; true when it did.</summary>
    private static bool Skip(string js, ref int i)
    {
        char c = js[i];
        if (c is '"' or '\'' or '`') { i = StringEnd(js, i); return true; }
        if (c == '/' && i + 1 < js.Length)
        {
            if (js[i + 1] == '/') { int nl = js.IndexOf('\n', i); i = nl < 0 ? js.Length : nl; return true; }
            if (js[i + 1] == '*') { int end = js.IndexOf("*/", i + 2, StringComparison.Ordinal); i = end < 0 ? js.Length : end + 1; return true; }
        }
        return false;
    }

    private static int StringEnd(string js, int open)
    {
        char q = js[open];
        for (int i = open + 1; i < js.Length; i++)
        {
            if (js[i] == '\\') { i++; continue; }
            if (js[i] == q) return i;
            if (q != '`' && js[i] == '\n') return i;
        }
        return js.Length - 1;
    }

    private static int Forward(string js, int i)
    {
        while (i < js.Length && char.IsWhiteSpace(js[i])) i++;
        return i;
    }

    private static int Back(string js, int i)
    {
        while (i >= 0 && char.IsWhiteSpace(js[i])) i--;
        return i;
    }

    private static bool EndsWithWord(string js, int at, string word) =>
        at + 1 >= word.Length && string.CompareOrdinal(js, at + 1 - word.Length, word, 0, word.Length) == 0;

    /// <summary>The identifier path before "=" or ":" at <paramref name="at"/> (info, imports.wbg, "env").</summary>
    private static string? NameBefore(string js, int at)
    {
        int end = Back(js, at - 1);
        if (end < 0) return null;
        if (js[end] is '"' or '\'')
        {
            int start = js.LastIndexOf(js[end], end - 1);
            return start >= 0 ? js[(start + 1)..end] : null;
        }
        int i = end;
        while (i >= 0 && (char.IsLetterOrDigit(js[i]) || js[i] is '_' or '$' or '.')) i--;
        return i < end ? js[(i + 1)..(end + 1)] : null;
    }

    private static string Unescape(string s) => s.Contains('\\') ? Regex.Unescape(s) : s;

    [GeneratedRegex(@"\b(?:WebAssembly\.(?:instantiateStreaming|instantiate|Instance|compileStreaming|compile)|instantiateStreaming|instantiateArrayBuffer|instantiateAsync)\s*\(")]
    private static partial Regex Instantiate();

    [GeneratedRegex(@"[\w$]+(?:\.(?<m>[\w$]+)|\[\s*[""'](?<m>[^""']+)[""']\s*\])(?:\.(?<n>[\w$]+)|\[\s*[""'](?<n>[^""']+)[""']\s*\])\s*=(?!=)")]
    private static partial Regex Assignment();

    [GeneratedRegex(@"\bexport\s+(?:async\s+)?(?:function\s*\*?\s*|const\s+|let\s+|var\s+)(?<n>[\w$]+)")]
    private static partial Regex ExportFunction();

    [GeneratedRegex(@"\.\s*(?<n>[\w$]+)|[""'](?<n>[^""'\n]{1,200})[""']")]
    private static partial Regex MemberOrString();
}
