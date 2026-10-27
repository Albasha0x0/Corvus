using System.Text;
using Corvus.Core;
using Corvus.Core.Mobile;

namespace Corvus.Services.Mobile;

/// <summary>Joins hybrid app web code to DEX classes: Cordova exec() through config.xml features, Capacitor registerPlugin() through @CapacitorPlugin.</summary>
internal static partial class WebBridges
{
    private const long MaxScript = 64L << 20, MaxTotal = 256L << 20;
    private const string CapacitorPlugin = "Lcom/getcapacitor/annotation/CapacitorPlugin;", NativePlugin = "Lcom/getcapacitor/NativePlugin;",
        PluginMethod = "Lcom/getcapacitor/PluginMethod;";

    /// <summary>One exec call: the script, the service and action named by string literals (action null when computed).</summary>
    public sealed record ExecCall(string Script, string Service, string? Action);

    public static void Add(AndroidPackage package, IReadOnlyList<string> entries, DexIndex index, List<AppLayer> layers, List<AppEdgeKind> kinds,
        List<AppEdge> edges, List<string> notes, CancellationToken ct)
    {
        var scripts = entries.Where(e => (e.StartsWith("assets/www/", StringComparison.Ordinal) || e.StartsWith("assets/public/", StringComparison.Ordinal))
            && e.EndsWith(".js", StringComparison.Ordinal)).Order(StringComparer.Ordinal).ToList();
        if (scripts.Count == 0) return;
        var texts = new List<(string Path, string Text)>();
        long total = 0;
        foreach (var path in scripts)
        {
            ct.ThrowIfCancellationRequested();
            var bytes = package.Read(path);
            if (bytes == null || bytes.Length > MaxScript) continue;
            if ((total += bytes.Length) > MaxTotal) { notes.Add($"Web code: scripts past {MaxTotal >> 20} MB are not read."); break; }
            texts.Add((path, Encoding.UTF8.GetString(bytes)));
        }
        layers.Add(new("web", texts.Count, $"scripts under {(scripts[0].StartsWith("assets/www/", StringComparison.Ordinal) ? "assets/www" : "assets/public")}"));
        Cordova(package, entries, index, texts, kinds, edges, notes);
        Capacitor(package, index, texts, kinds, edges, notes);
    }

    private static void Cordova(AndroidPackage package, IReadOnlyList<string> entries, DexIndex index, List<(string Path, string Text)> texts,
        List<AppEdgeKind> kinds, List<AppEdge> edges, List<string> notes)
    {
        var calls = texts.SelectMany(t => ExecCalls(t.Path, t.Text)).Distinct().ToList();
        if (calls.Count == 0) return;
        var features = Features(package, entries, notes);
        // The strings each feature class uses, gathered in one pass over the code references.
        var actionStrings = features.Values.Select(c => "L" + c.Replace('.', '/') + ";").Distinct().ToDictionary(d => d, _ => new HashSet<string>(StringComparer.Ordinal), StringComparer.Ordinal);
        if (actionStrings.Count > 0)
            foreach (var r in index.Refs)
            {
                if (r.Kind != DexRefKind.String) continue;
                var from = index.KeyText(r.From);
                int arrow = from.IndexOf("->", StringComparison.Ordinal);
                if (arrow > 0 && actionStrings.TryGetValue(from[..arrow], out var set)) set.Add(index.KeyText(r.Target));
            }
        int bound = 0;
        var missing = new SortedSet<string>(StringComparer.Ordinal);
        foreach (var call in calls)
        {
            if (!features.TryGetValue(call.Service, out var javaClass)) { missing.Add($"{call.Service} (no config.xml feature)"); continue; }
            var descriptor = "L" + javaClass.Replace('.', '/') + ";";
            if (!index.Classes.ContainsKey(descriptor)) { missing.Add($"{call.Service} ({javaClass} not in the DEX code)"); continue; }
            bound++;
            // The action reaches execute(String action, ...) as a string the plugin compares; finding it in the class confirms the pair.
            bool confirmed = call.Action != null && actionStrings[descriptor].Contains(call.Action);
            edges.Add(new("cordova_plugin", $"{call.Script}:exec({call.Service}.{call.Action ?? "?"})", $"{descriptor}->execute",
                confirmed ? "config_feature, action_string" : "config_feature"));
        }
        kinds.Add(new("cordova_plugin", bound, calls.Count, missing.Count == 0 ? "complete" : "partial",
            "the service of exec() bound to its class by a config.xml feature (android-package), the action found as a string of that class",
            missing.Count == 0 ? null : $"{calls.Count - bound} call(s) unbound: " + string.Join(", ", missing.Take(10))));
    }

    /// <summary>A script's exec() calls whose service is a string literal; the action is kept when it is a literal too.</summary>
    public static IEnumerable<ExecCall> ExecCalls(string path, string text)
    {
        for (int at = text.IndexOf("exec(", StringComparison.Ordinal); at >= 0; at = text.IndexOf("exec(", at + 5, StringComparison.Ordinal))
        {
            if (at > 0 && (char.IsLetterOrDigit(text[at - 1]) || text[at - 1] is '_' or '$')) continue;
            var args = Arguments(text, at + 5, 5);
            if (args.Count < 4 || Literal(args[2]) is not { Length: > 0 } service) continue;
            yield return new ExecCall(path, service, Literal(args[3]));
        }
    }

    /// <summary>Up to <paramref name="max"/> arguments from <paramref name="at"/>, split at commas outside brackets, strings and comments; within 4,000 characters.</summary>
    private static List<string> Arguments(string text, int at, int max)
    {
        var args = new List<string>();
        int depth = 0, start = at, end = Math.Min(text.Length, at + 4000);
        for (int i = at; i < end && args.Count < max; i++)
        {
            char c = text[i];
            if (c is '"' or '\'' or '`')
            {
                for (i++; i < end && text[i] != c; i++) if (text[i] == '\\') i++;
                continue;
            }
            if (c == '/' && i + 1 < end && text[i + 1] == '/') { while (i < end && text[i] != '\n') i++; continue; }
            if (c == '/' && i + 1 < end && text[i + 1] == '*') { int close = text.IndexOf("*/", i + 2, StringComparison.Ordinal); i = close < 0 ? end : close + 1; continue; }
            if (c is '(' or '[' or '{') depth++;
            else if (c is ')' or ']' or '}')
            {
                if (depth-- == 0) { args.Add(text[start..i].Trim()); return args; }
            }
            else if (c == ',' && depth == 0) { args.Add(text[start..i].Trim()); start = i + 1; }
        }
        return args;
    }

    /// <summary>The content of a '...' or "..." literal without escapes; null for anything else.</summary>
    private static string? Literal(string arg) =>
        arg.Length >= 2 && arg[0] is '"' or '\'' && arg[^1] == arg[0] && arg.IndexOf('\\') < 0 && arg.IndexOf(arg[0], 1) == arg.Length - 1 ? arg[1..^1] : null;

    /// <summary>Feature name to Java class (android-package param) from config.xml, or the compiled &lt;widget&gt; XML when names are shortened.</summary>
    private static Dictionary<string, string> Features(AndroidPackage package, IReadOnlyList<string> entries, List<string> notes)
    {
        var features = new Dictionary<string, string>(StringComparer.Ordinal);
        var candidates = entries.Where(e => e == "res/xml/config.xml").Concat(entries.Where(e => e.StartsWith("res/", StringComparison.Ordinal) && e.EndsWith(".xml", StringComparison.Ordinal) && e != "res/xml/config.xml"));
        foreach (var entry in candidates)
        {
            var bytes = package.Read(entry);
            if (bytes == null || !AxmlDocument.IsAxml(bytes)) continue;
            var root = AxmlDocument.Read(bytes).Root;
            if (root?.Name != "widget") continue;
            foreach (var feature in root.Elements("feature"))
            {
                var name = feature.Attribute("name", android: false)?.RawValue;
                var value = feature.Elements("param").FirstOrDefault(p => p.Attribute("name", android: false)?.RawValue == "android-package")?.Attribute("value", android: false)?.RawValue;
                if (name != null && value != null) features[name] = value;
            }
            return features;
        }
        notes.Add("Cordova: no config.xml (a compiled <widget> resource) was found; exec() services are unbound");
        return features;
    }

    private static void Capacitor(AndroidPackage package, DexIndex index, List<(string Path, string Text)> texts, List<AppEdgeKind> kinds, List<AppEdge> edges, List<string> notes)
    {
        // Capacitor's own list of the plugin classes it loads (by reflection, so their names survive shrinking).
        var registry = new List<string>();
        try
        {
            if (package.Read("assets/capacitor.plugins.json") is { } json)
                foreach (var entry in System.Text.Json.JsonDocument.Parse(json).RootElement.EnumerateArray())
                    if (entry.ValueKind == System.Text.Json.JsonValueKind.Object && entry.TryGetProperty("classpath", out var classpath) && classpath.GetString() is { } c) registry.Add(c);
        }
        catch (Exception e) when (e is System.Text.Json.JsonException or InvalidOperationException) { notes.Add($"Capacitor: assets/capacitor.plugins.json does not read: {e.Message}"); }
        // R8 renames the annotation types; the classes of the list carry them, so their types are learned from there.
        var pluginTypes = new HashSet<string>([CapacitorPlugin, NativePlugin], StringComparer.Ordinal);
        var methodTypes = new HashSet<string>([PluginMethod], StringComparer.Ordinal);
        foreach (var c in registry)
        {
            if (!index.Classes.TryGetValue("L" + c.Replace('.', '/') + ";", out var entry)) continue;
            var annotations = entry.File.Annotations(entry.Class);
            foreach (var a in annotations.Class.Where(a => a.Elements.Any(e => e.Name == "name" && e.Value.Kind == "string"))) pluginTypes.Add(a.Type);
            foreach (var a in annotations.Methods.Values.SelectMany(m => m).Where(a => a.Visibility == "runtime" && !a.Type.StartsWith("Ldalvik/", StringComparison.Ordinal)
                && !a.Type.StartsWith("Ljava/", StringComparison.Ordinal) && !a.Type.StartsWith("Lkotlin/", StringComparison.Ordinal))) methodTypes.Add(a.Type);
        }
        // Plugin name to its class and @PluginMethod method names.
        var plugins = new Dictionary<string, (string Descriptor, List<string> Methods)>(StringComparer.Ordinal);
        foreach (var entry in index.Classes.Values)
        {
            var annotations = entry.File.Annotations(entry.Class);
            var plugin = annotations.Class.FirstOrDefault(a => pluginTypes.Contains(a.Type));
            if (plugin == null) continue;
            var simple = entry.Class.Descriptor[(entry.Class.Descriptor.LastIndexOf('/') + 1)..^1];
            var name = plugin.Elements.FirstOrDefault(e => e.Name == "name").Value?.Value as string ?? simple;
            var methods = annotations.Methods.Where(m => m.Value.Any(a => methodTypes.Contains(a.Type))).Select(m => entry.File.Method(m.Key).Name).Distinct().Order(StringComparer.Ordinal).ToList();
            plugins.TryAdd(name, (entry.Class.Descriptor, methods));
        }
        var registered = new SortedDictionary<string, string>(StringComparer.Ordinal);
        foreach (var (path, text) in texts)
            foreach (var name in RegisteredPlugins(text)) registered.TryAdd(name, path);
        if (registered.Count == 0 && plugins.Count == 0) return;
        var all = string.Join("\n", texts.Select(t => t.Text));
        int bound = 0;
        var unbound = new List<string>();
        foreach (var (name, path) in registered)
        {
            if (!plugins.TryGetValue(name, out var plugin)) { unbound.Add(name); continue; }
            bound++;
            var called = plugin.Methods.Where(m => all.Contains("." + m + "(", StringComparison.Ordinal)).ToList();
            edges.Add(new("capacitor_plugin", $"{path}:registerPlugin({name})", plugin.Descriptor, "plugin_name"));
            foreach (var m in called)
                edges.Add(new("capacitor_plugin", $"{path}:{name}.{m}()", $"{plugin.Descriptor}->{m}(Lcom/getcapacitor/PluginCall;)V", "plugin_name, method_name"));
        }
        // A listed class that no web code names is loaded but not called by name.
        var loaded = registry.Where(c => !edges.Any(e => e.Kind == "capacitor_plugin" && e.To.StartsWith("L" + c.Replace('.', '/') + ";", StringComparison.Ordinal))).ToList();
        if (loaded.Count > 0) notes.Add($"Capacitor: {loaded.Count} plugin class(es) in capacitor.plugins.json that no web code names: {string.Join(", ", loaded.Take(10))}");
        // Each registered name and each method call found is a candidate; only names can stay unbound.
        int joined = edges.Count(e => e.Kind == "capacitor_plugin");
        kinds.Add(new("capacitor_plugin", joined, joined + unbound.Count, unbound.Count == 0 ? "complete" : "partial",
            "the registerPlugin() name bound to its @CapacitorPlugin class; @PluginMethod methods called by name in the web code",
            unbound.Count == 0 ? null : $"{unbound.Count} plugin(s) with no native class (web-only, or not in the DEX code): " + string.Join(", ", unbound.Take(10))));
    }

    /// <summary>Plugin names the web code reaches through registerPlugin (also renamed or wrapped), Capacitor.Plugins.Name and isPluginAvailable.</summary>
    public static IEnumerable<string> RegisteredPlugins(string text)
    {
        foreach (var marker in new[] { "registerPlugin", "isPluginAvailable" })
            for (int at = text.IndexOf(marker, StringComparison.Ordinal); at >= 0; at = text.IndexOf(marker, at + marker.Length, StringComparison.Ordinal))
            {
                int p = at + marker.Length;
                while (p < text.Length && (text[p] == ')' || char.IsWhiteSpace(text[p]))) p++;
                if (p >= text.Length || text[p] != '(') continue;
                var args = Arguments(text, p + 1, 1);
                if (args.Count > 0 && Literal(args[0]) is { Length: > 0 } name) yield return name;
            }
        foreach (System.Text.RegularExpressions.Match m in RenamedRegistration().Matches(text)) yield return m.Groups[2].Value;
        foreach (System.Text.RegularExpressions.Match m in PluginsMember().Matches(text)) yield return m.Groups[1].Success ? m.Groups[1].Value : m.Groups[3].Value;
    }

    [System.Text.RegularExpressions.GeneratedRegex("""\(\s*(['"])([A-Za-z_]\w*)\1\s*,\s*\{\s*web\s*:""")]
    private static partial System.Text.RegularExpressions.Regex RenamedRegistration();

    [System.Text.RegularExpressions.GeneratedRegex("""\bPlugins\s*(?:\??\.\s*([A-Z]\w*)|(?:\?\.)?\[\s*(['"])([A-Za-z_]\w*)\2\s*\])""")]
    private static partial System.Text.RegularExpressions.Regex PluginsMember();
}