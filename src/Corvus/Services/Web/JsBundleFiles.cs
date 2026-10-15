using System.Text;
using System.Text.Json;
using Corvus.Core;

namespace Corvus.Services.Web;

/// <summary>
/// A bundle opened as a container for unpack_container: one file per module, named by the bundler's key (esbuild,
/// Metro, AMD, webpack paths), else by the original source the source map gives the module, else modules/&lt;id&gt;.js;
/// each file starts with a comment naming its id and requires, and modules.json lists them all.
/// </summary>
internal static class JsBundleFiles
{
    private static readonly string[] Extensions = [".js", ".mjs", ".cjs", ".bundle"];
    private static readonly JsonSerializerOptions Indented = new() { WriteIndented = true };

    public static bool Looks(byte[] data, string name) =>
        Extensions.Any(e => name.EndsWith(e, StringComparison.OrdinalIgnoreCase)) && data.Length <= JsModules.MaxParseBytes && Blob.Identify(data) == "text";

    /// <summary>The modules as files, or null when the file has fewer than two modules (not a bundle).</summary>
    public static ContainerContents? Open(byte[] data, string path, CancellationToken ct)
    {
        var text = Encoding.UTF8.GetString(data);
        var notes = new List<string>();
        if (JsModules.Parse(text, notes) is not { } tree) return null;
        var modules = JsModules.Find(text, tree, ct);
        if (modules.Count < 2) return null;
        SourceMap? map = null;
        try { map = SourceMap.Locate(path, data)?.Map; }
        catch (ToolError ex) { notes.Add("source map: " + ex.Message); }
        catch (FormatException) { notes.Add("source map: inline data is not base64"); }
        var lines = JsModules.LineStarts(text);
        // Browserify and Parcel 1 dependency maps ("./lib/x" -> 12) name the modules they point at
        var requested = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var r in modules.SelectMany(x => x.Requires))
            if (r.Split(" -> ") is [var request, var target] && !requested.ContainsKey(target)) requested[target] = request;
        var used = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var items = new List<ExtractedItem>();
        var manifest = new List<object>();
        int fromKey = 0, fromMap = 0;
        foreach (var m in modules)
        {
            ct.ThrowIfCancellationRequested();
            string? original = m.Name == null && map != null ? JsModules.OriginalSource(map, lines, m) : null;
            var key = m.Name ?? (original == null ? requested.GetValueOrDefault(m.Id) : null);
            var file = Clean(key ?? original) ?? $"modules/{Clean(m.Id) ?? "module"}.js";
            if (key != null) fromKey++;
            else if (original != null) fromMap++;
            if (!Path.HasExtension(file)) file += ".js";
            if (!used.Add(file)) used.Add(file = $"{Path.ChangeExtension(file, null)}~{Clean(m.Id)}{Path.GetExtension(file)}");
            var head = $"// module {m.Id} ({m.Family}, {(key != null ? "bundler key" : original != null ? "source map" : "id only")}) of {Path.GetFileName(path)}, bytes {m.Start}-{m.End}" +
                       (m.Requires.Count > 0 ? $"\n// requires: {string.Join(", ", m.Requires.Take(100))}" : "") + "\n";
            items.Add(new ExtractedItem(file, Encoding.UTF8.GetBytes(head + text[m.Start..m.End] + "\n"), $"module {m.Id}"));
            manifest.Add(new { id = m.Id, file, family = m.Family, name = m.Name, original, requires = m.Requires, bytes = m.End - m.Start });
        }
        items.Add(new ExtractedItem("modules.json", JsonSerializer.SerializeToUtf8Bytes(manifest, Indented), "module list"));
        notes.Add($"{modules.Count} module(s): {fromKey} named by the bundler, {fromMap} by the source map, {modules.Count - fromKey - fromMap} by id.");
        return new ContainerContents($"{modules[0].Family} bundle", items, notes);
    }

    /// <summary>A module name as a relative path: scheme prefixes (webpack://), ./ and ../ dropped, query cut, unsafe characters replaced.</summary>
    internal static string? Clean(string? name)
    {
        if (string.IsNullOrWhiteSpace(name)) return null;
        var s = name.Replace('\\', '/');
        int scheme = s.IndexOf("://", StringComparison.Ordinal);
        if (scheme >= 0) s = s[(scheme + 3)..];
        int q = s.IndexOfAny(['?', '#']);
        if (q > 0) s = s[..q];
        var parts = s.Split('/', StringSplitOptions.RemoveEmptyEntries).Where(p => p is not ("." or "..")).Select(p =>
            new string(p.Select(c => char.IsControl(c) || Path.GetInvalidFileNameChars().Contains(c) ? '_' : c).ToArray()).Trim()).Where(p => p.Length > 0).ToList();
        return parts.Count == 0 ? null : string.Join('/', parts);
    }
}
