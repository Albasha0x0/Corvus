using System.Text;
using System.Text.Json;
using Corvus.Core;

namespace Corvus.Services.Web;

/// <summary>A script as an unpack_container container: one file per bundle module plus modules.json, and the source map's tree under original/ plus sources.json.</summary>
internal static class JsBundleFiles
{
    private static readonly string[] Extensions = [".js", ".mjs", ".cjs", ".bundle"];
    private static readonly JsonSerializerOptions Indented = new() { WriteIndented = true };

    /// <summary>Largest file read beside the map for a source without sourcesContent.</summary>
    private const long MaxBesideBytes = 64L * 1024 * 1024;

    public static bool Looks(byte[] data, string name) =>
        (Extensions.Any(e => name.EndsWith(e, StringComparison.OrdinalIgnoreCase)) || IsMap(name)) && Blob.Identify(data) == "text";

    private static bool IsMap(string name) => name.EndsWith(".map", StringComparison.OrdinalIgnoreCase);

    /// <summary>The modules and the original tree as files; null when the file is neither a bundle (two or more modules) nor source-mapped.</summary>
    public static ContainerContents? Open(byte[] data, string path, CancellationToken ct)
    {
        var notes = new List<string>();
        var items = new List<ExtractedItem>();
        SourceMap? map = null;
        string? mapDirectory = null;
        try
        {
            if (IsMap(path)) (map, mapDirectory) = (SourceMap.Parse(data), Path.GetDirectoryName(Path.GetFullPath(path)));
            else if (SourceMap.Locate(path, data) is { } found)
            {
                map = found.Map;
                var location = found.Location.Replace(" (no sourceMappingURL comment)", "", StringComparison.Ordinal);
                mapDirectory = Path.GetDirectoryName(Path.GetFullPath(location == "inline" ? path : location));
            }
        }
        catch (ToolError ex) { notes.Add("source map: " + ex.Message); }
        catch (FormatException) { notes.Add("source map: inline data is not base64"); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException) { notes.Add("source map: " + ex.Message); }
        string? kind = null;
        if (!IsMap(path) && data.Length <= JsModules.MaxParseBytes && Modules(data, path, map, items, notes, ct) is { } family) kind = $"{family} bundle";
        if (map is { Sources.Count: > 0 } && mapDirectory != null)
        {
            OriginalTree(map, mapDirectory, items, notes, ct);
            kind ??= "source-mapped script";
        }
        return kind == null ? null : new ContainerContents(kind, items, notes) { Entries = [.. items.Select(i => new ContainerEntry(i.Name, i.Bytes.Length, i.Origin))] };
    }

    /// <summary>One file per module and modules.json; the bundler family, or null when the script has fewer than two modules.</summary>
    private static string? Modules(byte[] data, string path, SourceMap? map, List<ExtractedItem> items, List<string> notes, CancellationToken ct)
    {
        var text = Encoding.UTF8.GetString(data);
        if (JsModules.Parse(text, []) is not { } tree) return null;
        var modules = JsModules.Find(text, tree, ct);
        if (modules.Count < 2) return null;
        var lines = JsModules.LineStarts(text);
        // Browserify and Parcel 1 dependency maps ("./lib/x" -> 12) name the modules they point at.
        var requested = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var r in modules.SelectMany(x => x.Requires))
            if (r.Split(" -> ") is [var request, var target] && !requested.ContainsKey(target)) requested[target] = request;
        var used = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
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
        return modules[0].Family;
    }

    /// <summary>The map's sources as original/&lt;source&gt; from sourcesContent, else a file under the map's folder, never above it; sources.json lists each.</summary>
    private static void OriginalTree(SourceMap map, string mapDirectory, List<ExtractedItem> items, List<string> notes, CancellationToken ct)
    {
        var used = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var manifest = new List<object>();
        var missing = new List<string>();
        int fromMap = 0, beside = 0;
        for (int i = 0; i < map.Sources.Count; i++)
        {
            ct.ThrowIfCancellationRequested();
            var source = map.Sources[i];
            var file = "original/" + (Clean(source) ?? $"source_{i}");
            if (!used.Add(file)) used.Add(file = $"{Path.ChangeExtension(file, null)}~{i}{Path.GetExtension(file)}");
            byte[]? bytes = null;
            string got;
            if (i < map.SourcesContent.Count && map.SourcesContent[i] is { } content) { bytes = Encoding.UTF8.GetBytes(content); got = "sourcesContent"; fromMap++; }
            else if (Beside(mapDirectory, source) is { } read) { bytes = read; got = "file beside the map"; beside++; }
            else { got = "missing"; missing.Add(source); }
            if (bytes != null) items.Add(new ExtractedItem(file, bytes, $"source {i} of the map ({got})"));
            manifest.Add(new { index = i, source, file = bytes != null ? file : null, content = got, bytes = bytes?.Length });
        }
        items.Add(new ExtractedItem("sources.json", JsonSerializer.SerializeToUtf8Bytes(manifest, Indented), "source list"));
        notes.Add($"{map.Sources.Count} source(s) in the map, written under original/: {fromMap} from sourcesContent, {beside} from files beside the map, {missing.Count} without content" +
                  (missing.Count > 0 ? $" ({string.Join(", ", missing.Take(20))}{(missing.Count > 20 ? ", ..." : "")}; all in sources.json)" : "") + ".");
        notes.AddRange(map.Issues.Take(5).Select(i => "source map: " + i));
    }

    /// <summary>The file a normalized source names under the map's folder; null when absent, too large or outside the folder.</summary>
    private static byte[]? Beside(string mapDirectory, string source)
    {
        if (source.Length == 0) return null;
        try
        {
            var full = Path.GetFullPath(Path.Combine(mapDirectory, source));
            var root = Path.TrimEndingDirectorySeparator(mapDirectory) + Path.DirectorySeparatorChar;
            if (!full.StartsWith(root, StringComparison.OrdinalIgnoreCase) || !File.Exists(full) || new FileInfo(full).Length > MaxBesideBytes) return null;
            return File.ReadAllBytes(full);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException) { return null; }
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
            new string(p.Select(c => char.IsControl(c) || InvalidNameChars.Contains(c) ? '_' : c).ToArray()).Trim()).Where(p => p.Length > 0).ToList();
        return parts.Count == 0 ? null : string.Join('/', parts);
    }

    // Windows' set on every OS, so a tree written on one machine opens on any other.
    private static readonly System.Buffers.SearchValues<char> InvalidNameChars = System.Buffers.SearchValues.Create("\"<>|:*?\\/");
}
