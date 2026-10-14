using System.IO.Compression;
using System.Text;
using Corvus.Core;

namespace Corvus.Services.Analysis;

/// <summary>
/// search_container kind=electron: the surface rows (<see cref="ElectronRow"/>) of the app's own scripts (node_modules
/// skipped); the query matches the value (channel, key, module) or the row kind (ipc-main, sink-shell...). An Electron
/// executable or .asar is read as summarize_file reads it; a zip of scripts is read directly; a required .node add-on is named with its N-API registrations.
/// </summary>
internal sealed class ElectronSearchKind : IContainerSearchKind
{
    private const long MaxScriptBytes = 16 * 1024 * 1024;

    public IReadOnlyList<string> Kinds => ["electron"];

    public IEnumerable<ContainerMatch> Search(ContainerScope scope, string kind, Func<string, bool> matches, CancellationToken ct)
    {
        var addons = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);
        foreach (var row in Rows(scope, ct))
            if (matches(row.Value) || matches(row.Kind))
            {
                var file = row.Site[..row.Site.IndexOf(':')];
                var detail = $"{row.Kind} at {row.Site}";
                if (row.Kind == "native-require" && Addon(scope.Source, file, row.Value, addons, ct) is { } exports) detail += "; " + exports;
                yield return new ContainerMatch(file, row.Value, "electron") { Detail = detail };
            }
    }

    /// <summary>
    /// The add-on a require names, beside the requiring script under the app's unpacked files (app.asar.unpacked, the
    /// or resources/app.asar.unpacked beside an executable), with the JavaScript names its N-API registrations expose.
    /// </summary>
    private static string? Addon(string source, string script, string request, Dictionary<string, string?> seen, CancellationToken ct)
    {
        if (!request.EndsWith(".node", StringComparison.OrdinalIgnoreCase) || !request.StartsWith('.')) return null;
        var root = source.EndsWith(".asar", StringComparison.OrdinalIgnoreCase) ? source + ".unpacked"
            : Path.Combine(Path.GetDirectoryName(source) ?? "", "resources", "app.asar.unpacked");
        var path = Path.GetFullPath(Path.Combine(root, Path.GetDirectoryName(script) ?? "", request));
        if (!path.StartsWith(Path.GetFullPath(root), StringComparison.OrdinalIgnoreCase) || !File.Exists(path)) return null;
        if (seen.TryGetValue(path, out var known)) return known;
        string? result = null;
        try
        {
            var image = Native.NativeImageLoader.Open(path);
            if (Native.NodeApi.IsAddon(image))
            {
                var registrations = Native.NodeApi.Find(Native.Code.NativeCodeIndex.Build(image, ct: ct), ct).Registrations;
                result = $"add-on {Path.GetRelativePath(root, path).Replace('\\', '/')}: {registrations.Count} N-API registration(s)" +
                         (registrations.Count > 0 ? ": " + string.Join(", ", registrations.Select(r => r.JsName).Distinct().Take(12)) + (registrations.Count > 12 ? ", ..." : "") : "");
            }
        }
        catch (ToolError) { }
        seen[path] = result;
        return result;
    }

    private static List<ElectronRow> Rows(ContainerScope scope, CancellationToken ct)
    {
        var rows = new List<ElectronRow>();
        var source = scope.Source;
        byte[] head = new byte[8];
        try
        {
            using var f = File.OpenRead(source);
            f.ReadAtLeast(head, head.Length, throwOnEndOfStream: false);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return rows; }
        if (Blob.Identify(head) == "zip")
        {
            using var zip = ZipFile.OpenRead(source);
            foreach (var e in zip.Entries)
            {
                ct.ThrowIfCancellationRequested();
                var path = e.FullName.Replace('\\', '/');
                if (!IsAppScript(path) || e.Length > MaxScriptBytes) continue;
                using var s = e.Open();
                using var copy = new MemoryStream();
                s.CopyTo(copy);
                if (!Add(path, copy.ToArray())) break;
            }
            return rows;
        }
        // an Electron executable or .asar: the facts summarize_file reports
        try
        {
            if (new FileInfo(source).Length <= AnalysisLimits.Default.MaxItemBytes
                && ElectronInspector.Of(source, File.ReadAllBytes(source), ct) is { } facts) return [.. facts.Surface];
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
        return rows;

        bool Add(string path, byte[] bytes)
        {
            ElectronSurface.Scan(Encoding.UTF8.GetString(bytes), path, rows);
            return rows.Count < ElectronSurface.MaxRows;
        }
    }

    private static bool IsAppScript(string p) =>
        (p.EndsWith(".js", StringComparison.OrdinalIgnoreCase) || p.EndsWith(".cjs", StringComparison.OrdinalIgnoreCase) || p.EndsWith(".mjs", StringComparison.OrdinalIgnoreCase))
        && !p.StartsWith("node_modules/", StringComparison.Ordinal) && !p.Contains("/node_modules/", StringComparison.Ordinal);
}
