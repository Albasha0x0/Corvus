using System.IO.Compression;
using System.Text;
using Corvus.Core;

namespace Corvus.Services.Analysis;

/// <summary>
/// search_container kind=electron: the surface rows (<see cref="ElectronRow"/>) of the app's own scripts (node_modules
/// skipped); the query matches the value (channel, key, module) or the row kind (ipc-main, sink-shell...). An Electron
/// executable or .asar is read as summarize_file reads it; a zip or folder of scripts is read directly.
/// </summary>
internal sealed class ElectronSearchKind : IContainerSearchKind
{
    private const long MaxScriptBytes = 16 * 1024 * 1024;

    public IReadOnlyList<string> Kinds => ["electron"];

    public IEnumerable<ContainerMatch> Search(ContainerScope scope, string kind, Func<string, bool> matches, CancellationToken ct)
    {
        foreach (var row in Rows(scope, ct))
            if (matches(row.Value) || matches(row.Kind))
                yield return new ContainerMatch(row.Site[..row.Site.IndexOf(':')], row.Value, "electron") { Detail = $"{row.Kind} at {row.Site}" };
    }

    private static List<ElectronRow> Rows(ContainerScope scope, CancellationToken ct)
    {
        var rows = new List<ElectronRow>();
        var source = scope.Source;
        if (Directory.Exists(source))
        {
            foreach (var file in Directory.EnumerateFiles(source, "*", new EnumerationOptions { RecurseSubdirectories = true, AttributesToSkip = FileAttributes.ReparsePoint }))
            {
                var relative = Path.GetRelativePath(source, file).Replace('\\', '/');
                if (!IsAppScript(relative) || new FileInfo(file).Length > MaxScriptBytes) continue;
                if (!Add(relative, File.ReadAllBytes(file))) break;
            }
            return rows;
        }
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
