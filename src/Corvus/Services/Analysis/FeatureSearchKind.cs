using System.IO.Compression;
using System.Text;
using Corvus.Core;

namespace Corvus.Services.Analysis;

/// <summary>
/// search_container kind=feature: on an Electron app (executable, .asar or zip of scripts) or a script, each literal
/// containing the query followed to where it leads (<see cref="ElectronGraph.Trace"/>); one row per chain, its steps in
/// Detail, and a native call ending at the add-on function its N-API registration names.
/// </summary>
internal sealed class FeatureSearchKind : IContainerSearchKind
{
    public IReadOnlyList<string> Kinds => ["feature"];

    public IEnumerable<ContainerMatch> Search(ContainerScope scope, string kind, Func<string, bool> matches, CancellationToken ct) => [];

    public UnpackService.ContainerSearch SearchFile(string path, string query, int offset, int limit, ContainerSearchArgs args, CancellationToken ct)
    {
        var full = InputFiles.RequireRegularFile(path, "app or script");
        if (string.IsNullOrWhiteSpace(query) || query.Trim() is "*" or "") throw new ToolError(ErrorCode.InvalidArgument, "kind=feature needs the text to follow.", "pass query=<a UI, log or error text>");
        query = query.Trim().Trim('"');
        var notes = new List<string>();
        var traces = Traces(full, query, notes, ct);
        var addons = new Dictionary<string, ElectronSearchKind.Addon?>(StringComparer.OrdinalIgnoreCase);
        var rows = new List<ContainerMatch>();
        foreach (var t in traces)
        {
            var steps = t.Steps.ToList();
            if (t is { Addon: { } request, Function: { } fn } && ElectronSearchKind.Find(full, t.File, request, addons, ct) is { } addon) steps.Add(addon.Join(fn));
            rows.Add(new ContainerMatch(t.File, t.Literal, "feature") { Detail = string.Join(" -> ", steps) });
        }
        if (rows.Count == 0) notes.Add($"no literal containing '{query}' in the app's own scripts (node_modules skipped)");
        return new UnpackService.ContainerSearch(full, "electron", traces.Select(t => t.File).Distinct().Count(), rows.Skip(offset).Take(limit).ToList(), offset, rows.Count, notes);
    }

    private static List<FeatureTrace> Traces(string path, string query, List<string> notes, CancellationToken ct)
    {
        var head = new byte[32];
        using (var f = File.OpenRead(path)) _ = f.ReadAtLeast(head, head.Length, throwOnEndOfStream: false);
        var kind = Blob.Identify(head);
        if (kind == "zip")
        {
            var graph = new ElectronGraph { KeepTexts = true };
            using var zip = ZipFile.OpenRead(path);
            foreach (var e in zip.Entries.Where(e => Endpoints.ApiSurface.IsScript(e.FullName.Replace('\\', '/')) && e.Length <= 16 << 20))
            {
                using var s = e.Open();
                if (Blob.ReadBounded(s, 16 << 20) is { } bytes) graph.Add(e.FullName.Replace('\\', '/'), Encoding.UTF8.GetString(bytes), ct);
            }
            graph.Finish();
            return graph.Trace(query, ct);
        }
        if (kind is "asar" or "native PE" or "elf" or "mach-o")
        {
            if (new FileInfo(path).Length > AnalysisLimits.Default.MaxItemBytes) throw new ToolError(ErrorCode.LimitExceeded, $"{path} is over the {AnalysisLimits.Default.MaxItemBytes:N0}-byte item limit.");
            var facts = ElectronInspector.Of(path, File.ReadAllBytes(path), ct, trace: query)
                        ?? throw new ToolError(ErrorCode.Unsupported, $"{Path.GetFileName(path)} is not an Electron app.", "pass an Electron executable, its app.asar, a zip of scripts or a .js file");
            notes.AddRange(facts.Notes.Take(5));
            return [.. facts.Traces ?? []];
        }
        var one = new ElectronGraph { KeepTexts = true };
        one.Add(Path.GetFileName(path), Encoding.UTF8.GetString(Web.JsAnalysis.Read(path)), ct);
        one.Finish();
        return one.Trace(query, ct);
    }
}
