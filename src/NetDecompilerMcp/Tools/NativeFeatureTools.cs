using System.ComponentModel;
using System.Text;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Mcp;
using NetDecompilerMcp.Native;
using NetDecompilerMcp.Native.Code;
using NetDecompilerMcp.Native.Msvc;
using NetDecompilerMcp.Services;
using static NetDecompilerMcp.Tools.ToolSupport;

namespace NetDecompilerMcp.Tools;

/// <summary>trace_native_feature: from a text to the native functions behind a behaviour.</summary>
[McpServerToolType]
public sealed class NativeFeatureTools(AssemblyWorkspace workspace, NativeCodeService code, OutputPager pager)
{
    [Description("A match of the query.")]
    public sealed record FeatureSeedRecord(int Id, [property: Description("string, name, import, export or class.")] string Kind, string Address, string Text,
        [property: Description("References followed from it.")] int References, [property: Description("Why following it failed; the trace went on.")] string? Error);

    public sealed record FeatureEvidenceRecord(string Site, [property: Description("string, table, named, data, call, pointer, resolve, exported, vftable or method.")] string Kind,
        string Detail, int Seed);

    public sealed record FeatureFunctionRecord(string Address, string Name, int Score, IReadOnlyList<int> Seeds, [property: Description("The first 20.")] IReadOnlyList<FeatureEvidenceRecord> Evidence,
        int EvidenceTotal, IReadOnlyList<string> Flags);

    public sealed record FeatureHubRecord(string Address, string Name, [property: Description("Feature functions it reaches (VAs).")] IReadOnlyList<string> Reaches,
        [property: Description("Calls to the nearest of them.")] int Depth);

    public sealed record FeatureReport(string Image, string Query, IReadOnlyList<FeatureSeedRecord> Seeds,
        [property: Description("Every match, followed or not (maxSeeds).")] int TotalSeeds, [property: Description("Functions of this page, ranked.")] IReadOnlyList<FeatureFunctionRecord> Functions,
        int TotalFunctions, int Offset, bool Truncated, IReadOnlyList<FeatureHubRecord> Hubs, IReadOnlyList<string> Notes);

    [McpServerTool(Name = "trace_native_feature", Title = "Trace a native feature", UseStructuredContent = true, OutputSchemaType = typeof(FeatureReport))]
    [Description("Finds the native code behind a behaviour from a text: seeds are the strings (ASCII, UTF-16), function and data names, imports " +
                 "(static and GetProcAddress), exports and RTTI classes matching query; their references (inside a string too, and through one table " +
                 "of pointers to it; import calls with their decoded arguments; a class's vftable users and methods) are grouped by function and ranked " +
                 "(distinct seeds, decoded API calls, exported, minus library and very large functions). Hubs are callers within callerDepth that reach " +
                 "several ranked functions. A seed that fails records its error; the trace goes on. Pages of functions reuse the computed trace. " +
                 "x86 / x64 / ARM64 (call arguments on x86 / x64).")]
    public Task<string> TraceNativeFeature(
        [Description(NativeTools.ImageDescription)] string image,
        [Description("Text to find (case-insensitive substring), or a regex with regex=true.")] string query,
        [Description("Treat query as a regular expression.")] bool regex = false,
        [Description("Comma-separated seed kinds (default all): strings, names, imports, exports, classes.")] string? kinds = null,
        [Description("Matches followed (default 50, 1-500); the rest are counted.")] int maxSeeds = 50,
        [Description("Caller levels searched for hubs (default 1, 0-3).")] int callerDepth = 1,
        [Description("Index of the first function.")] int offset = 0,
        [Description("Functions per page (default 50, max 500).")] int limit = 50,
        RequestContext<CallToolRequestParams> context = null!,
        CancellationToken cancellationToken = default) => OrderedProgress.Run(context, async progress =>
    {
        if (string.IsNullOrWhiteSpace(query)) throw new ToolError(ErrorCode.InvalidArgument, "query is empty.", "pass the text to find");
        var wanted = Kinds(kinds);
        var native = await Task.Run(() => NativeAnalysisTools.ResolveImage(workspace, image), cancellationToken);
        var waited = System.Diagnostics.Stopwatch.StartNew();
        var index = await code.Index(native, new Progress<CodeIndexProgress>(p => progress.Report(new ProgressNotificationValue
        {
            Progress = (float)waited.Elapsed.TotalSeconds, Message = $"indexing {native.Id}: {p.Phase}",
        })), cancellationToken);
        return await Task.Run(() =>
        {
            var classes = wanted.HasFlag(FeatureKinds.Classes) && index.Image.Format == ImageFormat.Pe
                ? native.GetAnalysis(n => MsvcRtti.Analyze(n.Image, ct: cancellationToken)).Classes
                    .SelectMany(c => c.Vtables.Take(1).Select(v => new FeatureClass(c.Name, v.VftableRva, v.SlotRvas))).ToList()
                : [];
            var result = FeatureTrace.Run(index, query.Trim(), regex, wanted, Math.Clamp(maxSeeds, 1, 500), Math.Clamp(callerDepth, 0, 3), classes, cancellationToken);
            var report = Report(native.Id, index, result, Math.Max(0, offset), Math.Clamp(limit, 1, 500));
            return StructuredOutput.With(Text(index, report, result), report);
        }, cancellationToken);
    });

    private static FeatureKinds Kinds(string? list)
    {
        if (string.IsNullOrWhiteSpace(list)) return FeatureKinds.All;
        var kinds = FeatureKinds.None;
        foreach (var k in list.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            kinds |= k.ToLowerInvariant() switch
            {
                "strings" or "string" => FeatureKinds.Strings,
                "names" or "name" => FeatureKinds.Names,
                "imports" or "import" => FeatureKinds.Imports,
                "exports" or "export" => FeatureKinds.Exports,
                "classes" or "class" => FeatureKinds.Classes,
                _ => throw new ToolError(ErrorCode.InvalidArgument, $"Unknown seed kind '{k}'.", "kinds: strings, names, imports, exports, classes"),
            };
        return kinds;
    }

    private static FeatureReport Report(string id, NativeCodeIndex index, FeatureTraceResult r, int offset, int limit)
    {
        string Va(uint rva) => NativeAddress.Va(index.Image, rva);
        var page = r.Functions.Skip(offset).Take(limit).Select(f => new FeatureFunctionRecord(Va(f.Function.Start), f.Name, f.Score, f.Seeds,
            f.Evidence.Select(e => new FeatureEvidenceRecord(Va(e.Site), e.Kind, e.Detail, e.Seed)).ToList(), f.EvidenceTotal, f.Flags)).ToList();
        return new FeatureReport(id, r.Query, r.Seeds.Select(s => new FeatureSeedRecord(s.Id, s.Kind, Va(s.Rva), s.Text, s.References, s.Error)).ToList(), r.TotalSeeds, page,
            r.Functions.Count, offset, offset + page.Count < r.Functions.Count,
            r.Hubs.Take(20).Select(h => new FeatureHubRecord(Va(h.Function.Start), h.Name, h.Reaches.Select(Va).ToList(), h.Depth)).ToList(), r.Notes);
    }

    private string Text(NativeCodeIndex index, FeatureReport r, FeatureTraceResult result)
    {
        var sb = new StringBuilder($"Feature trace of \"{r.Query}\" in {r.Image}: {Plural(r.TotalSeeds, "match")}, {Plural(r.Seeds.Count, "seed")} followed, " +
                                   $"{Plural(r.TotalFunctions, "function")}, {Plural(result.Hubs.Count, "hub")}\n");
        sb.AppendLine("\nSeeds:");
        foreach (var s in r.Seeds)
            sb.AppendLine($"  [{s.Id}] {s.Kind,-7} {s.Address}  {s.Text}  ({Plural(s.References, "reference")}{(s.Error != null ? $"; failed: {s.Error}" : "")})");
        if (r.Seeds.Count == 0) sb.AppendLine("  none: nothing matches (try regex=true, another spelling, or kinds=strings,names,imports)");
        sb.AppendLine($"\nFunctions (ranked; {r.Offset + 1}-{r.Offset + r.Functions.Count} of {r.TotalFunctions}):");
        foreach (var f in r.Functions)
        {
            sb.AppendLine($"  {f.Address}  {f.Name}  score {f.Score}, seeds {string.Join(",", f.Seeds)}{(f.Flags.Count > 0 ? $"  [{string.Join(", ", f.Flags)}]" : "")}");
            foreach (var e in f.Evidence.Take(6)) sb.AppendLine($"      {e.Site}  {e.Kind}: {Format.Clip(e.Detail, 200)}");
            if (f.EvidenceTotal > 6) sb.AppendLine($"      ... {f.EvidenceTotal - 6} more (structured output)");
        }
        if (r.Truncated) sb.AppendLine($"  [More functions: call again with offset={r.Offset + r.Functions.Count}]");
        if (r.Hubs.Count > 0)
        {
            sb.AppendLine("\nHubs (callers reaching several of them):");
            foreach (var h in r.Hubs) sb.AppendLine($"  {h.Address}  {h.Name}  reaches {h.Reaches.Count} within {h.Depth}: {string.Join(", ", h.Reaches.Take(8))}");
        }
        var silent = r.Seeds.Where(s => s.References == 0 && s.Error == null && s.Kind is "string" or "import" or "class").ToList();
        if (silent.Count > 0)
            sb.AppendLine($"\nUnreferenced seeds ({silent.Count}): {string.Join(", ", silent.Take(10).Select(s => s.Text))} — built at run time, reached through a " +
                          "computed offset, or not used");
        foreach (var n in r.Notes) sb.AppendLine("Note: " + n);
        if (index.Truncations.Count > 0) sb.AppendLine("Note: " + string.Join("; ", index.Truncations));
        var top = r.Functions.Take(3).ToList();
        if (top.Count > 0)
        {
            sb.AppendLine("\nNext:");
            foreach (var f in top) sb.AppendLine($"  analyze_native_function image={r.Image} address={f.Address}");
        }
        return pager.Page(sb.ToString());
    }
}
