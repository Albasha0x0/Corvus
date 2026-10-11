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
using NetDecompilerMcp.Native.Providers;
using NetDecompilerMcp.Services;
using static NetDecompilerMcp.Tools.ToolSupport;

namespace NetDecompilerMcp.Tools;

/// <summary>trace_native_feature: from a text to the native functions behind a behaviour.</summary>
[McpServerToolType]
public sealed class NativeFeatureTools(AssemblyWorkspace workspace, NativeCodeService code, OutputPager pager, NativeEngineService? engines = null)
{
    private const int TopPseudocode = 3;
    private const int MaxEngineStrings = 50_000;

    [Description("A match of the query.")]
    public sealed record FeatureSeedRecord(int Id, [property: Description("string, name, import, export, class or constant.")] string Kind, string Address, string Text,
        [property: Description("References followed from it.")] int References, [property: Description("Why following it failed; the trace went on.")] string? Error);

    public sealed record FeatureEvidenceRecord(string Site,
        [property: Description("string, table, named, data, call, pointer, resolve, exported, vftable, method, constant, engine_xref or pseudocode.")] string Kind,
        string Detail, int Seed);

    public sealed record FeatureFunctionRecord(string Address, string Name, int Score, IReadOnlyList<int> Seeds, [property: Description("The first 20.")] IReadOnlyList<FeatureEvidenceRecord> Evidence,
        int EvidenceTotal, IReadOnlyList<string> Flags);

    public sealed record FeatureHubRecord(string Address, string Name, [property: Description("Feature functions it reaches (VAs).")] IReadOnlyList<string> Reaches,
        [property: Description("Calls to the nearest of them.")] int Depth);

    public sealed record FeatureReport(string Image, string Query, IReadOnlyList<FeatureSeedRecord> Seeds,
        [property: Description("Every match, followed or not (maxSeeds).")] int TotalSeeds, [property: Description("Functions of this page, ranked.")] IReadOnlyList<FeatureFunctionRecord> Functions,
        int TotalFunctions, int Offset, bool Truncated, IReadOnlyList<FeatureHubRecord> Hubs, IReadOnlyList<string> Notes);

    [McpServerTool(Name = "trace_native_feature", Title = "Trace a native feature", UseStructuredContent = true, OutputSchemaType = typeof(FeatureReport))]
    [Description("Finds the native code behind a behaviour from a text or value: seeds are the strings (ASCII, UTF-16), function and data names, imports " +
                 "(static and late-bound), exports, RTTI classes and, for a number, constants in code matching query (\"quoted\": exact); their references " +
                 "(string interiors, one pointer table, import calls and the calls constants feed, with decoded arguments, a class's vftable users) are " +
                 "grouped by function and ranked (distinct seeds, decoded API calls, exported, minus library and very large functions). Hubs are callers " +
                 "within callerDepth reaching several ranked functions. An open IDA / Ghidra session adds its strings, its references where the index has " +
                 "none, and the matching pseudocode lines of the top functions. A failing seed records its error. Pages reuse the computed trace.")]
    public Task<string> TraceNativeFeature(
        [Description(NativeTools.ImageDescription)] string image,
        [Description("Text to find (case-insensitive substring), or a regex with regex=true.")] string query,
        [Description("Treat query as a regular expression.")] bool regex = false,
        [Description("Comma-separated seed kinds (default all): strings, names, imports, exports, classes, constants.")] string? kinds = null,
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
        var session = engines?.OpenSession(native);
        var engine = session != null ? await Engine(session, cancellationToken) : null;
        var result = await Task.Run(() =>
        {
            var classes = wanted.HasFlag(FeatureKinds.Classes)
                ? native.GetAnalysis(n => Native.Itanium.CppRtti.Analyze(n.Image, cancellationToken)).Classes
                    .SelectMany(c => c.Vtables.Take(1).Select(v => new FeatureClass(c.Name, v.VftableRva, v.SlotRvas))).ToList()
                : [];
            return FeatureTrace.Run(index, query.Trim(), regex, wanted, Math.Clamp(maxSeeds, 1, 500), Math.Clamp(callerDepth, 0, 3), classes, cancellationToken, engine);
        }, cancellationToken);
        if (session != null) result = await Pseudocode(session, result, query.Trim(), regex, cancellationToken);
        var report = Report(native.Id, index, result, Math.Max(0, offset), Math.Clamp(limit, 1, 500));
        return StructuredOutput.With(Text(index, report, result), report);
    });

    /// <summary>The open session's strings and references (references are read on demand, by the trace's thread).</summary>
    private static async Task<FeatureEngine> Engine(INativeDecompilerSession session, CancellationToken ct)
    {
        IReadOnlyList<(uint, string)> strings;
        try { strings = (await session.ListStringsAsync(MaxEngineStrings, ct)).Select(s => (s.Rva, s.Text)).ToList(); }
        catch (Exception e) when (e is ToolError or NotSupportedException) { strings = []; }
        return new FeatureEngine(session.ProviderId, strings, rva =>
        {
            try
            {
                return session.GetXrefsToAsync(rva, ct).GetAwaiter().GetResult()
                    .Where(x => x.Kind is not (NativeXrefKind.Call or NativeXrefKind.Jump)).Select(x => x.FromRva).Distinct().ToList();
            }
            catch (Exception e) when (e is ToolError or NotSupportedException) { return []; }
        });
    }

    /// <summary>The pseudocode lines of the top functions that hold the query, as evidence (one decompile batch).</summary>
    private static async Task<FeatureTraceResult> Pseudocode(INativeDecompilerSession session, FeatureTraceResult r, string query, bool regex, CancellationToken ct)
    {
        var top = r.Functions.Take(TopPseudocode).ToList();
        if (top.Count == 0 || !session.DecompilerAvailable) return r;
        IReadOnlyList<DecompileOutcome> outcomes;
        try { outcomes = await session.DecompileManyAsync([.. top.Select(f => f.Function.Start)], 30, 30 * top.Count, ct); }
        catch (ToolError e) { return r with { Notes = [.. r.Notes, $"pseudocode of the top functions: {e.Message}"] }; }
        var needle = query.Trim('"');
        System.Text.RegularExpressions.Regex? pattern = null;
        if (regex)
            try { pattern = new System.Text.RegularExpressions.Regex(query, System.Text.RegularExpressions.RegexOptions.IgnoreCase, RegexTimeouts.Limit); }
            catch (ArgumentException) { return r; }
        var functions = r.Functions.ToList();
        for (int i = 0; i < top.Count && i < outcomes.Count; i++)
        {
            if (outcomes[i].Function is not { } d) continue;
            var lines = d.Text.Split('\n').Select(l => l.Trim()).Where(l => l.Length > 0 && (pattern?.IsMatch(l) ?? l.Contains(needle, StringComparison.OrdinalIgnoreCase))).Take(10)
                .Select(l => new FeatureEvidence(top[i].Function.Start, "pseudocode", $"{Format.Clip(l, 200)} ({session.ProviderId})", -1)).ToList();
            if (lines.Count == 0) continue;
            functions[i] = top[i] with { Evidence = [.. top[i].Evidence, .. lines], EvidenceTotal = top[i].EvidenceTotal + lines.Count };
        }
        return r with { Functions = functions };
    }

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
                "constants" or "constant" => FeatureKinds.Constants,
                _ => throw new ToolError(ErrorCode.InvalidArgument, $"Unknown seed kind '{k}'.", "kinds: strings, names, imports, exports, classes, constants"),
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
