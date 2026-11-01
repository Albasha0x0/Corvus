namespace Corvus.Mcp;

/// <summary>What a tool returns; sets the default token budget of each result part.</summary>
public enum OutputClass { List, Code, Bytes, Report, Edit, Error }

/// <summary>Warm p95 target: instant 50 ms, interactive 500 ms, engine 1 s per query once the engine is open, long without a bound (reports progress).</summary>
public enum LatencyClass { Instant, Interactive, Engine, Long }

/// <summary>How a tool previews: read-only tools have nothing to preview; a changing tool without dryRun records why.</summary>
public enum DryRunPolicy { NotApplicable, DefaultTrue, None }

/// <summary>The saved state a tool's output reads, which a restarted server restores from the data folder; None reads only its arguments and the loaded file.</summary>
public enum ToolState
{
    None,
    /// <summary>Annotation sidecars and imported name layers.</summary>
    Names,
    /// <summary>Analyst notes.</summary>
    Notes,
    /// <summary>Journals of unsaved edits, offered for replay on load.</summary>
    Journal,
    /// <summary>Kept results read by id.</summary>
    Results,
    /// <summary>Derived caches keyed by file hash (symbols, decompiled sources, per-dump signatures).</summary>
    Cache,
    /// <summary>Engine databases and saved engine output.</summary>
    Engine,
    /// <summary>Recorded live sessions.</summary>
    Live,
}

public static class OutputClasses
{
    /// <summary>Default page per part in estimated tokens.</summary>
    public static int Budget(OutputClass output) => output switch
    {
        OutputClass.List => 6_000,
        OutputClass.Code => 8_000,
        OutputClass.Bytes => 6_000,
        OutputClass.Report => 4_000,
        OutputClass.Edit => 3_000,
        OutputClass.Error => 1_000,
        _ => throw new ArgumentOutOfRangeException(nameof(output)),
    };
}

/// <summary>A tool's contract beyond its annotations: output and latency class, profile membership, preview policy; rows are in the per-family files.</summary>
public sealed partial record ToolContract(string Tool, OutputClass Output, LatencyClass Latency, bool Lean, bool Core, DryRunPolicy DryRun,
    string? DryRunReason, string? SortKey, ToolState State = ToolState.None)
{
    public ToolEffects.Effects Effects => ToolEffects.Of(Tool);

    /// <summary>True when the result may quote the analyzed file, so its provenance says untrustedContent; every tool unless listed as server-only output.</summary>
    public bool UntrustedContent => !ServerOnlyOutput.Contains(Tool);

    /// <summary>Tools whose results hold only the server's own text and the caller's numbers.</summary>
    internal static readonly IReadOnlySet<string> ServerOnlyOutput = new HashSet<string>(StringComparer.Ordinal) { "server_status", "convert_number" };

    /// <summary>Tools whose result scans many files or members: coverage is unknown until the reader calls <see cref="ToolOutput.Complete"/>.</summary>
    internal static readonly IReadOnlySet<string> ScanOutput = new HashSet<string>(StringComparer.Ordinal)
        { "summarize_file", "survey_features", "search_container", "compare_folders" };

    /// <param name="sort">The default row order of a list.</param>
    /// <param name="dryRun">Takes dryRun and defaults it to true.</param>
    /// <param name="noDryRun">Why a tool that changes something has no dryRun.</param>
    /// <param name="state">The saved state the output reads.</param>
    private static ToolContract Row(OutputClass output, LatencyClass latency, bool lean = false, bool core = false, string? sort = null,
        bool dryRun = false, string? noDryRun = null, ToolState state = ToolState.None) =>
        new("", output, latency, lean, core, dryRun ? DryRunPolicy.DefaultTrue : noDryRun != null ? DryRunPolicy.None : DryRunPolicy.NotApplicable,
            noDryRun, sort, state);

    internal static readonly IReadOnlyDictionary<string, IReadOnlyDictionary<string, ToolContract>> ByFamily =
        new Dictionary<string, IReadOnlyDictionary<string, ToolContract>>(StringComparer.Ordinal)
        {
            ["session"] = SessionTools(),
            ["dotnet"] = DotnetTools(),
            ["containers"] = ContainersTools(),
            ["edit"] = EditTools(),
            ["aot"] = AotTools(),
            ["native"] = NativeTools(),
            ["native-edit"] = NativeEditTools(),
            ["builds"] = BuildsTools(),
            ["notes"] = NotesTools(),
            ["engine"] = EngineTools(),
            ["android"] = AndroidTools(),
            ["dumps"] = DumpsTools(),
            ["live"] = LiveTools(),
            ["web"] = WebTools(),
        };

    /// <summary>Every tool, by name.</summary>
    public static readonly IReadOnlyDictionary<string, ToolContract> Table =
        FamilyTables.Join(ByFamily).ToDictionary(t => t.Key, t => t.Value with { Tool = t.Key }, StringComparer.Ordinal);

    /// <summary>The contract of <paramref name="tool"/>; a tool the table does not list gets the most cautious one.</summary>
    public static ToolContract Of(string tool) =>
        Table.TryGetValue(tool, out var contract) ? contract : new(tool, OutputClass.Report, LatencyClass.Long, false, false, DryRunPolicy.NotApplicable, null, null);
}
