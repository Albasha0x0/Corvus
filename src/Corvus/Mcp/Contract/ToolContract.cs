namespace Corvus.Mcp;

/// <summary>What a tool returns (S1.3); sets the default token budget of each result part (D1).</summary>
public enum OutputClass { List, Code, Bytes, Report, Edit, Error }

/// <summary>Warm p95 target (S11.1): instant 50 ms, interactive 500 ms, engine 1 s per query once the engine is open, long without a bound (reports progress).</summary>
public enum LatencyClass { Instant, Interactive, Engine, Long }

/// <summary>How a tool previews (S7.3, D7): read-only tools have nothing to preview; a changing tool without dryRun records why.</summary>
public enum DryRunPolicy { NotApplicable, DefaultTrue, None }

public static class OutputClasses
{
    /// <summary>Default page per part in estimated tokens (D1).</summary>
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

/// <summary>
/// A tool's contract beyond its annotations: output and latency class, profile membership, preview policy and the order of
/// its rows. Rows are in the per-family files beside this one; Core records the intended core profile (D12, D14).
/// </summary>
public sealed partial record ToolContract(string Tool, OutputClass Output, LatencyClass Latency, bool Lean, bool Core, DryRunPolicy DryRun,
    string? DryRunReason, string? SortKey)
{
    public ToolEffects.Effects Effects => ToolEffects.Of(Tool);

    /// <param name="sort">The default row order of a list (S2.3).</param>
    /// <param name="dryRun">Takes dryRun and defaults it to true.</param>
    /// <param name="noDryRun">Why a tool that changes something has no dryRun.</param>
    private static ToolContract Row(OutputClass output, LatencyClass latency, bool lean = false, bool core = false, string? sort = null,
        bool dryRun = false, string? noDryRun = null) =>
        new("", output, latency, lean, core, dryRun ? DryRunPolicy.DefaultTrue : noDryRun != null ? DryRunPolicy.None : DryRunPolicy.NotApplicable,
            noDryRun, sort);

    internal static readonly IReadOnlyDictionary<string, IReadOnlyDictionary<string, ToolContract>> ByFamily =
        new Dictionary<string, IReadOnlyDictionary<string, ToolContract>>(StringComparer.Ordinal)
        {
            ["session"] = SessionTools(),
            ["dotnet"] = DotnetTools(),
            ["containers"] = ContainersTools(),
            ["edit"] = EditTools(),
            ["il2cpp"] = Il2CppTools(),
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
