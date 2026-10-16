using L = Corvus.Mcp.LatencyClass;
using O = Corvus.Mcp.OutputClass;

namespace Corvus.Mcp;

// Contract rows of the live family (Core/Toolsets.cs); the tables and their rules are in ToolEffects.cs, ParameterDomains.cs and ToolContract.cs.

public static partial class ToolEffects
{
    private static Dictionary<string, Effects> LiveTools() => new(StringComparer.Ordinal)
    {
        ["inspect_process"] = Reads(openWorld: true), // query and read handles to a running process only (docs/live-inspection.md); idempotent for the target
        // the session tools change the session (opened, closed, stop points), never the observed program; gated by --allow-live
        ["live_session"] = Changes(destructive: false, idempotent: false, openWorld: true),
        ["live_break"] = Changes(destructive: false, idempotent: false, openWorld: true),
        ["live_read"] = Reads(openWorld: true),
        ["live_events"] = Reads(openWorld: true),
    };
}

public static partial class ParameterDomains
{
    private static Dictionary<string, IReadOnlyDictionary<string, Domain>> LiveTools() => new(StringComparer.Ordinal)
    {
        ["inspect_process"] = new Dictionary<string, Domain> { ["regionFilter"] = Of(["committed", "all", "executable", "writable", "image", "private", "mapped"]) },
        ["live_session"] = new Dictionary<string, Domain> { ["action"] = Of(["list", "attach", "spawn", "status", "close"]) },
        ["live_break"] = new Dictionary<string, Domain> { ["action"] = Of(["list", "set", "clear"]) },
    };
}

public sealed partial record ToolContract
{
    private static Dictionary<string, ToolContract> LiveTools() => new(StringComparer.Ordinal)
    {
        ["inspect_process"] = Row(O.Report, L.Interactive),
        ["live_session"] = Row(O.Report, L.Interactive, noDryRun: "N14: gated by --allow-live"),
        ["live_break"] = Row(O.Report, L.Interactive, noDryRun: "N14: gated by --allow-live"),
        ["live_read"] = Row(O.Report, L.Interactive),
        ["live_events"] = Row(O.List, L.Instant, sort: "event sequence"),
    };
}
