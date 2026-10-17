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
        ["live_watch"] = Changes(destructive: false, idempotent: false, openWorld: true),
        ["live_read"] = Reads(openWorld: true),
        ["live_events"] = Reads(openWorld: true),
        // a user script runs inside the observed program and may change it; gated by --live-scripting as well
        ["live_script"] = Changes(destructive: true, idempotent: false, openWorld: true),
        // coverage stop points are resumed at once; the program runs as before
        ["live_coverage"] = Changes(destructive: false, idempotent: false, openWorld: true),
        // an event tracing session reads what the OS reports; the program is not touched
        ["live_timeline"] = Changes(destructive: false, idempotent: false, openWorld: true),
    };
}

public static partial class ParameterDomains
{
    private static Dictionary<string, IReadOnlyDictionary<string, Domain>> LiveTools() => new(StringComparer.Ordinal)
    {
        ["inspect_process"] = new Dictionary<string, Domain> { ["regionFilter"] = Of(["committed", "all", "executable", "writable", "image", "private", "mapped"]) },
        ["live_session"] = new Dictionary<string, Domain> { ["action"] = Of(["list", "processes", "attach", "spawn", "status", "close"]) },
        ["live_break"] = new Dictionary<string, Domain> { ["action"] = Of(["list", "set", "clear", "continue"]) },
        ["live_watch"] = new Dictionary<string, Domain> { ["action"] = Of(["list", "set", "clear"]) },
        ["live_script"] = new Dictionary<string, Domain> { ["action"] = Of(["list", "load", "unload"]) },
        ["live_coverage"] = new Dictionary<string, Domain>
        {
            ["action"] = Of(["start", "stop", "list", "report", "diff"]), ["show"] = Of(["ran", "missed", "all"]), ["format"] = Of(["text", "dot"]),
        },
        ["live_timeline"] = new Dictionary<string, Domain>
        {
            ["action"] = Of(["start", "stop", "list", "report"]), ["category"] = Of(["file", "registry", "network", "process"]),
        },
    };
}

public sealed partial record ToolContract
{
    private static Dictionary<string, ToolContract> LiveTools() => new(StringComparer.Ordinal)
    {
        ["inspect_process"] = Row(O.Report, L.Interactive),
        ["live_session"] = Row(O.Report, L.Interactive, noDryRun: "N14: gated by --allow-live"),
        ["live_break"] = Row(O.Report, L.Interactive, noDryRun: "N14: gated by --allow-live"),
        ["live_watch"] = Row(O.Report, L.Interactive, noDryRun: "N14: gated by --allow-live"),
        ["live_read"] = Row(O.Report, L.Interactive),
        ["live_events"] = Row(O.List, L.Instant, sort: "event sequence"),
        ["live_script"] = Row(O.Report, L.Interactive, noDryRun: "N14: gated by --allow-live and --live-scripting"),
        ["live_coverage"] = Row(O.Report, L.Interactive, noDryRun: "N14: gated by --allow-live"),
        ["live_timeline"] = Row(O.Report, L.Interactive, noDryRun: "N14: gated by --allow-live"),
    };
}
