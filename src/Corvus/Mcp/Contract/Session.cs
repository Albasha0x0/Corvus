using L = Corvus.Mcp.LatencyClass;
using O = Corvus.Mcp.OutputClass;

namespace Corvus.Mcp;

// Contract rows of the session family (Core/Toolsets.cs); the tables and their rules are in ToolEffects.cs, ParameterDomains.cs and ToolContract.cs.

public static partial class ToolEffects
{
    private static Dictionary<string, Effects> SessionTools() => new(StringComparer.Ordinal)
    {
        // Workspace
        ["load_assembly"] = Changes(destructive: false, idempotent: true, longRunning: true), // adds files and a search directory; same path again: no-op
        ["unload_assembly"] = Changes(destructive: true, idempotent: true), // discards unsaved edits
        ["reload_assembly"] = Changes(destructive: true, idempotent: true), // discards unsaved edits
        ["add_search_directory"] = Changes(destructive: false, idempotent: true),
        ["list_assemblies"] = Reads(),
        ["server_status"] = Reads(openWorld: true), // probes the Python idalib uses (a process launch, once per server)
        ["read_result"] = Changes(destructive: true, idempotent: true), // outputPath; overwrite=true replaces a file
        ["save_session"] = Changes(destructive: true, idempotent: true), // overwrite=true replaces the file at path
        ["load_session"] = Changes(destructive: true, idempotent: false, longRunning: true), // loads files and applies edits, patches and names; dryRun by default
    };
}

public static partial class ParameterDomains
{
    private static Dictionary<string, IReadOnlyDictionary<string, Domain>> SessionTools() => new(StringComparer.Ordinal)
    {
        ["load_session"] = new Dictionary<string, Domain> { ["targetBuild"] = Of(["same", "other"]) },
        ["read_result"] = new Dictionary<string, Domain> { ["format"] = Of(["text", "json", "jsonl"]) },
        ["load_assembly"] = new Dictionary<string, Domain>
        {
            ["slice"] = Of(["arm64e", "arm64", "x86_64", "x86_64h", "arm64_32", "armv7", "armv7s", "armv7k", "i386", "arm64-v8a", "armeabi-v7a", "x86"],
                [.. Enumerable.Range(0, 64).Select(i => i.ToString(System.Globalization.CultureInfo.InvariantCulture))]),
        },
    };
}

public sealed partial record ToolContract
{
    private static Dictionary<string, ToolContract> SessionTools() => new(StringComparer.Ordinal)
    {
        ["load_assembly"] = Row(O.Edit, L.Interactive, lean: true, core: true, noDryRun: "only adds to the session; unload_assembly removes it"),
        ["unload_assembly"] = Row(O.Edit, L.Instant, lean: true, core: true, noDryRun: "load_assembly restores the file; unsaved edits are named in the result"),
        ["reload_assembly"] = Row(O.Edit, L.Interactive, core: true, noDryRun: "rereads the file from disk; unsaved edits are named in the result"),
        ["add_search_directory"] = Row(O.Edit, L.Instant, core: true, noDryRun: "only adds a directory for reference resolution"),
        ["list_assemblies"] = Row(O.List, L.Instant, lean: true, core: true, sort: "load order"),
        ["server_status"] = Row(O.Report, L.Interactive, lean: true, core: true),
        ["read_result"] = Row(O.Bytes, L.Instant, lean: true, core: true, noDryRun: "writes only with outputPath; overwrite=false refuses an existing file"),
        ["save_session"] = Row(O.Edit, L.Instant, core: true, noDryRun: "writes only to the path it is given; overwrite=false refuses an existing file"),
        ["load_session"] = Row(O.Edit, L.Long, core: true, dryRun: true),
    };
}
