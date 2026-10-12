namespace Corvus.Mcp;

// Contract rows of the session family (Core/Toolsets.cs); the tables and their rules are in ToolEffects.cs and ParameterDomains.cs.

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
