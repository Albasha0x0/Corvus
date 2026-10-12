using L = Corvus.Mcp.LatencyClass;
using O = Corvus.Mcp.OutputClass;

namespace Corvus.Mcp;

// Contract rows of the builds family (Core/Toolsets.cs); the tables and their rules are in ToolEffects.cs, ParameterDomains.cs and ToolContract.cs.

public static partial class ToolEffects
{
    private static Dictionary<string, Effects> BuildsTools() => new(StringComparer.Ordinal)
    {
        // Builds
        ["compare_assemblies"] = Changes(destructive: true, idempotent: true, longRunning: true), // tokenMapPath; overwrite=true replaces a file
        ["compare_folders"] = Reads(longRunning: true),
        ["find_counterpart"] = Reads(longRunning: true),

        // Native builds
        ["compare_native_images"] = Reads(longRunning: true),
        ["map_address_between_builds"] = Reads(longRunning: true),
        ["diff_function"] = Reads(longRunning: true, openWorld: true), // view=pseudocode runs IDA
        ["make_code_pattern"] = Reads(longRunning: true, openWorld: true), // anchor=xrefs with engine=ida runs IDA
        ["search_code_pattern"] = Reads(longRunning: true),
        ["migrate_native_names"] = Changes(destructive: false, idempotent: true, longRunning: true), // never replaces a name; saved to the sidecar
        ["migrate_native_patches"] = Changes(destructive: true, idempotent: false, longRunning: true), // patches the new build; matches through both code indexes
        ["update_to_new_build"] = Changes(destructive: true, idempotent: true, longRunning: true), // dryRun=false patches the new build and replaces its imported layers; a re-run reports already_present
    };
}

public static partial class ParameterDomains
{
    private static Dictionary<string, IReadOnlyDictionary<string, Domain>> BuildsTools() => new(StringComparer.Ordinal)
    {
        ["make_code_pattern"] = new Dictionary<string, Domain> { ["anchor"] = Of(["auto", "address", "reference", "xrefs", "range"]), ["engine"] = Engine, ["format"] = Of(["ida", "x64dbg", "mask", "bitmask"]) },
        ["compare_native_images"] = new Dictionary<string, Domain> { ["view"] = Of(["pairs", "changed", "unmatched", "ambiguous"]) },
        ["compare_folders"] = new Dictionary<string, Domain> { ["change"] = Of(Services.Analysis.FolderCompare.Views) },
        ["diff_function"] = new Dictionary<string, Domain> { ["side"] = Of(["old", "new"]), ["view"] = Of(["asm", "pseudocode"]), ["engine"] = DecompilerEngine },
        ["update_to_new_build"] = new Dictionary<string, Domain>
        {
            ["stubPlacement"] = Placement,
            ["category"] = Of(["names", "pdb", "il2cpp_names", "patches", "patterns", "il2cpp_mapping", "notes", "dotnet"]),
            ["outcome"] = Of(["carried", "would_carry", "already_present", "refused", "not_applicable", "ambiguous"]),
        },
    };
}

public sealed partial record ToolContract
{
    private static Dictionary<string, ToolContract> BuildsTools() => new(StringComparer.Ordinal)
    {
        ["compare_assemblies"] = Row(O.Report, L.Long, noDryRun: "writes only with tokenMapPath; overwrite=false refuses an existing file"),
        ["find_counterpart"] = Row(O.Report, L.Instant),
        ["compare_folders"] = Row(O.Report, L.Interactive),
        ["compare_native_images"] = Row(O.Report, L.Long),
        ["diff_function"] = Row(O.Code, L.Interactive),
        ["map_address_between_builds"] = Row(O.Report, L.Instant),
        ["make_code_pattern"] = Row(O.Report, L.Instant),
        ["search_code_pattern"] = Row(O.List, L.Instant, sort: "image, section, address"),
        ["migrate_native_names"] = Row(O.Edit, L.Long, dryRun: true),
        ["migrate_native_patches"] = Row(O.Edit, L.Long, dryRun: true),
        ["update_to_new_build"] = Row(O.Report, L.Long, dryRun: true),
    };
}
