using L = Corvus.Mcp.LatencyClass;
using O = Corvus.Mcp.OutputClass;

namespace Corvus.Mcp;

// Contract rows of the containers family (Core/Toolsets.cs); the tables and their rules are in ToolEffects.cs, ParameterDomains.cs and ToolContract.cs.

public static partial class ToolEffects
{
    private static Dictionary<string, Effects> ContainersTools() => new(StringComparer.Ordinal)
    {
        // Files and containers (nothing executed)
        // A signature's revocation is checked online.
        ["summarize_file"] = Reads(openWorld: true),
        // category=capa runs capa (CORVUS_CAPA).
        ["survey_features"] = Reads(openWorld: true),
        // With read_result, outputPath exports the kept values.
        ["extract_strings"] = Reads(),
        // Writes unique names, never over a different file.
        ["extract_embedded"] = Changes(destructive: false, idempotent: true),
        ["search_container"] = Reads(),
        // Extracts into an empty directory (or its own earlier unpack) and loads.
        ["unpack_container"] = Changes(destructive: false, idempotent: true, longRunning: true),
        // Headers and listings only; detectItEasy=true launches diec.
        ["summarize_build"] = Reads(openWorld: true),
    };
}

public static partial class ParameterDomains
{
    private static Dictionary<string, IReadOnlyDictionary<string, Domain>> ContainersTools() => new(StringComparer.Ordinal)
    {
        ["search_container"] = new Dictionary<string, Domain> { ["kind"] = Of([.. Services.Analysis.UnpackService.SearchKinds], "any") },
        ["extract_strings"] = new Dictionary<string, Domain> { ["types"] = Of([.. Services.Analysis.Values.Types]) },
        ["summarize_file"] = new Dictionary<string, Domain>
        {
            ["view"] = Of(["overview", "managed", "dependencies", "indicators", .. Core.Providers.Of<Services.Analysis.IFileSummaryView>().Select(v => v.Name).Order(StringComparer.Ordinal), "all"]),
        },
    };
}

public sealed partial record ToolContract
{
    private static Dictionary<string, ToolContract> ContainersTools() => new(StringComparer.Ordinal)
    {
        ["summarize_file"] = Row(O.Report, L.Interactive, lean: true, core: true),
        ["survey_features"] = Row(O.Report, L.Interactive, core: true),
        ["extract_strings"] = Row(O.List, L.Interactive, core: true, sort: "type, count descending, value"),
        ["extract_embedded"] = Row(O.List, L.Interactive, core: true, sort: "assembly, then resources, static data, strings", noDryRun: "writes new names only, never over a different file"),
        ["search_container"] = Row(O.List, L.Interactive, core: true, sort: "exact, prefix, then substring matches; container entry, metadata order"),
        ["unpack_container"] = Row(O.Edit, L.Long, lean: true, core: true, noDryRun: "extracts only into an empty directory or its own earlier unpack"),
        ["summarize_build"] = Row(O.Report, L.Interactive, core: true),
    };
}
