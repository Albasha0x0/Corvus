namespace Corvus.Mcp;

// Contract rows of the containers family (Core/Toolsets.cs); the tables and their rules are in ToolEffects.cs and ParameterDomains.cs.

public static partial class ToolEffects
{
    private static Dictionary<string, Effects> ContainersTools() => new(StringComparer.Ordinal)
    {
        // Files and containers (nothing executed)
        ["summarize_file"] = Reads(),
        ["survey_features"] = Reads(),
        ["extract_strings"] = Changes(destructive: true, idempotent: true), // savePath; overwrite=true replaces a file
        ["extract_embedded"] = Changes(destructive: false, idempotent: true), // writes unique names, never over a different file
        ["search_container"] = Reads(),
        ["unpack_container"] = Changes(destructive: false, idempotent: true, longRunning: true), // extracts into an empty directory (or its own earlier unpack) and loads
        ["unity_overview"] = Reads(openWorld: true), // headers and listings only; detectItEasy=true launches diec
    };
}

public static partial class ParameterDomains
{
    private static Dictionary<string, IReadOnlyDictionary<string, Domain>> ContainersTools() => new(StringComparer.Ordinal)
    {
        ["search_container"] = new Dictionary<string, Domain> { ["kind"] = Of(["type", "method", "field", "property"], "any") },
        ["extract_strings"] = new Dictionary<string, Domain> { ["format"] = Of(["json", "csv"]) },
    };
}
