using L = Corvus.Mcp.LatencyClass;
using O = Corvus.Mcp.OutputClass;

namespace Corvus.Mcp;

// Contract rows of the web family (Core/Toolsets.cs); the tables and their rules are in ToolEffects.cs, ParameterDomains.cs and ToolContract.cs.

public static partial class ToolEffects
{
    private static Dictionary<string, Effects> WebTools() => new(StringComparer.Ordinal)
    {
        ["analyze_js"] = Reads(),
    };
}

public static partial class ParameterDomains
{
    private static Dictionary<string, IReadOnlyDictionary<string, Domain>> WebTools() => new(StringComparer.Ordinal)
    {
        ["analyze_js"] = new Dictionary<string, Domain>
        {
            ["view"] = Of(["summary", "modules", "module", "search", "refs", "position", "sources", "source", "endpoints", "secrets", "diff", "runtime", "flow", "origins",
                "functions", "decompile", "disassemble", "xrefs"]),
        },
    };
}

public sealed partial record ToolContract
{
    private static Dictionary<string, ToolContract> WebTools() => new(StringComparer.Ordinal)
    {
        ["analyze_js"] = Row(O.Report, L.Interactive),
    };
}
