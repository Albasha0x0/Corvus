using L = Corvus.Mcp.LatencyClass;
using O = Corvus.Mcp.OutputClass;

namespace Corvus.Mcp;

// Contract rows of the live family (Core/Toolsets.cs); the tables and their rules are in ToolEffects.cs, ParameterDomains.cs and ToolContract.cs.

public static partial class ToolEffects
{
    private static Dictionary<string, Effects> LiveTools() => new(StringComparer.Ordinal)
    {
        ["inspect_process"] = Reads(openWorld: true), // query and read handles to a running process only (docs/live-inspection.md); idempotent for the target
    };
}

public static partial class ParameterDomains
{
    private static Dictionary<string, IReadOnlyDictionary<string, Domain>> LiveTools() => new(StringComparer.Ordinal)
    {
        ["inspect_process"] = new Dictionary<string, Domain> { ["regionFilter"] = Of(["committed", "all", "executable", "writable", "image", "private", "mapped"]) },
    };
}

public sealed partial record ToolContract
{
    private static Dictionary<string, ToolContract> LiveTools() => new(StringComparer.Ordinal)
    {
        ["inspect_process"] = Row(O.Report, L.Interactive),
    };
}
