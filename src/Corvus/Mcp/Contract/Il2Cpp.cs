using L = Corvus.Mcp.LatencyClass;
using O = Corvus.Mcp.OutputClass;

namespace Corvus.Mcp;

// Contract rows of the il2cpp family (Core/Toolsets.cs); the tables and their rules are in ToolEffects.cs, ParameterDomains.cs and ToolContract.cs.

public static partial class ToolEffects
{
    private static Dictionary<string, Effects> Il2CppTools() => new(StringComparer.Ordinal)
    {
        // Il2Cpp
        ["get_il2cpp_info"] = Reads(),
        ["find_method_by_address"] = Reads(),
        ["export_il2cpp_symbols"] = Changes(destructive: true, idempotent: true, longRunning: true), // overwrite=true replaces the files it writes
        ["generate_cpp_binding"] = Reads(),
        ["apply_il2cpp_names"] = Changes(destructive: true, idempotent: true, longRunning: true), // replaces the image's il2cpp names
    };
}

public static partial class ParameterDomains
{
    private static Dictionary<string, IReadOnlyDictionary<string, Domain>> Il2CppTools() => new(StringComparer.Ordinal)
    {
        ["find_method_by_address"] = new Dictionary<string, Domain> { ["kind"] = Of(["auto", "rva", "va", "offset"], "any", "fileoffset") },
        ["generate_cpp_binding"] = new Dictionary<string, Domain> { ["style"] = Of(["mono", "il2cpp", "hostapi"]) },
    };
}

public sealed partial record ToolContract
{
    private static Dictionary<string, ToolContract> Il2CppTools() => new(StringComparer.Ordinal)
    {
        ["get_il2cpp_info"] = Row(O.Report, L.Instant, lean: true, core: true),
        ["find_method_by_address"] = Row(O.List, L.Instant, core: true, sort: "image, address"),
        ["export_il2cpp_symbols"] = Row(O.Edit, L.Long, core: true, noDryRun: "N14: overwrite=false refuses existing files"),
        ["generate_cpp_binding"] = Row(O.Code, L.Interactive, core: true),
        ["apply_il2cpp_names"] = Row(O.Edit, L.Long, core: true, noDryRun: "N14: clear=true removes the names it applied"),
    };
}
