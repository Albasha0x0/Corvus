using L = Corvus.Mcp.LatencyClass;
using O = Corvus.Mcp.OutputClass;

namespace Corvus.Mcp;

// Contract rows of the aot family (Core/Toolsets.cs); the tables and their rules are in ToolEffects.cs, ParameterDomains.cs and ToolContract.cs.

public static partial class ToolEffects
{
    private static Dictionary<string, Effects> AotTools() => new(StringComparer.Ordinal)
    {
        ["get_method_addresses"] = Reads(),
        ["find_method_by_address"] = Reads(),
        // overwrite=true replaces the files it writes.
        ["export_method_symbols"] = Changes(destructive: true, idempotent: true, longRunning: true),
        ["generate_cpp_binding"] = Reads(),
        // Replaces the image's metadata names.
        ["apply_metadata_names"] = Changes(destructive: true, idempotent: true, longRunning: true),
    };
}

public static partial class ParameterDomains
{
    private static Dictionary<string, IReadOnlyDictionary<string, Domain>> AotTools() => new(StringComparer.Ordinal)
    {
        ["find_method_by_address"] = new Dictionary<string, Domain> { ["kind"] = Of(["auto", "rva", "va", "offset"], "any", "fileoffset") },
        ["generate_cpp_binding"] = new Dictionary<string, Domain> { ["style"] = Of(["mono", "aot", "hostapi"]) },
    };
}

public sealed partial record ToolContract
{
    private static Dictionary<string, ToolContract> AotTools() => new(StringComparer.Ordinal)
    {
        ["get_method_addresses"] = Row(O.Report, L.Instant, lean: true, core: true),
        ["find_method_by_address"] = Row(O.List, L.Instant, core: true, sort: "image, address"),
        ["export_method_symbols"] = Row(O.Edit, L.Long, core: true, noDryRun: "overwrite=false refuses existing files"),
        ["generate_cpp_binding"] = Row(O.Code, L.Interactive, core: true),
        ["apply_metadata_names"] = Row(O.Edit, L.Long, core: true, noDryRun: "clear=true removes the names it applied"),
    };
}
