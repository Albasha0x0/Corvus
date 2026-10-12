namespace Corvus.Mcp;

// Contract rows of the il2cpp family (Core/Toolsets.cs); the tables and their rules are in ToolEffects.cs and ParameterDomains.cs.

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
