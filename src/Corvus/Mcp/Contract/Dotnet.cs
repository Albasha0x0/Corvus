namespace Corvus.Mcp;

// Contract rows of the dotnet family (Core/Toolsets.cs); the tables and their rules are in ToolEffects.cs and ParameterDomains.cs.

public static partial class ToolEffects
{
    private static Dictionary<string, Effects> DotnetTools() => new(StringComparer.Ordinal)
    {
        // .NET browse, decompile, search, navigate
        ["list_namespaces"] = Reads(),
        ["list_types"] = Reads(),
        ["get_type_info"] = Reads(),
        ["get_assembly_info"] = Reads(),
        ["get_attributes"] = Reads(),
        ["get_type_hierarchy"] = Reads(),
        ["resolve_symbol"] = Reads(),
        ["decompile_type"] = Reads(),
        ["decompile_member"] = Reads(),
        ["decompile_assembly_attributes"] = Reads(),
        ["get_il"] = Reads(),
        ["search_symbols"] = Reads(),
        ["search_strings"] = Reads(),
        ["search_constants"] = Reads(),
        ["search_il"] = Reads(),
        ["find_references"] = Reads(),
        ["find_callees"] = Reads(),
        ["find_overrides"] = Reads(),
        ["get_call_tree"] = Reads(),
        ["find_call_paths"] = Reads(),
        ["list_resources"] = Reads(),
        ["get_resource"] = Changes(destructive: true, idempotent: true), // savePath; overwrite=true replaces a file
        ["export_project"] = Changes(destructive: false, idempotent: true, longRunning: true), // refuses a non-empty directory
        ["get_r2r_code"] = Reads(),
        ["find_r2r_method"] = Reads(),
    };
}

public static partial class ParameterDomains
{
    private static Dictionary<string, IReadOnlyDictionary<string, Domain>> DotnetTools() => new(StringComparer.Ordinal)
    {
        ["resolve_symbol"] = new Dictionary<string, Domain> { ["kind"] = AnyKind },
        ["search_symbols"] = new Dictionary<string, Domain> { ["kind"] = AnyKind },
        ["find_references"] = new Dictionary<string, Domain> { ["kind"] = ResolveKind },
        ["decompile_member"] = new Dictionary<string, Domain> { ["kind"] = Of(["any", "method", "field", "property", "event"], [.. KindAliases, "type", "member"]) },
        ["list_types"] = new Dictionary<string, Domain> { ["kind"] = Of(["class", "struct", "interface", "enum", "delegate"], "static class") },
        ["get_call_tree"] = new Dictionary<string, Domain> { ["direction"] = Of(Direction.Values, "caller", "callee", "up", "down", "in", "out") },
    };
}
