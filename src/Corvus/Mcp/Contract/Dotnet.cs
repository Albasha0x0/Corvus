using L = Corvus.Mcp.LatencyClass;
using O = Corvus.Mcp.OutputClass;

namespace Corvus.Mcp;

// Contract rows of the dotnet family (Core/Toolsets.cs); the tables and their rules are in ToolEffects.cs, ParameterDomains.cs and ToolContract.cs.

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

public sealed partial record ToolContract
{
    private static Dictionary<string, ToolContract> DotnetTools() => new(StringComparer.Ordinal)
    {
        ["list_namespaces"] = Row(O.List, L.Instant, core: true, sort: "assembly, namespace"),
        ["list_types"] = Row(O.List, L.Instant, lean: true, core: true, sort: "assembly, metadata order"),
        ["get_type_info"] = Row(O.Report, L.Instant, lean: true, core: true),
        ["get_assembly_info"] = Row(O.Report, L.Instant, core: true),
        ["get_attributes"] = Row(O.List, L.Instant, core: true, sort: "metadata order"),
        ["get_type_hierarchy"] = Row(O.List, L.Instant, core: true, sort: "bases nearest first, interfaces by name, derived types in metadata order"),
        ["resolve_symbol"] = Row(O.List, L.Instant, core: true, sort: "assembly, metadata order"),
        ["decompile_type"] = Row(O.Code, L.Interactive),
        ["decompile_member"] = Row(O.Code, L.Interactive, lean: true, core: true),
        ["decompile_assembly_attributes"] = Row(O.Code, L.Interactive),
        ["get_il"] = Row(O.Code, L.Interactive, lean: true, core: true),
        ["search_symbols"] = Row(O.List, L.Interactive, lean: true, core: true, sort: "match rank, label length"),
        ["search_strings"] = Row(O.List, L.Interactive, lean: true, core: true, sort: "metadata order, IL offset"),
        ["search_constants"] = Row(O.List, L.Interactive, core: true, sort: "metadata order"),
        ["search_il"] = Row(O.List, L.Interactive, core: true, sort: "metadata order, IL offset"),
        ["find_references"] = Row(O.List, L.Interactive, lean: true, core: true, sort: "metadata order"),
        ["find_callees"] = Row(O.List, L.Instant, lean: true, core: true, sort: "IL offset"),
        ["find_overrides"] = Row(O.List, L.Instant, sort: "subtypes breadth first, metadata order"),
        ["get_call_tree"] = Row(O.List, L.Instant, lean: true, core: true, sort: "member name at each level"),
        ["find_call_paths"] = Row(O.List, L.Interactive, core: true, sort: "path length, virtual hops"),
        ["list_resources"] = Row(O.List, L.Instant, core: true, sort: "manifest resource order"),
        ["get_resource"] = Row(O.Bytes, L.Instant, core: true, noDryRun: "N14: writes only with savePath; overwrite=false refuses an existing file"),
        ["export_project"] = Row(O.Edit, L.Long, core: true, noDryRun: "writes only into an empty directory"),
        ["get_r2r_code"] = Row(O.Code, L.Interactive, core: true),
        ["find_r2r_method"] = Row(O.Report, L.Instant, core: true),
    };
}
