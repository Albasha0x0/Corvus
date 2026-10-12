using L = Corvus.Mcp.LatencyClass;
using O = Corvus.Mcp.OutputClass;

namespace Corvus.Mcp;

// Contract rows of the edit family (Core/Toolsets.cs); the tables and their rules are in ToolEffects.cs, ParameterDomains.cs and ToolContract.cs.

public static partial class ToolEffects
{
    private static Dictionary<string, Effects> EditTools() => new(StringComparer.Ordinal)
    {
        // .NET edits (in memory until save_assembly)
        ["rename_symbol"] = Changes(destructive: true, idempotent: false),
        ["rename_namespace"] = Changes(destructive: true, idempotent: false),
        ["stub_method"] = Changes(destructive: true, idempotent: false),
        ["patch_method_csharp"] = Changes(destructive: true, idempotent: false),
        ["patch_method_il"] = Changes(destructive: true, idempotent: false),
        ["add_members_csharp"] = Changes(destructive: false, idempotent: false),
        ["add_types_csharp"] = Changes(destructive: false, idempotent: false),
        ["simplify_methods"] = Changes(destructive: true, idempotent: false, longRunning: true),
        ["list_edits"] = Reads(),
        ["diff_edits"] = Reads(),
        ["undo_edit"] = Changes(destructive: true, idempotent: false),
        ["revert_edits"] = Changes(destructive: true, idempotent: true),
        ["export_edits"] = Changes(destructive: true, idempotent: true), // overwrite=true replaces the file at path
        ["apply_edits"] = Changes(destructive: true, idempotent: false),
        ["save_assembly"] = Changes(destructive: true, idempotent: true), // overwrite=true replaces a file (the original's .bak is made once)
    };
}

public static partial class ParameterDomains
{
    private static Dictionary<string, IReadOnlyDictionary<string, Domain>> EditTools() => new(StringComparer.Ordinal)
    {
        ["rename_symbol"] = new Dictionary<string, Domain> { ["kind"] = ResolveKind },
        ["patch_method_il"] = new Dictionary<string, Domain> { ["mode"] = Of(["replace", "prepend"], "prefix", "insert") },
        ["apply_edits"] = new Dictionary<string, Domain> { ["targetBuild"] = Of(["same", "other"]) },
    };
}

public sealed partial record ToolContract
{
    private static Dictionary<string, ToolContract> EditTools() => new(StringComparer.Ordinal)
    {
        ["rename_symbol"] = Row(O.Edit, L.Interactive, lean: true, core: true, dryRun: true),
        ["rename_namespace"] = Row(O.Edit, L.Instant, core: true, dryRun: true),
        ["stub_method"] = Row(O.Edit, L.Instant, core: true, dryRun: true),
        ["patch_method_csharp"] = Row(O.Edit, L.Long, lean: true, core: true, dryRun: true),
        ["patch_method_il"] = Row(O.Edit, L.Interactive, core: true, dryRun: true),
        ["add_members_csharp"] = Row(O.Edit, L.Long, core: true, dryRun: true),
        ["add_types_csharp"] = Row(O.Edit, L.Long, core: true, dryRun: true),
        ["simplify_methods"] = Row(O.Edit, L.Long, core: true, dryRun: true),
        ["list_edits"] = Row(O.List, L.Instant, lean: true, core: true, sort: "edit order"),
        ["diff_edits"] = Row(O.Code, L.Interactive, core: true),
        ["undo_edit"] = Row(O.Edit, L.Long, lean: true, core: true, noDryRun: "is itself the revert of one recorded edit"),
        ["revert_edits"] = Row(O.Edit, L.Interactive, core: true, noDryRun: "N12: the discarded edits are kept as a result that apply_edits restores"),
        ["export_edits"] = Row(O.Edit, L.Instant, core: true, noDryRun: "writes only to the path it is given; overwrite=false refuses an existing file"),
        ["apply_edits"] = Row(O.Edit, L.Long, core: true, dryRun: true),
        ["save_assembly"] = Row(O.Edit, L.Interactive, lean: true, core: true, noDryRun: "writes only the edited copy; the original's .bak is made once"),
    };
}
