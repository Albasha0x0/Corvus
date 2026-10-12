namespace Corvus.Mcp;

// Contract rows of the edit family (Core/Toolsets.cs); the tables and their rules are in ToolEffects.cs and ParameterDomains.cs.

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
