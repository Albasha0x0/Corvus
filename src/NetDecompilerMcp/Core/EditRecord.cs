namespace NetDecompilerMcp.Core;

/// <summary>
/// One applied edit, recorded with the exact inputs needed to apply it again. Records drive undo (rebuild from the
/// original image and replay the others), edit scripts (re-apply a patch set to a new build of the assembly) and diffs.
/// </summary>
/// <param name="Kind">The edit tool: rename_symbol, rename_namespace, stub_method, patch_method_il, patch_method_csharp, add_members_csharp, add_types_csharp.</param>
/// <param name="Args">Tool arguments. Symbols are stored as stable labels (Ns.Type::Method(int)), with the metadata token alongside.</param>
/// <param name="Description">Human-readable summary.</param>
/// <param name="Touched">Labels of the members this edit changed or added (for diffs).</param>
public sealed record EditRecord(string Kind, IReadOnlyDictionary<string, string?> Args, string Description, IReadOnlyList<string> Touched)
{
    public string? Arg(string name) => Args.TryGetValue(name, out var v) ? v : null;
}
