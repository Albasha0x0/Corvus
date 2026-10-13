using System.Text;
using Corvus.Core;

namespace Corvus.Native.Diff;

/// <summary>
/// The reason codes of the build tools (migrate_native_names, migrate_native_patches, update_to_new_build,
/// map_address_between_builds): one vocabulary, so the same case gets the same code from every tool. Published as
/// docs/migration-reasons.md.
/// </summary>
public static class MigrationReasons
{
    /// <summary>A reason code, the group it belongs to and what it means.</summary>
    public sealed record Reason(string Code, string Group, string Meaning);

    public const string Mapped = "mapped", SamePatch = "same_patch", SameNote = "same_note", Counterpart = "counterpart";

    public static readonly IReadOnlyList<Reason> All =
    [
        new("function_start", "mapping", "the function's start, through its match"),
        new("aligned_instruction", "mapping", "the instruction aligned to it in the matched function"),
        new("replaced_instruction", "mapping", "the instruction that took its place (other operands)"),
        new("same_string", "mapping", "the same string in the new build"),
        new("followed_references", "mapping", "data reached through the references of matched instructions"),
        new("same_build", "mapping", "a patch set replayed on the build it was made for"),
        new("function_not_matched", "not mapped", "the function has no counterpart in the other build"),
        new("ambiguous", "not mapped", "more than one candidate counterpart"),
        new("instruction_removed", "not mapped", "the instruction is gone from the matched function"),
        new("changed_region", "not mapped", "the code around it changed too much to align"),
        new("conflicting_references", "not mapped", "references to the data lead to different new addresses"),
        new("no_reference_to_follow", "not mapped", "no matched instruction references the data"),
        new("not_an_instruction", "not mapped", "the address is inside an instruction, not at its start"),
        new("below_min_tier", "filter", "matched in a weaker tier than minTier"),
        new("below_min_score", "filter", "mapping confidence below minScore"),
        new("same_name", "names", "the new build already has this name"),
        new("user_name_exists", "names", "the user named the new address otherwise; never replaced"),
        new("name_in_use", "names", "the name is a user name at another address of the new build"),
        new("new_has_own_name", "names", "a layer of the new build of the same or higher rank names it"),
        new("duplicate_target", "names", "another item already lands on this address"),
        new("invalid_name", "names", "the name is not a valid identifier"),
        new("same_comment", "comments", "the new build already has this comment"),
        new("user_comment_exists", "comments", "the new build has another comment there; never replaced"),
        new("copied", "types", "declarations have no address; copied as they are"),
        new("not_a_function_start", "types", "a function type or local whose address maps inside a function"),
        new("same_declarations", "types", "the new build already has these declarations"),
        new("same_type", "types", "the new build already has this type"),
        new("user_type_exists", "types", "the new build has another user type there"),
        new("same_type_edit", "types", "the new build already has this type edit"),
        new("user_type_edit_exists", "types", "the new build has another edit of this type"),
        new("same_enum_member", "types", "the new build already has this enum member"),
        new("user_enum_member_exists", "types", "the new build has another value for this enum member"),
        new("same_field", "types", "the new build already has this field"),
        new("user_field_exists", "types", "the new build has another field there"),
        new("same_analysis", "types", "the new build already has this analysis edit"),
        new("user_analysis_exists", "types", "the new build has another analysis edit there"),
        new("same_operand", "types", "the new build already shows this operand so"),
        new("user_operand_exists", "types", "the new build shows this operand otherwise"),
        new("same_local", "types", "the new build already has this local"),
        new("user_local_exists", "types", "the new build has another edit of this local"),
        new("same_stack_var", "types", "the new build already has this stack variable"),
        new("user_stack_var_exists", "types", "the new build has another edit of this stack variable"),
        new(Mapped, "patches", "the patch's site mapped and its original bytes match"),
        new(SamePatch, "patches", "the new build already has this patch at the mapped site"),
        new("already_present", "patches", "the replacement bytes are already at the mapped site"),
        new("original_bytes_differ", "patches", "the new build has other bytes where the patch expects its original ones"),
        new("displaced_bytes_differ", "patches", "a stub's displaced instructions differ in the new build"),
        new("assemble_failed", "patches", "the patch_asm text does not assemble at the new address"),
        new("relocation_slot_unavailable", "patches", "a relocation entry the patch needs is used by another patch"),
        new("mid_instruction", "patches", "the mapped site starts inside an instruction"),
        new("past_function_end", "patches", "the patch would run past the function's end"),
        new("conflicts_with_existing_patch", "patches", "an existing patch of the new build covers the site"),
        new("not_mapped", "patches", "only part of the patched bytes map to the new build"),
        new("extended_patch", "patches", "a patch-site extension; re-apply it with extend=true"),
        new("stub_code_unknown", "patches", "the patch set does not record the stub's code"),
        new("cannot_prepare", "patches", "the patch path refused the patch (detail says why)"),
        new("still_unique", "patterns", "the old pattern finds the same place in the new build"),
        new("now_ambiguous", "patterns", "the old pattern has several hits in the new build"),
        new("not_found", "patterns", "the old pattern has no hit in the new build"),
        new("points_elsewhere", "patterns", "the old pattern's one hit is not the mapped address"),
        new("not_unique_in_old", "patterns", "no unique pattern on the old build"),
        new("no_pattern", "patterns", "no pattern could be made at the address"),
        new("agree", "il2cpp", "metadata identity and the function match give the same new address"),
        new("disagree", "il2cpp", "metadata identity and the function match differ (metadata wins)"),
        new("metadata_only", "il2cpp", "mapped by metadata; the function match found no counterpart"),
        new("removed", "il2cpp", "no method of this identity has code in the new build"),
        new("pdb_loaded", "layers", "the new build already has its matching PDB"),
        new("matching_pdb_found", "layers", "the new build's own matching PDB is found (dry run)"),
        new("matching_pdb_loaded", "layers", "the new build's own matching PDB is loaded"),
        new("pdb_unreadable", "layers", "the matching PDB could not be read"),
        new("pdb_mismatch", "layers", "PDB names belong to their build only; no PDB matches the new build"),
        new("applied_from_metadata", "layers", "the new build has Il2Cpp names from its own metadata"),
        new("reapply_from_metadata", "layers", "Il2Cpp names would be applied from the new build's metadata (dry run)"),
        new("reapplied_from_metadata", "layers", "Il2Cpp names applied from the new build's metadata"),
        new("new_has_own_il2cpp_names", "layers", "the new build has its own Il2Cpp names; kept"),
        new("not_saved", "layers", "names applied but not saved for the next load"),
        new("file", "notes", "a note on the whole file"),
        new(SameNote, "notes", "the new build already has this note"),
        new(Counterpart, "notes", "a .NET member's counterpart (find_counterpart)"),
        new("no_counterpart", "notes", "the .NET member has no counterpart"),
        new("not_in_old_build", "notes", "the note's token names no member of the old build"),
    ];

    private static readonly HashSet<string> Codes = All.Select(r => r.Code).ToHashSet(StringComparer.Ordinal);

    public static bool IsKnown(string code) => Codes.Contains(code);

    /// <summary>The code of a patch the patch path refused while it was applied: the code the message starts with, else from the message.</summary>
    public static string PatchRefusal(ToolError error)
    {
        var m = System.Text.RegularExpressions.Regex.Match(error.Message, "^([a-z0-9_]+): ");
        if (m.Success && IsKnown(m.Groups[1].Value)) return m.Groups[1].Value;
        return error.Message.Contains("relocation slot", StringComparison.OrdinalIgnoreCase) ? "relocation_slot_unavailable"
            : error.Message.Contains("middle of an instruction", StringComparison.OrdinalIgnoreCase) ? "mid_instruction"
            : error.Message.Contains("past the end", StringComparison.OrdinalIgnoreCase) ? "past_function_end"
            : error.Code == ErrorCode.Conflict ? "conflicts_with_existing_patch"
            : "cannot_prepare";
    }

    /// <summary>docs/migration-reasons.md.</summary>
    public static string Markdown()
    {
        var sb = new StringBuilder("""
            # Migration reason codes

            <!-- Generated from Native/Diff/MigrationReasons.cs by MigrationReasonTests; run the tests with CORVUS_UPDATE_DOCS=1 to update. -->

            migrate_native_names, migrate_native_patches, update_to_new_build and map_address_between_builds report every
            item with one of these codes: how it was carried, or why not. The same case gets the same code from every tool.

            | Code | Group | Meaning |
            |---|---|---|

            """);
        foreach (var r in All) sb.Append($"| `{r.Code}` | {r.Group} | {r.Meaning} |\n");
        return sb.ToString().ReplaceLineEndings("\n");
    }
}
