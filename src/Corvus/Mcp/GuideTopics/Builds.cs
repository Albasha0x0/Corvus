namespace Corvus.Mcp;

public static partial class Guide
{
    private const string BuildsTopic = """
        New builds: load both (the second gets an id like app.dll#2).
        .NET: compare_assemblies, then find_counterpart carries renamed types/members and changed offsets forward; export_edits +
        apply_edits re-applies a patch set to the new build; update_to_new_build with two assembly ids carries notes on members through the same match.
        Native: update_to_new_build (dryRun=true first) carries names, comments, PDB / Il2Cpp layers, patches, code patterns, notes and
        the Il2Cpp method mapping in one call, with a reason code for everything that did not carry (docs/migration-reasons.md).
        Its categories: names, comments and engine types follow migrate_native_names (never replacing the new build's own);
        pdb loads the new build's own matching PDB (PDB names belong to one build); il2cpp re-applies names from the new
        build's metadata, else maps the old layer through the match; patches follow migrate_native_patches, stubs re-created
        after verification; patterns check each carried name and patch site for drift; notes move to the mapped address.
        dryRun=false applies names, layers, then patches; every applied name, type and patch is an undoable edit (editIds).
        The single steps:
        compare_native_images, diff_function (what changed in one function: aligned instructions, or pseudocode with view=pseudocode),
        map_address_between_builds, migrate_native_names, migrate_native_patches, make_code_pattern
        (anchor=xrefs: a signature at every referencing instruction) / search_code_pattern.
        Whole folders or packages first: compare_folders (changed, added, removed and moved files, versions and MVIDs, a next call per file).
        """;
}
