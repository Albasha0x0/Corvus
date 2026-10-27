namespace Corvus.Mcp;

public static partial class Guide
{
    private const string BuildsTopic = """
        New builds: load both; the second gets an id like app.dll#2.
        - .NET: compare_assemblies, then find_counterpart carries renamed members and changed offsets forward.
        - .NET: export_edits + apply_edits re-apply a patch set; update_to_new_build with two assembly ids carries notes.
        - Native: update_to_new_build (dryRun=true first) carries names, comments, PDB and metadata layers, patches, code patterns and notes.
        - Anything not carried gets a reason code (docs/migration-reasons.md); the new build's own names are never replaced.
        - dryRun=false applies names, layers, then patches, each as an undoable edit.
        - Single steps: compare_native_images, diff_function (view=pseudocode compares pseudocode), map_address_between_builds, migrate_native_names, migrate_native_patches.
        - make_code_pattern makes a byte pattern (anchor=xrefs: one at every reference); search_code_pattern finds it in a build.
        - Folders or packages: compare_folders lists changed, added, removed and moved files with a next call per file.
        """;
}
