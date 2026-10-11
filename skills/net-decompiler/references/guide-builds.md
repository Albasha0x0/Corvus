# Guide: builds

<!-- Generated from src/Corvus/Mcp/Guide.cs; run the tests with NDM_UPDATE_DOCS=1 to update. -->

New builds: load both (the second gets an id like app.dll#2).
.NET: compare_assemblies, then find_counterpart carries renamed types/members and changed offsets forward; export_edits +
apply_edits re-applies a patch set to the new build.
Native: update_to_new_build (dryRun=true first) carries names, comments, PDB / Il2Cpp layers, patches, code patterns, notes and
the Il2Cpp method mapping in one call, with a reason code for everything that did not carry. The single steps:
compare_native_images, diff_function (what changed in one function: aligned instructions, or pseudocode with view=pseudocode),
map_address_between_builds, migrate_native_names, migrate_native_patches, make_code_pattern
(anchor=xrefs: a signature at every referencing instruction) / search_code_pattern.
