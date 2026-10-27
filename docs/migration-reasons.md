# Migration reason codes

<!-- Generated from Native/Diff/MigrationReasons.cs by MigrationReasonTests; run the tests with CORVUS_UPDATE_DOCS=1 to update. -->

migrate_native_names, migrate_native_patches, update_to_new_build and map_address_between_builds report every
item with one of these codes: how it was carried, or why not. The same case gets the same code from every tool.

| Code | Group | Meaning |
|---|---|---|
| `function_start` | mapping | the function's start, through its match |
| `aligned_instruction` | mapping | the instruction aligned to it in the matched function |
| `replaced_instruction` | mapping | the instruction that took its place (other operands) |
| `same_string` | mapping | the same string in the new build |
| `followed_references` | mapping | data reached through the references of matched instructions |
| `same_build` | mapping | a patch set replayed on the build it was made for |
| `library_function` | mapping | a static library's function whose fixed bytes are at the function start |
| `function_not_matched` | not mapped | the function has no counterpart in the other build |
| `ambiguous` | not mapped | more than one candidate counterpart |
| `instruction_removed` | not mapped | the instruction is gone from the matched function |
| `changed_region` | not mapped | the code around it changed too much to align |
| `conflicting_references` | not mapped | references to the data lead to different new addresses |
| `no_reference_to_follow` | not mapped | no matched instruction references the data |
| `not_an_instruction` | not mapped | the address is inside an instruction, not at its start |
| `call_target_differs` | not mapped | a call in the library function reaches a function of another name |
| `below_min_tier` | filter | matched in a weaker tier than minTier |
| `below_min_score` | filter | mapping confidence below minScore |
| `same_name` | names | the new build already has this name |
| `user_name_exists` | names | the user named the new address otherwise; never replaced |
| `name_in_use` | names | the name is a user name at another address of the new build |
| `new_has_own_name` | names | a layer of the new build of the same or higher rank names it |
| `duplicate_target` | names | another item already lands on this address |
| `invalid_name` | names | the name is not a valid identifier |
| `same_comment` | comments | the new build already has this comment |
| `user_comment_exists` | comments | the new build has another comment there; never replaced |
| `copied` | types | declarations have no address; copied as they are |
| `not_a_function_start` | types | a function type or local whose address maps inside a function |
| `same_declarations` | types | the new build already has these declarations |
| `same_type` | types | the new build already has this type |
| `user_type_exists` | types | the new build has another user type there |
| `same_type_edit` | types | the new build already has this type edit |
| `user_type_edit_exists` | types | the new build has another edit of this type |
| `same_enum_member` | types | the new build already has this enum member |
| `user_enum_member_exists` | types | the new build has another value for this enum member |
| `same_field` | types | the new build already has this field |
| `user_field_exists` | types | the new build has another field there |
| `same_analysis` | types | the new build already has this analysis edit |
| `user_analysis_exists` | types | the new build has another analysis edit there |
| `same_operand` | types | the new build already shows this operand so |
| `user_operand_exists` | types | the new build shows this operand otherwise |
| `same_local` | types | the new build already has this local |
| `user_local_exists` | types | the new build has another edit of this local |
| `same_stack_var` | types | the new build already has this stack variable |
| `user_stack_var_exists` | types | the new build has another edit of this stack variable |
| `mapped` | patches | the patch's site mapped and its original bytes match |
| `same_patch` | patches | the new build already has this patch at the mapped site |
| `already_present` | patches | the replacement bytes are already at the mapped site |
| `original_bytes_differ` | patches | the new build has other bytes where the patch expects its original ones |
| `displaced_bytes_differ` | patches | a stub's displaced instructions differ in the new build |
| `assemble_failed` | patches | the patch_asm text does not assemble at the new address |
| `relocation_slot_unavailable` | patches | a relocation entry the patch needs is used by another patch |
| `mid_instruction` | patches | the mapped site starts inside an instruction |
| `past_function_end` | patches | the patch would run past the function's end |
| `conflicts_with_existing_patch` | patches | an existing patch of the new build covers the site |
| `not_mapped` | patches | only part of the patched bytes map to the new build |
| `extended_patch` | patches | a patch-site extension; re-apply it with extend=true |
| `stub_code_unknown` | patches | the patch set does not record the stub's code |
| `cannot_prepare` | patches | the patch path refused the patch (detail says why) |
| `still_unique` | patterns | the old pattern finds the same place in the new build |
| `now_ambiguous` | patterns | the old pattern has several hits in the new build |
| `not_found` | patterns | the old pattern has no hit in the new build |
| `points_elsewhere` | patterns | the old pattern's one hit is not the mapped address |
| `not_unique_in_old` | patterns | no unique pattern on the old build |
| `no_pattern` | patterns | no pattern could be made at the address |
| `agree` | method_mapping | metadata identity and the function match give the same new address |
| `disagree` | method_mapping | metadata identity and the function match differ (metadata wins) |
| `metadata_only` | method_mapping | mapped by metadata; the function match found no counterpart |
| `removed` | method_mapping | no method of this identity has code in the new build |
| `pdb_loaded` | layers | the new build already has its matching PDB |
| `matching_pdb_found` | layers | the new build's own matching PDB is found (dry run) |
| `matching_pdb_loaded` | layers | the new build's own matching PDB is loaded |
| `pdb_unreadable` | layers | the matching PDB could not be read |
| `pdb_mismatch` | layers | PDB names belong to their build only; no PDB matches the new build |
| `applied_from_metadata` | layers | the new build has metadata names from its own metadata |
| `reapply_from_metadata` | layers | metadata names would be applied from the new build's metadata (dry run) |
| `reapplied_from_metadata` | layers | metadata names applied from the new build's metadata |
| `new_has_own_metadata_names` | layers | the new build has its own metadata names; kept |
| `not_saved` | layers | names applied but not saved for the next load |
| `file` | notes | a note on the whole file |
| `same_note` | notes | the new build already has this note |
| `counterpart` | notes | a .NET member's counterpart (find_counterpart) |
| `no_counterpart` | notes | the .NET member has no counterpart |
| `not_in_old_build` | notes | the note's token names no member of the old build |
