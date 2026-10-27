# Guide: edits

<!-- Generated from src/Corvus/Mcp/Guide.cs; run the tests with CORVUS_UPDATE_DOCS=1 to update. -->

Editing and saving: edits stay in memory until saved; edit tools preview by default and dryRun=false applies.
- .NET: rename_symbol, rename_namespace, stub_method, patch_method_csharp, add_members_csharp, add_types_csharp, patch_method_il.
- patch_method_il lines: '[label:] opcode [operand]'; operands are numbers, "strings", labels, arg / local names, members or tokens.
- patch_method_il: '.local <type>' adds a local; get_il output pastes back as is.
- simplify_methods cleans transformed code: fold runs string decoder calls in a safe IL interpreter and replaces them with the literal (I/O, reflection and native calls are kept and reported), cfg removes constant branches and flattening, inline calls proxies' targets.
- simplify_methods changes a body only when it stack-verifies, else names a reason code (docs/simplify.md); decompile_member simplified=true previews it.
- Review: list_edits, diff_edits, undo_edit (editId <assembly>#<n>), revert_edits.
- export_edits writes an edit script; apply_edits replays it (another build needs targetBuild=other).
- Unsaved edits are journaled; a [workspace] notice names the journal of a session that ended without saving.
- save_assembly writes a new file; replaceOriginal=true needs --allow-replace-original and keeps a .bak.
- save_assembly strict=true refuses a save that cannot keep untouched parts byte-for-byte.
- Native: rename_native, comment_native (kept per file hash), patch_bytes, patch_asm.
- Patches are relocation-correct; extend=true moves a large patch into a code cave; unsafe sites are refused with a reason.
- Each applied native edit gets an editId: list_native_edits lists them, undo_native_edit takes one back.
- save_native writes a new file with a recomputed checksum and reports an invalidated signature.
- export_native_annotations writes IDA / Ghidra scripts; export_native_patches writes IDAPython, IDA .dif, IPS or JSON.
- Engine edits (IDA or Ghidra): set_native_type, set_native_local, get_native_frame, set_native_stack_var, declare_native_types, list_native_types, define_native, reanalyze_native, set_native_operand.
- Engine edits are kept with the image's annotations: replayed into new databases, exported and carried to new builds.
- list_functions view=candidates finds code outside functions for define_native.
- ida_python runs IDAPython (off unless --ida-scripting); ghidra_script runs a Java GhidraScript in one transaction (off unless --ghidra-scripting).
- export_engine_database writes the IDA .i64 or Ghidra .gzf for the engine's GUI.
- record_note anchors a finding to '<image>@<address>', '<assembly>:<symbol>', a file or a dump; notes persist per user by file SHA-256 or module MVID.
- update_note changes a note in part (expectedRevision; a conflict returns the current note); list_notes filters by status, kind, anchor, tag and text.
- decompile_member and decompile_native start with "// notes: N open" when the target has open notes.
- save_session writes loaded files, edits, patches, names and notes to one JSON file.
- load_session restores it (dryRun first); searchRoots finds moved files; targetBuild=other carries the work to a new build.
