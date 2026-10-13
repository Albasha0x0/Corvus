namespace Corvus.Mcp;

public static partial class Guide
{
    private const string EditsTopic = """
        Editing and saving (in memory until saved; edit tools preview by default, dryRun=false applies).
        .NET: rename_symbol, rename_namespace, stub_method (always return X), patch_method_csharp (C# body; lambdas, async, LINQ),
        add_members_csharp, add_types_csharp, patch_method_il (prepend hooks, IL that C# cannot express).
        patch_method_il lines: '[label:] opcode [operand]'; operands are numbers, "strings", labels, switch (L1, L2), arg / local
        index or name, members ('Ns.Type::Method(int)') or tokens; '.local <type>' adds a local; get_il's header lines are ignored
        and its /* token */ comments resolve operands exactly.
        simplify_methods cleans transformed code. fold: calls that compute a string from constant inputs (string decoders; char,
        array, StringBuilder, Encoding and Base64 helpers) run in a safe IL interpreter and become the literal; calls outside the
        safe subset (I/O, reflection, exceptions, instance objects, native code, mutable statics) are kept and reported. cfg: constant
        branches and switches fold (constant propagation through locals, readonly statics and calls with constant arguments), dead
        stores, empty try/finally, dead handlers and unreachable code go, and flattened control flow becomes sequential code; a
        dispatcher whose state differs between runs is kept (flattened-shape). inline: forwarders and static delegate fields (call
        proxies) call their real target when the field's initializer always sets the same one (else delegate-target). Every body is
        stack-verified or left unchanged, with a reason code (docs/simplify.md). decompile_member simplified=true previews it.
        Review: list_edits, diff_edits; undo_edit (by the number of an editId <assembly>#<n>), revert_edits. Carry edits: export_edits writes a script, apply_edits replays it
        (tied to its build: another build needs targetBuild=other). Unsaved edits and patches are journaled; a
        file whose last session ended without saving gets a [workspace] notice naming the journal to replay.
        save_assembly writes a new file (never overwrites the original without overwrite=true; keeps a .bak; untouched parts are
        written byte-for-byte, anything that cannot be is listed; strict=true refuses such a save).
        Native: rename_native and comment_native (kept per file hash), patch_bytes / patch_asm (relocation-correct under ASLR; a
        patch larger than its site: extend=true moves it into a code cave or a new section; unsafe sites are refused with a reason),
        They preview until dryRun=false; each applied edit gets an editId: list_native_edits lists them, undo_native_edit editId=... takes back a patch,
        name, comment or engine edit and pushes it to the engines; save_native writes a new file (checksum recomputed, an invalidated signature reported).
        export_native_annotations writes IDA / Ghidra scripts; export_native_patches writes IDAPython, IDA .dif, IPS or JSON.
        Engine edits (IDA or Ghidra): set_native_type (prototypes), set_native_local (decompiler locals), get_native_frame and
        set_native_stack_var (stack frames), declare_native_types and list_native_types (C declarations kept per image),
        define_native (code, functions, data items, undefined bytes; list_functions view=candidates finds code outside functions),
        reanalyze_native (the engine's auto-analysis again, with per-run analyzer options), set_native_operand (operand display: number base,
        offset, stack variable, enum member, struct offset). These engine edits are kept with the image's annotations: replayed into new
        engine databases, exported and carried to new builds;
        ida_python runs IDAPython in the image's IDA worker, off unless --ida-scripting; ghidra_script runs a Java GhidraScript in the
        Ghidra worker (one transaction, rolled back on failure, saved after), off unless --ghidra-scripting; export_engine_database
        writes the IDA database as an .i64, or the Ghidra program as a .gzf, for the engine's GUI.
        Notes: record_note anchors a finding, question, hypothesis or todo to '<image>@<address>', '<assembly>:<symbol>', a file or
        a dump; notes persist per user by file SHA-256 / module MVID. update_note changes one in part (expectedRevision; a conflict
        returns the current note); list_notes filters by status, kind, anchor, tag and text. decompile_member and decompile_native
        start with a "// notes: N open" line when the target has open notes.
        Sessions: save_session writes the loaded files (path, SHA-256), edits, patches, names, comments and notes to one JSON file;
        load_session restores it (dryRun first), finding moved files by SHA-256 under searchRoots; targetBuild=other carries the
        work to the build now at the recorded path.
        """;
}
