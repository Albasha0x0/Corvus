using Corvus.Core;
using Corvus.Native;
using Corvus.Native.Annotations;
using Corvus.Native.Providers;
using Corvus.Services;

namespace Corvus.Tests;

public class NativeEditJournalTests
{
    private static byte[] TinyImage()
    {
        var b = new PeBuilder { Is64 = true, Machine = 0x8664, ImageBase = 0x140000000 };
        var code = new byte[64];
        code[0] = 0xB8; code[1] = 0x01; code[5] = 0xC3;
        for (int i = 6; i < code.Length; i++) code[i] = 0x90;
        var text = b.Add(".text", code, 0x60000020);
        b.EntryPoint = text.Rva;
        return b.Build();
    }

    private sealed class Harness : IDisposable
    {
        public readonly TempDir Dir = new();
        public readonly Env Env = new();
        public readonly NativeCodeService Code;
        public readonly NativeEditJournal Journal;
        public readonly LoadedNative Native;

        public Harness()
        {
            Code = new NativeCodeService(Env.Workspace, Env.Options, null, new AnnotationStore(Dir.File("ann")));
            Journal = new NativeEditJournal(Env.Workspace, Code);
            var path = Dir.File("tiny.dll");
            File.WriteAllBytes(path, TinyImage());
            Native = Env.Workspace.LoadAny(path).Native!;
        }

        public void Dispose() { Env.Dispose(); Dir.Dispose(); }
    }

    [Fact]
    public async Task Annotations_record_and_undo_restores_previous_name()
    {
        using var h = new Harness();
        var ann = h.Code.Annotations(h.Native);
        ann.SetName(0x1000, "first");
        var id = h.Journal.RecordAnnotations(h.Native, "rename_native", [0x1000], () => ann.SetName(0x1000, "second"));
        Assert.Equal(new EditId(h.Native.Id, 1), id);
        Assert.Null(h.Journal.RecordAnnotations(h.Native, "rename_native", [0x1000], () => ann.SetName(0x1000, "second")));

        var undo = await h.Journal.UndoAsync(h.Native, id, default);
        Assert.Equal("first", ann.NameAt(0x1000));
        Assert.Equal(new EditChange("name", "0x140001000", "second", "first"), Assert.Single(undo.Changes));
        Assert.Empty(h.Journal.Entries(h.Native));
    }

    [Fact]
    public async Task Annotations_later_edit_of_same_address_refuses_undo_naming_it()
    {
        using var h = new Harness();
        var ann = h.Code.Annotations(h.Native);
        var first = h.Journal.RecordAnnotations(h.Native, "comment_native", [0x1000], () => ann.SetComment(0x1000, "a"))!.Value;
        var second = h.Journal.RecordAnnotations(h.Native, "comment_native", [0x1000], () => ann.SetComment(0x1000, "b"))!.Value;
        var e = await Assert.ThrowsAsync<ToolError>(() => h.Journal.UndoAsync(h.Native, first, default));
        Assert.Equal(ErrorCode.Conflict, e.Code);
        Assert.Contains(second.ToString(), e.Remediation);
        await h.Journal.UndoAsync(h.Native, null, default);
        await h.Journal.UndoAsync(h.Native, null, default);
        Assert.Null(ann.CommentAt(0x1000));
        var none = await Assert.ThrowsAsync<ToolError>(() => h.Journal.UndoAsync(h.Native, null, default));
        Assert.Contains("list_native_edits", none.Remediation);
    }

    [Fact]
    public async Task Annotations_a_comment_after_a_rename_does_not_block_undoing_the_rename()
    {
        using var h = new Harness();
        var ann = h.Code.Annotations(h.Native);
        var rename = h.Journal.RecordAnnotations(h.Native, "rename_native", [0x1000], () => ann.SetName(0x1000, "named"))!.Value;
        h.Journal.RecordAnnotations(h.Native, "comment_native", [0x1000], () => ann.SetComment(0x1000, "kept"));
        await h.Journal.UndoAsync(h.Native, rename, default);
        Assert.Equal((null, "kept"), (ann.NameAt(0x1000), ann.CommentAt(0x1000)));
    }

    [Fact]
    public async Task User_types_undo_reverts_only_that_edit()
    {
        using var h = new Harness();
        var ann = h.Code.Annotations(h.Native);
        var before = ann.UserTypes;
        var mid = ann.ChangeUserTypes(l => l.WithType(0x1000, "int f(void);"));
        var id = h.Journal.RecordUserTypes(h.Native, "set_native_type", "ida", before, mid)!.Value;
        var after = ann.ChangeUserTypes(l => l.WithStackVar(new NativeStackVarEdit(0x1000, 8, "count", "int")));
        h.Journal.RecordUserTypes(h.Native, "set_native_stack_var", "ida", mid, after);

        var undo = await h.Journal.UndoAsync(h.Native, id, default);
        Assert.False(ann.UserTypes.Types.ContainsKey(0x1000));
        Assert.Single(ann.UserTypes.StackVars[0x1000]);
        Assert.Equal(new EditChange("type", "rva 0x1000", "int f(void);", null), Assert.Single(undo.Changes));
    }

    [Fact]
    public void User_type_delta_inverse_clears_what_the_edit_added()
    {
        var before = UserTypeLayer.Empty.WithOperand(new NativeOperandEdit(0x20, 1, "hex", null));
        var after = before.WithType(0x10, "int x;").WithLocal(new NativeLocalEdit(0x10, "v1", 8, "count", null))
            .WithOperand(new NativeOperandEdit(0x20, 1, "dec", null)).WithTypeEdit(new NativeTypeEdit("A", "B"));
        var delta = UserTypeDelta.Between(before, after);
        var inverse = delta.Inverse(delta.Revert(after, out var conflicts), out var lost);
        Assert.Empty(conflicts);
        Assert.Empty(lost);
        Assert.Equal(new NativePrototype(0x10, ""), Assert.Single(inverse.Types));
        Assert.True(Assert.Single(inverse.Locals).Clear);
        Assert.Equal("hex", Assert.Single(inverse.Operands).Display);
        Assert.Equal(new NativeTypeEdit("B", "A"), Assert.Single(inverse.TypeEdits!));
        Assert.Equal(before.Stamp, delta.Revert(after, out _).Stamp);
    }

    [Fact]
    public void Export_import_keeps_edits_undoable()
    {
        using var h = new Harness();
        var ann = h.Code.Annotations(h.Native);
        h.Journal.RecordAnnotations(h.Native, "rename_native", [0x1000], () => ann.SetName(0x1000, "named"));
        var before = ann.UserTypes;
        h.Journal.RecordUserTypes(h.Native, "set_native_local", "ghidra", before,
            ann.ChangeUserTypes(l => l.WithLocal(new NativeLocalEdit(0x1000, "v1", null, "n", "int"))));
        var json = h.Journal.Export(h.Native);

        using var other = new Harness();
        var ids = other.Journal.Import(other.Native, json);
        Assert.Equal(2, ids.Count);
        var entries = other.Journal.Entries(other.Native);
        Assert.Equal("named", entries[0].Annotations[0].After.Name);
        Assert.Equal(new NativeLocalEdit(0x1000, "v1", null, "n", "int"), entries[1].UserTypes!.Items[0].After);
        Assert.Equal("ghidra", entries[1].Engine);
    }
}

/// <summary>The native edit tools on the journal: D7 previews, edit ids in the outcome, undo by id, batch semantics (S6.5).</summary>
public class NativeEditToolOutcomeTests
{
    private sealed class Rig : IDisposable
    {
        public readonly TempDir Dir = new();
        public readonly Env Env = new();
        public readonly NativeCodeService Code;
        public readonly NativeEditService Edits;
        public readonly Corvus.Tools.NativeEditTools Tools;
        public readonly string Path;

        public Rig()
        {
            Code = new NativeCodeService(Env.Workspace, Env.Options, null, new AnnotationStore(Dir.File("ann")));
            Edits = new NativeEditService(Env.Workspace, Code);
            Tools = new Corvus.Tools.NativeEditTools(Env.Workspace, Code, Edits);
            Path = Dir.File("tiny.dll");
            var b = new PeBuilder { Is64 = true, Machine = 0x8664, ImageBase = 0x140000000 };
            var code = new byte[64];
            code[0] = 0xB8; code[1] = 0x01; code[5] = 0xC3;
            for (int i = 6; i < code.Length; i++) code[i] = 0x90;
            b.EntryPoint = b.Add(".text", code, 0x60000020).Rva;
            File.WriteAllBytes(Path, b.Build());
        }

        public LoadedNative Native => Env.Workspace.Read(() => Env.Workspace.GetNative("tiny.dll"));

        public void Dispose() { Env.Dispose(); Dir.Dispose(); }
    }

    [Fact]
    public async Task Rename_defaults_to_a_preview_then_records_an_edit_ID_that_undo_restores()
    {
        using var r = new Rig();
        var collector = Corvus.Mcp.ToolOutput.Collect();
        var preview = await r.Tools.RenameNative(r.Path, "rva:0x1000", "First");
        Assert.StartsWith("Dry run: would have named function 0x140001000 'First'", preview);
        var dry = Assert.IsType<EditOutcome>(collector.Value);
        Assert.Equal((false, true, 0), (dry.Applied, dry.DryRun, dry.EditIds.Count));
        Assert.Null(r.Code.Annotations(r.Native).NameAt(0x1000));

        await r.Tools.RenameNative(r.Path, "rva:0x1000", "First", dryRun: false);
        var text = await r.Tools.RenameNative(r.Path, "rva:0x1000", "Second", dryRun: false);
        var outcome = Assert.IsType<EditOutcome>(collector.Value);
        Assert.Equal(new EditId("tiny.dll", 2), Assert.Single(outcome.EditIds));
        Assert.Equal(new EditChange("name", "0x140001000", "First", "Second"), Assert.Single(outcome.Changes));
        Assert.Contains("undo_native_edit editId=tiny.dll#2", text);

        var undone = await r.Tools.UndoNativeEdit(r.Path, "tiny.dll#2");
        Assert.StartsWith("Undid tiny.dll#2", undone);
        Assert.Equal("First", r.Code.Annotations(r.Native).NameAt(0x1000));
        Assert.Equal(new EditId("tiny.dll", 2), Assert.Single(Assert.IsType<EditOutcome>(collector.Value).EditIds));
    }

    [Fact]
    public async Task Digests_match_from_dry_run_to_save_the_patches_only_and_an_undone_patch_leaves_the_save()
    {
        using var r = new Rig();
        var collector = Corvus.Mcp.ToolOutput.Collect();
        async Task<EditOutcome> PreviewThenApply(Func<bool, Task<string>> edit)
        {
            var text = await edit(true);
            var dry = Assert.IsType<EditOutcome>(collector.Value);
            await edit(false);
            var applied = Assert.IsType<EditOutcome>(collector.Value);
            Assert.Matches("^[0-9a-f]{16}$", dry.Digest);
            Assert.Equal(dry.Digest, applied.Digest);
            return applied;
        }
        var bytes = await PreviewThenApply(d => r.Tools.PatchBytes(r.Path, "rva:0x1006", hex: "CC", dryRun: d));
        var previewText = await r.Tools.PatchBytes(r.Path, "rva:0x1008", hex: "CC");
        Assert.Contains($"Digest {Assert.IsType<EditOutcome>(collector.Value).Digest}", previewText);
        var asm = await PreviewThenApply(d => r.Tools.PatchAsm(r.Path, "rva:0x1008", "int3", dryRun: d));
        var name = await PreviewThenApply(d => r.Tools.RenameNative(r.Path, "rva:0x1000", "entry", dryRun: d));
        Assert.Equal(3, new[] { bytes.Digest, asm.Digest, name.Digest }.Distinct().Count());

        var text = await r.Tools.SaveNative(r.Path, r.Dir.File("out.dll"));
        var saved = Assert.IsType<Corvus.Tools.NativeEditTools.NativeSaveResult>(collector.Value);
        Assert.Equal([new SavedEdit(bytes.EditIds[0], bytes.Digest!), new SavedEdit(asm.EditIds[0], asm.Digest!)], saved.EditList);
        Assert.Contains($"Patches written: {bytes.EditIds[0]} ({bytes.Digest})", text);

        await r.Tools.UndoNativeEdit(r.Path, bytes.EditIds[0].ToString());
        await r.Tools.SaveNative(r.Path, r.Dir.File("out2.dll"));
        Assert.Equal([new SavedEdit(asm.EditIds[0], asm.Digest!)], Assert.IsType<Corvus.Tools.NativeEditTools.NativeSaveResult>(collector.Value).EditList);
    }

    [Fact]
    public async Task Batch_all_failed_is_an_error_some_failed_is_a_success_with_failed_items()
    {
        using var r = new Rig();
        var collector = Corvus.Mcp.ToolOutput.Collect();
        var all = await Assert.ThrowsAsync<ToolError>(() => r.Tools.RenameNative(r.Path, items: "nowhere = A\nalso_nowhere = B", dryRun: false));
        Assert.Contains("all 2 targets failed", all.Message);
        await Assert.ThrowsAsync<ToolError>(() => r.Tools.CommentNative(r.Path, "nowhere", "x", dryRun: false));

        await r.Tools.RenameNative(r.Path, items: "rva:0x1000 = A\nnowhere = B", dryRun: false);
        var some = Assert.IsType<EditOutcome>(collector.Value);
        Assert.Equal((true, 1, 1), (some.Applied, some.Failed, some.Items!.Count));
    }

    [Fact]
    public async Task Patch_and_comment_listed_with_IDs_undone_out_of_order_conflict_names_the_edit()
    {
        using var r = new Rig();
        var collector = Corvus.Mcp.ToolOutput.Collect();
        Assert.Contains("Nothing recorded", await r.Tools.PatchBytes(r.Path, "rva:0x1006", hex: "CC"));
        Assert.False(r.Native.HasPatches);
        await r.Tools.PatchBytes(r.Path, "rva:0x1006", hex: "CC", dryRun: false);
        Assert.Equal(new EditId("tiny.dll", 1), Assert.Single(Assert.IsType<EditOutcome>(collector.Value).EditIds));
        await r.Tools.CommentNative(r.Path, "rva:0x1000", "entry", scope: "line", dryRun: false);

        var clash = await Assert.ThrowsAsync<ToolError>(() => r.Tools.PatchBytes(r.Path, "rva:0x1006", hex: "90", dryRun: false));
        Assert.Contains("undo_native_edit editId=tiny.dll#1", clash.Remediation);

        var list = await r.Tools.ListNativeEdits(r.Path, limit: 1);
        var page = Assert.IsType<Corvus.Tools.NativeEditTools.NativeEditList>(collector.Value);
        Assert.Equal((2, "tiny.dll#1", "patch"), (page.Total, page.Items[0].EditId, page.Items[0].Kind));
        Assert.Contains("[More: offset=1]", list);

        await r.Tools.UndoNativeEdit(r.Path, "#1");
        Assert.False(r.Native.HasPatches);
        Assert.Equal("tiny.dll#2", Assert.Single(r.Edits.Journal.Entries(r.Native)).Id.ToString());
        await r.Tools.UndoNativeEdit(r.Path);
        Assert.Null(r.Code.Annotations(r.Native).CommentAt(0x1000));
        var none = await Assert.ThrowsAsync<ToolError>(() => r.Tools.UndoNativeEdit(r.Path));
        Assert.Contains("list_native_edits", none.Remediation);
    }
}
