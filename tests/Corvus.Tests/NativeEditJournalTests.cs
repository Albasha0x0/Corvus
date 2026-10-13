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
    public async Task Annotations_RecordAndUndo_RestoresPreviousName()
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
    public async Task Annotations_LaterEditOfSameAddress_RefusesUndoNamingIt()
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
    public async Task UserTypes_UndoRevertsOnlyThatEdit()
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
    public void UserTypeDelta_InverseClearsWhatTheEditAdded()
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
    public void Export_Import_KeepsEditsUndoable()
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
