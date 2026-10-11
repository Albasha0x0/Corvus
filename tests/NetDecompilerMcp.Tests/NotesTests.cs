using NetDecompilerMcp.Core;
using NetDecompilerMcp.Native.Annotations;
using NetDecompilerMcp.Services;
using NetDecompilerMcp.Tools;

namespace NetDecompilerMcp.Tests;

/// <summary>record_note / update_note / list_notes: persistence, partial updates, revision conflicts, anchors, filters, concurrent writers.</summary>
public sealed class NotesTests : IDisposable
{
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    private NotesService Store() => new(new AnnotationStore(_dir.File("annotations")));

    private (NoteTools Tools, AssemblyWorkspace Workspace, NotesService Notes) Tools()
    {
        var options = new ServerOptions { BackgroundIndexing = false };
        var workspace = new AssemblyWorkspace(options);
        var store = new AnnotationStore(_dir.File("annotations"));
        var code = new NativeCodeService(workspace, options, annotations: store);
        var notes = new NotesService(store);
        return (new NoteTools(workspace, notes, code, new MinidumpService(workspace, code)), workspace, notes);
    }

    [Fact]
    public void RecordUpdateAndReadBack()
    {
        var store = Store();
        var note = store.Record("decoder at the second call", "hypothesis", null, NoteAnchor.Global, ["crypto", "crypto"], ["get_il x"], "tester");
        Assert.Matches("^n[a-z2-7]{8}$", note.Id);
        Assert.Equal((1, "open", "hypothesis"), (note.Revision, note.Status, note.Kind));
        Assert.Equal(["crypto"], note.Tags);

        var updated = store.Update(note.Id, 1, new NoteChange(Status: "confirmed", AppendText: "verified by stepping", AddTags: ["xor"], RemoveTags: ["CRYPTO"]));
        Assert.Equal(2, updated.Revision);
        Assert.Equal("confirmed", updated.Status);
        Assert.Equal("decoder at the second call\nverified by stepping", updated.Text);
        Assert.Equal(["xor"], updated.Tags);
        Assert.Equal(["get_il x"], updated.Evidence);

        // a fresh store (another process) reads the same note
        var read = Store().All().Single();
        Assert.Equal((updated.Id, updated.Revision, updated.Text, updated.Updated), (read.Id, read.Revision, read.Text, read.Updated));
        Assert.Equal(updated.Tags, read.Tags);
        Assert.Equal((0, 1), Store().Counts());
    }

    [Fact]
    public void StaleRevisionIsAConflictCarryingTheCurrentNote()
    {
        var store = Store();
        var note = store.Record("first", null, null, NoteAnchor.Global, null, null, null);
        store.Update(note.Id, 1, new NoteChange(Text: "second"));
        var error = Assert.Throws<ToolError>(() => Store().Update(note.Id, 1, new NoteChange(Status: "dropped")));
        Assert.Equal(ErrorCode.Conflict, error.Code);
        var current = (Note)error.Details!.GetType().GetProperty("current")!.GetValue(error.Details)!;
        Assert.Equal((2, "second", "open"), (current.Revision, current.Text, current.Status));
        Assert.Equal(ErrorCode.NotFound, Assert.Throws<ToolError>(() => store.Update("nzzzzzzzz", 1, new NoteChange())).Code);
        Assert.Equal(ErrorCode.InvalidArgument, Assert.Throws<ToolError>(() => store.Update(note.Id, 2, new NoteChange(Status: "closed"))).Code);
        Assert.Equal(ErrorCode.LimitExceeded, Assert.Throws<ToolError>(() => store.Record(new string('x', 4001), null, null, NoteAnchor.Global, null, null, null)).Code);
    }

    [Fact]
    public async Task ConcurrentWritersKeepEveryNote()
    {
        var anchor = new NoteAnchor(NoteAnchor.Native, Sha256: new string('a', 64), Rva: 0x1000, Label: "x@0x1000");
        var a = Store();
        var b = Store();
        await Task.WhenAll(
            Task.Run(() => { for (int i = 0; i < 40; i++) a.Record($"a{i}", null, null, anchor, null, null, null); }),
            Task.Run(() => { for (int i = 0; i < 40; i++) b.Record($"b{i}", null, null, anchor, null, null, null); }));
        Assert.Equal(80, Store().Read(anchor.StoreKey).Select(n => n.Id).Distinct().Count());
    }

    [Fact]
    public async Task DecompileOutputCountsOpenNotes()
    {
        using var env = new Env();
        var notes = new NotesService(new AnnotationStore(_dir.File("annotations")));
        var tools = new DecompileTools(env.Workspace, env.Decompiler, env.Pager, notes);
        Assert.DoesNotContain("// notes:", await tools.DecompileMember("Account::Score"));
        var score = env.One("Account::Score");
        var anchor = new NoteAnchor(NoteAnchor.DotNet, Sha256: env.Fixture.OriginalSha256, Mvid: env.Fixture.Module.Mvid!.ToString(), Token: score.Member.MDToken.Raw);
        notes.Record("capped at 100", null, null, anchor, null, null, null);
        notes.Record("old idea", null, "dropped", anchor, null, null, null);
        Assert.StartsWith($"// notes: 1 open (list_notes anchor=TestFixture:{Format.Token(score.Member)})", await tools.DecompileMember("Account::Score"));
        Assert.StartsWith("// notes: 1 open", await tools.DecompileMember("Fixture.Model.Account"));
        Assert.DoesNotContain("// notes:", await tools.DecompileMember("Account::Charge"));
    }

    [Fact]
    public async Task AnchorsResolveAndFilter()
    {
        var (tools, workspace, notes) = Tools();
        var image = McpProtocolTests.NativeSample(_dir);
        workspace.LoadAny(image);
        workspace.Load(Env.FixturePath);
        var native = workspace.FindNative("native.dll")!;

        var atFirst = await tools.RecordNote("entry point stub", anchor: "native.dll@First", tags: "entry");
        Assert.Equal((NoteAnchor.Native, native.OriginalSha256), (atFirst.Anchor.Kind, atFirst.Anchor.Sha256));
        Assert.NotNull(atFirst.Anchor.Rva);
        var member = await tools.RecordNote("scores are capped", kind: "finding", anchor: "TestFixture:Account::Score");
        Assert.Equal(NoteAnchor.DotNet, member.Anchor.Kind);
        Assert.Equal(workspace.Get("TestFixture").Module.Mvid.ToString(), member.Anchor.Mvid);
        Assert.Equal(0x06000000u, member.Anchor.Token & 0xFF000000);
        var byToken = await tools.RecordNote("same member by token", anchor: $"TestFixture:0x{member.Anchor.Token:X8}");
        Assert.Equal(member.Anchor.Token, byToken.Anchor.Token);
        var file = await tools.RecordNote("packed?", kind: "question", anchor: "TestFixture");
        Assert.Equal(NoteAnchor.File, file.Anchor.Kind);
        await tools.RecordNote("global todo", kind: "todo");
        await Assert.ThrowsAsync<ToolError>(() => tools.RecordNote("x", anchor: "NoSuchThing:Foo"));

        Assert.Equal(5, (await tools.ListNotes()).Total);
        Assert.Equal(3, (await tools.ListNotes(anchor: "TestFixture")).Total);
        Assert.Equal(2, (await tools.ListNotes(anchor: "TestFixture:Account")).Total); // the type includes its members
        Assert.Equal(["entry point stub"], (await tools.ListNotes(anchor: "native.dll@First")).Items.Select(n => n.Text));
        Assert.Equal(["packed?"], (await tools.ListNotes(kind: "question")).Items.Select(n => n.Text));
        Assert.Equal(["entry point stub"], (await tools.ListNotes(tag: "ENTRY")).Items.Select(n => n.Text));
        Assert.Equal(["global todo"], (await tools.ListNotes(anchor: "global")).Items.Select(n => n.Text));

        await tools.UpdateNote(file.Id, 1, status: "answered", text: "not packed");
        Assert.Equal(4, (await tools.ListNotes()).Total);
        Assert.Equal(["not packed"], (await tools.ListNotes(status: "answered")).Items.Select(n => n.Text));
        var page = await tools.ListNotes(status: "all", offset: 1, limit: 2);
        Assert.Equal((2, 5, true), (page.Items.Count, page.Total, page.Truncated));
        Assert.Equal((4, 5), notes.Counts());
    }
}
