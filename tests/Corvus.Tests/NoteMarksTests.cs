using Corvus.Core;
using Corvus.Native;
using Corvus.Native.Annotations;
using Corvus.Services;
using Corvus.Tools;

namespace Corvus.Tests;

/// <summary>Notes as engine marks (pushed once per change, dropped notes left out) and list_native_edits search= over names and comments.</summary>
public sealed class NoteMarksTests : IDisposable
{
    private readonly TempDir _dir = new();
    private readonly List<IDisposable> _owned = [];

    public void Dispose()
    {
        foreach (var d in _owned) d.Dispose();
        _dir.Dispose();
    }

    private sealed record Rig(NativeAnalysisTools Analysis, NativeEditTools Edits, NotesService Notes, ScriptedEngine Engine, LoadedNative Native);

    private Rig Setup()
    {
        var options = new ServerOptions { BackgroundIndexing = false };
        var workspace = new AssemblyWorkspace(options);
        var store = new AnnotationStore(_dir.File("annotations"));
        var code = new NativeCodeService(workspace, options, null, store);
        var engine = new ScriptedEngine();
        engine.Add(0x1000, "f", "int f(void)", "{ return 0; }");
        var engines = new NativeEngineService([engine], _dir.File("cache"), code, workspace, options);
        _owned.Add(engines);
        _owned.Add(workspace);
        var notes = new NotesService(store);
        var native = workspace.LoadAny(McpProtocolTests.NativeSample(_dir)).Native!;
        return new Rig(new NativeAnalysisTools(workspace, engines, new OutputPager(options), null, null, null, null, notes),
            new NativeEditTools(workspace, code, new NativeEditService(workspace, code)), notes, engine, native);
    }

    private static NoteAnchor At(LoadedNative native, uint rva) => new(NoteAnchor.Native, native.OriginalSha256.ToLowerInvariant(), Rva: rva);

    [Fact]
    public async Task Notes_become_marks_once_per_change()
    {
        var rig = Setup();
        rig.Notes.Record("decrypts the config\nwith a fixed key", "finding", null, At(rig.Native, 0x1004), null, null, null);
        var dropped = rig.Notes.Record("not interesting", "todo", null, At(rig.Native, 0x1008), null, null, null);
        rig.Notes.Update(dropped.Id, dropped.Revision, new NoteChange(Status: "dropped"));
        rig.Notes.Record("session-wide", "question", null, NoteAnchor.Global, null, null, null);

        var text = await rig.Analysis.DecompileNative(rig.Native.Id, "rva:0x1000");
        Assert.Contains("// notes: 1 mark(s) in ida", text);
        var (marks, _) = Assert.Single(rig.Engine.MarkPushes);
        var mark = Assert.Single(marks);
        Assert.Equal(0x1004u, mark.Rva);
        Assert.StartsWith("[finding/open] decrypts the config with a fixed key (", mark.Text);

        Assert.DoesNotContain("notes:", await rig.Analysis.DecompileNative(rig.Native.Id, "rva:0x1000", addresses: true));
        Assert.Single(rig.Engine.MarkPushes);

        rig.Notes.Record("second", "hypothesis", null, At(rig.Native, 0x1000), null, null, null);
        Assert.Contains("// notes: 2 mark(s) in ida", await rig.Analysis.DecompileNative(rig.Native.Id, "rva:0x1000", addresses: false, offset: 0, maxTokens: 50_000));
        Assert.Equal([0x1000u, 0x1004u], rig.Engine.MarkPushes[1].Marks.Select(m => m.Rva));
    }

    [Fact]
    public async Task Search_lists_matching_names_and_comments()
    {
        var rig = Setup();
        await rig.Edits.RenameNative(rig.Native.Id, "rva:0x1000", "DecryptConfig");
        await rig.Edits.CommentNative(rig.Native.Id, "rva:0x1004", "xor key loaded here");
        await rig.Edits.CommentNative(rig.Native.Id, "rva:0x1008", "unrelated");
        var text = await rig.Edits.ListNativeEdits(rig.Native.Id, search: "/decrypt|xor/");
        Assert.Contains("2 name(s) and comment(s) matching '/decrypt|xor/'", text);
        Assert.Contains("0x140001000  user      name     DecryptConfig", text);
        Assert.Contains("0x140001004  user      comment  xor key loaded here", text);
        Assert.DoesNotContain("unrelated", text);
        Assert.Contains("native edit", await rig.Edits.ListNativeEdits(rig.Native.Id));
    }
}
