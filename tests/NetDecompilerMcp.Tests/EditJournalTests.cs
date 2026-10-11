using System.Text.Json.Nodes;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Native.Annotations;
using NetDecompilerMcp.Services;
using NetDecompilerMcp.Tools;

namespace NetDecompilerMcp.Tests;

/// <summary>The edit and patch journal: written after changes, removed on save / revert / unload, offered and replayed after a lost session.</summary>
public sealed class EditJournalTests : IDisposable
{
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    private AnnotationStore Store() => new(_dir.File("annotations"));

    private string Copy()
    {
        var path = _dir.File("Fixture.dll");
        if (!File.Exists(path)) File.Copy(Env.FixturePath, path);
        return path;
    }

    /// <summary>Marks a journal as written by a process that is gone.</summary>
    private static void Orphan(string file)
    {
        var doc = JsonNode.Parse(File.ReadAllText(file))!;
        doc["journal"]!["processStart"] = 1;
        File.WriteAllText(file, doc.ToJsonString());
    }

    [Fact]
    public void EditsAreJournaledAndOfferedToTheNextSession()
    {
        string journalFile;
        using (var env = new Env(Copy()))
        {
            var journal = new EditJournal(env.Workspace, Store(), env.History);
            env.Edit(() => env.Edits.StubMethod(env.One("Secret::Validate"), "true"));
            journal.Sync();
            journalFile = Assert.Single(Directory.GetFiles(journal.Root, "*" + EditJournal.EditsSuffix));
            Assert.StartsWith(env.Fixture.OriginalSha256, Path.GetFileName(journalFile));
            Assert.Single(EditHistoryService.ReadScript(journalFile).Edits); // the apply_edits format
            Assert.True(Assert.Single(new EditJournal(env.Workspace, Store(), env.History).Others(env.Fixture.OriginalSha256)).Live); // not offered as lost work
        }
        Orphan(journalFile);

        using var next = new Env(Copy());
        var offered = new EditJournal(next.Workspace, Store(), next.History);
        next.Workspace.Unload(next.Fixture);
        next.Workspace.Load(Copy());
        var notice = Assert.Single(next.Workspace.DrainNotices(), n => n.Contains("apply_edits", StringComparison.Ordinal));
        Assert.Contains("1 unsaved edit(s)", notice);
        Assert.Contains(journalFile, notice);

        var asm = next.Workspace.Get("TestFixture");
        Assert.Contains("1 applied", next.Workspace.Write(() => next.History.Apply(journalFile, asm.Id, false, true, default)));
        Assert.Contains("return true;", next.Decompile("Secret::Validate"));
        offered.Replayed(journalFile);
        Assert.False(File.Exists(journalFile));
    }

    [Fact]
    public void SaveRevertAndUnloadRemoveTheJournal()
    {
        using var env = new Env(Copy());
        var journal = new EditJournal(env.Workspace, Store(), env.History);
        string[] Files() => Directory.Exists(journal.Root) ? Directory.GetFiles(journal.Root) : [];

        env.Edit(() => env.Edits.StubMethod(env.One("Secret::Validate"), "true"));
        journal.Sync();
        Assert.Single(Files());
        env.Edits.Save(env.Fixture, _dir.File("saved.dll"), overwrite: false);
        journal.Saved(env.Fixture);
        Assert.Empty(Files());

        env.Edit(() => env.Edits.StubMethod(env.One("Account::Score"), "3"));
        journal.Sync();
        Assert.Contains("\"stub_method\"", File.ReadAllText(Assert.Single(Files())));
        env.Edit(() => env.Edits.RevertAll(env.Fixture, default));
        journal.Sync();
        Assert.Empty(Files());

        env.Edit(() => env.Edits.StubMethod(env.One("Account::Score"), "3"));
        journal.Sync();
        Assert.Single(Files());
        env.Workspace.Unload(env.Fixture);
        journal.Sync();
        Assert.Empty(Files());
    }

    [Fact]
    public async Task PatchesAreJournaledAndReplayedOnTheSameBuild()
    {
        using var env = new Env();
        var store = Store();
        var code = new NativeCodeService(env.Workspace, env.Options, null, store) { SymbolStarts = (_, _) => [0x1000u, 0x1040u] };
        var edits = new NativeEditService(env.Workspace, code);
        var tools = new NativePatchTools(env.Workspace, code, edits);
        var journal = new EditJournal(env.Workspace, store, env.History);
        var path = _dir.File("native.dll");
        File.WriteAllBytes(path, NativePatchMigrationTests.X64Image(0x1000, 0x2000, 0x1040, 1));
        var native = env.Workspace.LoadAny(path).Native!;
        var index = await code.Index(native, null, default);

        edits.ApplyPatch(native, index, edits.PreparePatch(index, 0x1040, [0xB8, 0x02, 0, 0, 0], false, "patch_bytes 5 bytes"), dryRun: false);
        journal.Sync();
        var file = Assert.Single(Directory.GetFiles(journal.Root, "*" + EditJournal.PatchesSuffix));
        var kept = _dir.File("kept.patches.json");
        File.Copy(file, kept);
        edits.Undo(native, null);
        journal.Sync();
        Assert.False(File.Exists(file));

        var replay = await tools.MigrateNativePatches(native.Id, native.Id, patchSet: kept, dryRun: false);
        Assert.Equal((1, 0), (replay.Applied, replay.Refused));
        var imm = new byte[1];
        native.Image.Read(0x1041, imm);
        Assert.Equal(0x02, imm[0]);
        var again = await tools.MigrateNativePatches(native.Id, native.Id, patchSet: kept, dryRun: true);
        Assert.Equal("already_present", Assert.Single(again.Entries).Reason);
        await Assert.ThrowsAsync<ToolError>(() => tools.MigrateNativePatches(native.Id, native.Id));
    }
}
