using Corvus.Core;
using Corvus.Native.Annotations;
using Corvus.Services;
using Corvus.Tools;

namespace Corvus.Tests;

/// <summary>save_session / load_session: same build, moved files, changed files refused, and work carried to another build.</summary>
public sealed class SessionFileTests : IDisposable
{
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    /// <summary>One server's services over its own annotation store (another user or machine when the store differs).</summary>
    private sealed class Stack : IDisposable
    {
        public readonly AssemblyWorkspace Workspace;
        public readonly EditService Edits;
        public readonly EditHistoryService History;
        public readonly NativeCodeService Code;
        public readonly NativeEditService NativeEdits;
        public readonly NotesService Notes;
        public readonly SessionFileTools Tools;
        public readonly MinidumpService Dumps = new();

        public Stack(string store)
        {
            var options = new ServerOptions { TimeoutSeconds = 120, BackgroundIndexing = false };
            Workspace = new AssemblyWorkspace(options);
            var decompiler = new DecompilerService(Workspace, options);
            Edits = new EditService(Workspace, new IlAssembler(Workspace), new CSharpPatcher(Workspace, decompiler));
            History = new EditHistoryService(Workspace, Edits, decompiler, new AssemblyComparer(Workspace));
            var annotations = new AnnotationStore(store);
            // the two synthetic builds: functions at 0x1000 / 0x1040 (old) and 0x1010 / 0x1050 (new)
            Code = new NativeCodeService(Workspace, options, null, annotations)
            {
                SymbolStarts = (n, _) => n.OriginalSha256 == NewSha ? [0x1010u, 0x1050u] : [0x1000u, 0x1040u],
            };
            NativeEdits = new NativeEditService(Workspace, Code);
            Notes = new NotesService(annotations);
            Tools = new SessionFileTools(Workspace, new SessionService(Workspace, History, Code, Notes, Dumps), History, Code, NativeEdits, Notes,
                il2cppRaw: new Il2CppRawLoader(Workspace, System.IO.Path.Combine(store, "il2cpp")), dumps: Dumps);
        }

        public async Task PatchAndName(string image)
        {
            var native = Workspace.LoadAny(image).Native!;
            var index = await Code.Index(native, null, default);
            NativeEdits.ApplyPatch(native, index, NativeEdits.PreparePatch(index, 0x1040, [0xB8, 0x02, 0, 0, 0], false, "patch_bytes 5 bytes"), dryRun: false);
            index = await Code.Index(native, null, default);
            NativeEdits.Rename(native, index, 0x1040, "make_two", allowDuplicate: false);
            NativeEdits.Comment(native, index, 0x1000, "reads g");
        }

        public void Dispose() => Workspace.Dispose();
    }

    private string Place(string folder, string name, byte[] bytes)
    {
        var path = _dir.File(Path.Combine(folder, name));
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllBytes(path, bytes);
        return path;
    }

    private static byte[] OldImage => NativePatchMigrationTests.X64Image(0x1000, 0x2000, 0x1040, 1);

    private static byte[] NewImage => NativePatchMigrationTests.X64Image(0x1010, 0x2020, 0x1050, 1);

    private static readonly string NewSha = Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(NewImage));

    private static SessionFileTools.SessionItem Item(SessionFileTools.SessionLoadReport r, string kind) => Assert.Single(r.Items, i => i.Kind == kind);

    /// <summary>Saves a session over a stubbed fixture, a patched and named image and a note; returns the session path.</summary>
    private async Task<string> Save(string folder)
    {
        var fixture = Place(folder, "TestFixture.dll", File.ReadAllBytes(Env.FixturePath));
        var image = Place(folder, "native.dll", OldImage);
        using var a = new Stack(_dir.File("store-a"));
        var asm = a.Workspace.Load(fixture);
        a.Workspace.Write(() => a.Edits.StubMethod(SymbolResolver.ResolveOne(a.Workspace, asm.Id, "Secret::Validate"), "true"));
        await a.PatchAndName(image);
        var native = a.Workspace.FindNative("native.dll")!;
        a.Notes.Record("f2 returns a constant", null, null, new NoteAnchor(NoteAnchor.Native, Sha256: native.OriginalSha256, Rva: 0x1040, Label: "native.dll@f2"), null, null, null);
        var path = _dir.File(Path.Combine(folder, "work.session.json"));
        var saved = await a.Tools.SaveSession(path);
        Assert.Equal((2, 1, 1, 1, 1, 1, 1, 1), (saved.Files, saved.EditedAssemblies, saved.Edits, saved.PatchedImages, saved.Patches, saved.Names, saved.Comments, saved.Notes));
        await Assert.ThrowsAsync<ToolError>(() => a.Tools.SaveSession(path));
        return path;
    }

    /// <summary>
    /// An Il2Cpp game read by the built-in reader is recorded by its metadata and binary, not by the dummy assemblies in
    /// the reader's cache; an open minidump by its file. load_session finds both again and reopens the dump.
    /// </summary>
    [Fact]
    public async Task Il2CppGamesAndMinidumpsAreRecordedByTheirInputs()
    {
        var metadataBytes = new byte[0x400];
        BitConverter.TryWriteBytes(metadataBytes.AsSpan(0), 0xFAB11BAF);
        BitConverter.TryWriteBytes(metadataBytes.AsSpan(4), 29);
        var metadata = Place("game", "global-metadata.dat", metadataBytes);
        var binary = Place("game", "GameAssembly.dll", OldImage);
        // The reader's cache entry: marker, model and a dummy assembly.
        var entry = _dir.File(Path.Combine("cache", "0123456789abcdef"));
        var dummy = Place(Path.Combine("cache", "0123456789abcdef", Il2CppRawLoader.DummyFolder), "Assembly-CSharp.dll", File.ReadAllBytes(Env.FixturePath));
        File.WriteAllText(Path.Combine(entry, Il2CppGameModel.FileName), "");
        File.WriteAllText(Path.Combine(entry, Il2CppRawLoader.MarkerFileName), System.Text.Json.JsonSerializer.Serialize(
            new Il2CppRawLoader.Marker(binary, metadata, "-", "-", 2, "test", DateTime.UtcNow)));
        using var dumps = new TempDir();
        var dump = SyntheticCrash.Write(dumps);
        var session = _dir.File("work.json");
        using (var a = new Stack(_dir.File("store-a")))
        {
            a.Workspace.Load(dummy);
            a.Workspace.LoadAny(binary);
            await a.Dumps.Summarize(dump, null, 0, 1, 0, 1, default);
            await a.Tools.SaveSession(session);
        }
        var doc = SessionService.Read(session);
        var game = Assert.Single(doc.Il2Cpp!);
        Assert.Equal((metadata, binary), (game.Input.Path, game.Binary));
        Assert.Equal(Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(OldImage)), game.BinarySha256);
        Assert.DoesNotContain(doc.Files, f => f.Path == dummy); // regenerated by the reader, not recorded
        Assert.Contains(doc.Files, f => f.Path == binary);
        Assert.Equal("synth.dmp", Assert.Single(doc.Dumps!).File.Id);

        using var b = new Stack(_dir.File("store-b"));
        var dry = await b.Tools.LoadSession(session);
        Assert.Equal((SessionFileTools.WouldLoad, "recorded_path"), (Item(dry, "il2cpp").Outcome, Item(dry, "il2cpp").Reason));
        Assert.Equal(SessionFileTools.WouldLoad, Item(dry, "dump").Outcome);
        var applied = await b.Tools.LoadSession(session, dryRun: false);
        Assert.Equal(SessionFileTools.Refused, Item(applied, "il2cpp").Outcome); // the stand-in metadata cannot be read
        Assert.Contains("Tried: Unity", Item(applied, "il2cpp").Detail);
        Assert.Equal(SessionFileTools.Loaded, Item(applied, "dump").Outcome);
        Assert.Equal(["synth.dmp"], b.Dumps.OpenIds);
        Assert.Equal(SessionFileTools.AlreadyLoaded, Item(await b.Tools.LoadSession(session, dryRun: false), "dump").Outcome);
    }

    /// <summary>A real game (CORVUS_IL2CPP_GAME: game folder or global-metadata.dat): saved after load_assembly, read again by load_session.</summary>
    [RequiresRealDataFact("CORVUS_IL2CPP_GAME")]
    [Trait("Speed", "Slow")]
    public async Task Il2CppGameRoundTrips()
    {
        var session = _dir.File("game.json");
        string binarySha;
        using (var a = new Stack(_dir.File("store-a")))
        {
            var il2cpp = new Il2CppService(a.Workspace);
            var options = new ServerOptions { BackgroundIndexing = false, WatchFiles = false };
            var tools = new WorkspaceTools(a.Workspace, il2cpp, new IndexingService(a.Workspace, new CallGraphService(a.Workspace), options),
                new Corvus.Services.Analysis.UnpackService(a.Workspace), il2cppRaw: new Il2CppRawLoader(a.Workspace, _dir.File("cache")));
            await tools.LoadAssembly(RealData.Path("CORVUS_IL2CPP_GAME"));
            binarySha = Assert.Single(a.Workspace.Natives).OriginalSha256;
            await a.Tools.SaveSession(session);
        }
        Assert.Equal(binarySha, Assert.Single(SessionService.Read(session).Il2Cpp!).BinarySha256);
        using var b = new Stack(_dir.File("store-b"));
        var item = Item(await b.Tools.LoadSession(session, dryRun: false), "il2cpp");
        Assert.Equal(SessionFileTools.Loaded, item.Outcome);
        Assert.NotEqual("other_binary", item.Reason);
        Assert.True(item.Count > 0 && b.Workspace.Assemblies.Count == item.Count);
        Assert.Equal(binarySha, Assert.Single(b.Workspace.Natives).OriginalSha256);
    }

    [Fact]
    public async Task RestoresTheSameBuildFromMovedFiles()
    {
        var session = await Save("a");
        Directory.Move(_dir.File("a"), _dir.File("moved"));
        session = _dir.File(Path.Combine("moved", "work.session.json"));
        File.Move(session, _dir.File("work.session.json"));
        session = _dir.File("work.session.json");

        using var b = new Stack(_dir.File("store-b"));
        var dry = await b.Tools.LoadSession(session, searchRoots: _dir.File("moved"));
        Assert.All(dry.Items.Where(i => i.Kind == "file"), i => Assert.Equal(("would_load", "search_root"), (i.Outcome, i.Reason)));
        Assert.Equal((SessionFileTools.WouldApply, "not_loaded"), (Item(dry, "edits").Outcome, Item(dry, "edits").Reason)); // was refused, not_found
        Assert.Empty(b.Workspace.Assemblies);

        var run = await b.Tools.LoadSession(session, dryRun: false, searchRoots: _dir.File("moved"));
        Assert.Equal(2, run.Items.Count(i => i is { Kind: "file", Outcome: "loaded" }));
        Assert.Equal(("applied", 1), (Item(run, "edits").Outcome, Item(run, "edits").Count));
        Assert.Equal(("applied", 1), (Item(run, "patches").Outcome, Item(run, "patches").Count));
        Assert.Equal(("applied", 2), (Item(run, "names").Outcome, Item(run, "names").Count));
        Assert.Equal(("applied", 1), (Item(run, "notes").Outcome, Item(run, "notes").Count));
        var native = b.Workspace.FindNative("native.dll")!;
        Assert.Equal("make_two", b.Code.Annotations(native).NameAt(0x1040));
        var imm = new byte[1];
        native.Image.Read(0x1041, imm);
        Assert.Equal(2, imm[0]);
        Assert.Single(b.Workspace.Get("TestFixture").Edits);
        // the rename and the comment are journaled again, so undo takes the name back
        Assert.Equal(("applied", 2), (Item(run, "journal").Outcome, Item(run, "journal").Count));
        var rename = b.NativeEdits.Journal.Entries(native).Single(e => e.Tool == "rename_native");
        await b.NativeEdits.Journal.UndoAsync(native, rename.Id, default);
        Assert.Null(b.Code.Annotations(native).NameAt(0x1040));
        b.NativeEdits.Rename(native, b.Code.Ready(native) ?? await b.Code.Index(native, null, default), 0x1040, "make_two", allowDuplicate: false);

        // again: everything is there already
        var again = await b.Tools.LoadSession(session, dryRun: false, include: "patches,annotations,notes", searchRoots: _dir.File("moved"));
        Assert.All(again.Items, i => Assert.Contains(i.Outcome, new[] { "already_loaded", "already_present" }));
    }

    [Fact]
    public async Task ChangedFilesAreRefusedUnlessCarriedToTheOtherBuild()
    {
        var session = await Save("a");
        // a new build replaces the old one at the recorded path; the old one is kept elsewhere
        Place("old", "native.dll", OldImage);
        Place("a", "native.dll", NewImage);

        using var b = new Stack(_dir.File("store-b"));
        var same = await b.Tools.LoadSession(session, dryRun: false, include: "patches,annotations");
        Assert.Contains(same.Items, i => i is { Kind: "file", Outcome: "refused", Reason: "sha_mismatch" });

        using var c = new Stack(_dir.File("store-c"));
        var other = await c.Tools.LoadSession(session, dryRun: false, targetBuild: "other", include: "patches,annotations", searchRoots: _dir.File("old"));
        Assert.Contains(other.Items, i => i is { Kind: "file", Outcome: "loaded", Reason: "other_build" });
        var patches = Item(other, "patches");
        Assert.True(patches is { Outcome: "applied", Reason: "other_build", Count: 1 }, $"{patches.Outcome} {patches.Reason}: {patches.Detail}");
        var newBuild = c.Workspace.Natives.Single(n => n.OriginalSha256 == NewSha);
        var imm = new byte[1];
        newBuild.Image.Read(0x1051, imm);
        Assert.Equal(2, imm[0]);
        Assert.Equal("make_two", c.Code.Annotations(newBuild).NameAt(0x1050));
    }
}
