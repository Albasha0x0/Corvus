using System.Diagnostics;
using ModelContextProtocol.Client;
using ModelContextProtocol.Protocol;
using NetDecompilerMcp.Native.Annotations;
using NetDecompilerMcp.Native.Code;
using Xunit.Abstractions;

namespace NetDecompilerMcp.Tests;

/// <summary>Imported name layers (load_pdb, apply_il2cpp_names) saved beside the annotations and restored on load.</summary>
public class ImportedNamesTests(ITestOutputHelper output)
{
    [Fact]
    public void LayerFilesRoundTripAndBadFilesReadAsNothing()
    {
        using var dir = new TempDir();
        var store = new AnnotationStore(dir.File("ann"));
        const string sha = "ab12";
        var info = new ImportInfo(@"C:\x\a.pdb", "guid 3", new DateTime(2026, 10, 10, 1, 2, 3, DateTimeKind.Utc), [0x1040, 0x1010]);
        var layer = new NativeNameLayers.Layer(NativeNameSource.Pdb, new Dictionary<uint, string> { [0x1010] = "Bar::Foo", [0xFFFFFFF0] = "ü_é" },
            new Dictionary<uint, string> { [0x1010] = "line\nbreak" }, "a.pdb", info);
        Assert.Null(store.SaveLayer(sha, @"C:\x\a.dll", layer));

        var back = store.LoadLayer(sha, NativeNameSource.Pdb)!;
        Assert.Equal(layer.Names, back.Names);
        Assert.Equal(layer.Comments, back.Comments);
        Assert.Equal("a.pdb", back.Origin);
        Assert.Equal(info with { FunctionStarts = null, Restored = true }, back.Info! with { FunctionStarts = null });
        Assert.Equal([0x1010u, 0x1040u], back.Info!.FunctionStarts);
        Assert.Null(store.LoadLayer(sha, NativeNameSource.Il2Cpp));
        Assert.Null(store.LoadLayer("other", NativeNameSource.Pdb));

        // an old-format sidecar (names and comments only) beside the layer file still loads
        File.WriteAllText(Path.Combine(store.Root, sha + ".json"), """{"path":"a.dll","sha256":"ab12","imageBase":0,"names":{"1000":"Mine"},"comments":{}}""");
        Assert.Equal("Mine", store.Load(sha)!.Names["1000"]);

        // truncated or foreign bytes read as no layer, never an exception
        var file = store.LayerFileFor(sha, NativeNameSource.Pdb);
        var bytes = File.ReadAllBytes(file);
        foreach (var cut in new[] { 0, 5, bytes.Length / 2, bytes.Length - 16 })
        {
            File.WriteAllBytes(file, bytes[..cut]);
            Assert.Null(store.LoadLayer(sha, NativeNameSource.Pdb));
        }
        File.WriteAllText(file, "not a layer");
        Assert.Null(store.LoadLayer(sha, NativeNameSource.Pdb));
        Assert.True(store.DeleteLayer(sha, NativeNameSource.Pdb));
        Assert.False(store.DeleteLayer(sha, NativeNameSource.Pdb));
    }

    /// <summary>
    /// A real restart: one server imports PDB names (from a PDB away from the image) and Il2Cpp names into a native image
    /// and exits; the PDB is deleted; a second server with the same annotation folder loads the image only and has both
    /// layers, with their sources, the PDB's function starts and the restore reported; clearing removes the saved copies.
    /// </summary>
    [Fact]
    [Trait("Speed", "Slow")]
    public async Task NamesSurviveAServerRestart()
    {
        using var dir = new TempDir();
        var image = dir.File("tiny.dll");
        File.WriteAllBytes(image, PdbTests.TinyImage(PdbBuilder.Sample().Guid, 3));
        var syms = Directory.CreateDirectory(dir.File("syms")).FullName;
        File.WriteAllBytes(Path.Combine(syms, "tiny.pdb"), PdbBuilder.Sample().Build());

        var watch = Stopwatch.StartNew();
        await using (var first = await McpProtocolTests.StartServerInAsync(dir.Path, "--load", Env.FixturePath))
        {
            Assert.Contains("saved with the image's annotations", await Call(first, "load_pdb", new() { ["image"] = image, ["path"] = syms }));
            Assert.Contains("Saved with the image's annotations", await Call(first, "apply_il2cpp_names", new() { ["image"] = "tiny.dll", ["assembly"] = "TestFixture" }));
            var listed = await Call(first, "list_native_edits", new() { ["image"] = "tiny.dll" });
            Assert.Contains("saved for the next load", listed);
            Assert.DoesNotContain("restored on load", listed);
        }
        output.WriteLine($"first session {watch.Elapsed.TotalSeconds:0.0} s");
        File.Delete(Path.Combine(syms, "tiny.pdb"));

        watch.Restart();
        await using (var second = await McpProtocolTests.StartServerInAsync(dir.Path))
        {
            await Call(second, "load_assembly", new() { ["path"] = image });
            var functions = await Call(second, "list_functions", new() { ["image"] = "tiny.dll" });
            Assert.Contains("Bar::Foo", functions);
            Assert.Contains("helper", functions); // a PDB function start discovery alone does not find
            Assert.Contains("Fixture_Native_NativeThing__First", functions);
            Assert.Contains("name Bar::Foo (pdb)", await Call(second, "resolve_address", new() { ["image"] = "tiny.dll", ["address"] = "0x140001010" }));
            Assert.Contains("name Fixture_Native_NativeThing__First (il2cpp)", await Call(second, "resolve_address", new() { ["image"] = "tiny.dll", ["address"] = "0x140001000" }));
            var edits = await Call(second, "list_native_edits", new() { ["image"] = "tiny.dll" });
            output.WriteLine(edits);
            Assert.Contains("pdb: 3 name(s)", edits);
            Assert.Contains("restored on load", edits);
            Assert.Contains("GUID age 11223344-5566-7788-99aa-bbccddeeff00 3", edits);
            Assert.Contains("il2cpp:", edits);
            output.WriteLine($"second session (load + names) {watch.Elapsed.TotalSeconds:0.0} s");

            Assert.Contains("removed 3 PDB names and the saved copy", await Call(second, "load_pdb", new() { ["image"] = "tiny.dll", ["clear"] = true }));
            Assert.Contains("and the saved copy", await Call(second, "apply_il2cpp_names", new() { ["image"] = "tiny.dll", ["clear"] = true }));
        }
        Assert.Empty(Directory.GetFiles(Path.Combine(dir.Path, ".ndm-annotations"), "*.names"));
    }

    private static async Task<string> Call(McpClient client, string tool, Dictionary<string, object?> args)
    {
        var result = await client.CallToolAsync(tool, args);
        var text = string.Join("\n", result.Content.OfType<TextContentBlock>().Select(c => c.Text));
        Assert.True(result.IsError != true, $"{tool}: {text}");
        return text;
    }
}

/// <summary>Saved imported names on real data; timed, so they run in the sweep collection.</summary>
[Collection(SweepCollection.Name)]
public class ImportedNamesRealDataTests(ITestOutputHelper output)
{
    /// <summary>
    /// A real game (NDM_IL2CPP_GAME, read by the built-in reader): the il2cpp layer is saved, then restored by a fresh
    /// workspace and service over the same annotation folder. Reports counts, the saved file size and the timings.
    /// </summary>
    [RequiresRealDataFact("NDM_IL2CPP_GAME")]
    [Trait("Speed", "Slow")]
    public void RealIl2CppNamesRestore()
    {
        using var dir = new TempDir();
        var files = NetDecompilerMcp.Services.Il2CppGameFiles.Find(RealData.Path("NDM_IL2CPP_GAME")) ?? throw new InvalidOperationException("not an Il2Cpp game");
        var store = new AnnotationStore(dir.File("ann"));
        var cache = Environment.GetEnvironmentVariable(NetDecompilerMcp.Services.Il2CppRawLoader.RootVariable) is { Length: > 0 } c ? c : dir.File("il2cpp-cache");
        int names, comments;
        var watch = Stopwatch.StartNew();
        using (var ws = new NetDecompilerMcp.Core.AssemblyWorkspace(new NetDecompilerMcp.Core.ServerOptions { WatchFiles = false, BackgroundIndexing = false }))
        {
            var il2cpp = new NetDecompilerMcp.Services.Il2CppService(ws);
            var navigator = new NetDecompilerMcp.Services.Il2CppNavigator(ws, il2cpp, new NetDecompilerMcp.Services.Il2CppStringService(ws, il2cpp));
            var code = new NetDecompilerMcp.Services.NativeCodeService(ws, new NetDecompilerMcp.Core.ServerOptions { BackgroundIndexing = false }, null, store);
            new NetDecompilerMcp.Services.Il2CppRawLoader(ws).Load(files, loadBinary: false, null, default, cache);
            var native = ws.LoadAny(files.Binary).Native!;
            output.WriteLine($"metadata read and binary loaded in {watch.Elapsed.TotalSeconds:0.0} s");
            watch.Restart();
            var report = new NetDecompilerMcp.Services.Il2CppNativeNames(il2cpp, navigator, code).Apply(native, null, ws.Scope(null), default);
            var layer = NativeNameLayers.Of(native).Get(NativeNameSource.Il2Cpp)!;
            (names, comments) = (layer.Names.Count, layer.Comments.Count);
            output.WriteLine($"apply_il2cpp_names (with the save) {watch.Elapsed.TotalSeconds:0.00} s: {report.Functions} functions, {report.Strings} strings, " +
                             $"{report.MetadataSlots} metadata slots, {report.MethodInfoSlots} MethodInfo slots; layer {names} names, {comments} comments; notes: {string.Join("; ", report.Notes)}");
        }
        var file = new FileInfo(Assert.Single(Directory.GetFiles(store.Root, "*.il2cpp.names")));
        output.WriteLine($"saved {file.Name}: {file.Length / 1048576.0:0.0} MB ({file.Length / (double)names:0.0} bytes per name with its comment)");

        using var again = new NetDecompilerMcp.Core.AssemblyWorkspace(new NetDecompilerMcp.Core.ServerOptions { WatchFiles = false, BackgroundIndexing = false });
        var code2 = new NetDecompilerMcp.Services.NativeCodeService(again, new NetDecompilerMcp.Core.ServerOptions { BackgroundIndexing = false }, null, store);
        watch.Restart();
        var native2 = again.LoadAny(files.Binary).Native!;
        output.WriteLine($"second session: binary loaded in {watch.Elapsed.TotalSeconds:0.00} s");
        watch.Restart();
        code2.RestoreImported(native2);
        var restored = NativeNameLayers.Of(native2).Get(NativeNameSource.Il2Cpp)!;
        output.WriteLine($"restored {restored.Names.Count} names, {restored.Comments.Count} comments in {watch.Elapsed.TotalSeconds:0.00} s; source {restored.Info!.SourcePath} sha256 {restored.Info.SourceIdentity}");
        Assert.Equal((names, comments), (restored.Names.Count, restored.Comments.Count));
        Assert.True(restored.Info.Restored);
    }

    /// <summary>
    /// A System32 DLL whose PDB is in a local symbol store: load_pdb from a copy of the PDB, delete the copy, and a fresh
    /// service restores the names and function starts from the saved layer alone; reports counts and timings.
    /// </summary>
    [Fact]
    [Trait("Speed", "Slow")]
    public async Task RealPdbNamesRestoreWithoutThePdb()
    {
        string? dll = null, pdb = null;
        var candidates = new[] { Environment.SpecialFolder.System, Environment.SpecialFolder.SystemX86 }
            .Select(Environment.GetFolderPath).Where(Directory.Exists).Distinct()
            .SelectMany(d => new DirectoryInfo(d).EnumerateFiles("*.dll")).Where(f => f.Length is > 1 << 20 and < 64 << 20)
            .OrderByDescending(f => f.Length).Take(300).Select(f => f.FullName);
        foreach (var path in candidates)
        {
            try
            {
                if (NetDecompilerMcp.Native.Pdb.PdbLocator.Locate(NetDecompilerMcp.Native.Pe.PeFile.FromBytes(File.ReadAllBytes(path), path)).Path is { } found) { (dll, pdb) = (path, found); break; }
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
        }
        if (dll == null) { output.WriteLine("no System32 DLL with a local PDB: nothing to measure"); return; }
        using var dir = new TempDir();
        var copy = dir.File(Path.GetFileName(pdb!));
        File.Copy(pdb!, copy);
        var store = new AnnotationStore(dir.File("ann"));
        var options = new NetDecompilerMcp.Core.ServerOptions { WatchFiles = false, BackgroundIndexing = false };
        Environment.SetEnvironmentVariable("NDM_AUTO_PDB", "0"); // only the saved layer may name the second session
        try
        {
            int names;
            using (var ws = new NetDecompilerMcp.Core.AssemblyWorkspace(options))
            {
                var code = new NetDecompilerMcp.Services.NativeCodeService(ws, options, null, store);
                var native = ws.LoadAny(dll).Native!;
                var watch = Stopwatch.StartNew();
                var r = await new NetDecompilerMcp.Services.PdbService(code).Load(native, copy, false, null, false, TimeSpan.FromSeconds(5), 1 << 30, default);
                names = r.State!.Names.Count;
                output.WriteLine($"{Path.GetFileName(dll)}: load_pdb {pdb} {watch.Elapsed.TotalSeconds:0.00} s, {names} names, {r.State.FunctionStarts.Count} function starts; save problem: {r.SaveProblem ?? "none"}");
            }
            File.Delete(copy);
            var file = new FileInfo(Assert.Single(Directory.GetFiles(store.Root, "*.pdb.names")));
            output.WriteLine($"saved {file.Name}: {file.Length / 1024.0:0} KB");

            using var again = new NetDecompilerMcp.Core.AssemblyWorkspace(options);
            var code2 = new NetDecompilerMcp.Services.NativeCodeService(again, options, null, store);
            _ = new NetDecompilerMcp.Services.PdbService(code2);
            var native2 = again.LoadAny(dll).Native!;
            var w2 = Stopwatch.StartNew();
            code2.RestoreImported(native2);
            output.WriteLine($"restored in {w2.Elapsed.TotalSeconds:0.00} s");
            var index = await code2.Index(native2, null, default);
            output.WriteLine($"index with the restored names and starts in {w2.Elapsed.TotalSeconds:0.0} s: {index.Sourced.Count(NativeNameSource.Pdb)} pdb names, {index.Functions.Count} functions");
            Assert.Equal(names, index.Sourced.Count(NativeNameSource.Pdb));
        }
        finally { Environment.SetEnvironmentVariable("NDM_AUTO_PDB", null); }
    }
}
