using Corvus.Core;

namespace Corvus.Tests;

public class WorkspaceTests
{
    [Fact]
    public void DirectoryLoadSkipsNonDotNetAndDoesNotLockFiles()
    {
        using var dir = new TempDir();
        var copy = dir.File("TestFixture.dll");
        File.Copy(Env.FixturePath, copy);
        File.WriteAllText(dir.File("native.dll"), "not a PE file");
        Directory.CreateDirectory(dir.File("sub"));
        File.Copy(Env.ConsumerPath, dir.File("sub/TestFixture.Consumer.dll"));

        using var ws = new AssemblyWorkspace();
        var progress = new List<int>();
        var report = ws.LoadDirectory(dir.Path, recursive: false, (done, _, _) => progress.Add(done));
        Assert.Single(report.Loaded);
        Assert.Single(report.Skipped);
        Assert.Equal([0, 1], progress);
        Assert.Same(report.Loaded[0], ws.Load(copy)); // idempotent
        File.Copy(Env.FixturePath, copy, overwrite: true); // not locked

        var recursive = ws.LoadDirectory(dir.Path, recursive: true);
        Assert.Contains(recursive.Loaded, a => a.Id == "TestFixture.Consumer");
    }

    [Fact]
    public void DuplicateNamesGetDistinctIdsAndAmbiguityIsReported()
    {
        using var dir = new TempDir();
        var copy = dir.File("TestFixture.dll");
        File.Copy(Env.FixturePath, copy);
        using var ws = new AssemblyWorkspace();
        var a = ws.Load(Env.FixturePath);
        var b = ws.Load(copy);
        Assert.Equal("TestFixture", a.Id);
        Assert.Equal("TestFixture#2", b.Id);
        Assert.Throws<ToolError>(() => ws.Read(() => SymbolResolver.ResolveOne(ws, null, "Account", SymbolKind.Type)));
        Assert.Same(b, ws.Read(() => SymbolResolver.ResolveOne(ws, "TestFixture#2", "Account", SymbolKind.Type)).Assembly);
        Assert.Same(b, ws.Get(copy)); // by full path
        Assert.Throws<ToolError>(() => ws.Get("TestFixture.dll")); // file name matches both
    }

    [Fact]
    public void GetByIdFileNameAndPath()
    {
        using var ws = new AssemblyWorkspace();
        var a = ws.Load(Env.FixturePath);
        Assert.Same(a, ws.Get("testfixture"));
        Assert.Same(a, ws.Get("TestFixture.dll"));
        Assert.Same(a, ws.Get(Env.FixturePath));
        Assert.Throws<ToolError>(() => ws.Get(" "));
    }

    [Fact]
    public void ErrorsForMissingAndInvalidInput()
    {
        using var ws = new AssemblyWorkspace();
        Assert.Contains("No assemblies are loaded", Assert.Throws<ToolError>(() => ws.Get("x")).Message);
        Assert.Contains("No assemblies are loaded", Assert.Throws<ToolError>(() => ws.Scope(null)).Message);
        Assert.Contains("File not found", Assert.Throws<ToolError>(() => ws.Load(@"C:\nope\missing.dll")).Message);
        Assert.Throws<ToolError>(() => ws.LoadDirectory(@"C:\nope\missing", false));
        Assert.Throws<ToolError>(() => ws.AddSearchDirectory(@"C:\nope\missing"));
        using var dir = new TempDir();
        File.WriteAllText(dir.File("bad.dll"), "not an assembly");
        Assert.Contains("Not a loadable .NET assembly", Assert.Throws<ToolError>(() => ws.Load(dir.File("bad.dll"))).Message);
    }

    [Fact]
    public void OnlyNativeImagesLoadedSaysSoAndPointsToTheNativeTools()
    {
        using var ws = new AssemblyWorkspace();
        ws.LoadAny(NativeFormats.NativeFixtures.WinArm64DbgShim);
        foreach (var error in new[] { Assert.Throws<ToolError>(() => ws.Scope(null)), Assert.Throws<ToolError>(() => ws.Get("Other")) })
        {
            Assert.Equal(ErrorCode.NotLoaded, error.Code);
            Assert.Contains("only native images (dbgshim.dll)", error.Message);
            Assert.Contains("native:<image>!<function>", error.Remediation);
        }
    }

    [Fact]
    public async Task Dispose_waits_for_calls_holding_or_queued_for_the_lock()
    {
        // Regression: CI on b8f374e0 threw SynchronizationLockException here.
        var ws = new AssemblyWorkspace();
        using var held = new ManualResetEventSlim();
        using var release = new ManualResetEventSlim();
        var reader = Task.Run(() => ws.Read(() => { held.Set(); release.Wait(); return 0; }));
        held.Wait();
        var writer = Task.Run(() => ws.Write(() => 1));
        SpinWait.SpinUntil(() => ws.Waiting.Writers == 1);

        var dispose = Task.Run(ws.Dispose);
        Assert.NotSame(dispose, await Task.WhenAny(dispose, Task.Delay(200)));
        release.Set();
        await dispose;
        Assert.Equal((0, 1), (await reader, await writer));
        Assert.Throws<ObjectDisposedException>(() => ws.Read(() => 0));
    }

    [Fact]
    public void Dispose_inside_the_callers_own_lock_returns_without_waiting()
    {
        var ws = new AssemblyWorkspace();
        var watch = System.Diagnostics.Stopwatch.StartNew();
        ws.Read(() => { ws.Dispose(); return 0; });
        // The elapsed time is the only sign that dispose skipped its wait; half of DisposeWait (10 s) leaves a wide margin.
        Assert.True(watch.Elapsed < ws.DisposeWait / 2);
        Assert.Throws<ObjectDisposedException>(() => ws.Write(() => 0));
    }

    [Fact]
    public async Task A_call_still_in_the_lock_after_the_dispose_wait_keeps_its_assemblies_until_it_leaves()
    {
        // Regression: a push run on d055446d ended with an access violation in background indexing after a dispose.
        var ws = new AssemblyWorkspace { DisposeWait = TimeSpan.FromMilliseconds(100) };
        var asm = ws.Load(Env.FixturePath);
        using var held = new ManualResetEventSlim();
        using var release = new ManualResetEventSlim();
        var reader = Task.Run(() => ws.Read(() =>
        {
            held.Set();
            release.Wait();
            return asm.Module.GetTypes().SelectMany(t => t.Methods).Count(m => FastIlReader.Read(asm, m) != null);
        }));
        held.Wait();

        ws.Dispose();
        Assert.False(asm.IsDisposed);
        release.Set();
        Assert.True(await reader > 0);
        Assert.True(asm.IsDisposed);
        Assert.Throws<ObjectDisposedException>(() => ws.Read(() => 0));
    }

    [Fact]
    public void UnloadAndGenerationInvalidation()
    {
        using var ws = new AssemblyWorkspace();
        var a = ws.Load(Env.FixturePath);
        int generation = ws.Generation;
        ws.Load(Env.ConsumerPath);
        Assert.True(ws.Generation > generation);
        ws.Unload(a);
        Assert.Single(ws.Assemblies);
    }

    [Fact]
    public void ResolvesReferencesFromSearchPathAndRuntime()
    {
        using var ws = new AssemblyWorkspace();
        ws.Load(Env.ConsumerPath); // TestFixture is next to it -> found via the auto-added search directory
        Assert.NotNull(ws.FindAssemblyFile("TestFixture"));
        Assert.NotNull(ws.FindAssemblyFile("System.Runtime")); // runtime directory fallback
        Assert.Null(ws.FindAssemblyFile("Definitely.Not.Here"));
    }

    [Fact]
    public void PagerSplitsOnLinesCachesAndPagesRows()
    {
        var pager = new OutputPager(new ServerOptions { MaxOutputChars = 2_000 });
        var text = string.Join("\n", Enumerable.Range(0, 500).Select(i => $"line {i:D4}"));
        var first = pager.Page(text);
        Assert.Contains("\n[More: offset=", first);
        int next = int.Parse(System.Text.RegularExpressions.Regex.Match(first, @"offset=(\d+)").Groups[1].Value);
        Assert.Equal('\n', text[next - 1]);
        Assert.StartsWith($"[Continuing from offset {next}]", pager.Page(text, next));
        Assert.Throws<ToolError>(() => pager.Page(text, text.Length + 5));
        Assert.Equal("short", pager.Page("short"));

        int calls = 0;
        pager.GetOrCreate("k", () => { calls++; return "v"; });
        pager.GetOrCreate("k", () => { calls++; return "v"; });
        Assert.Equal(1, calls);

        var rows = Enumerable.Range(0, 10).Select(i => $"row{i}").ToList();
        var page = pager.PageRows(rows, 2, 3, "row");
        Assert.Contains("10 rows (showing 3-5)", page);
        Assert.Contains("offset=5", page);
    }

    [Fact]
    public void ServerOptionsParsing()
    {
        var o = ServerOptions.Parse(["--load", "a.dll", "--load", "b", "--search-dir", "c", "--max-output", "5000", "--timeout", "30"]);
        Assert.Equal(["a.dll", "b"], o.Preload.Take(2));
        Assert.Equal(["c"], o.SearchDirectories);
        Assert.Equal(5000, o.MaxOutputChars);
        Assert.Equal(30, o.TimeoutSeconds);
        Assert.Throws<ArgumentException>(() => ServerOptions.Parse(["--bogus"]));
        Assert.Throws<ArgumentException>(() => ServerOptions.Parse(["--load"]));
    }

    [Fact]
    public void AttachSpawnAndScripting_EachTurnOnTheSessionTools()
    {
        Assert.False(new ServerOptions().AllowLive);
        Assert.True(new ServerOptions { AllowLiveAttach = true }.AllowLive);
        Assert.True(new ServerOptions { AllowLiveSpawn = true }.AllowLive);
        Assert.True(new ServerOptions { LiveScripting = true }.AllowLive);
        var o = ServerOptions.Parse(["--allow-live-attach"]);
        Assert.True(o.AllowLive);
        Assert.True(o.AllowLiveAttach);
        Assert.False(o.AllowLiveSpawn);
    }
}
