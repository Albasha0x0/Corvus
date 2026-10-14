using System.Collections.Concurrent;
using Corvus.Core;
using Corvus.Services;

namespace Corvus.Tests;

/// <summary>Readers and writers hammer one workspace at the same time; nothing may throw or observe a half-applied edit.</summary>
// Cancellation latency is measured, so the class runs alone: on small CI runners parallel classes starve the thread pool.
[Collection(nameof(SerialTimingTests))]
public class ConcurrencyTests
{
    [Trait("Speed", "Slow")]
    [Fact]
    public async Task ReadersAndWritersInterleaveSafely()
    {
        using var env = new Env(withConsumer: true);
        var errors = new ConcurrentBag<Exception>();
        // A clock deadline and dedicated threads: a timer callback can starve on a busy thread pool.
        var deadline = System.Diagnostics.Stopwatch.StartNew();
        bool Running() => (deadline.Elapsed < TimeSpan.FromSeconds(5) || env.Fixture.Edits.Count <= 10)
                         && deadline.Elapsed < TimeSpan.FromSeconds(60) && env.Fixture.Edits.Count < 2_000;

        Task Loop(Action body) => Task.Factory.StartNew(() =>
        {
            while (Running())
            {
                try { body(); }
                catch (Exception ex) { errors.Add(ex); }
            }
        }, TaskCreationOptions.LongRunning);

        var readers = new[]
        {
            Loop(() => env.Workspace.Read(() => env.Decompiler.DecompileType(env.Fixture, env.Def<dnlib.DotNet.TypeDef>("Shop", SymbolKind.Type), default))),
            Loop(() => env.Workspace.Read(() => env.References.FindReferences(env.One("Account::_balance"), true, 100, default).Total)),
            Loop(() => env.Workspace.Read(() => env.Search.SearchStrings("LICENSE", false, env.Workspace.Assemblies, 10, default).Total)),
            Loop(() => env.Workspace.Read(() => env.Decompiler.Disassemble(env.Fixture, env.One("Account::Score").Member, default))),
        };
        int i = 0;
        string current = "Describe";
        var writer = Loop(() =>
        {
            var next = ++i % 2 == 0 ? "DescribeA" : "DescribeB";
            env.Edit(() => env.Edits.Rename(env.One("Shop::" + current), next));
            current = next;
            env.Edit(() => env.Edits.StubMethod(env.One("Account::Score"), (i % 100).ToString()));
        });

        await Task.WhenAll(readers.Append(writer));
        Assert.Empty(errors);
        Assert.True(env.Fixture.Edits.Count > 10);
    }

    /// <summary>
    /// An edit, a reload and an unload issued while export_project decompiles: none of them waits for the export, and the export
    /// finishes from the snapshot it took (the image before the edit), not from readers the writers replaced or disposed.
    /// </summary>
    [Fact]
    public Task EditReloadAndUnloadDuringAnExportLeaveItConsistent() => ExportRound(new Env(withConsumer: true), pauseAtFirstFile: true);

    /// <summary>The same with no pause, many times over: the writers land at random points of the export.</summary>
    [Trait("Speed", "Slow")]
    [Fact]
    public async Task ExportsStayConsistentUnderRepeatedEditsReloadsAndUnloads()
    {
        for (int round = 0; round < 150; round++)
            await ExportRound(new Env(withConsumer: true), pauseAtFirstFile: round % 2 == 0);
    }

    private static async Task ExportRound(Env env, bool pauseAtFirstFile)
    {
        using var _ = env;
        using var dir = new TempDir();
        var editTools = new Corvus.Tools.EditTools(env.Workspace, env.Edits, env.History, env.Decompiler, env.Pager);
        var workspaceTools = new Corvus.Tools.WorkspaceTools(env.Workspace, new Il2CppService(env.Workspace),
            new IndexingService(env.Workspace, new CallGraphService(env.Workspace), new ServerOptions()), new Corvus.Services.Analysis.UnpackService(env.Workspace));
        using var started = new ManualResetEventSlim();
        using var resume = new ManualResetEventSlim(!pauseAtFirstFile);
        // As export_project runs it: without the workspace lock.
        var export = Task.Run(() =>
        {
            var result = env.Decompiler.ExportProject(env.Fixture, dir.File("export"), (_, _, _) =>
            {
                started.Set();
                Assert.True(resume.Wait(30_000), "the writers did not finish while the export was paused");
            }, default);
            return $"{result.FileCount} files, {result.FailedTypes.Count} failed";
        });
        Assert.True(started.Wait(30_000), "the export reported no progress");

        var writers = Task.Run(async () => new[]
        {
            await editTools.StubMethod("Fixture.Model.Account::Score", "7", dryRun: false),
            await workspaceTools.ReloadAssembly("TestFixture.Consumer"),
            await workspaceTools.UnloadAssembly("TestFixture.Consumer"),
        });
        // Paused, the export holds no lock: the writers finish first.
        if (pauseAtFirstFile) Assert.True(await Task.WhenAny(writers, Task.Delay(30_000)) == writers, "a writer waited for the export");
        resume.Set();
        var outcome = await writers;
        Assert.Matches(@"^\d+ files, 0 failed$", await export);
        Assert.Contains("stub", outcome[0]);
        Assert.StartsWith("Reloaded", outcome[1]);
        Assert.StartsWith("Unloaded", outcome[2]);
        var sources = Directory.GetFiles(dir.File("export"), "*.cs", SearchOption.AllDirectories).Select(File.ReadAllText).ToList();
        Assert.Contains(sources, s => s.Contains("_balance * 2", StringComparison.Ordinal));
        Assert.Single(Directory.GetDirectories(dir.Path)); // no staging folder left
    }

    /// <summary>Holds the exclusive lock on a dedicated thread until the returned event is set.</summary>
    private static (Task Holder, ManualResetEventSlim Release) HoldWriteLock(AssemblyWorkspace workspace)
    {
        var entered = new ManualResetEventSlim();
        var release = new ManualResetEventSlim();
        var holder = Task.Factory.StartNew(() => workspace.Write(() => { entered.Set(); release.Wait(); return 0; }), TaskCreationOptions.LongRunning);
        Assert.True(entered.Wait(10_000));
        return (holder, release);
    }

    [Fact]
    public async Task QueuedLockWaitEndsWhenItsCallIsCancelled()
    {
        using var workspace = new AssemblyWorkspace();
        var (holder, release) = HoldWriteLock(workspace);
        try
        {
            using var cts = new CancellationTokenSource();
            var explicitToken = Task.Run(() => workspace.Read(() => 1, cts.Token));
            async Task<int> Call()
            {
                using var scope = AssemblyWorkspace.CancelWaitsWith(cts.Token);
                await Task.Yield();
                return workspace.Write(() => 2);
            }
            var ambient = Task.Run(Call);
            await Task.Delay(150);
            Assert.False(explicitToken.IsCompleted || ambient.IsCompleted);
            var watch = System.Diagnostics.Stopwatch.StartNew();
            cts.Cancel();
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => explicitToken);
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => ambient);
            Assert.True(watch.Elapsed < TimeSpan.FromSeconds(5), $"cancelled waits took {watch.Elapsed}");
        }
        finally
        {
            release.Set();
            await holder;
        }
        Assert.Equal(3, workspace.Read(() => 3));
    }

    [Fact]
    public async Task WorkLeftRunningAfterItsCallWaitsUncancellably()
    {
        using var workspace = new AssemblyWorkspace();
        using var cts = new CancellationTokenSource();
        Task<int> background;
        using (AssemblyWorkspace.CancelWaitsWith(cts.Token))
            background = Task.Run(async () => { await Task.Delay(200); return workspace.Read(() => 4); });
        var (holder, release) = HoldWriteLock(workspace);
        cts.Cancel();
        await Task.Delay(400);
        release.Set();
        await holder;
        Assert.Equal(4, await background);
    }

    [Fact]
    public async Task LongReadInSections_LetsAQueuedWriterIn()
    {
        using var workspace = new AssemblyWorkspace();
        var order = new ConcurrentQueue<char>();
        using var inside = new ManualResetEventSlim();
        var reader = Task.Run(() => workspace.ReadEach<int>(null, Enumerable.Range(0, 40).ToList(), _ =>
        {
            inside.Set();
            Thread.Sleep(10);
            order.Enqueue('r');
            return true;
        }, default));
        inside.Wait();
        var writer = Task.Run(() => workspace.Write(() => { order.Enqueue('w'); return 0; }));
        await Task.WhenAll(reader, writer);
        var seen = new string(order.ToArray());
        Assert.True(seen.IndexOf('w') < 30, seen); // in the first sections, not after the whole read
    }

    [Fact]
    public async Task MonitorWaitOfACall_EndsWhenTheCallIsCancelled()
    {
        var gate = new object();
        using var release = new ManualResetEventSlim();
        using var held = new ManualResetEventSlim();
        var holder = Task.Factory.StartNew(() =>
        {
            using (AssemblyWorkspace.Lock(gate)) { held.Set(); release.Wait(); }
        }, TaskCreationOptions.LongRunning);
        held.Wait();
        using var cts = new CancellationTokenSource();
        async Task Call()
        {
            using var scope = AssemblyWorkspace.CancelWaitsWith(cts.Token);
            await Task.Yield();
            using (AssemblyWorkspace.Lock(gate)) { }
        }
        var waiter = Task.Run(Call);
        await Task.Delay(100);
        Assert.False(waiter.IsCompleted);
        cts.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => waiter).WaitAsync(TimeSpan.FromSeconds(5));
        release.Set();
        await holder;
        using (AssemblyWorkspace.Lock(gate)) using (AssemblyWorkspace.Lock(gate)) { } // re-entrant
    }
}
