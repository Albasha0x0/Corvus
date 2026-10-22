using System.Text.Json.Nodes;
using Corvus.Native.Providers;
using Corvus.Native.Providers.Ghidra;

namespace Corvus.Tests;

/// <summary><see cref="GhidraSpareWorkers"/> with in-process workers, and the provider settings that turn spares and the worker root on.</summary>
public class GhidraSpareWorkersTests
{
    private static readonly TimeSpan StartTimeout = TimeSpan.FromMinutes(1);

    // Each test keys its own command: the pool is shared with the engine tests of the run.
    private static string NewCommand() => "test-" + Guid.NewGuid().ToString("N");

    private static async Task<WorkerConnection> Adopted(string command)
    {
        for (var clock = System.Diagnostics.Stopwatch.StartNew(); clock.Elapsed < TimeSpan.FromSeconds(30); await Task.Delay(20))
            if (GhidraSpareWorkers.Take(command) is { } spare) return spare;
        throw new TimeoutException("no spare was kept");
    }

    [Fact]
    public async Task A_spare_is_adopted_once_by_the_next_take()
    {
        var command = NewCommand();
        GhidraSpareWorkers.Use(command);
        using var first = new FakeWorkerProcess(ready: true);
        using var spareProcess = new FakeWorkerProcess(ready: true);
        GhidraSpareWorkers.Refill(command, () => spareProcess.Connect(null), first.Connect(null), StartTimeout);
        using var spare = await Adopted(command);
        Assert.True(spare.IsAlive);
        Assert.Null(GhidraSpareWorkers.Take(command));
        GhidraSpareWorkers.Release(command);
    }

    [Fact]
    public async Task A_spare_starts_only_after_the_worker_it_follows_is_ready()
    {
        var command = NewCommand();
        GhidraSpareWorkers.Use(command);
        using var first = new FakeWorkerProcess();
        using var spareProcess = new FakeWorkerProcess(ready: true);
        var launched = 0;
        GhidraSpareWorkers.Refill(command, () => { Interlocked.Increment(ref launched); return spareProcess.Connect(null); }, first.Connect(null), StartTimeout);
        await Task.Delay(300);
        Assert.Equal(0, Volatile.Read(ref launched));
        first.Emit(new JsonObject { ["event"] = "ready" });
        using var spare = await Adopted(command);
        Assert.Equal(1, Volatile.Read(ref launched));
        GhidraSpareWorkers.Release(command);
    }

    [Fact]
    public async Task A_spare_ends_after_its_last_provider_releases_it()
    {
        var command = NewCommand();
        GhidraSpareWorkers.Use(command);
        using var first = new FakeWorkerProcess(ready: true);
        using var spareProcess = new FakeWorkerProcess(ready: true);
        var kept = new TaskCompletionSource<WorkerConnection>();
        GhidraSpareWorkers.Refill(command, () => { var w = spareProcess.Connect(null); kept.SetResult(w); return w; }, first.Connect(null), StartTimeout);
        var spare = await kept.Task.WaitAsync(TimeSpan.FromSeconds(30));
        await spare.Ready.WaitAsync(TimeSpan.FromSeconds(30));
        // The pool stores the spare just after its ready event.
        await Task.Delay(200);
        GhidraSpareWorkers.Release(command, TimeSpan.FromMilliseconds(100));
        Assert.Same(spare.Closed, await Task.WhenAny(spare.Closed, Task.Delay(TimeSpan.FromSeconds(30))));
        Assert.Null(GhidraSpareWorkers.Take(command));
    }

    [Fact]
    public async Task Ending_the_pool_ends_a_spare_that_is_still_starting()
    {
        var command = NewCommand();
        GhidraSpareWorkers.Use(command);
        using var first = new FakeWorkerProcess(ready: true);
        // This spare never sends its ready event, so it is still starting when the pool ends.
        using var spareProcess = new FakeWorkerProcess();
        var launched = new TaskCompletionSource<WorkerConnection>();
        GhidraSpareWorkers.Refill(command, () => { var w = spareProcess.Connect(null); launched.SetResult(w); return w; }, first.Connect(null), StartTimeout);
        var spare = await launched.Task.WaitAsync(TimeSpan.FromSeconds(30));
        GhidraSpareWorkers.EndAll(TimeSpan.FromSeconds(30), command);
        Assert.True(spareProcess.HasExited);
        Assert.False(spare.IsAlive);
        Assert.Null(GhidraSpareWorkers.Take(command));
        GhidraSpareWorkers.Release(command);
    }

    [Theory]
    [InlineData(null, false)]
    [InlineData("", false)]
    [InlineData("off", false)]
    [InlineData("on", true)]
    [InlineData(" Yes ", true)]
    [InlineData("1", true)]
    public void Spare_workers_are_off_unless_turned_on(string? value, bool expected) =>
        Assert.Equal(expected, GhidraOptions.SpareWorker(value));

    [Fact]
    public void A_worker_root_keeps_the_worker_folders_apart_from_the_cache()
    {
        using var dir = new TempDir();
        using var provider = new GhidraProvider(new GhidraProviderOptions { CacheRoot = dir.File("cache"), WorkerRoot = dir.File("workers") });
        Assert.Equal(Path.Combine(dir.File("workers"), "base"), provider.Directories.Root);
        Assert.Equal(Path.Combine(dir.File("cache"), GhidraProvider.ProviderId), provider.CacheDirectory);
    }
}
