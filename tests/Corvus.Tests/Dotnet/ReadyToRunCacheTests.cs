using Corvus.Core;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>Build-once caches (ReadyToRun, dumps, Il2Cpp, NativeAOT): a caller waiting for another's build stops when its call is cancelled.</summary>
public class ReadyToRunCacheTests(ITestOutputHelper output)
{
    [Fact]
    [Trait(PerfBudget.Trait, PerfBudget.Timing)]
    public async Task AWaiterStopsWhenCancelledAndTheBuildStillCompletes()
    {
        var once = new Once<int>();
        using var started = new ManualResetEventSlim();
        using var release = new ManualResetEventSlim();
        var builder = Task.Run(() => once.Get(() => { started.Set(); release.Wait(); return 42; }, default));
        Assert.True(started.Wait(10_000));

        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(100));
        var clock = System.Diagnostics.Stopwatch.StartNew();
        Assert.ThrowsAny<OperationCanceledException>(() => once.Get(() => throw new InvalidOperationException("built twice"), cts.Token));
        PerfBudget.Time("dotnet/once-cancelled-waiter", clock.Elapsed, TimeSpan.FromSeconds(5), output);

        release.Set();
        Assert.Equal(42, await builder);
        Assert.Equal(42, once.Get(() => throw new InvalidOperationException("built twice"), default));
    }

    [Fact]
    public void ABuildErrorReachesEveryCaller()
    {
        var once = new Once<int>();
        Assert.Throws<InvalidOperationException>(() => once.Get(() => throw new InvalidOperationException("bad image"), default));
        Assert.Equal("bad image", Assert.Throws<InvalidOperationException>(() => once.Get(() => 1, default)).Message);
    }

    /// <summary>Deferred (the minidump name tables, Il2Cpp string indexes, NativeAOT stages) builds once for concurrent readers.</summary>
    [Fact]
    public async Task DeferredBuildsOnceForConcurrentReaders()
    {
        int builds = 0;
        var deferred = new Deferred<int>(() => { Interlocked.Increment(ref builds); Thread.Sleep(50); return 7; });
        var values = await Task.WhenAll(Enumerable.Range(0, 8).Select(_ => Task.Run(() => deferred.Value)));
        Assert.All(values, v => Assert.Equal(7, v));
        Assert.Equal(1, builds);
    }
}
