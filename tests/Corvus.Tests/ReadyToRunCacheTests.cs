using Corvus.Services;

namespace Corvus.Tests;

/// <summary>The ReadyToRun caches build once; a caller waiting for another's build stops when its call is cancelled.</summary>
public class ReadyToRunCacheTests
{
    [Fact]
    public async Task AWaiterStopsWhenCancelledAndTheBuildStillCompletes()
    {
        var once = new ReadyToRunService.Once<int>();
        using var started = new ManualResetEventSlim();
        using var release = new ManualResetEventSlim();
        var builder = Task.Run(() => once.Get(() => { started.Set(); release.Wait(); return 42; }, default));
        Assert.True(started.Wait(10_000));

        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(100));
        var clock = System.Diagnostics.Stopwatch.StartNew();
        Assert.ThrowsAny<OperationCanceledException>(() => once.Get(() => throw new InvalidOperationException("built twice"), cts.Token));
        Assert.True(clock.Elapsed < TimeSpan.FromSeconds(5), $"waited {clock.Elapsed}");

        release.Set();
        Assert.Equal(42, await builder);
        Assert.Equal(42, once.Get(() => throw new InvalidOperationException("built twice"), default));
    }

    [Fact]
    public void ABuildErrorReachesEveryCaller()
    {
        var once = new ReadyToRunService.Once<int>();
        Assert.Throws<InvalidOperationException>(() => once.Get(() => throw new InvalidOperationException("bad image"), default));
        Assert.Equal("bad image", Assert.Throws<InvalidOperationException>(() => once.Get(() => 1, default)).Message);
    }
}
