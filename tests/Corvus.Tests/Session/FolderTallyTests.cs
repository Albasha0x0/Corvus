using Corvus.Core;

namespace Corvus.Tests;

/// <summary>Status reports never wait long for a folder's size: a slow first count is reported as being counted.</summary>
public class FolderTallyTests
{
    [Fact]
    [Trait(PerfBudget.Trait, PerfBudget.Timing)]
    public void A_slow_count_is_reported_as_being_counted_and_kept_once_done()
    {
        var folder = "tally-" + Guid.NewGuid().ToString("N");
        using var release = new ManualResetEventSlim();
        var clock = System.Diagnostics.Stopwatch.StartNew();
        var first = FolderTally.Of(folder, () => { release.Wait(); return (7, 70); });
        Assert.Equal((-1, -1L), first);
        Assert.True(clock.Elapsed.TotalSeconds >= 1.5, $"answered after {clock.Elapsed}");
        PerfBudget.Check(clock.Elapsed.TotalSeconds <= 10, $"answered after {clock.Elapsed}");
        release.Set();
        SpinWait.SpinUntil(() => FolderTally.Of(folder, () => (0, 0)) != (-1, -1L), TimeSpan.FromSeconds(10));
        Assert.Equal((7, 70L), FolderTally.Of(folder, () => (0, 0)));
        Assert.Equal("results being counted", FolderTally.Text(-1, -1, b => $"{b} B", "results"));
    }
}
