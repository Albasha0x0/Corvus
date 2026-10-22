namespace Corvus.Tests;

/// <summary>MachinePermits: slot files bound a resource across test processes.</summary>
public class MachinePermitsTests
{
    [Fact]
    public async Task A_taken_permit_is_waited_for_until_its_holder_releases_it()
    {
        var folder = Path.Combine(Path.GetTempPath(), $"corvus-permits-{Guid.NewGuid():N}");
        var counts = new Dictionary<string, int> { ["one"] = 1, ["two"] = 2 };
        try
        {
            var (first, firstWait) = await MachinePermits.TakeAsync(["one", "two"], folder, counts, default);
            var (second, _) = await MachinePermits.TakeAsync(["two"], folder, counts, default);
            var third = MachinePermits.TakeAsync(["one"], folder, counts, default);
            await Task.Delay(TimeSpan.FromMilliseconds(600));
            Assert.False(third.IsCompleted);
            first.Dispose();
            var (held, waited) = await third.WaitAsync(TimeSpan.FromSeconds(30));
            Assert.True(waited >= TimeSpan.FromMilliseconds(500), $"{waited}");
            Assert.True(firstWait < waited, $"{firstWait}");
            held.Dispose();
            second.Dispose();
        }
        finally { Directory.Delete(folder, true); }
    }

    [Fact]
    public async Task A_cancelled_wait_releases_the_permits_it_took()
    {
        var folder = Path.Combine(Path.GetTempPath(), $"corvus-permits-{Guid.NewGuid():N}");
        var counts = new Dictionary<string, int> { ["a"] = 1, ["b"] = 1 };
        try
        {
            var (b, _) = await MachinePermits.TakeAsync(["b"], folder, counts, default);
            using var cancel = new CancellationTokenSource(TimeSpan.FromMilliseconds(300));
            await Assert.ThrowsAnyAsync<OperationCanceledException>(() => MachinePermits.TakeAsync(["a", "b"], folder, counts, cancel.Token));
            // The permit of "a" taken before the wait on "b" was released, so it is free again.
            var (a, _) = await MachinePermits.TakeAsync(["a"], folder, counts, default).WaitAsync(TimeSpan.FromSeconds(30));
            a.Dispose();
            b.Dispose();
        }
        finally { Directory.Delete(folder, true); }
    }
}
