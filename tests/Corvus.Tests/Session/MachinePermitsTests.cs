using System.Diagnostics;

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

    [Fact]
    public async Task A_wait_without_progress_past_its_limit_names_the_slot_and_its_holder()
    {
        var folder = Path.Combine(Path.GetTempPath(), $"corvus-permits-{Guid.NewGuid():N}");
        var counts = new Dictionary<string, int> { ["one"] = 1 };
        try
        {
            var (held, _) = await MachinePermits.TakeAsync(["one"], folder, counts, default);
            var late = await Assert.ThrowsAsync<TimeoutException>(() => MachinePermits.TakeAsync(["one"], folder, counts, default, TimeSpan.FromMilliseconds(500)));
            held.Dispose();
            Assert.Contains("No one permit within ", late.Message);
            Assert.Contains(Path.Combine(folder, "one", "slot-0") + " is held by ", late.Message);
            if (OperatingSystem.IsWindows()) Assert.Contains($"process {Environment.ProcessId} (", late.Message);
        }
        finally { Directory.Delete(folder, true); }
    }

    [Fact]
    public async Task A_wait_outlasts_its_limit_while_the_holder_reports_progress()
    {
        var folder = Path.Combine(Path.GetTempPath(), $"corvus-permits-{Guid.NewGuid():N}");
        var counts = new Dictionary<string, int> { ["one"] = 1 };
        try
        {
            var (held, _) = await MachinePermits.TakeAsync(["one"], folder, counts, default);
            var waiter = MachinePermits.TakeAsync(["one"], folder, counts, default, TimeSpan.FromMilliseconds(600));
            // The holder finishes a unit of work every 150 ms for three times the waiter's limit.
            for (int i = 0; i < 12; i++)
            {
                await Task.Delay(150);
                held.Progress();
            }
            Assert.False(waiter.IsCompleted, waiter.Exception?.InnerException?.Message);
            held.Dispose();
            var (next, waited) = await waiter.WaitAsync(TimeSpan.FromSeconds(30));
            next.Dispose();
            Assert.True(waited >= TimeSpan.FromMilliseconds(1500), $"{waited}");
        }
        finally { Directory.Delete(folder, true); }
    }

    [Fact]
    public async Task A_script_hold_counts_as_progress_only_while_its_process_lives()
    {
        var folder = Path.Combine(Path.GetTempPath(), $"corvus-permits-{Guid.NewGuid():N}");
        var counts = new Dictionary<string, int> { ["one"] = 1 };
        var dir = Path.Combine(folder, "one");
        Directory.CreateDirectory(dir);
        try
        {
            // A script holds the slot as live-slot.ps1 does: the file open for exclusive use and an owner record.
            using (new FileStream(Path.Combine(dir, "slot-0"), FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None))
            {
                File.WriteAllText(Path.Combine(dir, "slot-0.owner"), $"{Environment.ProcessId} script");
                var waiter = MachinePermits.TakeAsync(["one"], folder, counts, default, TimeSpan.FromMilliseconds(600));
                await Task.Delay(1800);
                Assert.False(waiter.IsCompleted, waiter.Exception?.InnerException?.Message);

                var (shell, exit) = OperatingSystem.IsWindows() ? (Path.Combine(Environment.SystemDirectory, "cmd.exe"), "/c exit") : ("/bin/sh", "-c exit");
                using var ended = Process.Start(new ProcessStartInfo(shell, exit) { UseShellExecute = false, CreateNoWindow = true })!;
                await ended.WaitForExitAsync();
                File.WriteAllText(Path.Combine(dir, "slot-0.owner"), $"{ended.Id} script");
                var late = await Assert.ThrowsAsync<TimeoutException>(() => waiter.WaitAsync(TimeSpan.FromSeconds(30)));
                Assert.Contains("without progress", late.Message);
            }
        }
        finally { Directory.Delete(folder, true); }
    }

    [Fact]
    public async Task A_wait_outlasts_its_limit_while_the_holder_is_alive_in_one_long_test()
    {
        var folder = Path.Combine(Path.GetTempPath(), $"corvus-permits-{Guid.NewGuid():N}");
        var counts = new Dictionary<string, int> { ["one"] = 1 };
        try
        {
            // The holder reports nothing itself; only its 150 ms heartbeat runs.
            var (held, _) = await MachinePermits.TakeAsync(["one"], folder, counts, default, heartbeat: TimeSpan.FromMilliseconds(150));
            var waiter = MachinePermits.TakeAsync(["one"], folder, counts, default, TimeSpan.FromMilliseconds(600));
            await Task.Delay(1800);
            Assert.False(waiter.IsCompleted, waiter.Exception?.InnerException?.Message);
            held.Dispose();
            var (next, _) = await waiter.WaitAsync(TimeSpan.FromSeconds(30));
            next.Dispose();
        }
        finally { Directory.Delete(folder, true); }
    }
}
