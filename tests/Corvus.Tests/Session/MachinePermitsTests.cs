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
            // The holder lookup is waited for however long the machine's load makes it.
            var late = await Assert.ThrowsAsync<TimeoutException>(() => MachinePermits.TakeAsync(["one"], folder, counts, default, TimeSpan.FromMilliseconds(500),
                holderLookupLimit: Timeout.InfiniteTimeSpan));
            held.Dispose();
            Assert.Contains("No one permit within ", late.Message);
            Assert.Contains(Path.Combine(folder, "one", "slot-0") + " is held by ", late.Message);
            if (OperatingSystem.IsWindows()) Assert.Contains($"process {Environment.ProcessId} (", late.Message);
        }
        finally { Directory.Delete(folder, true); }
    }

    [Fact]
    public async Task A_holder_lookup_that_does_not_answer_leaves_the_holder_unknown_and_the_wait_ends()
    {
        var folder = Path.Combine(Path.GetTempPath(), $"corvus-permits-{Guid.NewGuid():N}");
        var counts = new Dictionary<string, int> { ["one"] = 1 };
        using var answer = new ManualResetEventSlim();
        try
        {
            var (held, _) = await MachinePermits.TakeAsync(["one"], folder, counts, default);
            var clock = Stopwatch.StartNew();
            // The lookup answers only after the test, as the Restart Manager can beside a whole run.
            var late = await Assert.ThrowsAsync<TimeoutException>(() => MachinePermits.TakeAsync(["one"], folder, counts, default, TimeSpan.FromMilliseconds(500),
                holders: _ => { answer.Wait(); return []; }, holderLookupLimit: TimeSpan.FromSeconds(1)).WaitAsync(TimeSpan.FromSeconds(30)));
            held.Dispose();
            Assert.Contains("No one permit within ", late.Message);
            if (OperatingSystem.IsWindows()) Assert.Contains(Path.Combine(folder, "one", "slot-0") + " is held by a process not known yet (the holder lookup took over 1 s)", late.Message);
            Assert.True(clock.Elapsed < TimeSpan.FromSeconds(25), $"{clock.Elapsed}");
        }
        finally
        {
            answer.Set();
            Directory.Delete(folder, true);
        }
    }

    [Fact]
    public async Task A_wait_outlasts_its_limit_while_the_holder_reports_progress()
    {
        using var steps = new SteppedWait();
        try
        {
            var (held, _) = await MachinePermits.TakeAsync(["one"], steps.Folder, steps.Counts, default);
            var waiter = steps.Wait();
            // Each step passes most of the limit on the waiter's clock, then reports progress.
            for (int i = 0; i < 4; i++)
            {
                await steps.Advance(TimeSpan.FromMilliseconds(500), held.Progress);
                Assert.False(waiter.IsCompleted, waiter.Exception?.InnerException?.Message);
            }
            held.Dispose();
            (await waiter.WaitAsync(TimeSpan.FromSeconds(30))).Held.Dispose();
        }
        finally { steps.Delete(); }
    }

    [Fact]
    public async Task A_script_hold_counts_as_progress_only_while_its_process_lives()
    {
        using var steps = new SteppedWait();
        try
        {
            // A script holds the slot as live-slot.ps1 does: the file open for exclusive use and an owner record.
            using (new FileStream(Path.Combine(steps.Dir, "slot-0"), FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None))
            {
                File.WriteAllText(Path.Combine(steps.Dir, "slot-0.owner"), $"{Environment.ProcessId} script");
                var waiter = steps.Wait();
                for (int i = 0; i < 4; i++)
                {
                    await steps.Advance(TimeSpan.FromMilliseconds(500), () => { });
                    Assert.False(waiter.IsCompleted, waiter.Exception?.InnerException?.Message);
                }

                var (shell, exit) = OperatingSystem.IsWindows() ? (Path.Combine(Environment.SystemDirectory, "cmd.exe"), "/c exit") : ("/bin/sh", "-c exit");
                using var ended = Process.Start(new ProcessStartInfo(shell, exit) { UseShellExecute = false, CreateNoWindow = true })!;
                await ended.WaitForExitAsync();
                await steps.Advance(TimeSpan.Zero, () => File.WriteAllText(Path.Combine(steps.Dir, "slot-0.owner"), $"{ended.Id} script"));
                steps.Pass(TimeSpan.FromMilliseconds(700));
                var late = await Assert.ThrowsAsync<TimeoutException>(() => waiter.WaitAsync(TimeSpan.FromSeconds(30)));
                Assert.Contains("without progress", late.Message);
            }
        }
        finally { steps.Delete(); }
    }

    [Fact]
    public async Task A_wait_outlasts_its_limit_while_the_holder_is_alive_in_one_long_test()
    {
        using var steps = new SteppedWait();
        try
        {
            // The holder reports nothing itself; only its 50 ms heartbeat rewrites the record.
            var (held, _) = await MachinePermits.TakeAsync(["one"], steps.Folder, steps.Counts, default, heartbeat: TimeSpan.FromMilliseconds(50));
            using (held)
            {
                var waiter = steps.Wait();
                for (int i = 0; i < 4; i++)
                {
                    var before = "";
                    Assert.True(SpinWait.SpinUntil(() => (before = steps.Record()).Length > 0, 30_000), "no record");
                    await steps.Advance(TimeSpan.FromMilliseconds(500), () => Assert.True(SpinWait.SpinUntil(() => steps.Record() is { Length: > 0 } r && r != before, 30_000), "no heartbeat"));
                    Assert.False(waiter.IsCompleted, waiter.Exception?.InnerException?.Message);
                }
                held.Dispose();
                (await waiter.WaitAsync(TimeSpan.FromSeconds(30))).Held.Dispose();
            }
        }
        finally { steps.Delete(); }
    }

    /// <summary>A wait on one slot with a 600 ms limit measured on a clock the test advances, naming holders found within 5 s.</summary>
    private sealed class SteppedWait : IDisposable
    {
        public readonly string Folder = Path.Combine(Path.GetTempPath(), $"corvus-permits-{Guid.NewGuid():N}");
        public readonly Dictionary<string, int> Counts = new() { ["one"] = 1 };
        private readonly SemaphoreSlim _polls = new(0);
        private TimeSpan _now;

        public SteppedWait() => Directory.CreateDirectory(Dir);

        public string Dir => Path.Combine(Folder, "one");

        public Task<(PermitHandle Held, TimeSpan Waited)> Wait() =>
            MachinePermits.TakeAsync(["one"], Folder, Counts, default, TimeSpan.FromMilliseconds(600), clock: () => _now, polled: () => _polls.Release(),
                holderLookupLimit: TimeSpan.FromSeconds(5));

        /// <summary>
        /// Moves the clock on, runs <paramref name="act"/>, then waits for two of the waiter's polls, so one checked the
        /// records after the act whatever the machine's load.
        /// </summary>
        public async Task Advance(TimeSpan by, Action act)
        {
            _now += by;
            act();
            while (_polls.CurrentCount > 0) await _polls.WaitAsync();
            for (int i = 0; i < 2; i++) Assert.True(await _polls.WaitAsync(TimeSpan.FromSeconds(30)), "the waiter stopped polling");
        }

        /// <summary>The slot's owner record; empty while its holder rewrites it.</summary>
        public string Record()
        {
            try
            {
                using var reader = new StreamReader(new FileStream(Path.Combine(Dir, "slot-0.owner"), FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete));
                return reader.ReadToEnd();
            }
            catch (IOException) { return ""; }
        }

        /// <summary>Moves the clock on without waiting for the waiter, which may end on its next poll.</summary>
        public void Pass(TimeSpan by) => _now += by;

        public void Delete() => Directory.Delete(Folder, true);

        public void Dispose() => _polls.Dispose();
    }
}
