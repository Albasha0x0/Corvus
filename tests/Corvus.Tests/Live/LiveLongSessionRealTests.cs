using System.Diagnostics;
using System.Globalization;
using System.Runtime.CompilerServices;
using System.Text.RegularExpressions;
using Corvus.Services;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>
/// Sessions over time on a native program per target: a watched program observed for minutes (status latency, cursor
/// continuity of the event pages, a stop point each minute, the test process's memory growth), the session deadline
/// closing a session by itself, and two sessions at once. The first two run in a process of their own: one measures the
/// process's heap and working set, the other sets a variable of the process.
/// </summary>
[Trait("Speed", "Slow")]
[Trait("Data", "Real")]
[Permit("live")]
public sealed class LiveLongSessionRealTests(ITestOutputHelper output) : LiveToolCalls(output), IDisposable
{
    /// <summary>Minutes the observed program runs under its session (default 2).</summary>
    public const string SoakMinutesVariable = "CORVUS_LIVE_SOAK_MINUTES";

    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    private static long Number(string digits) => long.Parse(digits.Replace(",", ""), CultureInfo.InvariantCulture);

    // ---- a watched program observed for minutes

    [LiveTargetFact("win-x64")] [Trait(PerfBudget.Trait, PerfBudget.Timing)] public Task Observed_for_minutes_on_win_x64() => Observed(LiveTarget.WinX64);
    // The server's memory over minutes is the same on both Windows targets; the second runs at release strength.
    [LiveTargetFact("win-x86")] [Trait(PerfBudget.Trait, PerfBudget.Timing)] [Trait("Tier", "Release")] public Task Observed_for_minutes_on_win_x86() => Observed(LiveTarget.WinX86);
    [LiveTargetFact("win-arm64")] [Trait(PerfBudget.Trait, PerfBudget.Timing)] public Task Observed_for_minutes_on_win_arm64() => Observed(LiveTarget.WinArm64);
    [LiveTargetFact("linux-x64")] [Trait(PerfBudget.Trait, PerfBudget.Timing)] public Task Observed_for_minutes_on_linux_x64() => Observed(LiveTarget.LinuxX64);
    [LiveTargetFact("linux-x86")] [Trait(PerfBudget.Trait, PerfBudget.Timing)] public Task Observed_for_minutes_on_linux_x86() => Observed(LiveTarget.LinuxX86);

    private async Task Observed(LiveTarget target, [CallerMemberName] string test = "")
    {
        if (ChildTest.Rerun(this, Output, method: test)) return;
        var minutes = double.TryParse(Environment.GetEnvironmentVariable(SoakMinutesVariable), NumberStyles.Float, CultureInfo.InvariantCulture, out var m) && m > 0 ? m : 2;
        var exe = target.Build(_dir, "orders", LivePrograms.Orders);
        var name = Regex.Escape(target.Exe("orders"));
        using var self = Process.GetCurrentProcess();
        await using var server = await Server();

        var pid = await Spawn(server, exe, "live-1", "100000000", "1");
        Assert.Contains("w1", await Ok(server, "live_watch", new() { ["session"] = "live-1", ["action"] = "set", ["at"] = "AddLine", ["rateLimit"] = 200 }));
        await Ok(server, "live_break", new() { ["session"] = "live-1", ["action"] = "continue" });

        var clock = Stopwatch.StartNew();
        long? cursor = null;
        long events = 0, calls = 0, dropped = 0, slowest = 0;
        int statuses = 0, stops = 0;
        long heap0 = 0, workingSet0 = 0;
        var nextStop = TimeSpan.FromSeconds(30);
        while (clock.Elapsed < TimeSpan.FromMinutes(minutes))
        {
            var sw = Stopwatch.StartNew();
            var status = await Ok(server, "live_session", new() { ["action"] = "status", ["session"] = "live-1" }, log: false);
            slowest = Math.Max(slowest, sw.ElapsedMilliseconds);
            statuses++;
            PerfBudget.Time($"live/long-session-status/{target.Name}", sw.Elapsed, TimeSpan.FromSeconds(2), Output);
            Assert.Contains($"pid {pid}, running", status);

            // Every page continues where the last one ended; its gaps add up to what its drop markers count.
            for (int page = 0; page < 1_000; page++)
            {
                var args = new Dictionary<string, object?> { ["session"] = "live-1", ["limit"] = 1_000 };
                if (cursor != null) args["cursor"] = $"{cursor}";
                var text = await Ok(server, "live_events", args, log: false);
                long lost = Regex.Matches(text, @"(?m)^([\d,]+) (?:call )?events? dropped \(ring capacity").Sum(g => Number(g.Groups[1].Value));
                var rows = Regex.Matches(text, @"(?m)^#(\d+) (\w+)").Select(r => (Seq: Number(r.Groups[1].Value), Kind: r.Groups[2].Value)).ToList();
                if (rows.Count == 0) break; // "No events.": the cursor stays
                long gaps = rows[0].Seq - (cursor ?? 1);
                for (int i = 1; i < rows.Count; i++) gaps += rows[i].Seq - rows[i - 1].Seq - 1;
                Assert.True(gaps == lost, $"page after cursor {cursor} misses {gaps} events, its drop markers count {lost}:\n{text[..Math.Min(text.Length, 2_000)]}");
                dropped += lost;
                events += rows.Count;
                calls += rows.Count(r => r.Kind == "call");
                var next = Regex.Match(text, @"(more: |poll again with )cursor=(\d+)");
                Assert.True(next.Success, text[..Math.Min(text.Length, 2_000)]);
                Assert.Equal(rows[^1].Seq + 1, Number(next.Groups[2].Value));
                cursor = Number(next.Groups[2].Value);
                if (!next.Groups[1].Value.StartsWith("more", StringComparison.Ordinal)) break;
            }

            // the baseline once the session is set up: images loaded, the watch placed, the first events read
            if (statuses == 1) (heap0, workingSet0) = Memory(self);

            // once a minute: a stop point set, hit, read, cleared, and the thread continued
            if (clock.Elapsed >= nextStop)
            {
                nextStop += TimeSpan.FromMinutes(1);
                stops++;
                var set = await Ok(server, "live_break", new() { ["session"] = "live-1", ["action"] = "set", ["at"] = "AddLine" });
                var point = Regex.Match(set, @"(s\d+) set at").Groups[1].Value;
                Assert.False(point.Length == 0, set);
                var stop = await Ok(server, "live_break", new() { ["session"] = "live-1", ["wait"] = true, ["waitSeconds"] = 30 });
                Assert.Matches($@"thread \d+ stopped at {point} \({name}!AddLine\)", stop);
                Assert.Matches($@"pc +0x[0-9a-f]+  {name}!AddLine", await Ok(server, "live_read", new() { ["session"] = "live-1", ["registers"] = "pc" }));
                Assert.Contains($"{point} cleared", await Ok(server, "live_break", new() { ["session"] = "live-1", ["action"] = "clear", ["stopPoint"] = point }));
                Assert.Contains("resumed thread(s)", await Ok(server, "live_break", new() { ["session"] = "live-1", ["action"] = "continue" }));
            }
            await Task.Delay(3_000);
        }

        var watches = await Ok(server, "live_watch", new() { ["session"] = "live-1" });
        var w = Regex.Match(watches, @"w1 [^:]+: ([\d,]+) call\(s\) recorded(?:.*?, ([\d,]+) over the rate limit)?");
        Assert.True(w.Success, watches);
        long recorded = Number(w.Groups[1].Value), over = w.Groups[2].Success ? Number(w.Groups[2].Value) : 0;
        var (heap1, workingSet1) = Memory(self);
        Output.WriteLine($"observed {clock.Elapsed.TotalMinutes:F1} min: {recorded:N0} call(s) recorded, {over:N0} over the rate limit; " +
                         $"{events:N0} events read ({calls:N0} calls), {dropped:N0} dropped; {stops} stop(s); {statuses} status calls, slowest {slowest} ms; " +
                         $"managed heap {heap0 / 1048576.0:F1} -> {heap1 / 1048576.0:F1} MB, working set {workingSet0 / 1048576.0:F1} -> {workingSet1 / 1048576.0:F1} MB");
        Assert.True(stops >= 1 && recorded > 0 && calls > 0);
        Assert.True(heap1 - heap0 < 300L << 20, $"managed heap grew {(heap1 - heap0) >> 20} MB");
        Assert.True(workingSet1 - workingSet0 < 300L << 20, $"working set grew {(workingSet1 - workingSet0) >> 20} MB");

        Assert.Contains($"pid {pid}, closed", await Ok(server, "live_session", new() { ["action"] = "close", ["session"] = "live-1" }));
        Ended(pid);
    }

    private static (long Heap, long WorkingSet) Memory(Process self)
    {
        GC.Collect();
        GC.WaitForPendingFinalizers();
        var heap = GC.GetTotalMemory(forceFullCollection: true);
        self.Refresh();
        return (heap, self.WorkingSet64);
    }

    // ---- the session deadline

    [LiveTargetFact("win-x64")] public Task Deadline_closes_the_session_on_win_x64() => Deadline(LiveTarget.WinX64);
    // The deadline is the server's own timer; the second Windows target runs at release strength.
    [LiveTargetFact("win-x86")] [Trait("Tier", "Release")] public Task Deadline_closes_the_session_on_win_x86() => Deadline(LiveTarget.WinX86);
    [LiveTargetFact("win-arm64")] public Task Deadline_closes_the_session_on_win_arm64() => Deadline(LiveTarget.WinArm64);
    [LiveTargetFact("linux-x64")] public Task Deadline_closes_the_session_on_linux_x64() => Deadline(LiveTarget.LinuxX64);
    [LiveTargetFact("osx-arm64")] public Task Deadline_closes_the_session_on_osx_arm64() => Deadline(LiveTarget.MacArm64);
    [LiveTargetFact("linux-x86")] public Task Deadline_closes_the_session_on_linux_x86() => Deadline(LiveTarget.LinuxX86);

    private async Task Deadline(LiveTarget target, [CallerMemberName] string test = "")
    {
        if (ChildTest.Rerun(this, Output, method: test)) return;
        var exe = target.Build(_dir, "orders", LivePrograms.Orders);
        await using var server = await Server();
        // read when the session opens; the process is this test's own, so the variable is set for this open only
        var saved = Environment.GetEnvironmentVariable(LiveSessionService.MaxMinutesVariable);
        int pid;
        Environment.SetEnvironmentVariable(LiveSessionService.MaxMinutesVariable, "1");
        try { pid = await Spawn(server, exe, "live-1", "100000000", "1"); }
        finally { Environment.SetEnvironmentVariable(LiveSessionService.MaxMinutesVariable, saved); }
        var clock = Stopwatch.StartNew();
        await Ok(server, "live_break", new() { ["session"] = "live-1", ["action"] = "continue" });

        string status = "";
        while (clock.Elapsed < TimeSpan.FromSeconds(120))
        {
            status = (await Call(server, "live_session", new() { ["action"] = "status", ["session"] = "live-1" })).Text;
            if (status.Contains(", closed")) break;
            await Task.Delay(1_000);
        }
        Output.WriteLine($"closed after {clock.Elapsed.TotalSeconds:F1} s");
        Assert.Contains($"pid {pid}, closed", status);
        Assert.InRange(clock.Elapsed.TotalSeconds, 55, 90);
        Ended(pid);
        // the close's own event follows the state, once the session's worker has shut down
        string exits = "";
        for (int i = 0; i < 100 && !exits.Contains("session closed (deadline)"); i++)
        {
            exits = await Events(server, "live-1", kind: "exit", log: false);
            await Task.Delay(100);
        }
        Assert.Contains("session closed (deadline)", exits);
        Assert.Contains("deadline", status);
    }

    // ---- two sessions at once

    [LiveTargetFact("win-x64")] public Task Two_sessions_on_win_x64() => TwoSessions(LiveTarget.WinX64);
    [LiveTargetFact("win-x86")] public Task Two_sessions_on_win_x86() => TwoSessions(LiveTarget.WinX86);
    [LiveTargetFact("win-arm64")] public Task Two_sessions_on_win_arm64() => TwoSessions(LiveTarget.WinArm64);
    [LiveTargetFact("linux-x64")] public Task Two_sessions_on_linux_x64() => TwoSessions(LiveTarget.LinuxX64);
    [LiveTargetFact("osx-arm64")] public Task Two_sessions_on_osx_arm64() => TwoSessions(LiveTarget.MacArm64);
    [LiveTargetFact("linux-x86")] public Task Two_sessions_on_linux_x86() => TwoSessions(LiveTarget.LinuxX86);

    private async Task TwoSessions(LiveTarget target)
    {
        var exe = target.Build(_dir, "orders", LivePrograms.Orders);
        var name = Regex.Escape(target.Exe("orders"));
        await using var server = await Server();
        var pid1 = await Spawn(server, exe, "live-1", "100000", "5");
        var pid2 = await Spawn(server, exe, "live-2", "300", "5");
        foreach (var session in new[] { "live-1", "live-2" })
        {
            Assert.Contains("s1 set", await Ok(server, "live_break", new() { ["session"] = session, ["action"] = "set", ["at"] = "AddLine" }));
            Assert.Matches($@"thread \d+ stopped at s1 \({name}!AddLine\)",
                await Ok(server, "live_break", new() { ["session"] = session, ["action"] = "continue", ["wait"] = true, ["waitSeconds"] = 60 }));
        }
        var list = await Ok(server, "live_session", new() { ["action"] = "list" });
        Assert.Contains($"live-1 (frida): {exe} pid {pid1}, stopped", list);
        Assert.Contains($"live-2 (frida): {exe} pid {pid2}, stopped", list);
        foreach (var session in new[] { "live-1", "live-2" })
            Assert.Matches($@"pc +0x[0-9a-f]+  {name}!AddLine", await Ok(server, "live_read", new() { ["session"] = session, ["registers"] = "pc" }));

        Assert.Contains($"pid {pid1}, closed", await Ok(server, "live_session", new() { ["action"] = "close", ["session"] = "live-1" }));
        Ended(pid1);

        // the other session keeps working: another stop, then the program runs to its end
        Assert.Matches($@"thread \d+ stopped at s1 \({name}!AddLine\)",
            await Ok(server, "live_break", new() { ["session"] = "live-2", ["action"] = "continue", ["wait"] = true, ["waitSeconds"] = 60 }));
        Assert.Matches(@"stop point s1 hit 2\b", await Events(server, "live-2", kind: "stop"));
        Assert.Contains(", 0 stop point(s)", await Ok(server, "live_break", new() { ["session"] = "live-2", ["action"] = "clear", ["stopPoint"] = "s1" }));
        await Ok(server, "live_break", new() { ["session"] = "live-2", ["action"] = "continue" });
        Assert.Matches(@"exit code 0(?![0-9xX])", await UntilExited(server, "live-2"));
        Assert.Contains("lines 300", await Events(server, "live-2", kind: "output"));
        Assert.Contains($"pid {pid1}, closed", await Ok(server, "live_session", new() { ["action"] = "status", ["session"] = "live-1" }));
        await Ok(server, "live_session", new() { ["action"] = "close", ["session"] = "live-2" });
        Ended(pid2);
    }
}
