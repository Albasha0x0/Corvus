using System.Diagnostics;
using System.Globalization;
using System.Text.RegularExpressions;
using Corvus.Services;
using Microsoft.Extensions.DependencyInjection;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>
/// Every way a session's program ends, repeated per target: a return from main with watched calls still queued, _exit,
/// an access violation, termination from outside, a close at the start of the exit, and an exit held in a module's
/// shutdown past the 10 s limit. Each run ends with the program gone, the session's worker ended and no call left waiting.
/// </summary>
[Trait("Speed", "Slow")]
[Trait("Data", "Real")]
[Collection(LiveSessions.Collection)]
public sealed class LiveLifecycleRealTests(ITestOutputHelper output) : LiveToolCalls(output), IDisposable
{
    private const int Runs = 10;
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    private string Build(LiveTarget target) => target.Build(_dir, "lifecycle", LivePrograms.Lifecycle);

    private static long Number(Group g) => g.Success ? long.Parse(g.Value.Replace(",", ""), CultureInfo.InvariantCulture) : 0;

    /// <summary>Calls recorded plus calls over the rate limit for watch w1.</summary>
    private async Task<long> Watched(InProcessServer server, string session)
    {
        var list = await Ok(server, "live_watch", new() { ["session"] = session });
        var w = Regex.Match(list, @"w1 [^:]+: ([\d,]+) call\(s\) recorded(?:.*?, ([\d,]+) over the rate limit)?");
        Assert.True(w.Success, list);
        return Number(w.Groups[1]) + Number(w.Groups[2]);
    }

    /// <summary>Closes the session and checks nothing is left: no held thread, the worker ended, the started program gone.</summary>
    private async Task CloseReleased(InProcessServer server, string session, int? pid)
    {
        Assert.Contains("closed", await Ok(server, "live_session", new() { ["action"] = "close", ["session"] = session }));
        var s = server.Services.GetRequiredService<LiveSessionService>().Get(session);
        Assert.Empty(s.Held);
        Assert.True(s.Worker.Closed.Wait(10_000), $"the worker of {session} is still running after close");
        if (pid is { } p) Ended(p);
    }

    // ---- a return from main while watched calls are still queued to be sent

    [LiveTargetFact("win-x64")] public Task Exit_with_calls_queued_on_win_x64() => ExitWithCallsQueued(LiveTarget.WinX64);
    [LiveTargetFact("win-x86")] public Task Exit_with_calls_queued_on_win_x86() => ExitWithCallsQueued(LiveTarget.WinX86);
    [LiveTargetFact("linux-x64")] public Task Exit_with_calls_queued_on_linux_x64() => ExitWithCallsQueued(LiveTarget.LinuxX64);

    private async Task ExitWithCallsQueued(LiveTarget target)
    {
        var exe = Build(target);
        const int calls = 20_000;
        await using var server = await Server();
        for (int run = 1; run <= Runs; run++)
        {
            var session = $"live-{run}";
            var pid = await Spawn(server, exe, session, "exit", $"{calls}");
            await Ok(server, "live_watch", new() { ["session"] = session, ["action"] = "set", ["at"] = "AddLine", ["rateLimit"] = 100_000 });
            // no stop point: the wait ends with the program
            var sw = Stopwatch.StartNew();
            var ended = await Ok(server, "live_break", new() { ["session"] = session, ["action"] = "continue", ["wait"] = true, ["waitSeconds"] = 120 });
            Output.WriteLine($"run {run}: the wait returned {sw.ElapsedMilliseconds} ms after the start");
            Assert.True(sw.Elapsed < TimeSpan.FromSeconds(60), $"the wait took {sw.Elapsed}");
            Assert.Contains("the program ended before a stop", ended);
            Assert.Matches(@"exit code 5(?![0-9xX])", await UntilExited(server, session, seconds: 30));
            Assert.Equal(calls, await Watched(server, session));
            Assert.Contains($"lines {calls}", await Events(server, session, kind: "output", log: false));

            // calls after the end are refused by the session's state, not by the backend
            foreach (var (tool, args) in new (string, Dictionary<string, object?>)[]
            {
                ("live_break", new() { ["session"] = session, ["action"] = "set", ["at"] = "AddLine" }),
                ("live_watch", new() { ["session"] = session, ["action"] = "set", ["at"] = "AddLine" }),
                ("live_read", new() { ["session"] = session, ["memory"] = "AddLine", ["type"] = "uint8[4]" }),
            })
            {
                var (late, failed) = await Call(server, tool, args);
                Assert.True(failed, late);
                Assert.Contains("\"code\":\"unsupported\"", late);
                Assert.Contains($"Session {session} is exited", late);
            }
            await CloseReleased(server, session, pid);
        }
    }

    // ---- the C runtime's fast exit

    [LiveTargetFact("win-x64")] public Task Fast_exit_on_win_x64() => FastExit(LiveTarget.WinX64, Runs);
    [LiveTargetFact("win-x86")] public Task Fast_exit_on_win_x86() => FastExit(LiveTarget.WinX86, Runs);
    [LiveTargetFact("linux-x64")] public Task Fast_exit_on_linux_x64() => FastExit(LiveTarget.LinuxX64, 40);

    private async Task FastExit(LiveTarget target, int runs)
    {
        var exe = Build(target);
        const int calls = 2_000;
        await using var server = await Server();
        for (int run = 1; run <= runs; run++)
        {
            var session = $"live-{run}";
            var pid = await Spawn(server, exe, session, "fastexit", $"{calls}");
            await Ok(server, "live_watch", new() { ["session"] = session, ["action"] = "set", ["at"] = "AddLine", ["rateLimit"] = 100_000 });
            var sw = Stopwatch.StartNew();
            await Ok(server, "live_break", new() { ["session"] = session, ["action"] = "continue" });
            Assert.Matches(@"exit code 3(?![0-9xX])", await UntilExited(server, session, seconds: 30));
            Output.WriteLine($"run {run}: exited {sw.ElapsedMilliseconds} ms after the start");
            Assert.Equal(calls, await Watched(server, session));
            Assert.Contains($"lines {calls}", await Events(server, session, kind: "output", log: false));
            Assert.DoesNotContain("did not finish", await Events(server, session, kind: "error"));
            await CloseReleased(server, session, pid);
        }
    }

    // ---- an access violation nothing handles

    [LiveTargetFact("win-x64")] public Task Fault_on_win_x64() => Fault(LiveTarget.WinX64);
    [LiveTargetFact("win-x86")] public Task Fault_on_win_x86() => Fault(LiveTarget.WinX86);
    [LiveTargetFact("linux-x64")] public Task Fault_on_linux_x64() => Fault(LiveTarget.LinuxX64);

    private async Task Fault(LiveTarget target)
    {
        var exe = Build(target);
        const int calls = 100;
        await using var server = await Server();
        for (int run = 1; run <= Runs; run++)
        {
            var session = $"live-{run}";
            var pid = await Spawn(server, exe, session, "fault", $"{calls}");
            await Ok(server, "live_watch", new() { ["session"] = session, ["action"] = "set", ["at"] = "AddLine", ["rateLimit"] = 100_000 });
            var sw = Stopwatch.StartNew();
            var ended = await Ok(server, "live_break", new() { ["session"] = session, ["action"] = "continue", ["wait"] = true, ["waitSeconds"] = 120 });
            Output.WriteLine($"run {run}: the wait returned {sw.ElapsedMilliseconds} ms after the start");
            Assert.Contains("the program ended before a stop", ended);
            var exited = await UntilExited(server, session, seconds: 30);
            if (target.Windows) Assert.Contains("exit code 0xC0000005 (EXCEPTION_ACCESS_VIOLATION)", exited);
            Assert.Matches(@"access-violation \(write of 0x0\)", await Events(server, session, kind: "exception"));
            Assert.Contains($"lines {calls}", await Events(server, session, kind: "output", log: false));
            Assert.Equal(calls, await Watched(server, session));
            Assert.Contains("exited, 0 stop point(s)", await Ok(server, "live_break", new() { ["session"] = session }));
            await CloseReleased(server, session, pid);
        }
    }

    // ---- termination from outside, with a wait outstanding

    [LiveTargetFact("win-x64")] public Task Terminated_on_win_x64() => Terminated(LiveTarget.WinX64);
    [LiveTargetFact("win-x86")] public Task Terminated_on_win_x86() => Terminated(LiveTarget.WinX86);
    [LiveTargetFact("linux-x64")] public Task Terminated_on_linux_x64() => Terminated(LiveTarget.LinuxX64);

    private async Task Terminated(LiveTarget target)
    {
        var exe = Build(target);
        await using var server = await Server();
        for (int run = 1; run <= Runs; run++)
        {
            var session = $"live-{run}";
            var pid = await Spawn(server, exe, session, "sleep");
            await Ok(server, "live_break", new() { ["session"] = session, ["action"] = "set", ["at"] = "AddLine" });
            await Ok(server, "live_break", new() { ["session"] = session, ["action"] = "continue" });
            var wait = Call(server, "live_break", new() { ["session"] = session, ["wait"] = true, ["waitSeconds"] = 120 });
            await Task.Delay(300);
            if (wait.IsCompleted) Assert.Fail($"the wait returned before the kill: {(await wait).Text}");
            var sw = Stopwatch.StartNew();
            using (var program = Process.GetProcessById(pid)) program.Kill();
            var (ended, failed) = await wait;
            Output.WriteLine($"run {run}: the wait returned {sw.ElapsedMilliseconds} ms after the kill");
            Assert.False(failed, ended);
            Assert.True(sw.Elapsed < TimeSpan.FromSeconds(15), $"the wait returned {sw.Elapsed} after the kill");
            Assert.Contains("the program ended before a stop", ended);
            var exited = await UntilExited(server, session, seconds: 30);
            if (target.Windows) Assert.Contains("exit code 0xFFFFFFFF", exited);
            await CloseReleased(server, session, pid);
        }
    }

    // ---- a close at the start of the exit of a program the session attached to: the program finishes its exit by itself

    [LiveTargetFact("win-x64")] public Task Close_during_exit_on_win_x64() => CloseDuringExit(LiveTarget.WinX64);
    [LiveTargetFact("win-x86")] public Task Close_during_exit_on_win_x86() => CloseDuringExit(LiveTarget.WinX86);
    [LiveTargetFact("linux-x64")] public Task Close_during_exit_on_linux_x64() => CloseDuringExit(LiveTarget.LinuxX64);

    private async Task CloseDuringExit(LiveTarget target)
    {
        var exe = Build(target);
        var name = Regex.Escape(target.Exe("lifecycle"));
        await using var server = await Server();
        var load = MachineLoad.Factor();
        // odd runs close while the exiting thread is held at AtExit, even runs release it and close at once
        for (int run = 1; run <= 2 * Runs; run++)
        {
            var session = $"live-{run}";
            using var program = Process.Start(new ProcessStartInfo(exe, "line 50") { RedirectStandardInput = true, RedirectStandardOutput = true, UseShellExecute = false })!;
            try
            {
                Assert.Contains($"{session} (frida): ", await Ok(server, "live_session", new() { ["action"] = "attach", ["program"] = $"{program.Id}" }));
                await Ok(server, "live_break", new() { ["session"] = session, ["action"] = "set", ["at"] = "AtExit" });
                program.StandardInput.WriteLine("go");
                program.StandardInput.Flush();
                Assert.Matches($@"stopped at s1 \({name}!AtExit\)", await Ok(server, "live_break", new() { ["session"] = session, ["wait"] = true, ["waitSeconds"] = 60 }));
                if (run % 2 == 0) await Ok(server, "live_break", new() { ["session"] = session, ["action"] = "continue" });
                var sw = Stopwatch.StartNew();
                Assert.Contains("closed", await Ok(server, "live_session", new() { ["action"] = "close", ["session"] = session }));
                var closeMs = sw.ElapsedMilliseconds;
                Assert.True(program.WaitForExit(20_000), $"run {run}: the program did not finish its exit after the close");
                Output.WriteLine($"run {run}: close {closeMs} ms, program ended {sw.ElapsedMilliseconds} ms after the close began");
                var closeTime = MachineLoad.Check(TimeSpan.FromMilliseconds(closeMs), TimeSpan.FromSeconds(15), load);
                Assert.True(closeTime.Within, $"close took {closeTime.Note}");
                Assert.Equal(5, program.ExitCode);
                Assert.Contains("lines 50", program.StandardOutput.ReadToEnd());
                var s = server.Services.GetRequiredService<LiveSessionService>().Get(session);
                Assert.Empty(s.Held);
                Assert.True(s.Worker.Closed.Wait(10_000), $"the worker of {session} is still running after close");
            }
            finally
            {
                if (!program.HasExited) program.Kill();
                program.WaitForExit(10_000);
            }
        }
    }

    // ---- an exit held in a module's shutdown is ended after 10 s with the exit code the program chose (Windows)

    [LiveTargetFact("win-x64")] public Task Stuck_exit_of_a_started_program_on_win_x64() => StuckExit(LiveTarget.WinX64, attach: false);
    [LiveTargetFact("win-x86")] public Task Stuck_exit_of_a_started_program_on_win_x86() => StuckExit(LiveTarget.WinX86, attach: false);
    [LiveTargetFact("win-x64")] public Task Stuck_exit_of_an_attached_program_on_win_x64() => StuckExit(LiveTarget.WinX64, attach: true);
    [LiveTargetFact("win-x86")] public Task Stuck_exit_of_an_attached_program_on_win_x86() => StuckExit(LiveTarget.WinX86, attach: true);

    private async Task StuckExit(LiveTarget target, bool attach)
    {
        var exe = Build(target);
        const int together = 5;
        await using var server = await Server();
        int next = 0;
        // two rounds of five sessions at once, each program held in its exit
        for (int round = 0; round < Runs / together; round++)
        {
            var sessions = new List<(string Session, int Pid, Process? Program)>();
            try
            {
                for (int i = 0; i < together; i++)
                {
                    var session = $"live-{++next}";
                    if (attach)
                    {
                        var program = Process.Start(new ProcessStartInfo(exe, "line+stuck 10") { RedirectStandardInput = true, RedirectStandardOutput = true, UseShellExecute = false })!;
                        sessions.Add((session, program.Id, program));
                        Assert.Contains($"{session} (frida): ", await Ok(server, "live_session", new() { ["action"] = "attach", ["program"] = $"{program.Id}" }));
                    }
                    else sessions.Add((session, await Spawn(server, exe, session, "stuck", "10"), null));
                }
                var sw = Stopwatch.StartNew();
                foreach (var (session, _, program) in sessions)
                {
                    if (program != null)
                    {
                        program.StandardInput.WriteLine("go");
                        program.StandardInput.Flush();
                    }
                    else await Ok(server, "live_break", new() { ["session"] = session, ["action"] = "continue" });
                }
                foreach (var (session, pid, _) in sessions)
                {
                    var exited = await UntilExited(server, session, seconds: 60);
                    Output.WriteLine($"{session}: exited {sw.Elapsed.TotalSeconds:F1} s after the start");
                    Assert.Matches(@"exit code 7(?![0-9xX])", exited);
                    Assert.Contains("called ExitProcess(7) but its exit did not finish in 10 s", await Events(server, session, kind: "error"));
                    Ended(pid);
                }
                Assert.InRange(sw.Elapsed.TotalSeconds, 9.5, 40);
                foreach (var (session, pid, _) in sessions) await CloseReleased(server, session, pid);
            }
            finally
            {
                foreach (var (_, _, program) in sessions)
                {
                    if (program is { HasExited: false }) program.Kill();
                    program?.WaitForExit(10_000);
                    program?.Dispose();
                }
            }
        }
    }

    // ---- a start that fails after the program is running

    /// <summary>The worker ends a program it started as soon as the session cannot be set up (here: a script that does not load).</summary>
    [LiveTargetFact("win-x64")]
    public void A_start_that_fails_after_the_program_runs_ends_the_program()
    {
        var python = new Native.Providers.Live.FridaBackend().Python ?? throw new InvalidOperationException("no Python with Frida");
        var exe = _dir.File($"failed-start-{Guid.NewGuid():N}.exe");
        File.Copy(Build(LiveTarget.WinX64), exe);
        var worker = _dir.File("live_worker.py");
        File.WriteAllBytes(worker, Native.Providers.EmbeddedScript.Read("Corvus.Native.Providers.Live.live_worker.py"));
        var agent = _dir.File("live_agent.js");
        File.WriteAllText(agent, "this is not a script (");
        // Frida unpacks its helpers into TEMP and a killed worker leaves them: a folder of the test's own, as the server gives each worker
        var temp = Directory.CreateDirectory(_dir.File("worker-temp")).FullName;
        var start = new ProcessStartInfo(python.Executable, new[] { "-I", "-u", worker, agent })
            { RedirectStandardInput = true, RedirectStandardOutput = true, UseShellExecute = false };
        start.Environment["TEMP"] = start.Environment["TMP"] = temp;
        using var p = Process.Start(start)!;
        p.StandardInput.WriteLine(System.Text.Json.JsonSerializer.Serialize(new { id = 1, op = "open", args = new { spawn = exe, arguments = new[] { "line 50" } } }));
        p.StandardInput.Flush();
        string? reply;
        while ((reply = p.StandardOutput.ReadLine()) != null && !reply.Contains("\"id\":1", StringComparison.Ordinal)) { }
        Assert.NotNull(reply);
        Assert.Contains("\"ok\":false", reply);
        // the server ends a worker that failed to open without a close (its timeout, or its own end): nothing else ends the program
        p.Kill();
        Assert.True(p.WaitForExit(20_000), "the worker did not end");
        var left = Process.GetProcessesByName(Path.GetFileNameWithoutExtension(exe)); // a unique name: only this start's program
        foreach (var program in left) program.Kill();
        Assert.Empty(left);
    }
}
