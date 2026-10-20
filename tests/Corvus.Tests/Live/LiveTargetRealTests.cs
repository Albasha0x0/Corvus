using System.Diagnostics;
using System.Globalization;
using System.Text.RegularExpressions;
using Corvus.Core;
using ModelContextProtocol.Protocol;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>
/// Every session tool and action on programs built for each target (Windows x64 and x86 with MSVC, Linux x64 and x86
/// with gcc): start and attach, stop points by name and file:line, held-thread reads, watches, events, scripts,
/// coverage, snapshots, close; a 16-thread program under stops and watches; the Windows-only tools on Linux.
/// </summary>
[Trait("Speed", "Slow")]
[Trait("Data", "Real")]
[Collection(LiveSessions.Collection)]
public sealed class LiveTargetRealTests(ITestOutputHelper output) : IDisposable
{
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    private async Task<(string Text, bool IsError)> Call(InProcessServer server, string tool, Dictionary<string, object?> args)
    {
        var sw = Stopwatch.StartNew();
        var r = await server.Client.CallToolAsync(tool, args);
        var text = string.Concat(r.Content.OfType<TextContentBlock>().Select(b => b.Text));
        output.WriteLine($"{tool} {string.Join(" ", args.Select(a => $"{a.Key}={(a.Value is string[] l ? string.Join(",", l) : a.Value)}"))} ({sw.ElapsedMilliseconds} ms):\n{text}");
        return (text, r.IsError == true);
    }

    private async Task<string> Ok(InProcessServer server, string tool, Dictionary<string, object?> args)
    {
        var (text, failed) = await Call(server, tool, args);
        Assert.False(failed, text);
        return text;
    }

    private static Task<InProcessServer> Server(bool scripting = false) => InProcessServer.StartAsync(options: new ServerOptions
    {
        BackgroundIndexing = false, WatchFiles = false, AllowLiveAttach = true, AllowLiveSpawn = true, LiveScripting = scripting,
    });

    private async Task<int> Spawn(InProcessServer server, string exe, string session, params string[] arguments)
    {
        var open = await Ok(server, "live_session", new() { ["action"] = "spawn", ["program"] = exe, ["arguments"] = arguments });
        Assert.Contains($"{session} (frida): ", open);
        Assert.Contains("suspended", open);
        return int.Parse(Regex.Match(open, @"pid (\d+)").Groups[1].Value, CultureInfo.InvariantCulture);
    }

    private async Task<string> UntilExited(InProcessServer server, string session, int seconds = 120)
    {
        for (int i = 0; i < seconds * 10; i++)
        {
            var (status, _) = await Call(server, "live_session", new() { ["action"] = "status", ["session"] = session });
            if (status.Contains(", exited")) return status;
            await Task.Delay(100);
        }
        Assert.Fail($"{session} did not exit within {seconds} s");
        return "";
    }

    /// <summary>All events of one kind, every page.</summary>
    private async Task<string> Events(InProcessServer server, string session, string? kind = null, string? from = null)
    {
        var all = new System.Text.StringBuilder();
        string? cursor = null;
        for (int page = 0; page < 200; page++)
        {
            var args = new Dictionary<string, object?> { ["session"] = session, ["limit"] = 500 };
            if (kind != null) args["kind"] = kind;
            if (from != null) args["from"] = from;
            if (cursor != null) args["cursor"] = cursor;
            var (text, failed) = await Call(server, "live_events", args);
            Assert.False(failed, text);
            all.Append(text);
            var next = Regex.Match(text, @"cursor=(\S+)");
            if (!next.Success || !text.Contains("more", StringComparison.OrdinalIgnoreCase)) break;
            cursor = next.Groups[1].Value;
        }
        return all.ToString();
    }

    private static void Ended(int pid)
    {
        try
        {
            using var p = Process.GetProcessById(pid);
            Assert.True(p.WaitForExit(10_000), $"process {pid} is still running");
        }
        catch (ArgumentException) { /* already gone */ }
    }

    /// <summary>The address of the Order the held thread's first argument points at.</summary>
    private async Task<string> FirstArgument(InProcessServer server, LiveTarget target)
    {
        if (target.FirstArgument is { } register) return register;
        // x86: at the entry, [esp] is the return address and [esp+4] the first argument
        var stack = await Ok(server, "live_read", new() { ["session"] = "live-1", ["memory"] = "esp", ["type"] = "uint32[2]" });
        var value = Regex.Match(stack, @"\[1\] (0x[0-9A-Fa-f]+|\d+)").Groups[1].Value;
        Assert.False(string.IsNullOrEmpty(value), stack);
        return value.StartsWith("0x", StringComparison.Ordinal) ? value : $"0x{ulong.Parse(value, CultureInfo.InvariantCulture):X}";
    }

    // ---- the core flow: every action of live_session, live_break, live_read, live_watch and live_events

    [LiveTargetFact("win-x64")] public Task Sessions_on_win_x64() => Sessions(LiveTarget.WinX64);
    [LiveTargetFact("win-x86")] public Task Sessions_on_win_x86() => Sessions(LiveTarget.WinX86);
    [LiveTargetFact("linux-x64")] public Task Sessions_on_linux_x64() => Sessions(LiveTarget.LinuxX64);
    [LiveTargetFact("linux-x86")] public Task Sessions_on_linux_x86() => Sessions(LiveTarget.LinuxX86);

    private async Task Sessions(LiveTarget target)
    {
        var exe = target.Build(_dir, "orders", LivePrograms.Orders);
        var name = Regex.Escape(target.Exe("orders"));
        int entryLine = LivePrograms.Line(LivePrograms.Orders, "NOINLINE int AddLine"), totalLine = LivePrograms.Line(LivePrograms.Orders, "o->total +="),
            callLine = LivePrograms.Line(LivePrograms.Orders, "g_sink = AddLine");
        await using var server = await Server();

        var pid = await Spawn(server, exe, "live-1", "400", "20");
        Assert.Contains($"{pid}", await Ok(server, "live_session", new() { ["action"] = "processes", ["program"] = "orders" }));
        Assert.Contains($"live-1 (frida): {exe} pid {pid}, suspended", await Ok(server, "live_session", new() { ["action"] = "list" }));
        Assert.Contains("suspended", await Ok(server, "live_session", new() { ["action"] = "status", ["session"] = "live-1" }));

        var s1 = await Ok(server, "live_break", new() { ["session"] = "live-1", ["action"] = "set", ["at"] = "AddLine" });
        Assert.Matches($@"s1 set at 0x[0-9A-F]+ {name}!AddLine  .*orders\.c:({entryLine}|{entryLine + 1})\b", s1);
        var s2 = await Ok(server, "live_break", new() { ["session"] = "live-1", ["action"] = "set", ["at"] = $"orders.c:{totalLine}" });
        Assert.Matches($@"s2 set at 0x[0-9A-F]+ {name}!AddLine\+0x[0-9A-F]+  .*orders\.c:{totalLine}\b", s2);
        Assert.Contains("live-1: suspended, 2 stop point(s)", await Ok(server, "live_break", new() { ["session"] = "live-1", ["action"] = "list" }));

        var first = await Ok(server, "live_break", new() { ["session"] = "live-1", ["action"] = "continue", ["wait"] = true, ["waitSeconds"] = 60 });
        Assert.Contains("program started", first);
        Assert.Matches($@"thread \d+ stopped at s1 \({name}!AddLine\)", first);
        Assert.Matches($@"#0 0x[0-9A-F]+ {name}!AddLine", first);
        Assert.Matches($@"#1 0x[0-9A-F]+ {name}!main\+0x[0-9A-F]+  .*orders\.c:{callLine}\b", first);

        var order = await FirstArgument(server, target);
        var fields = await Ok(server, "live_read", new() { ["session"] = "live-1", ["memory"] = order, ["type"] = "int32[2]" });
        Assert.Contains("[0] 7", fields);
        Assert.Contains("[1] 0", fields);
        Assert.Matches($@"pc +0x[0-9a-f]+  {name}!AddLine", await Ok(server, "live_read", new() { ["session"] = "live-1", ["registers"] = "pc" }));

        // the second stop of the same call, reported however the resume and the stop interleave
        Assert.Contains("resumed thread(s)", await Ok(server, "live_break", new() { ["session"] = "live-1", ["action"] = "continue" }));
        var second = await Ok(server, "live_break", new() { ["session"] = "live-1", ["wait"] = true, ["waitSeconds"] = 60 });
        Assert.Matches($@"stopped at s2 \({name}!AddLine\+0x[0-9A-F]+\)", second);
        var stops = await Events(server, "live-1", kind: "stop");
        Assert.Matches($@"stop thread \d+ 0x[0-9A-F]+ {name}!AddLine: stop point s1 hit 1", stops);
        Assert.Matches($@"stop thread \d+ 0x[0-9A-F]+ {name}!AddLine\+0x[0-9A-F]+: stop point s2 hit 1", stops);
        Assert.Contains("s1 cleared", await Ok(server, "live_break", new() { ["session"] = "live-1", ["action"] = "clear", ["stopPoint"] = "s1" }));
        Assert.Contains("0 stop point(s)", await Ok(server, "live_break", new() { ["session"] = "live-1", ["action"] = "clear", ["stopPoint"] = "s2" }));

        var w1 = await Ok(server, "live_watch", new() { ["session"] = "live-1", ["action"] = "set", ["at"] = "AddLine", ["rateLimit"] = 100_000 });
        Assert.Matches($@"w1 .*{name}!AddLine", w1);
        Assert.Contains("w2", await Ok(server, "live_watch", new() { ["session"] = "live-1", ["action"] = "set", ["at"] = target.FileOpen }));
        Assert.Contains("w3", await Ok(server, "live_watch", new() { ["session"] = "live-1", ["action"] = "set", ["at"] = "Discount" }));
        Assert.Contains("w3 cleared", await Ok(server, "live_watch", new() { ["session"] = "live-1", ["action"] = "clear", ["watch"] = "w3" }));
        Assert.Contains("live-1: stopped, 2 watch(es)", await Ok(server, "live_watch", new() { ["session"] = "live-1" }));

        await Ok(server, "live_break", new() { ["session"] = "live-1", ["action"] = "continue" });
        var exited = await UntilExited(server, "live-1");
        Assert.Matches(@"exit code 0(?![0-9xX])", exited);
        await Task.Delay(500); // the last batch
        var watches = await Ok(server, "live_watch", new() { ["session"] = "live-1" });
        var recorded = long.Parse(Regex.Match(watches, @"w1 [^:]+: ([\d,]+) call\(s\) recorded").Groups[1].Value.Replace(",", ""), CultureInfo.InvariantCulture);
        Assert.InRange(recorded, 399, 400); // the first call was already inside AddLine
        var calls = await Events(server, "live-1", from: "w1");
        var row = Regex.Match(calls, @"AddLine\(o=0x[0-9A-F]+, qty=(\d+)\) -> (\d+)");
        Assert.True(row.Success, calls);
        Assert.Equal(row.Groups[1].Value, row.Groups[2].Value); // each call adds one line: the count returned is the qty passed
        var opens = await Events(server, "live-1", from: "w2");
        Assert.Matches(target.Windows ? @"CreateFileA\(lpFileName=""[^""]*orders\.exe""" : @"open\(", opens);
        Assert.Contains("lines 400", await Events(server, "live-1", kind: "output"));
        Assert.Contains("exit", await Events(server, "live-1", kind: "exit"));
        Assert.Contains("closed", await Ok(server, "live_session", new() { ["action"] = "close", ["session"] = "live-1" }));
        Ended(pid);
    }

    // ---- attach to a running program; close leaves it running

    [LiveTargetFact("win-x64")] public Task Attach_on_win_x64() => Attach(LiveTarget.WinX64);
    [LiveTargetFact("win-x86")] public Task Attach_on_win_x86() => Attach(LiveTarget.WinX86);
    [LiveTargetFact("linux-x64")] public Task Attach_on_linux_x64() => Attach(LiveTarget.LinuxX64);
    [LiveTargetFact("linux-x86")] public Task Attach_on_linux_x86() => Attach(LiveTarget.LinuxX86);

    private async Task Attach(LiveTarget target)
    {
        var exe = target.Build(_dir, "orders", LivePrograms.Orders);
        var name = Regex.Escape(target.Exe("orders"));
        using var program = Process.Start(new ProcessStartInfo(exe, "100000 5") { RedirectStandardOutput = true, UseShellExecute = false })!;
        try
        {
            await using var server = await Server();
            var open = await Ok(server, "live_session", new() { ["action"] = "attach", ["program"] = $"{program.Id}" });
            Assert.Contains("live-1 (frida): ", open);
            Assert.DoesNotContain("suspended", open);
            await Ok(server, "live_break", new() { ["session"] = "live-1", ["action"] = "set", ["at"] = "AddLine" });
            var stop = await Ok(server, "live_break", new() { ["session"] = "live-1", ["wait"] = true, ["waitSeconds"] = 60 });
            Assert.Matches($@"stopped at s1 \({name}!AddLine\)", stop);
            var order = await FirstArgument(server, target);
            Assert.Matches(@"(?m)^  7$", (await Ok(server, "live_read", new() { ["session"] = "live-1", ["memory"] = order, ["type"] = "int32" })).ReplaceLineEndings("\n"));

            var snapshot = await Ok(server, "live_session", new() { ["action"] = "snapshot", ["session"] = "live-1" });
            var dump = Regex.Match(snapshot, @"written to (.+?) \(([\d,]+) bytes\), opened as (\S+);");
            Assert.True(dump.Success, snapshot);
            Assert.True(File.Exists(dump.Groups[1].Value), snapshot);
            try
            {
                var stack = await Ok(server, "dump_stack", new() { ["dump"] = dump.Groups[3].Value, ["thread"] = Regex.Match(stop, @"thread (\d+) stopped").Groups[1].Value });
                // the stopped thread waits inside the backend; at a function's entry its caller is the first frame of the program
                Assert.Matches($@"{Regex.Escape(Path.GetFileNameWithoutExtension(target.Exe("orders")))}!main\+", stack);
            }
            finally { File.Delete(dump.Groups[1].Value); }

            Assert.Contains("closed", await Ok(server, "live_session", new() { ["action"] = "close", ["session"] = "live-1" }));
            Thread.Sleep(1_000);
            Assert.False(program.HasExited, "close ended a program the session attached to");
        }
        finally
        {
            if (!program.HasExited) program.Kill();
            program.WaitForExit(10_000);
        }
    }

    // ---- scripts: load, list, messages, unload

    [LiveTargetFact("win-x64")] public Task Scripts_on_win_x64() => Scripts(LiveTarget.WinX64);
    [LiveTargetFact("win-x86")] public Task Scripts_on_win_x86() => Scripts(LiveTarget.WinX86);
    [LiveTargetFact("linux-x64")] public Task Scripts_on_linux_x64() => Scripts(LiveTarget.LinuxX64);
    [LiveTargetFact("linux-x86")] public Task Scripts_on_linux_x86() => Scripts(LiveTarget.LinuxX86);

    private async Task Scripts(LiveTarget target)
    {
        var exe = target.Build(_dir, "orders", LivePrograms.Orders);
        await using var server = await Server(scripting: true);
        var pid = await Spawn(server, exe, "live-1", "100000", "5");
        var loaded = await Ok(server, "live_script", new()
        {
            ["session"] = "live-1", ["action"] = "load",
            ["source"] = "send({ pid: Process.id, arch: Process.arch, bits: Process.pointerSize * 8 });",
        });
        Assert.Contains("u1 loaded (inline)", loaded);
        Assert.Contains("u1", await Ok(server, "live_script", new() { ["session"] = "live-1" }));
        string events = "";
        for (int i = 0; i < 100 && !events.Contains($"\"pid\":{pid}"); i++)
        {
            events = await Events(server, "live-1", kind: "script");
            await Task.Delay(100);
        }
        Assert.Contains($"script: u1: {{\"pid\":{pid},\"arch\":\"{(target.Is64 ? "x64" : "ia32")}\",\"bits\":{(target.Is64 ? 64 : 32)}}}", events);
        Assert.Contains("u1 unloaded", await Ok(server, "live_script", new() { ["session"] = "live-1", ["action"] = "unload", ["script"] = "u1" }));
        Assert.Contains("0 script(s)", await Ok(server, "live_script", new() { ["session"] = "live-1" }));
        await Ok(server, "live_session", new() { ["action"] = "close", ["session"] = "live-1" });
        Ended(pid);
    }

    // ---- coverage: two runs, report, call graph, diff

    [LiveTargetFact("win-x64")] public Task Coverage_on_win_x64() => Coverage(LiveTarget.WinX64);
    [LiveTargetFact("win-x86")] public Task Coverage_on_win_x86() => Coverage(LiveTarget.WinX86);
    [LiveTargetFact("linux-x64")] public Task Coverage_on_linux_x64() => Coverage(LiveTarget.LinuxX64);
    [LiveTargetFact("linux-x86")] public Task Coverage_on_linux_x86() => Coverage(LiveTarget.LinuxX86);

    private async Task Coverage(LiveTarget target)
    {
        var exe = target.Build(_dir, "orders", LivePrograms.Orders);
        await using var server = await Server();
        foreach (var (session, args) in new[] { ("live-1", new[] { "30", "0" }), ("live-2", new[] { "30", "0", "discount" }) })
        {
            await Spawn(server, exe, session, args);
            Assert.Contains("cov-", await Ok(server, "live_coverage", new() { ["session"] = session, ["action"] = "start" }));
            await Ok(server, "live_break", new() { ["session"] = session, ["action"] = "continue" });
            Assert.Matches(@"exit code 0(?![0-9xX])", await UntilExited(server, session));
        }
        await Task.Delay(500);
        Assert.Contains("cov-2", await Ok(server, "live_coverage", new() { ["action"] = "list" }));
        var report = await Ok(server, "live_coverage", new() { ["action"] = "report", ["run"] = "cov-1" });
        Assert.Matches(@"\b30  0x[0-9A-F]+  AddLine\b", report);
        Assert.Matches(@"\b1  0x[0-9A-F]+  main\b", await Ok(server, "live_coverage", new() { ["action"] = "report", ["run"] = "cov-1", ["match"] = "main" }));
        Assert.Contains("Discount", await Ok(server, "live_coverage", new() { ["action"] = "report", ["run"] = "cov-1", ["show"] = "missed", ["match"] = "Discount" }));
        Assert.Contains("digraph", await Ok(server, "live_coverage", new() { ["action"] = "report", ["run"] = "cov-2", ["format"] = "dot", ["match"] = "AddLine" }));
        var diff = await Ok(server, "live_coverage", new() { ["action"] = "diff", ["run"] = "cov-1", ["other"] = "cov-2" });
        Assert.Matches(@"(?s)only in cov-2.*Discount", diff);
    }

    // ---- 16 threads: every stop reported, every watched call counted, the program's result unchanged

    [LiveTargetFact("win-x64")] public Task Threads_on_win_x64() => Threads(LiveTarget.WinX64);
    [LiveTargetFact("win-x86")] public Task Threads_on_win_x86() => Threads(LiveTarget.WinX86);
    [LiveTargetFact("linux-x64")] public Task Threads_on_linux_x64() => Threads(LiveTarget.LinuxX64);
    [LiveTargetFact("linux-x86")] public Task Threads_on_linux_x86() => Threads(LiveTarget.LinuxX86);

    private async Task Threads(LiveTarget target)
    {
        var exe = target.Build(_dir, "workers", LivePrograms.Workers);
        var name = Regex.Escape(target.Exe("workers"));
        await using var server = await Server();

        // stops: each continue releases every held thread, each wait returns the next stop
        const int calls = 300;
        var pid = await Spawn(server, exe, "live-1", $"{calls}", "1");
        await Ok(server, "live_break", new() { ["session"] = "live-1", ["action"] = "set", ["at"] = "Work" });
        var threads = new HashSet<string>();
        var sw = Stopwatch.StartNew();
        for (int i = 0; i < 300; i++)
        {
            var (stop, failed) = await Call(server, "live_break", new() { ["session"] = "live-1", ["action"] = "continue", ["wait"] = true, ["waitSeconds"] = 30 });
            Assert.False(failed, stop);
            var m = Regex.Match(stop, $@"thread (\d+) stopped at s1 \({name}!Work\)");
            Assert.True(m.Success, $"stop {i}: {stop}");
            threads.Add(m.Groups[1].Value);
        }
        output.WriteLine($"300 stops in {sw.ElapsedMilliseconds} ms, {threads.Count} threads");
        Assert.True(threads.Count >= LivePrograms.WorkerThreads / 2, $"{threads.Count} threads stopped");
        await Ok(server, "live_break", new() { ["session"] = "live-1", ["action"] = "clear", ["stopPoint"] = "s1" });
        await Ok(server, "live_break", new() { ["session"] = "live-1", ["action"] = "continue" });
        Assert.Matches(@"exit code 0(?![0-9xX])", await UntilExited(server, "live-1"));
        Assert.Contains($"total {LivePrograms.WorkersTotal(calls)}", await Events(server, "live-1", kind: "output"));
        var started = await Events(server, "live-1", kind: "thread");
        Assert.True(Regex.Count(started, "thread started") >= LivePrograms.WorkerThreads, started);
        Ended(pid);

        // watch: 16 threads x 2,000 calls, each recorded or counted over the limit
        const int burst = 2_000;
        await Spawn(server, exe, "live-2", $"{burst}", "0");
        await Ok(server, "live_watch", new() { ["session"] = "live-2", ["action"] = "set", ["at"] = "Work", ["rateLimit"] = 100_000 });
        await Ok(server, "live_break", new() { ["session"] = "live-2", ["action"] = "continue" });
        Assert.Matches(@"exit code 0(?![0-9xX])", await UntilExited(server, "live-2"));
        await Task.Delay(500);
        var list = await Ok(server, "live_watch", new() { ["session"] = "live-2" });
        var w = Regex.Match(list, @"w1 [^:]+: ([\d,]+) call\(s\) recorded(?:.*?, ([\d,]+) over the rate limit)?");
        Assert.True(w.Success, list);
        long Count(Group g) => g.Success ? long.Parse(g.Value.Replace(",", ""), CultureInfo.InvariantCulture) : 0;
        Assert.Equal(LivePrograms.WorkerThreads * burst, Count(w.Groups[1]) + Count(w.Groups[2]));
        Assert.Contains($"total {LivePrograms.WorkersTotal(burst)}", await Events(server, "live-2", kind: "output"));
        // 32,000 calls overflow the ring, so only the latest thread events are kept
        var threadEvents = await Events(server, "live-2", kind: "thread");
        Assert.True(Regex.Count(threadEvents, "thread ended") >= LivePrograms.WorkerThreads, threadEvents);
    }

    // ---- the Windows-only tools answer provider_unavailable on Linux

    [LiveTargetFact("linux-x64")]
    public async Task Timeline_and_console_say_they_are_unavailable_on_linux()
    {
        var exe = LiveTarget.LinuxX64.Build(_dir, "orders", LivePrograms.Orders);
        await using var server = await Server();
        await Spawn(server, exe, "live-1", "10", "0");
        var (timeline, e1) = await Call(server, "live_timeline", new() { ["session"] = "live-1", ["action"] = "start" });
        Assert.True(e1, timeline);
        Assert.Contains("\"code\":\"provider_unavailable\"", timeline);
        var (console, e2) = await Call(server, "live_console", new() { ["action"] = "start", ["program"] = exe, ["script"] = new[] { "wait lines" } });
        Assert.True(e2, console);
        Assert.Contains("\"code\":\"provider_unavailable\"", console);
        await Ok(server, "live_session", new() { ["action"] = "close", ["session"] = "live-1" });
    }
}

/// <summary>The real session tests run one at a time: each holds programs, stop points and an event-tracing session.</summary>
[CollectionDefinition(Collection, DisableParallelization = true)]
public sealed class LiveSessions
{
    public const string Collection = "Live sessions";
}
