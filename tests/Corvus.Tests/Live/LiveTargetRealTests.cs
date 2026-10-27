using System.Diagnostics;
using System.Globalization;
using System.Text.RegularExpressions;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>Every session tool and action on MSVC and gcc programs for each target, a 16-thread program under load, and the Windows-only tools on Linux.</summary>
[Trait("Speed", "Slow")]
[Trait("Data", "Real")]
[Permit("live")]
public sealed class LiveTargetRealTests(ITestOutputHelper output) : LiveToolCalls(output), IDisposable
{
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

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
    [LiveTargetFact("win-arm64")] public Task Sessions_on_win_arm64() => Sessions(LiveTarget.WinArm64);
    [LiveTargetFact("linux-x64")] public Task Sessions_on_linux_x64() => Sessions(LiveTarget.LinuxX64);
    [LiveTargetFact("osx-arm64")] public Task Sessions_on_osx_arm64() => Sessions(LiveTarget.MacArm64);
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

        // The second stop of the same call, reported however the resume and the stop interleave.
        Assert.Contains("resumed thread(s)", await Ok(server, "live_break", new() { ["session"] = "live-1", ["action"] = "continue" }));
        var second = await Ok(server, "live_break", new() { ["session"] = "live-1", ["wait"] = true, ["waitSeconds"] = 60 });
        Assert.Matches($@"stopped at s2 \({name}!AddLine\+0x[0-9A-F]+\)", second);
        var stops = await Events(server, "live-1", kind: "stop");
        Assert.Matches($@"stop thread \d+ 0x[0-9A-F]+ {name}!AddLine: stop point s1 hit 1", stops);
        Assert.Matches($@"stop thread \d+ 0x[0-9A-F]+ {name}!AddLine\+0x[0-9A-F]+: stop point s2 hit 1", stops);
        Assert.Contains("s1 cleared", await Ok(server, "live_break", new() { ["session"] = "live-1", ["action"] = "clear", ["stopPoint"] = "s1" }));
        Assert.Contains(", 0 stop point(s)", await Ok(server, "live_break", new() { ["session"] = "live-1", ["action"] = "clear", ["stopPoint"] = "s2" }));

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

    // ---- the smoke set, for targets observed under emulation: start, a stop point by name, the named stack, a memory read, close

    [LiveTargetFact("linux-arm64")] public Task Smoke_on_linux_arm64() => Smoke(LiveTarget.LinuxArm64);
    [LiveTargetFact("osx-arm64")] public Task Smoke_on_osx_arm64() => Smoke(LiveTarget.MacArm64);

    private async Task Smoke(LiveTarget target)
    {
        var exe = target.Build(_dir, "orders", LivePrograms.Orders);
        var name = Regex.Escape(target.Exe("orders"));
        int callLine = LivePrograms.Line(LivePrograms.Orders, "g_sink = AddLine");
        await using var server = await Server();

        var pid = await Spawn(server, exe, "live-1", "3", "0");
        Assert.Matches($@"s1 set at 0x[0-9A-F]+ {name}!AddLine", await Ok(server, "live_break", new() { ["session"] = "live-1", ["action"] = "set", ["at"] = "AddLine" }));
        var stop = await Ok(server, "live_break", new() { ["session"] = "live-1", ["action"] = "continue", ["wait"] = true, ["waitSeconds"] = 300 });
        Assert.Matches($@"thread \d+ stopped at s1 \({name}!AddLine\)", stop);
        Assert.Matches($@"#0 0x[0-9A-F]+ {name}!AddLine", stop);
        Assert.Matches($@"#1 0x[0-9A-F]+ {name}!main\+0x[0-9A-F]+  .*orders\.c:{callLine}\b", stop);
        var fields = await Ok(server, "live_read", new() { ["session"] = "live-1", ["memory"] = await FirstArgument(server, target), ["type"] = "int32[2]" });
        Assert.Contains("[0] 7", fields);
        Assert.Contains("[1] 0", fields);
        Assert.Contains("closed", await Ok(server, "live_session", new() { ["action"] = "close", ["session"] = "live-1" }));
        Ended(pid);
    }

    // ---- a session reads the program's threads without starting a process in it

    [LiveTargetFact("linux-x64", attaches: true)] public Task A_session_starts_no_process_in_the_program_on_linux_x64() => NoProcessStarted(LiveTarget.LinuxX64);
    [LiveTargetFact("linux-x86", attaches: true)] public Task A_session_starts_no_process_in_the_program_on_linux_x86() => NoProcessStarted(LiveTarget.LinuxX86);

    // Frida's register reads start a helper process that signals SIGCHLD; reading only thread ids starts none.
    private async Task NoProcessStarted(LiveTarget target)
    {
        var exe = target.Build(_dir, "children", LivePrograms.ChildSignals);
        using var program = Process.Start(new ProcessStartInfo(exe) { RedirectStandardInput = true, RedirectStandardOutput = true, UseShellExecute = false })!;
        Assert.Equal("ready", program.StandardOutput.ReadLine());
        await using var server = await Server();
        if (Corvus.Native.Live.PtraceScope.Refusing(started: false) is not null)
        {
            program.Kill();
            return;
        }
        await Ok(server, "live_session", new() { ["action"] = "attach", ["program"] = $"{program.Id}" });
        // Long enough for several thread scans.
        await Task.Delay(1000);
        await Ok(server, "live_session", new() { ["action"] = "close", ["session"] = "live-1" });
        program.StandardInput.WriteLine("go");
        program.StandardInput.Flush();
        Assert.Equal("children 0", program.StandardOutput.ReadLine());
        if (!program.WaitForExit(30_000)) Assert.Fail($"the program did not exit after the session closed:\n{ProcState(program.Id)}");
    }

    // A Linux process's state and each thread's wait channel and state, read from /proc; an unreadable entry is named so.
    private static string ProcState(int pid)
    {
        string Read(string path)
        {
            try { return File.ReadAllText(path).Trim(); }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException) { return $"unknown ({e.GetType().Name})"; }
        }
        var tasks = Directory.Exists($"/proc/{pid}/task") ? Directory.GetDirectories($"/proc/{pid}/task") : [];
        return string.Join("\n", tasks.Select(t => $"thread {Path.GetFileName(t)}: wchan {Read($"{t}/wchan")}, " +
            (Read($"{t}/status").Split('\n').FirstOrDefault(l => l.StartsWith("State:", StringComparison.Ordinal)) ?? "state unknown"))
            .Prepend($"process {pid}: " + (Read($"/proc/{pid}/status").Split('\n').FirstOrDefault(l => l.StartsWith("State:", StringComparison.Ordinal)) ?? "state unknown")));
    }

    // ---- attach to a running program; close leaves it running

    [LiveTargetFact("win-x64")] public Task Attach_on_win_x64() => Attach(LiveTarget.WinX64);
    [LiveTargetFact("win-x86")] public Task Attach_on_win_x86() => Attach(LiveTarget.WinX86);
    [LiveTargetFact("win-arm64")] public Task Attach_on_win_arm64() => Attach(LiveTarget.WinArm64);
    [LiveTargetFact("linux-x64", attaches: true)] public Task Attach_on_linux_x64() => Attach(LiveTarget.LinuxX64);
    [LiveTargetFact("osx-arm64", attaches: true)] public Task Attach_on_osx_arm64() => Attach(LiveTarget.MacArm64);
    [LiveTargetFact("linux-x86", attaches: true)] public Task Attach_on_linux_x86() => Attach(LiveTarget.LinuxX86);

    private async Task Attach(LiveTarget target)
    {
        var exe = target.Build(_dir, "orders", LivePrograms.Orders);
        var name = Regex.Escape(target.Exe("orders"));
        using var program = Process.Start(new ProcessStartInfo(exe, "100000 5") { RedirectStandardOutput = true, UseShellExecute = false })!;
        try
        {
            await using var server = await Server();
            // The session's worker is not the program's parent.
            if (Corvus.Native.Live.PtraceScope.Refusing(started: false) is { } scope)
            {
                Assert.Contains($"ptrace_scope is {scope}", await Refused(server, "live_session", new() { ["action"] = "attach", ["program"] = $"{program.Id}" }, "access_denied"));
                return;
            }
            var open = await Ok(server, "live_session", new() { ["action"] = "attach", ["program"] = $"{program.Id}" });
            Assert.Contains("live-1 (frida): ", open);
            Assert.DoesNotContain("suspended", open);
            await Ok(server, "live_break", new() { ["session"] = "live-1", ["action"] = "set", ["at"] = "AddLine" });
            var stop = await Ok(server, "live_break", new() { ["session"] = "live-1", ["wait"] = true, ["waitSeconds"] = 60 });
            Assert.Matches($@"stopped at s1 \({name}!AddLine\)", stop);
            var order = await FirstArgument(server, target);
            Assert.Matches(@"(?m)^  7$", (await Ok(server, "live_read", new() { ["session"] = "live-1", ["memory"] = order, ["type"] = "int32" })).ReplaceLineEndings("\n"));

            if (target.Emulated)
                Assert.Contains("emulated on an ARM64 machine", await Refused(server, "live_session", new() { ["action"] = "snapshot", ["session"] = "live-1" }, "unsupported"));
            else
            {
                var snapshot = await Ok(server, "live_session", new() { ["action"] = "snapshot", ["session"] = "live-1" });
                var dump = Regex.Match(snapshot, @"written to (.+?) \(([\d,]+) bytes\), opened as (\S+);");
                Assert.True(dump.Success, snapshot);
                Assert.True(File.Exists(dump.Groups[1].Value), snapshot);
                try
                {
                    // A Mach-O core numbers threads as lldb does: the program's
                    // main thread is the first.
                    var thread = target.Mac ? "#0" : Regex.Match(stop, @"thread (\d+) stopped").Groups[1].Value;
                    var stack = await Ok(server, "dump_stack", new() { ["dump"] = dump.Groups[3].Value, ["thread"] = thread });
                    // The stopped thread waits inside the backend; at a
                    // function's entry its caller is the first frame of the
                    // program.
                    Assert.Matches($@"{Regex.Escape(Path.GetFileNameWithoutExtension(target.Exe("orders")))}!main\+", stack);
                }
                finally { File.Delete(dump.Groups[1].Value); }
            }

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

    /// <summary>A snapshot at a held export stop records that stop as the exception, so the walk reaches the program, not the backend's wait.</summary>
    [LiveTargetFact("win-x64")] public Task A_snapshot_at_a_stop_walks_from_the_stop_on_win_x64() => SnapshotAtStop(LiveTarget.WinX64);
    [LiveTargetFact("win-x86")] public Task A_snapshot_at_a_stop_walks_from_the_stop_on_win_x86() => SnapshotAtStop(LiveTarget.WinX86);
    [LiveTargetFact("linux-x64")] public Task A_snapshot_at_a_stop_walks_from_the_stop_on_linux_x64() => SnapshotAtStop(LiveTarget.LinuxX64);
    [LiveTargetFact("linux-x86")] public Task A_snapshot_at_a_stop_walks_from_the_stop_on_linux_x86() => SnapshotAtStop(LiveTarget.LinuxX86);
    [LiveTargetFact("win-arm64")] public Task A_snapshot_at_a_stop_walks_from_the_stop_on_win_arm64() => SnapshotAtStop(LiveTarget.WinArm64);

    private async Task SnapshotAtStop(LiveTarget target)
    {
        var exe = target.Build(_dir, "orders", LivePrograms.Orders);
        var dump = target.Windows ? "stop.dmp" : "stop.core";
        await using var server = await Server();
        await Spawn(server, exe, "live-1", "3", "0");
        await Ok(server, "live_break", new() { ["session"] = "live-1", ["action"] = "set", ["at"] = target.FileOpen });
        var stop = await Ok(server, "live_break", new() { ["session"] = "live-1", ["action"] = "continue", ["wait"] = true });
        Assert.Contains("stopped at s1", stop);
        if (target.Emulated)
        {
            Assert.Contains("emulated on an ARM64 machine", await Refused(server, "live_session", new() { ["action"] = "snapshot", ["session"] = "live-1" }, "unsupported"));
            return;
        }
        var snapshot = await Ok(server, "live_session", new() { ["action"] = "snapshot", ["session"] = "live-1", ["outputPath"] = _dir.File(dump) });
        var thread = Regex.Match(stop, @"thread (\d+) stopped").Groups[1].Value;
        Assert.Contains("the stop of thread " + thread, snapshot);
        var stack = await Ok(server, "dump_stack", new() { ["dump"] = dump });
        if (target.Windows)
        {
            Assert.Matches(@"#0 0x[0-9A-F]+ KERNELBASE!CreateFileA .*  native, context,", stack);
            Assert.Contains("from the exception context", stack);
            Assert.Contains("EXCEPTION_BREAKPOINT", await Ok(server, "open_minidump", new() { ["path"] = dump }));
        }
        else
        {
            // The core's signal thread is the stopped one, with the stop's registers in place of those it waits with.
            Assert.Matches($@"thread {thread}, ", stack);
            Assert.Matches(@"#0 0x[0-9A-F]+ libc\.so\.6!\S+ .*  native, context,", stack);
            Assert.DoesNotContain("frida-agent", stack);
            Assert.Contains("SIGTRAP", await Ok(server, "open_minidump", new() { ["path"] = dump }));
        }
        Assert.Matches($@"#1 0x[0-9A-F]+ {Regex.Escape(Path.GetFileNameWithoutExtension(exe))}!Touch\+0x[0-9A-F]+ .*  native, (?!scan)", stack);
        Assert.Matches(@"orders!main\+0x[0-9A-F]+", stack);
        await Ok(server, "live_session", new() { ["action"] = "close", ["session"] = "live-1" });
    }

    // ---- musl libc: starting a program fails with Frida's own error, at once, and leaves nothing running

    [MuslFact]
    public async Task Starting_a_program_on_musl_fails_with_a_typed_error()
    {
        var exe = LiveTarget.LinuxX64.Build(_dir, "orders", LivePrograms.Orders);
        await using var server = await Server();
        var refused = await Refused(server, "live_session", new() { ["action"] = "spawn", ["program"] = exe, ["arguments"] = new[] { "3", "0" } }, "failed");
        Assert.Contains("ProcessNotRespondingError", refused);
        Assert.DoesNotMatch(@"pid \d+, (running|suspended|stopped)", await Ok(server, "live_session", new() { ["action"] = "list" }));
        await Task.Delay(1_000);
        Assert.Empty(Process.GetProcessesByName("orders"));
    }

    // ---- a statically linked program: refused with the cause before Frida's loader runs, started or running

    [LiveTargetFact("linux-x64", attaches: true)] public Task Static_program_is_refused_on_linux_x64() => StaticRefused(LiveTarget.LinuxX64);
    [LiveTargetFact("linux-x86", attaches: true)] public Task Static_program_is_refused_on_linux_x86() => StaticRefused(LiveTarget.LinuxX86);

    private async Task StaticRefused(LiveTarget target)
    {
        var exe = target.Build(_dir, "orders", LivePrograms.Orders, linkStatic: true);
        await using var server = await Server();
        Assert.Contains("statically linked", await Refused(server, "live_session", new() { ["action"] = "spawn", ["program"] = exe, ["arguments"] = new[] { "3", "0" } }, "unsupported"));
        using var running = Process.Start(new ProcessStartInfo(exe) { ArgumentList = { "1000", "20" }, RedirectStandardOutput = true })!;
        try
        {
            Assert.Contains("statically linked", await Refused(server, "live_session", new() { ["action"] = "attach", ["program"] = running.Id.ToString(CultureInfo.InvariantCulture) }, "unsupported"));
            Assert.False(running.HasExited, "the refusal touched the running program");
        }
        finally
        {
            running.Kill();
            running.WaitForExit(10_000);
        }
    }

    // ---- scripts: load, list, messages, unload

    [LiveTargetFact("win-x64")] public Task Scripts_on_win_x64() => Scripts(LiveTarget.WinX64);
    [LiveTargetFact("win-x86")] public Task Scripts_on_win_x86() => Scripts(LiveTarget.WinX86);
    [LiveTargetFact("win-arm64")] public Task Scripts_on_win_arm64() => Scripts(LiveTarget.WinArm64);
    [LiveTargetFact("linux-x64")] public Task Scripts_on_linux_x64() => Scripts(LiveTarget.LinuxX64);
    [LiveTargetFact("osx-arm64")] public Task Scripts_on_osx_arm64() => Scripts(LiveTarget.MacArm64);
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
        Assert.Contains($"script: u1: {{\"pid\":{pid},\"arch\":\"{target.FridaArch}\",\"bits\":{(target.Is64 ? 64 : 32)}}}", events);
        Assert.Contains("u1 unloaded", await Ok(server, "live_script", new() { ["session"] = "live-1", ["action"] = "unload", ["script"] = "u1" }));
        Assert.Contains(", 0 script(s)", await Ok(server, "live_script", new() { ["session"] = "live-1" }));

        // An error in the top-level code, a later one with a message carrying data, and a script from a file.
        Assert.Contains("u2 reported error: Error: on purpose",
            await Ok(server, "live_script", new() { ["session"] = "live-1", ["action"] = "load", ["source"] = "throw new Error('on purpose');" }));
        await Ok(server, "live_script", new()
        {
            ["session"] = "live-1", ["action"] = "load",
            ["source"] = "setTimeout(() => { send({ late: 1 }, new Uint8Array([1, 2, 3]).buffer); throw new Error('later'); }, 50);",
        });
        File.WriteAllText(_dir.File("trace.js"), "send({ file: Process.arch });");
        Assert.Contains($"u4 loaded ({_dir.File("trace.js")})", await Ok(server, "live_script", new() { ["session"] = "live-1", ["action"] = "load", ["path"] = _dir.File("trace.js") }));
        string late = "", fromFile = "";
        for (int i = 0; i < 100 && !(late.Contains("u3: error: Error: later") && fromFile.Contains("\"file\"")); i++, await Task.Delay(100))
            (late, fromFile) = (await Events(server, "live-1", from: "u3"), await Events(server, "live-1", from: "u4"));
        Assert.Contains("u3: {\"late\":1} (+3 bytes of data)", late);
        Assert.Contains("u3: error: Error: later", late);
        Assert.Contains($"u4: {{\"file\":\"{target.FridaArch}\"}}", fromFile);
        Assert.DoesNotContain("u4", late);
        await Ok(server, "live_session", new() { ["action"] = "close", ["session"] = "live-1" });
        Ended(pid);
    }

    // ---- coverage: two runs, report, call graph, diff

    [LiveTargetFact("win-x64")] public Task Coverage_on_win_x64() => Coverage(LiveTarget.WinX64);
    [LiveTargetFact("win-x86")] public Task Coverage_on_win_x86() => Coverage(LiveTarget.WinX86);
    [LiveTargetFact("win-arm64")] public Task Coverage_on_win_arm64() => Coverage(LiveTarget.WinArm64);
    [LiveTargetFact("linux-x64")] public Task Coverage_on_linux_x64() => Coverage(LiveTarget.LinuxX64);
    [LiveTargetFact("osx-arm64")] public Task Coverage_on_osx_arm64() => Coverage(LiveTarget.MacArm64);
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
    [LiveTargetFact("win-arm64")] public Task Threads_on_win_arm64() => Threads(LiveTarget.WinArm64);
    [LiveTargetFact("linux-x64")] public Task Threads_on_linux_x64() => Threads(LiveTarget.LinuxX64);
    [LiveTargetFact("osx-arm64")] public Task Threads_on_osx_arm64() => Threads(LiveTarget.MacArm64);
    [LiveTargetFact("linux-x86")] public Task Threads_on_linux_x86() => Threads(LiveTarget.LinuxX86);

    private async Task Threads(LiveTarget target)
    {
        var exe = target.Build(_dir, "workers", LivePrograms.Workers);
        var name = Regex.Escape(target.Exe("workers"));
        await using var server = await Server();

        // Stops: each continue releases every held thread, each wait returns the next stop.
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
        Output.WriteLine($"300 stops in {sw.ElapsedMilliseconds} ms, {threads.Count} threads");
        Assert.True(threads.Count >= LivePrograms.WorkerThreads / 2, $"{threads.Count} threads stopped");
        await Ok(server, "live_break", new() { ["session"] = "live-1", ["action"] = "clear", ["stopPoint"] = "s1" });
        await Ok(server, "live_break", new() { ["session"] = "live-1", ["action"] = "continue" });
        Assert.Matches(@"exit code 0(?![0-9xX])", await UntilExited(server, "live-1"));
        Assert.Contains($"total {LivePrograms.WorkersTotal(calls)}", await Events(server, "live-1", kind: "output"));
        var threadEvents = await Events(server, "live-1", kind: "thread");
        Assert.True(Regex.Count(threadEvents, "thread started") >= LivePrograms.WorkerThreads, threadEvents);
        Assert.True(Regex.Count(threadEvents, "thread ended") >= LivePrograms.WorkerThreads, threadEvents);
        Ended(pid);

        // watch: 16 threads x 2,000 calls, each recorded or counted over the limit; repeated, since a program
        // could stay in its exit when the last batches were sent during it (1 run in 4 on x86)
        const int burst = 2_000;
        long Count(Group g) => g.Success ? long.Parse(g.Value.Replace(",", ""), CultureInfo.InvariantCulture) : 0;
        for (int run = 2; run <= 9; run++)
        {
            var session = $"live-{run}";
            await Spawn(server, exe, session, $"{burst}", "0");
            await Ok(server, "live_watch", new() { ["session"] = session, ["action"] = "set", ["at"] = "Work", ["rateLimit"] = 100_000 });
            await Ok(server, "live_break", new() { ["session"] = session, ["action"] = "continue" });
            Assert.Matches(@"exit code 0(?![0-9xX])", await UntilExited(server, session, seconds: 30));
            var list = await Ok(server, "live_watch", new() { ["session"] = session });
            var w = Regex.Match(list, @"w1 [^:]+: ([\d,]+) call\(s\) recorded(?:.*?, ([\d,]+) over the rate limit)?");
            Assert.True(w.Success, list);
            Assert.Equal(LivePrograms.WorkerThreads * burst, Count(w.Groups[1]) + Count(w.Groups[2]));
            Assert.Contains($"total {LivePrograms.WorkersTotal(burst)}", await Events(server, session, kind: "output"));
            Assert.DoesNotContain("did not finish", await Events(server, session, kind: "error"));
            await Ok(server, "live_session", new() { ["action"] = "close", ["session"] = session });
        }
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
