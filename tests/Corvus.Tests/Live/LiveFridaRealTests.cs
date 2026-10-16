using System.Diagnostics;
using System.Text.RegularExpressions;
using Corvus.Core;
using Corvus.Native.Providers.Live;
using ModelContextProtocol.Protocol;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>Runs on Windows when Frida's Python bindings and the MSVC toolset are found.</summary>
public sealed class FridaFactAttribute : FactAttribute
{
    private static readonly Lazy<string?> Missing = new(() =>
        !OperatingSystem.IsWindows() ? "Windows only (the fixture is built with MSVC)."
        : new FridaBackend().Unavailable() is { } f ? f.Reason
        : VisualStudio.VcVarsAll() == null ? "No Visual Studio C++ toolset." : null);

    public FridaFactAttribute()
    {
        if (Missing.Value is { } reason) Skip = reason;
    }
}

/// <summary>
/// The session tools by name on a program built here with its PDB: started suspended, stop points by name and file:line,
/// a stop's stack named by the PDB with source lines, typed reads, events, a saved record verified, and close ending it.
/// </summary>
[Trait("Speed", "Slow")]
[Trait("Data", "Real")]
public sealed class LiveFridaRealTests(ITestOutputHelper output) : IDisposable
{
    private const string Source = """
        #include <stdio.h>
        #include <stdlib.h>
        #include <windows.h>
        struct Order { int id; int lines; double total; };
        static volatile int g_sink;
        __declspec(noinline) int AddLine(struct Order* o, int qty)
        {
            o->lines += 1;
            o->total += qty * 2.5;
            return o->lines;
        }
        int main(int argc, char** argv)
        {
            struct Order o = { 7, 0, 0.0 };
            int rounds = argc > 1 ? atoi(argv[1]) : 1000, pause = argc > 2 ? atoi(argv[2]) : 20;
            for (int i = 0; i < rounds; i++) { g_sink = AddLine(&o, i + 1); if (pause) Sleep(pause); }
            HANDLE h = CreateFileA(argv[0], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL); if (h != INVALID_HANDLE_VALUE) CloseHandle(h); printf("%d\n", o.lines);
            return 0;
        }
        """;

    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    private string Build()
    {
        File.WriteAllText(_dir.File("orders.c"), Source);
        var psi = new ProcessStartInfo("cmd.exe")
        {
            WorkingDirectory = _dir.Path,
            Arguments = $"/s /c \"\"{VisualStudio.VcVarsAll()}\" x64 >nul && cl /nologo /Od /Zi orders.c /link /DEBUG:FULL /INCREMENTAL:NO /OUT:orders.exe\"",
        };
        var (code, log) = Tools.Run(psi, 300_000);
        Assert.True(code == 0 && File.Exists(_dir.File("orders.exe")), log);
        return _dir.File("orders.exe");
    }

    private async Task<(string Text, bool IsError)> Call(InProcessServer server, string tool, Dictionary<string, object?> args)
    {
        var sw = Stopwatch.StartNew();
        var r = await server.Client.CallToolAsync(tool, args);
        var text = string.Concat(r.Content.OfType<TextContentBlock>().Select(b => b.Text));
        output.WriteLine($"{tool} ({sw.ElapsedMilliseconds} ms): {text}");
        return (text, r.IsError == true);
    }

    [FridaFact]
    public async Task A_started_program_stops_by_name_and_line_with_a_named_stack()
    {
        var exe = Build();
        await using var server = await InProcessServer.StartAsync(options: new ServerOptions
        {
            BackgroundIndexing = false, WatchFiles = false, AllowLive = true, AllowLiveSpawn = true,
        });

        var sw = Stopwatch.StartNew();
        var (open, failed) = await Call(server, "live_session", new() { ["action"] = "spawn", ["program"] = exe, ["arguments"] = new[] { "400" } });
        var openMs = sw.ElapsedMilliseconds;
        Assert.False(failed, open);
        Assert.Contains("live-1 (frida): ", open);
        Assert.Contains("suspended", open);
        Assert.Matches(@"0x[0-9A-F]+ orders\.exe  = orders\.exe", open);
        var pid = int.Parse(Regex.Match(open, @"pid (\d+)").Groups[1].Value);
        output.WriteLine($"session open {openMs} ms (target 2,000)");
        Assert.True(openMs < 10_000, $"open took {openMs} ms");

        var (byName, e1) = await Call(server, "live_break", new() { ["session"] = "live-1", ["action"] = "set", ["at"] = "AddLine" });
        Assert.False(e1, byName);
        Assert.Matches(@"s1 set at 0x[0-9A-F]+ orders\.exe!AddLine  .*orders\.c:7", byName);
        var (byLine, e2) = await Call(server, "live_break", new() { ["session"] = "live-1", ["action"] = "set", ["at"] = "orders.c:9" });
        Assert.False(e2, byLine);
        Assert.Matches(@"s2 set at 0x[0-9A-F]+ orders\.exe!AddLine\+0x[0-9A-F]+  .*orders\.c:9", byLine);

        var (first, e3) = await Call(server, "live_break", new() { ["session"] = "live-1", ["action"] = "continue", ["wait"] = true, ["waitSeconds"] = 30 });
        Assert.False(e3, first);
        Assert.Contains("program started", first);
        Assert.Matches(@"thread \d+ stopped at s1 \(orders\.exe!AddLine\)", first);
        Assert.Matches(@"#0 0x[0-9A-F]+ orders\.exe!AddLine  .*orders\.c:7", first);
        Assert.Matches(@"#1 0x[0-9A-F]+ orders\.exe!main\+0x[0-9A-F]+  .*orders\.c:16", first);

        var (verified, _) = await Call(server, "read_result", new() { ["id"] = "last:1", ["format"] = "verify" });
        Assert.Contains("resolve to the same names in the same images", verified);

        var (regs, e4) = await Call(server, "live_read", new() { ["session"] = "live-1", ["registers"] = "rcx,rdx,pc", ["memory"] = "rcx", ["type"] = "int32[2]" });
        Assert.False(e4, regs);
        Assert.Matches(@"rdx +0x1\b", regs);
        Assert.Contains("[0] 7", regs);
        Assert.Contains("[1] 0", regs);
        Assert.Matches(@"pc +0x[0-9a-f]+  orders\.exe!AddLine", regs);

        // the next stop is s2, in the same call: its stack is named within the target once the stop is held
        await Call(server, "live_break", new() { ["session"] = "live-1", ["action"] = "continue" });
        await Task.Delay(500);
        sw.Restart();
        var (second, _) = await Call(server, "live_break", new() { ["session"] = "live-1", ["wait"] = true });
        var namedMs = sw.ElapsedMilliseconds;
        Assert.Matches(@"stopped at s2 \(orders\.exe!AddLine\+0x[0-9A-F]+\)", second);
        output.WriteLine($"held stop to named stack {namedMs} ms (target 300)");
        Assert.True(namedMs < 2_000, $"naming took {namedMs} ms");

        var (summary, e5) = await Call(server, "inspect_process", new() { ["process"] = "live-1" });
        Assert.False(e5, summary);
        Assert.Contains($"{pid}", summary);
        Assert.Contains("orders.exe", summary);

        var (events, _) = await Call(server, "live_events", new() { ["session"] = "live-1", ["kind"] = "stop" });
        Assert.Matches(@"#\d+ stop thread \d+ 0x[0-9A-F]+ orders\.exe!AddLine: stop point s1 hit 1", events);

        var (closed, _) = await Call(server, "live_session", new() { ["action"] = "close", ["session"] = "live-1" });
        Assert.Contains("closed", closed);
        try
        {
            using var left = Process.GetProcessById(pid);
            Assert.True(left.WaitForExit(5_000), "the started program is still running after close");
        }
        catch (ArgumentException) { /* already gone */ }
    }

    /// <summary>Starts the program with its arguments; returns once the session is open.</summary>
    private async Task Spawn(InProcessServer server, string exe, string session, params string[] arguments)
    {
        var (open, failed) = await Call(server, "live_session", new() { ["action"] = "spawn", ["program"] = exe, ["arguments"] = arguments });
        Assert.False(failed, open);
        Assert.Contains($"{session} (frida): ", open);
    }

    private async Task UntilExited(InProcessServer server, string session)
    {
        for (int i = 0; i < 600; i++)
        {
            var (status, _) = await Call(server, "live_session", new() { ["action"] = "status", ["session"] = session });
            if (status.Contains(", exited")) return;
            await Task.Delay(100);
        }
        Assert.Fail($"{session} did not exit within 60 s");
    }

    [FridaFact]
    public async Task Watched_calls_are_decoded_from_the_pdb_and_the_api_table_and_recorded_at_speed()
    {
        var exe = Build();
        await using var server = await InProcessServer.StartAsync(options: new ServerOptions
        {
            BackgroundIndexing = false, WatchFiles = false, AllowLive = true, AllowLiveSpawn = true,
        });

        // 20,000 calls without a pause: every one recorded under a high limit
        await Spawn(server, exe, "live-1", "20000", "0");
        var (pdb, e1) = await Call(server, "live_watch", new() { ["session"] = "live-1", ["action"] = "set", ["at"] = "AddLine", ["rateLimit"] = 100_000 });
        Assert.False(e1, pdb);
        Assert.Contains("orders.exe!AddLine: int AddLine(Order * o, int qty) (PDB prototype)", pdb);
        var (api, e2) = await Call(server, "live_watch", new() { ["session"] = "live-1", ["action"] = "set", ["at"] = "kernelbase!CreateFileA" });
        Assert.False(e2, api);
        Assert.Contains("(known API table)", api);
        var sw = Stopwatch.StartNew();
        await Call(server, "live_break", new() { ["session"] = "live-1", ["action"] = "continue" });
        await UntilExited(server, "live-1");
        output.WriteLine($"20,000 watched calls ran in {sw.ElapsedMilliseconds} ms");
        await Task.Delay(300); // the last batch
        var (list, _) = await Call(server, "live_watch", new() { ["session"] = "live-1" });
        Assert.Contains("w1 orders.exe!AddLine: 20,000 call(s) recorded", list);
        var rate = double.Parse(Regex.Match(list, @"w1 [^:]+: [\d,]+ call\(s\) recorded \(([\d,]+)/s\)").Groups[1].Value.Replace(",", ""));
        output.WriteLine($"recorded {rate:N0} calls/s (target 5,000)");
        Assert.True(rate >= 5_000, $"{rate} calls/s");

        var (calls, _) = await Call(server, "live_events", new() { ["session"] = "live-1", ["kind"] = "call", ["limit"] = 3 });
        var m = Regex.Match(calls, @"call thread \d+ 0x[0-9A-F]+ orders\.exe!main\+0x[0-9A-F]+: AddLine\(o=0x[0-9A-F]+, qty=(\d+)\) -> (\d+)");
        Assert.True(m.Success, calls);
        Assert.Equal(m.Groups[1].Value, m.Groups[2].Value); // each call adds one line: the count returned is the qty passed
        var (file, _) = await Call(server, "live_events", new() { ["session"] = "live-1", ["from"] = "w2" });
        Assert.Matches(@"CreateFileA\(lpFileName=""[^""]*orders\.exe"", dwDesiredAccess=GENERIC_READ, dwShareMode=FILE_SHARE_READ, lpSecurityAttributes=0x0, dwCreationDisposition=OPEN_EXISTING, dwFlagsAndAttributes=FILE_ATTRIBUTE_NORMAL, hTemplateFile=0x0\) -> 0x", file);

        // a low limit: the rest are counted, not recorded
        await Spawn(server, exe, "live-2", "20000", "0");
        await Call(server, "live_watch", new() { ["session"] = "live-2", ["action"] = "set", ["at"] = "AddLine", ["rateLimit"] = 1_000 });
        await Call(server, "live_break", new() { ["session"] = "live-2", ["action"] = "continue" });
        await UntilExited(server, "live-2");
        await Task.Delay(300);
        var (limited, _) = await Call(server, "live_watch", new() { ["session"] = "live-2" });
        var lm = Regex.Match(limited, @"w1 [^:]+: ([\d,]+) call\(s\) recorded.*, ([\d,]+) over the rate limit");
        Assert.True(lm.Success, limited);
        Assert.Equal(20_000, long.Parse(lm.Groups[1].Value.Replace(",", "")) + long.Parse(lm.Groups[2].Value.Replace(",", "")));
    }

    [FridaFact]
    public async Task A_user_script_runs_in_the_program_and_its_messages_are_events()
    {
        var exe = Build();
        await using var server = await InProcessServer.StartAsync(options: new ServerOptions
        {
            BackgroundIndexing = false, WatchFiles = false, AllowLive = true, AllowLiveSpawn = true, LiveScripting = true,
        });
        await Spawn(server, exe, "live-1", "50");
        var (loaded, failed) = await Call(server, "live_script", new()
        {
            ["session"] = "live-1", ["action"] = "load",
            ["source"] = "send({ pid: Process.id, main: Process.enumerateModules()[0].name });",
        });
        Assert.False(failed, loaded);
        Assert.Contains("u1 loaded (inline)", loaded);
        string events = "";
        for (int i = 0; i < 50 && !events.Contains("orders.exe"); i++)
        {
            (events, _) = await Call(server, "live_events", new() { ["session"] = "live-1", ["kind"] = "script" });
            await Task.Delay(100);
        }
        Assert.Matches(@"script: u1: \{""pid"":\d+,""main"":""orders\.exe""\}", events);
        var (bad, _) = await Call(server, "live_script", new() { ["session"] = "live-1", ["action"] = "load", ["source"] = "this is not javascript(" });
        Assert.Contains("SyntaxError", bad);
        Assert.Contains("\"code\":\"invalid_argument\"", bad);
        await Call(server, "live_session", new() { ["action"] = "close", ["session"] = "live-1" });
    }
}
