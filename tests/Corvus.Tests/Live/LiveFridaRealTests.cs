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
            int rounds = argc > 1 ? atoi(argv[1]) : 1000;
            for (int i = 0; i < rounds; i++) { g_sink = AddLine(&o, i + 1); Sleep(20); }
            printf("%d\n", o.lines);
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
}
