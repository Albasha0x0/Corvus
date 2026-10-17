using System.Diagnostics;
using System.Text;
using System.Text.RegularExpressions;
using Corvus.Core;
using ModelContextProtocol.Protocol;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>Code coverage through Frida on a program built here: two inputs, the functions only each one ran, drawn on the static call graph.</summary>
[Trait("Speed", "Slow")]
[Trait("Data", "Real")]
public sealed class LiveCoverageRealTests(ITestOutputHelper output) : IDisposable
{
    private const string Source = """
        #include <stdio.h>
        #include <stdlib.h>
        __declspec(noinline) int Square(int x) { return x * x; }
        __declspec(noinline) int Cube(int x) { return x * x * x; }
        __declspec(noinline) int Pick(int mode, int x)
        {
            if (mode == 2) return Square(x);
            if (mode == 3) return Cube(x);
            return x;
        }
        int main(int argc, char** argv)
        {
            int mode = argc > 1 ? atoi(argv[1]) : 2, sum = 0;
            for (int i = 0; i < 10; i++) sum += Pick(mode, i);
            printf("%d\n", sum);
            return 0;
        }
        """;

    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    private async Task<string> Call(InProcessServer server, string tool, Dictionary<string, object?> args)
    {
        var sw = Stopwatch.StartNew();
        var r = await server.Client.CallToolAsync(tool, args);
        var text = string.Concat(r.Content.OfType<TextContentBlock>().Select(b => b.Text));
        output.WriteLine($"{tool} ({sw.ElapsedMilliseconds} ms): {text}");
        Assert.False(r.IsError == true, text);
        return text;
    }

    /// <summary>Starts the program with <paramref name="mode"/>, starts a coverage run on it, runs it to its end.</summary>
    private async Task Run(InProcessServer server, string exe, string session, string mode, Dictionary<string, object?> coverage)
    {
        await Call(server, "live_session", new() { ["action"] = "spawn", ["program"] = exe, ["arguments"] = new[] { mode } });
        var sw = Stopwatch.StartNew();
        var start = await Call(server, "live_coverage", new(coverage) { ["session"] = session, ["action"] = "start" });
        output.WriteLine($"points set in {sw.ElapsedMilliseconds} ms");
        Assert.Contains("counting", start);
        await Call(server, "live_break", new() { ["session"] = session, ["action"] = "continue" });
        for (int i = 0; i < 600; i++)
        {
            if (i == 10) await Call(server, "live_coverage", new() { ["action"] = "report", ["run"] = "cov-1", ["limit"] = 400 });
            if (i % 20 == 5) { await Call(server, "live_coverage", new() { ["action"] = "list" }); await Call(server, "live_events", new() { ["session"] = session, ["limit"] = 20 }); }
            if ((await Call(server, "live_session", new() { ["action"] = "status", ["session"] = session })).Contains(", exited")) return;
            await Task.Delay(100);
        }
        Assert.Fail($"{session} did not exit within 60 s");
    }

    /// <summary>The whole format=dot report, its character pages joined.</summary>
    private async Task<string> Dot(InProcessServer server, Dictionary<string, object?> args)
    {
        var all = new StringBuilder();
        for (int offset = 0; ;)
        {
            var page = await Call(server, "live_coverage", new(args) { ["offset"] = offset });
            var more = Regex.Match(page, @"\n\[More: offset=(\d+)\][^\n]*\n?$");
            all.Append(more.Success ? page[..more.Index] + "\n" : page);
            if (!more.Success) return all.ToString();
            offset = int.Parse(more.Groups[1].Value);
        }
    }

    [FridaFact]
    public async Task Two_inputs_run_different_functions_drawn_on_the_static_call_graph()
    {
        var exe = LiveFridaRealTests.Build(_dir, "shapes", Source);
        await using var server = await InProcessServer.StartAsync(options: new ServerOptions
        {
            BackgroundIndexing = false, WatchFiles = false, AllowLive = true, AllowLiveSpawn = true,
        });

        await Run(server, exe, "live-1", "2", new() { ["hitLimit"] = 1 });
        await Run(server, exe, "live-2", "3", new() { ["hitLimit"] = 1 });
        var report = await Call(server, "live_coverage", new() { ["action"] = "report", ["run"] = "cov-1", ["match"] = "Square" });
        Assert.Matches(@"1\+\s+0x[0-9A-F]+\s+Square", report);
        var verified = await Call(server, "read_result", new() { ["id"] = "last:1", ["format"] = "verify" });
        Assert.Contains("resolve to the same names in the same images", verified);

        var diff = await Call(server, "live_coverage", new() { ["action"] = "diff", ["run"] = "cov-1", ["other"] = "cov-2" });
        var onlyFirst = Regex.Match(diff, @"only in cov-1:\r?\n((?:\s+\S+\s+0x[0-9A-F]+\s+\S+\r?\n)+)").Groups[1].Value;
        var onlySecond = Regex.Match(diff, @"only in cov-2:\r?\n((?:\s+\S+\s+0x[0-9A-F]+\s+\S+\r?\n)+)").Groups[1].Value;
        Assert.Contains("Square", onlyFirst);
        Assert.DoesNotContain("Cube", onlyFirst);
        Assert.Contains("Cube", onlySecond);
        Assert.DoesNotContain("Square", onlySecond);

        var cfg = await Dot(server, new() { ["action"] = "report", ["run"] = "cov-1", ["format"] = "dot" });
        string Node(string name) => Regex.Match(cfg, $@"(n\d+) \[label=""{name}\\n").Groups[1].Value;
        Assert.Contains($"  {Node("Pick")} -> {Node("Square")};", cfg);
        Assert.Contains($"  {Node("main")} -> {Node("Pick")};", cfg);
        Assert.Equal("", Node("Cube"));
        Assert.Matches(@"label=""Cube\\n-"" style=dashed", await Dot(server, new() { ["action"] = "report", ["run"] = "cov-1", ["match"] = "Cube", ["show"] = "all", ["format"] = "dot" }));
    }
}
