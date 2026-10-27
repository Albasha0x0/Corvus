using System.Text.RegularExpressions;
using Corvus.Core;
using ModelContextProtocol.Protocol;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>A coverage run through Frida while the server's thread pool is starved; runs alone, as it starves the process.</summary>
[Collection(nameof(PoolStarvationTests))]
[Trait("Speed", "Slow")]
[Trait("Data", "Real")]
[Permit("live")]
public sealed class LiveCoverageStarvedPoolRealTests(ITestOutputHelper output) : IDisposable
{
    // The program writes the file argv[2] names once its work is done, before
    // its exit, whose coverage point holds the thread for the server.
    private const string Source = """
        #include <stdio.h>
        #include <stdlib.h>
        __declspec(noinline) int Square(int x) { return x * x; }
        __declspec(noinline) int Cube(int x) { return x * x * x; }
        int main(int argc, char** argv)
        {
            int sum = 0;
            for (int i = 0; i < 10; i++) sum += argv[1][0] == '2' ? Square(i) : Cube(i);
            FILE* f = fopen(argv[2], "w");
            fprintf(f, "%d\n", sum);
            fclose(f);
            return 0;
        }
        """;

    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    private async Task<string> Call(InProcessServer server, string tool, Dictionary<string, object?> args)
    {
        var r = await server.Client.CallToolAsync(tool, args);
        var text = string.Concat(r.Content.OfType<TextContentBlock>().Select(b => b.Text));
        output.WriteLine($"{tool}: {text}");
        Assert.False(r.IsError == true, text);
        return text;
    }

    // Regression (fa39d88b): each first call held its thread for a resume from the busy pool.
    [FridaFact]
    public async Task A_program_runs_to_its_exit_under_coverage_while_the_thread_pool_is_starved()
    {
        var exe = LiveFridaRealTests.Build(_dir, "counted", Source);
        var done = _dir.File("done.txt");
        await using var server = await InProcessServer.StartAsync(options: new ServerOptions
        {
            BackgroundIndexing = false, WatchFiles = false, AllowLive = true, AllowLiveSpawn = true,
        });
        await Call(server, "live_session", new() { ["action"] = "spawn", ["program"] = exe, ["arguments"] = new[] { "2", done } });
        Assert.Contains("counting", await Call(server, "live_coverage", new() { ["session"] = "live-1", ["action"] = "start", ["hitLimit"] = 1 }));
        await Call(server, "live_break", new() { ["session"] = "live-1", ["action"] = "continue" });

        // Starve the pool first, then wait on this thread, so no resume can come
        // from the server while the program runs.
        var release = PoolStarvationTests.Starve();
        bool finished;
        try { finished = SpinWait.SpinUntil(() => File.Exists(done), TimeSpan.FromSeconds(30)); }
        finally { release.Set(); }
        Assert.True(finished, "the program did not finish its work within 30 s while the pool was starved");

        for (int i = 0; i < 300 && !(await Call(server, "live_session", new() { ["action"] = "status", ["session"] = "live-1" })).Contains(", exited"); i++)
            await Task.Delay(100);
        var report = await Call(server, "live_coverage", new() { ["action"] = "report", ["run"] = "cov-1", ["match"] = "Square" });
        Assert.Matches(new Regex(@"1\+\s+0x[0-9A-F]+\s+Square"), report);
    }
}
