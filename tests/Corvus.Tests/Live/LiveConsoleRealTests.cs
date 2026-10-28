using System.Diagnostics;
using Corvus.Core;
using Corvus.Native.Diagnostics;
using ModelContextProtocol.Protocol;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>Needs the pseudoconsole and a Visual Studio C++ toolset for the fixture, checked when a test runs (vswhere).</summary>
[Xunit.Sdk.XunitTestCaseDiscoverer(RunTimeSkips.FactDiscoverer, RunTimeSkips.Assembly)]
public sealed class ConsoleFactAttribute : FactAttribute, IRunTimeSkip
{
    private static readonly Lazy<string?> Missing = new(() =>
        !OperatingSystem.IsWindows() ? "Windows only (the pseudoconsole; the fixture is built with MSVC)."
        : new PseudoConsoleHost().Unavailable() is { } c ? c.Reason
        : !VisualStudio.HasVcVars ? "No Visual Studio C++ toolset." : null);

    public string? RunTimeSkip() => Missing.Value;
}

/// <summary>A console run through the pseudoconsole of a program built here: the script waits for its prompt, types a line, and the transcript shows the echo.</summary>
[Trait("Speed", "Slow")]
[Trait("Data", "Real")]
public sealed class LiveConsoleRealTests(ITestOutputHelper output) : IDisposable
{
    private const string Source = """
        #include <stdio.h>
        #include <string.h>
        int main(void)
        {
            char line[256];
            printf("ready\n");
            printf("name? ");
            fflush(stdout);
            if (!fgets(line, sizeof line, stdin)) return 1;
            line[strcspn(line, "\r\n")] = 0;
            printf("echo: %s\n", line);
            fflush(stdout);
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
        output.WriteLine($"{tool} ({sw.ElapsedMilliseconds} ms): {(text.Length > 2000 ? text[..2000] + "…" : text)}");
        Assert.False(r.IsError == true, text);
        return text;
    }

    [ConsoleFact]
    public async Task The_script_answers_the_prompt_and_the_transcript_shows_the_echo()
    {
        var exe = LiveFridaRealTests.Build(_dir, "prompt", Source);
        await using var server = await InProcessServer.StartAsync(options: new ServerOptions
        {
            BackgroundIndexing = false, WatchFiles = false, AllowLive = true, AllowLiveSpawn = true, LiveAllowAny = true,
        });

        var run = await Call(server, "live_console", new()
        {
            ["action"] = "start", ["program"] = exe, ["script"] = new[] { "wait name?", "send Ada\\r", "wait echo: Ada" },
        });
        Assert.Contains("script complete (3 steps)", run);

        string list = "";
        for (int i = 0; i < 100 && !list.Contains("exited"); i++)
        {
            await Task.Delay(50);
            list = await Call(server, "live_console", new() { ["action"] = "list" });
        }
        Assert.Contains("con-1 prompt.exe", list);
        Assert.Contains("exited (0)", list);

        var transcript = await Call(server, "live_console", new() { ["action"] = "transcript", ["run"] = "con-1" });
        Assert.Contains("ready", transcript);
        Assert.Contains("name? Ada", transcript);
        Assert.Contains("echo: Ada", transcript);
        Assert.Contains("end of the transcript (exited, exit code 0)", transcript);
    }
}
