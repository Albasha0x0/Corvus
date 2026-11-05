using System.Text.RegularExpressions;
using Corvus.Core;
using ModelContextProtocol.Protocol;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>Event order in a running session: a call precedes the stop it caused.</summary>
[Trait("Speed", "Slow")]
[Trait("Data", "Real")]
[Permit("live")]
public sealed class LiveEventOrderRealTests(ITestOutputHelper output) : IDisposable
{
    private const string Source = """
        #include <windows.h>
        static volatile int g_sink;
        __declspec(noinline) int AddLine(int qty)
        {
            int total = qty * 2;
            g_sink = total;
            return total;
        }
        int main(void)
        {
            Sleep(200);
            for (int i = 0; i < 3; i++) AddLine(i + 1);
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
        Assert.True(r.IsError != true, text);
        return text;
    }

    [FridaFact]
    public async Task A_watched_call_is_listed_before_the_stop_inside_it()
    {
        var exe = LiveFridaRealTests.Build(_dir, "ordered", Source);
        await using var server = await InProcessServer.StartAsync(options: new ServerOptions
        {
            BackgroundIndexing = false, WatchFiles = false, AllowLive = true, AllowLiveSpawn = true, LiveAllowAny = true,
        });
        await Call(server, "live_session", new() { ["action"] = "spawn", ["program"] = exe });
        await Call(server, "live_watch", new() { ["session"] = "live-1", ["action"] = "set", ["at"] = "AddLine" });
        await Call(server, "live_break", new() { ["session"] = "live-1", ["action"] = "set", ["at"] = "ordered.c:6" });
        await Call(server, "live_break", new() { ["session"] = "live-1", ["action"] = "continue", ["wait"] = true, ["waitSeconds"] = LiveWaits.Seconds(30) });
        // The call's batch is sent after the call returns, so it arrives after the stop.
        await Call(server, "live_break", new() { ["session"] = "live-1", ["action"] = "clear", ["stopPoint"] = "s1" });
        await Call(server, "live_break", new() { ["session"] = "live-1", ["action"] = "continue" });
        string events = "";
        for (int i = 0; i < LiveWaits.Polls(100); i++)
        {
            events = await Call(server, "live_events", new() { ["session"] = "live-1" });
            if (Regex.IsMatch(events, @"#\d+ call ")) break;
            await Task.Delay(100);
        }
        var call = Regex.Match(events, @"#(\d+) call ");
        var stop = Regex.Match(events, @"#(\d+) stop ");
        Assert.True(call.Success && stop.Success, events);
        Assert.True(call.Index < stop.Index, events);
        Assert.True(long.Parse(call.Groups[1].Value) > long.Parse(stop.Groups[1].Value), "the call arrived after the stop: " + events);
    }
}
