using System.Diagnostics;
using ModelContextProtocol.Protocol;
using Corvus.Core;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>A cold Ghidra open past the client's deadline answers timeout in time, and a retry joins the running open.</summary>
public class ClientDeadlineRealTests(ITestOutputHelper output)
{
    [GhidraFact, Trait("Speed", "Slow")]
    [Trait(PerfBudget.Trait, PerfBudget.Timing)]
    public async Task A_cold_open_past_the_client_deadline_answers_in_time_and_the_retry_joins_it()
    {
        using var dir = new TempDir();
        // Bytes past the end that differ per run: no saved analysis matches, so the open is cold.
        var path = dir.File("e_sqlite3.dll");
        File.WriteAllBytes(path, [.. File.ReadAllBytes(RealPackages.File("SQLitePCLRaw.lib.e_sqlite3", "2.1.11", "runtimes", "win-x64", "native", "e_sqlite3.dll")), .. Guid.NewGuid().ToByteArray()]);
        var options = new ServerOptions { BackgroundIndexing = false, WatchFiles = false, ClientTimeoutSeconds = 20 };
        await using var server = await InProcessServer.StartAsync(options: options);
        var args = new Dictionary<string, object?> { ["image"] = path, ["address"] = "sqlite3_libversion", ["engine"] = "ghidra" };
        string Text(CallToolResult r) => string.Concat(r.Content.OfType<TextContentBlock>().Select(b => b.Text));

        var clock = Stopwatch.StartNew();
        var first = await server.Client.CallToolAsync("decompile_native", args);
        PerfBudget.Time("engines/cold-open-client-deadline", clock.Elapsed, TimeSpan.FromSeconds(20), output);
        Assert.True(first.IsError == true, Text(first));
        Assert.Contains("still finishing in the background", Text(first));
        Assert.Contains("\"stillRunning\":true", Text(first));

        CallToolResult last;
        int calls = 1;
        do
        {
            last = await server.Client.CallToolAsync("decompile_native", args);
            calls++;
        }
        while (last.IsError == true && Text(last).Contains("in the background") && clock.Elapsed < TimeSpan.FromMinutes(15));
        Assert.True(last.IsError != true, Text(last));
        Assert.Contains("sqlite3_libversion", Text(last));
        // One open served every call: the engine sessions list one Ghidra session for the image.
        var status = await server.Client.CallToolAsync("server_status", new Dictionary<string, object?>());
        Assert.Single(status.StructuredContent!.Value.GetProperty("engineSessions").EnumerateArray(), s => s.GetProperty("engine").GetString() == "ghidra");
        Assert.True(calls >= 2);
    }
}
