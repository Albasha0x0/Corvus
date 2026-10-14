using System.Diagnostics;
using ModelContextProtocol.Client;

namespace Corvus.Tests;

/// <summary>
/// SC-11 latency: initialize ≤ 1 s and tools/list p50 ≤ 50 ms over stdio. CORVUS_SERVER_EXE names a published server to
/// time (the release figure); without it the test build runs through dotnet and only tools/list is held to its target.
/// </summary>
[Trait("Speed", "Slow")]
[Collection(nameof(SerialTimingTests))]
public class CatalogTimingTests(Xunit.Abstractions.ITestOutputHelper output)
{
    public const string ServerExeVariable = "CORVUS_SERVER_EXE";

    [Fact]
    public async Task InitializeAndToolsListAreFast()
    {
        var exe = Environment.GetEnvironmentVariable(ServerExeVariable);
        using var dir = new TempDir();
        var watch = Stopwatch.StartNew();
        await using var client = await McpClient.CreateAsync(new StdioClientTransport(new StdioClientTransportOptions
        {
            Name = "corvus",
            Command = exe ?? "dotnet",
            Arguments = exe == null ? [McpProtocolTests.ServerDll] : [],
            EnvironmentVariables = new Dictionary<string, string?> { ["CORVUS_ANNOTATIONS_DIR"] = dir.File("annotations") },
            ShutdownTimeout = TimeSpan.FromMilliseconds(200),
        }), new McpClientOptions { DiscoverProbeTimeout = Timeout.InfiniteTimeSpan });
        var initialize = watch.Elapsed;

        var times = new List<double>();
        for (int i = 0; i < 21; i++)
        {
            watch.Restart();
            var tools = await client.ListToolsAsync();
            times.Add(watch.Elapsed.TotalMilliseconds);
            Assert.NotEmpty(tools);
        }
        var p50 = times.Skip(1).Order().ElementAt(10);
        output.WriteLine($"{exe ?? "dotnet corvus.dll"}: initialize {initialize.TotalMilliseconds:0} ms, first tools/list {times[0]:0} ms, p50 {p50:0.0} ms");
        Assert.True(p50 <= 50, $"tools/list p50 {p50:0.0} ms, over 50 ms");
        if (exe != null) Assert.True(initialize <= TimeSpan.FromSeconds(1), $"initialize {initialize.TotalMilliseconds:0} ms, over 1 s");
    }
}
