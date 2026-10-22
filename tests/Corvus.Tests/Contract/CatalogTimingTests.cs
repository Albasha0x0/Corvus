using System.Diagnostics;
using Microsoft.Extensions.DependencyInjection;
using ModelContextProtocol.Client;

namespace Corvus.Tests;

/// <summary>
/// SC-11 latency: initialize ≤ 1 s and tools/list p50 ≤ 50 ms over stdio on a quiet machine (MachineLoad scales both). CORVUS_SERVER_EXE names a published server to
/// time (the release figure); without it the test build runs through dotnet and only tools/list is held to its target.
/// </summary>
[Trait("Speed", "Slow")]
public class CatalogTimingTests(Xunit.Abstractions.ITestOutputHelper output)
{
    public const string ServerExeVariable = "CORVUS_SERVER_EXE";

    [Fact]
    [Trait(PerfBudget.Trait, PerfBudget.Timing)]
    public async Task InitializeAndToolsListAreFast()
    {
        var exe = Environment.GetEnvironmentVariable(ServerExeVariable);
        using var dir = new TempDir();
        var before = MachineLoad.Factor();
        var watch = Stopwatch.StartNew();
        await using var client = await McpClient.CreateAsync(new StdioClientTransport(new StdioClientTransportOptions
        {
            Name = "corvus",
            Command = exe ?? "dotnet",
            Arguments = exe == null ? [McpProtocolTests.ServerDll] : [],
            EnvironmentVariables = new Dictionary<string, string?> { ["CORVUS_ANNOTATIONS_DIR"] = dir.File("annotations"), ["PATH"] = Tools.CmdPath() },
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
        var after = MachineLoad.Factor();
        var (_, load) = MachineLoad.Budget(TimeSpan.FromMilliseconds(50), before, after);
        output.WriteLine($"{exe ?? "dotnet corvus.dll"}: initialize {initialize.TotalMilliseconds:0} ms, first tools/list {times[0]:0} ms, p50 {p50:0.0} ms ({load})");
        PerfBudget.AtMost("catalog/tools-list-p50", p50, 50, "ms", output, load);
        if (exe != null) PerfBudget.Time("catalog/initialize", initialize, TimeSpan.FromSeconds(1), output, load);

        // tools/list is answered from one serialized listing built at start, not from the tools on each request.
        await using var server = await InProcessServer.StartAsync();
        var mcp = server.Services.GetRequiredService<Microsoft.Extensions.Options.IOptions<ModelContextProtocol.Server.McpServerOptions>>().Value;
        var (built, served) = Corvus.Mcp.ToolListCache.Counts(mcp);
        for (int i = 0; i < 21; i++) Assert.NotEmpty(await server.Client.ListToolsAsync());
        Assert.Equal((built, served + 21), Corvus.Mcp.ToolListCache.Counts(mcp));
        Assert.Equal(1, built);
    }
}
