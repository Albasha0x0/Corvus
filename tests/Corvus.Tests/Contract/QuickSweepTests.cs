using System.Diagnostics;
using Corvus.Mcp;

namespace Corvus.Tests;

/// <summary>Every tool but the long-running ones, once valid and once invalid, answers with a schema-valid success or a coded error.</summary>
public sealed class QuickSweepTests(Xunit.Abstractions.ITestOutputHelper output)
{
    /// <summary>Tools left out besides the long-running class, with the reason.</summary>
    private static readonly Dictionary<string, string> LeftOut = new(StringComparer.Ordinal);

    public static bool Covers(string tool) => ToolContract.Of(tool).Latency != LatencyClass.Long && !LeftOut.ContainsKey(tool);

    [Fact]
    public async Task Every_covered_tool_keeps_the_contract()
    {
        using var dir = new TempDir();
        await using var client = await ContractSweep.StartAsync(dir);
        var tools = (await client.ListToolsAsync()).Where(t => Covers(t.Name)).ToList();
        var cases = ContractSweep.Build(tools, dir, ContractSweep.Depth.Quick);
        var watch = Stopwatch.StartNew();
        var results = await ContractSweep.RunAsync(client, tools, cases, byTool: false, parallelism: 8);
        output.WriteLine($"{watch.Elapsed.TotalSeconds:0.0} s\n{ContractSweep.Summary(results)}");
        Assert.True(ContractSweep.Failures(results) is "", ContractSweep.Failures(results));
        Assert.Equal(tools.Count, results.Select(r => r.Case.Tool).Distinct().Count());
    }
}
