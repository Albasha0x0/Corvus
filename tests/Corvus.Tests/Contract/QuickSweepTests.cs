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

    [Fact]
    public async Task Every_tool_family_has_a_success_reply_with_an_action_line()
    {
        using var dir = new TempDir();
        await using var client = await ContractSweep.StartAsync(dir);
        var byFamily = SuccessNoteCases.ByFamily(dir);
        var missing = ToolContract.ByFamily.Keys.Where(f => !byFamily.ContainsKey(f) && !SuccessNoteCases.NotReachable.ContainsKey(f)).ToList();
        Assert.True(missing.Count == 0, $"tool families with no success-with-note case: {string.Join(", ", missing)}");
        var all = byFamily.SelectMany(f => f.Value.Select(e => (Family: f.Key, Entry: e))).ToList();
        foreach (var (family, entry) in all)
            Assert.True(ToolContract.ByFamily[family].ContainsKey(entry.Tool), $"{entry.Tool} is not a tool of the {family} family");
        // An address anchor resolves against a loaded image.
        await client.CallToolAsync("load_assembly", new Dictionary<string, object?> { ["path"] = McpProtocolTests.NativeSample(dir) });
        var tools = (await client.ListToolsAsync()).Where(t => all.Any(a => a.Entry.Tool == t.Name)).ToList();
        var cases = all.Select(a => new ContractSweep.Case(a.Entry.Tool, a.Entry.Label, a.Entry.Args)).ToList();
        // Sequential: apply_metadata_names changes the image the other cases read.
        var results = await ContractSweep.RunAsync(client, tools, cases, byTool: false, parallelism: 1);
        Assert.True(ContractSweep.Failures(results) is "", ContractSweep.Failures(results));
        var without = all.Where(a => !results.Any(r => r.Case.Tool == a.Entry.Tool && r.Case.Label == a.Entry.Label && r.Outcome == "ok"
                && r.Notes.Any(n => n.StartsWith(a.Entry.Expect, StringComparison.Ordinal))))
            .Select(a => $"{a.Family}: {a.Entry.Tool} ({a.Entry.Label}) expects {a.Entry.Expect}; has: "
                + string.Join(" | ", results.Where(r => r.Case.Tool == a.Entry.Tool && r.Case.Label == a.Entry.Label).SelectMany(r => r.Notes).Select(n => n.Split('\n')[0])))
            .ToList();
        Assert.True(without.Count == 0, $"cases whose reply lacks the expected action line:\n{string.Join("\n", without)}\n"
            + string.Join("\n", results.Where(r => r.Outcome != "ok").Select(r => $"  {r.Case.Tool}: {r.Outcome}")));
    }
}
