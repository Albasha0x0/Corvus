using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Corvus.Core;
using Corvus.Mcp;

namespace Corvus.Tests;

/// <summary>S12 obligations per tool: a contract row, a dryRun policy that matches the schema, a quick-sweep entry, a protocol sample and a real-data test.</summary>
[Collection(InProcessCatalogCollection.Name)]
public partial class ToolObligationsTests
{
    private static readonly List<JsonNode> Tools = Catalog.OfThisBuild(Toolsets.All).Tools;
    private static IEnumerable<string> Names => Tools.Select(t => (string)t["name"]!);

    [Fact]
    public void EveryToolHasAContractRow()
    {
        foreach (var name in Names)
        {
            Assert.True(ToolContract.Table.TryGetValue(name, out var row), $"{name}: no row in Mcp/Contract (output class, latency class, lean, core, dryRun policy)");
            Assert.True(Enum.IsDefined(row!.Output) && Enum.IsDefined(row.Latency), name);
            Assert.True(row.DryRun != DryRunPolicy.None || row.DryRunReason != null, $"{name}: changes something without dryRun and records no reason");
            Assert.True(ToolEffects.Of(name).ReadOnly == (row.DryRun == DryRunPolicy.NotApplicable), $"{name}: dryRun policy {row.DryRun} does not fit its effects");
        }
    }

    [Fact]
    public void DryRunPolicyMatchesTheSchema()
    {
        var violations = new Dictionary<string, string>();
        foreach (var tool in Tools)
        {
            var name = (string)tool["name"]!;
            var dryRun = tool["inputSchema"]!["properties"]?["dryRun"];
            bool defaultTrue = dryRun?["default"] is JsonValue v && v.TryGetValue<bool>(out var b) && b;
            var policy = ToolContract.Of(name).DryRun;
            if (policy == DryRunPolicy.DefaultTrue && !defaultTrue) violations[name] = dryRun is null ? "recorded dryRun=true, takes no dryRun" : "recorded dryRun=true, the schema defaults it to false";
            else if (policy != DryRunPolicy.DefaultTrue && dryRun is not null) violations[name] = $"takes dryRun, recorded {policy}";
        }
        Ratchet.Check("dryrun-policy", "a tool recorded dryRun=true takes dryRun defaulting to true, and only those take it (S7.3, D7)", violations);
    }

    [Fact]
    public void EveryToolIsInTheQuickSweep()
    {
        var violations = Names.Where(n => !QuickSweepTests.Covers(n)).ToDictionary(n => n, n => ToolContract.Of(n).Latency == LatencyClass.Long ? "long-running" : "left out");
        Ratchet.Check("quick-sweep", "every tool has a minimal valid and an invalid call in the quick contract sweep (S12.1)", violations);
    }

    /// <summary>The quick sweep leaves out the Long latency class, so only tools that can run past 10 s belong there.</summary>
    [Fact]
    public void LongLatencyToolsAreLongRunning()
    {
        var notLong = Names.Where(n => ToolContract.Of(n).Latency == LatencyClass.Long && !ToolEffects.Of(n).LongRunning).ToList();
        Assert.True(notLong.Count == 0, "latency Long without longRunning in ToolEffects: " + string.Join(", ", notLong));
    }

    [Fact]
    public void EveryToolHasAProtocolSample()
    {
        var violations = Names.Where(n => !File.Exists(ProtocolSampleTests.SampleFile(n))).ToDictionary(n => n, _ => "no recorded request/response");
        Ratchet.Check("protocol-sample", "every tool has a recorded request/response in tests/Corvus.Tests/ProtocolSamples (S12.2)", violations);
    }

    [GeneratedRegex("""\[Trait\("Data",\s*"Real"\)\]""")]
    private static partial Regex RealTrait();

    [Fact]
    public void EveryToolHasARealDataTest()
    {
        var sources = Directory.EnumerateFiles(Path.Combine(DocsTests.RepoRoot(), "tests", "Corvus.Tests"), "*.cs", SearchOption.AllDirectories)
            .Select(File.ReadAllText).Where(s => RealTrait().IsMatch(s)).ToList();
        var violations = Names.Where(n => !sources.Any(s => s.Contains($"\"{n}\"", StringComparison.Ordinal)))
            .ToDictionary(n => n, _ => "no test with [Trait(\"Data\", \"Real\")] names it");
        Ratchet.Check("real-data-test", "every tool has a full-set test on a real library that names it (S12.3)", violations);
    }
}
