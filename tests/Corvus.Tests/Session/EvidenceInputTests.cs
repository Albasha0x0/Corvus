using System.Text.Json;
using ModelContextProtocol.Protocol;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>Evidence as input: kept results, recent calls and bundle entries feed compare_*, diff_function and read_result format=verify.</summary>
public sealed class EvidenceInputTests(ITestOutputHelper output) : IDisposable
{
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    private static string Text(CallToolResult r) => string.Concat(r.Content.OfType<TextContentBlock>().Select(b => b.Text));

    private async Task<CallToolResult> Call(InProcessServer server, string tool, Dictionary<string, object?> args)
    {
        var r = await server.Client.CallToolAsync(tool, args);
        output.WriteLine($"{tool}: {Text(r)}");
        return r;
    }

    [Fact]
    public async Task Comparisons_take_two_results_and_a_partial_side_is_unknown_not_removed()
    {
        await using var server = await InProcessServer.StartAsync();
        await Call(server, "load_assembly", new() { ["path"] = Env.FixturePath });
        await Call(server, "list_types", new() { ["assembly"] = "TestFixture.dll", ["limit"] = 200 });
        await Call(server, "list_types", new() { ["assembly"] = "TestFixture.dll", ["limit"] = 3 });
        foreach (var (tool, old, @new) in new[] { ("compare_assemblies", "last:2", "last:1"), ("compare_native_images", "last:3", "last:2"), ("compare_folders", "last:4", "last:3") })
        {
            var r = await Call(server, tool, new() { ["oldResult"] = old, ["newResult"] = @new });
            Assert.NotEqual(true, r.IsError);
            var evidence = r.StructuredContent!.Value.GetProperty("evidence");
            Assert.Equal("partial", evidence.GetProperty("completeness").GetString());
            Assert.Equal("recent", evidence.GetProperty("old").GetProperty("kind").GetString());
            Assert.Equal("list_types", evidence.GetProperty("new").GetProperty("tool").GetString());
            Assert.Equal(0, evidence.GetProperty("removed").GetInt32());
            Assert.True(evidence.GetProperty("unknown").GetInt32() > 0);
            Assert.Equal(3, evidence.GetProperty("same").GetInt32());
        }
        var both = await Call(server, "compare_assemblies", new() { ["oldAssembly"] = "TestFixture.dll", ["newAssembly"] = "TestFixture.dll", ["oldResult"] = "last:1", ["newResult"] = "last:2" });
        Assert.Equal(true, both.IsError);
        Assert.Contains("not both", Text(both));
    }

    [Fact]
    public async Task Diff_function_diffs_two_bundle_entries_without_the_images()
    {
        var bundle = _dir.File("findings.json");
        await using var server = await InProcessServer.StartAsync();
        await Call(server, "load_assembly", new() { ["path"] = Env.FixturePath });
        var names = (await Call(server, "list_types", new() { ["assembly"] = "TestFixture.dll", ["limit"] = 200 })).StructuredContent!.Value
            .GetProperty("items").EnumerateArray().Select(t => t.GetProperty("name").GetString()!).ToList();
        foreach (var name in names.Take(2)) await Call(server, "decompile_member", new() { ["assembly"] = "TestFixture.dll", ["member"] = name });
        await Call(server, "read_result", new() { ["id"] = "last:2", ["format"] = "evidence", ["outputPath"] = bundle });
        var ids = JsonDocument.Parse(File.ReadAllText(bundle)).RootElement.GetProperty("records").EnumerateArray().Select(r => r.GetProperty("id").GetString()).ToList();
        var r = await Call(server, "diff_function", new() { ["oldResult"] = $"{bundle}#{ids[0]}", ["newResult"] = $"{bundle}#{ids[1]}" });
        Assert.NotEqual(true, r.IsError);
        var record = r.StructuredContent!.Value;
        Assert.Equal("bundle", record.GetProperty("evidence").GetProperty("old").GetProperty("kind").GetString());
        Assert.True(record.GetProperty("removed").GetInt32() > 0 && record.GetProperty("added").GetInt32() > 0);
        Assert.Contains(record.GetProperty("items").EnumerateArray(), row => row.GetProperty("op").GetString() == "+");
    }

    [Fact]
    public async Task Verify_compares_a_result_with_another_without_running_it()
    {
        await using var server = await InProcessServer.StartAsync();
        await Call(server, "load_assembly", new() { ["path"] = Env.FixturePath });
        await Call(server, "list_types", new() { ["assembly"] = "TestFixture.dll", ["limit"] = 5 });
        await Call(server, "list_types", new() { ["assembly"] = "TestFixture.dll", ["limit"] = 5 });
        await Call(server, "list_types", new() { ["assembly"] = "TestFixture.dll", ["limit"] = 4 });
        var same = Text(await Call(server, "read_result", new() { ["id"] = "last:3", ["format"] = "verify", ["against"] = "last:2" }));
        Assert.Contains("1 verified, 0 differ (compared with last:2 (recent list_types", same);
        var other = Text(await Call(server, "read_result", new() { ["id"] = "last:3", ["format"] = "verify", ["against"] = "last:1" }));
        Assert.Contains("DIFFERS  last:3 list_types: other arguments; the content differs", other);
        var rerun = Text(await Call(server, "read_result", new() { ["id"] = "last:1", ["format"] = "verify" }));
        Assert.Contains("1 verified, 0 differ (each call re-run)", rerun);
    }

    /// <summary>E6: a facet either side lacks, or a side that is not complete, makes the comparison's verdicts unknown.</summary>
    [Fact]
    public void A_missing_facet_or_an_incomplete_side_is_unknown_not_equal_or_changed()
    {
        Corvus.Tools.EvidenceInput.Item Side(string record) =>
            new(new Corvus.Core.EvidenceSource("r-1", "kept", "analyze_native_function", null, [], null), "", record);
        const string Two = """{"address":"0x1","name":"a"},{"address":"0x2","name":"b"}""";
        var whole = Side("""{"items":[""" + Two + """],"offset":0,"total":2}""");
        var noCallers = Side("""{"items":[""" + Two.Replace("\"b\"", "\"c\"") +
            """],"offset":0,"total":2,"coverage":{"status":"complete","facets":{"callers":"unavailable: not decoded"}}}""");
        var (gap, changes) = Corvus.Tools.EvidenceInput.Compare(whole, noCallers);
        Assert.Equal("partial", gap.Completeness);
        Assert.Equal(["unknown"], changes.Select(c => c.Kind).Distinct());
        Assert.Equal(["callers"], Corvus.Tools.EvidenceInput.FacetGaps(null, System.Text.Json.Nodes.JsonNode.Parse("""{"coverage":{"facets":{"callers":"unavailable: x","cfg":"available"}}}""")!.AsObject()));

        var stopped = Side("""{"items":[{"address":"0x1","name":"a"}],"offset":0,"total":1,"coverage":{"status":"partial"}}""");
        var (_, absent) = Corvus.Tools.EvidenceInput.Compare(whole, stopped);
        Assert.Equal("unknown", Assert.Single(absent).Kind);
    }
}
