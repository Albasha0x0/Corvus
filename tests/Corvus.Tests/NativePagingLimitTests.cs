using System.Text.Json;
using System.Text.Json.Nodes;
using Corvus.Core;
using Corvus.Mcp;

namespace Corvus.Tests;

/// <summary>Paged native tools: a limit below 1 is an error, and rows cut by the output limit say where to continue.</summary>
[Collection(InProcessCatalogCollection.Name)]
public class NativePagingLimitTests
{
    private static readonly Dictionary<string, JsonObject> Schemas =
        Catalog.OfThisBuild().Tools.ToDictionary(t => (string)t["name"]!, t => t["inputSchema"]!.AsObject());

    private static Dictionary<string, JsonElement> Args(params (string Name, object? Value)[] args) =>
        args.ToDictionary(a => a.Name, a => JsonSerializer.SerializeToElement(a.Value));

    [Fact]
    public void EveryPagedNativeToolRejectsALimitBelowOne()
    {
        var paged = Schemas.Where(s => ArgumentCheck.IsNativeTool(s.Key) && s.Value["properties"]?["limit"] != null).Select(s => s.Key).ToList();
        Assert.Contains("list_functions", paged);
        Assert.Contains("search_instructions", paged);
        foreach (var tool in paged)
            foreach (var bad in new[] { 0, -5 })
            {
                var e = Assert.Throws<ToolError>(() => ArgumentCheck.Apply(JsonSerializer.SerializeToElement(Schemas[tool]), Args(("limit", bad)), tool));
                Assert.Equal(ErrorCode.InvalidArgument, e.Code);
                Assert.Contains("'limit' must be at least 1", e.Message);
            }
        ArgumentCheck.Apply(JsonSerializer.SerializeToElement(Schemas["list_functions"]), Args(("limit", 1)), "list_functions");
    }

    [Fact]
    public void OtherToolsKeepTheirClamp()
    {
        var other = Schemas.First(s => !ArgumentCheck.IsNativeTool(s.Key) && s.Value["properties"]?["limit"] != null);
        ArgumentCheck.Apply(JsonSerializer.SerializeToElement(other.Value), Args(("limit", 0)), other.Key);
    }

    [Fact]
    public void RowsCutByTheOutputLimitNameTheNextOffset()
    {
        var pager = new OutputPager(new ServerOptions { MaxOutputChars = 2_000 });
        var rows = Enumerable.Range(0, 300).Select(i => $"row {i:D4} " + new string('x', 80)).ToList();
        var text = pager.PageRows(rows, 0, 200, "row");
        var note = System.Text.RegularExpressions.Regex.Match(text, @"\[(\d+) of 200 rows fit in the output limit; use offset=(\d+)");
        Assert.True(note.Success, text);
        Assert.Equal(note.Groups[1].Value, note.Groups[2].Value);
        int fit = int.Parse(note.Groups[1].Value);
        Assert.InRange(fit, 1, 199);
        Assert.Contains($"row {fit - 1:D4}", text);
        Assert.DoesNotContain($"row {fit:D4}", text);
        Assert.DoesNotContain("Output truncated", text);
        // the next page starts where the note says
        Assert.StartsWith($"300 rows (showing {fit + 1}-", pager.PageRows(rows, fit, 200, "row"));
    }

    [Fact]
    public void RowsThatFitKeepTheUsualFooter()
    {
        var pager = new OutputPager(new ServerOptions());
        var text = pager.PageRows(Enumerable.Range(0, 10).Select(i => $"r{i}").ToList(), 0, 4, "row");
        Assert.Contains("[More: call again with offset=4]", text);
        Assert.DoesNotContain("rows fit", text);
    }
}
