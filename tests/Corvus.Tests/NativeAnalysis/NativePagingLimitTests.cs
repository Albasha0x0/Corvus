using System.Text.Json;
using System.Text.Json.Nodes;
using Corvus.Core;
using Corvus.Mcp;

namespace Corvus.Tests;

/// <summary>Paged native tools: a limit below 1 is an error, and rows cut by the output limit say where to continue.</summary>
public class NativePagingLimitTests
{
    private static readonly Dictionary<string, JsonObject> Schemas =
        Catalog.OfThisBuild().Tools.ToDictionary(t => (string)t["name"]!, t => t["inputSchema"]!.AsObject());

    private static Dictionary<string, JsonElement> Args(params (string Name, object? Value)[] args) =>
        args.ToDictionary(a => a.Name, a => JsonSerializer.SerializeToElement(a.Value));

    [Fact]
    public void Every_paged_native_tool_rejects_a_limit_below_one()
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
    public void Other_tools_keep_their_clamp()
    {
        var other = Schemas.First(s => !ArgumentCheck.IsNativeTool(s.Key) && s.Value["properties"]?["limit"] != null);
        ArgumentCheck.Apply(JsonSerializer.SerializeToElement(other.Value), Args(("limit", 0)), other.Key);
    }

    [Fact]
    public void Rows_cut_by_the_output_limit_name_the_next_offset()
    {
        var pager = new OutputPager(new ServerOptions { MaxOutputChars = 2_000 });
        var rows = Enumerable.Range(0, 300).Select(i => $"row {i:D4} " + new string('x', 80)).ToList();
        var text = pager.PageRows(rows, 0, 200, "row");
        var note = System.Text.RegularExpressions.Regex.Match(text, @"showing 1-(\d+)\):[\s\S]*\[More: offset=(\d+)\]\n$");
        Assert.True(note.Success, text);
        Assert.Equal(note.Groups[1].Value, note.Groups[2].Value);
        int fit = int.Parse(note.Groups[1].Value);
        Assert.InRange(fit, 1, 199);
        Assert.Contains($"row {fit - 1:D4}", text);
        Assert.DoesNotContain($"row {fit:D4}", text);
        Assert.DoesNotContain("Output truncated", text);
        // The next page starts where the note says.
        Assert.StartsWith($"300 rows (showing {fit + 1}-", pager.PageRows(rows, fit, 200, "row"));
    }

    [Fact]
    public void Rows_that_fit_keep_the_usual_footer()
    {
        var pager = new OutputPager(new ServerOptions());
        var text = pager.PageRows(Enumerable.Range(0, 10).Select(i => $"r{i}").ToList(), 0, 4, "row");
        Assert.EndsWith("[More: offset=4]\n", text);
        Assert.Contains("10 rows (showing 1-4):", text);
    }
}
