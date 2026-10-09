using System.Text.Json;
using ModelContextProtocol.Protocol;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Mcp;

namespace NetDecompilerMcp.Tests;

public class ResponseBudgetTests
{
    private static CallToolResult TextResult(int chars) => new() { Content = [new TextContentBlock { Text = new string('x', chars) }] };

    [Fact]
    public void ResultWithinBudgetPassesUnchanged()
    {
        var options = new ServerOptions { MaxOutputChars = 10_000 };
        var result = TextResult(10_000 + ResponseBudget.Slack);
        Assert.Same(result, ResponseBudget.Enforce(result, "t", options, new ResultStore(), null));
    }

    [Fact]
    public void OversizedResultIsKeptAndPagedThroughReadResult()
    {
        var options = new ServerOptions { MaxOutputChars = 10_000 };
        var store = new ResultStore();
        var limited = ResponseBudget.Enforce(TextResult(100_000), "decompile_type", options, store, null);
        Assert.True(limited.IsError);
        var text = ((TextContentBlock)limited.Content.Single()).Text;
        Assert.StartsWith("Error (limit_exceeded) in decompile_type: the result is 100,000 characters", text);
        Assert.Contains("read_result id=r1", text);

        var tools = new NetDecompilerMcp.Tools.SessionTools(null!, null!, options, store, new OutputPager(options));
        var page = tools.ReadResult("r1");
        Assert.StartsWith("[r1: decompile_type result, 100,000 chars]", page);
        Assert.Contains("Call again with offset=10000", page);
        Assert.Contains("chars 90000-100000 of 100000", tools.ReadResult("R1", offset: 90_000));
        Assert.StartsWith("Error (not_found)", Assert.Throws<ToolError>(() => tools.ReadResult("r2")).Render(null));
    }

    [Fact]
    public void RequestedPageSizeRaisesTheBudget()
    {
        var options = new ServerOptions { MaxOutputChars = 10_000 };
        var request = new CallToolRequestParams
        {
            Name = "decompile_type",
            Arguments = new Dictionary<string, JsonElement> { ["maxChars"] = JsonSerializer.SerializeToElement(200_000) },
        };
        var result = TextResult(150_000);
        Assert.Same(result, ResponseBudget.Enforce(result, "decompile_type", options, new ResultStore(), request));
    }

    [Fact]
    public void StructuredContentCounts()
    {
        var options = new ServerOptions { MaxOutputChars = 2_000 };
        var big = JsonSerializer.SerializeToElement(new { items = Enumerable.Range(0, 5_000).Select(i => $"item {i}").ToArray() });
        var result = new CallToolResult { Content = [new TextContentBlock { Text = "{}" }], StructuredContent = big };
        var limited = ResponseBudget.Enforce(result, "extract_strings", options, new ResultStore(), null);
        Assert.True(limited.IsError);
    }

    [Fact]
    public void StoreDropsOldestBeyondItsCapacity()
    {
        var store = new ResultStore();
        var first = store.Add("a", new string('a', ResultStore.MaxTotalChars / 2 + 1));
        var second = store.Add("b", new string('b', ResultStore.MaxTotalChars / 2 + 1));
        Assert.Throws<ToolError>(() => store.Get(first));
        Assert.Equal("b", store.Get(second).Tool);
    }
}
