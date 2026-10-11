using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
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
        var text = ((TextContentBlock)limited.Content[0]).Text;
        Assert.StartsWith("Error (limit_exceeded) in decompile_type: the result is 100,000 characters", text);
        Assert.Contains("read_result id=r1", text);
        var json = McpProtocolTests.ErrorJson(limited);
        Assert.Equal("r1", json.GetProperty("details").GetProperty("resultId").GetString());
        Assert.Equal(100_000, json.GetProperty("details").GetProperty("chars").GetInt64());

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
        var limited = ResponseBudget.Enforce(result, "search_strings", options, new ResultStore(), null);
        Assert.True(limited.IsError);
    }

    /// <summary>simplify_methods applied its edit and then reported limit_exceeded, which reads as if nothing had changed.</summary>
    [Fact]
    public void OversizedResultOfAToolThatChangesStateStaysASuccess()
    {
        var options = new ServerOptions { MaxOutputChars = 10_000 };
        var store = new ResultStore();
        var limited = ResponseBudget.Enforce(TextResult(100_000), "simplify_methods", options, store, null);
        Assert.NotEqual(true, limited.IsError);
        var text = ((TextContentBlock)limited.Content[0]).Text;
        Assert.StartsWith(new string('x', 10_000) + "\n\n[The call completed.", text);
        Assert.Contains("read_result id=r1", text);
        Assert.True(ResponseBudget.Size(limited) <= ResponseBudget.Budget(options, null));
        Assert.Equal(100_000, store.Get("r1").Text.Length);
    }

    [Fact]
    public void SizeCountsTextAndStructuredContent()
    {
        var result = new CallToolResult { Content = [new TextContentBlock { Text = new string('x', 100) }], StructuredContent = JsonSerializer.SerializeToElement(new string('y', 48)) };
        Assert.Equal(150, ResponseBudget.Size(result));
    }

    [Fact]
    public void OversizedErrorKeepsItsCodeAndIsKept()
    {
        var options = new ServerOptions { MaxOutputChars = 2_000 };
        var store = new ResultStore();
        var huge = new ToolError(ErrorCode.Conflict, "compilation failed: " + string.Concat(Enumerable.Range(0, 5_000).Select(i => $"error {i}; ")), "fix the code")
        {
            Details = new { errors = 5_000 },
        };
        var limited = ResponseBudget.Enforce(ErrorResult.From(huge, "patch_method_csharp"), "patch_method_csharp", options, store, null);
        Assert.True(ResponseBudget.Size(limited) < ResponseBudget.Budget(options, null));
        var json = McpProtocolTests.ErrorJson(limited);
        Assert.Equal("conflict", json.GetProperty("code").GetString());
        Assert.StartsWith("compilation failed: error 0; ", json.GetProperty("message").GetString());
        Assert.Equal("read_result id=r1 shows the full error", json.GetProperty("next").GetString());
        Assert.Equal("r1", json.GetProperty("details").GetProperty("resultId").GetString());
        Assert.Contains("error 4999; ", store.Get("r1").Text);
        Assert.Contains("Next: fix the code", store.Get("r1").Text);

        var small = ErrorResult.From(new ToolError(ErrorCode.NotFound, "no such type"), "decompile_type");
        Assert.Same(small, ResponseBudget.Enforce(small, "decompile_type", options, store, null));
    }

    [Fact]
    public async Task FilterBoundsThrownErrorsAndStripsStructuredContentFromErrors()
    {
        var services = new ServiceCollection()
            .AddSingleton(new ServerOptions { MaxOutputChars = 2_000 }).AddSingleton<ResultStore>();
        using var provider = services.BuildServiceProvider();
        var request = new CallToolRequestParams { Name = "t" };

        var thrown = await CallFilter.Run(request, null, provider, _ => throw new ToolError(ErrorCode.Failed, new string('e', 50_000)), default);
        Assert.Contains("kept as r1", McpProtocolTests.ErrorJson(thrown).GetProperty("message").GetString());

        var withRecord = await CallFilter.Run(request, null, provider, _ => ValueTask.FromResult(new CallToolResult
        {
            IsError = true,
            Content = [new TextContentBlock { Text = "failed" }],
            StructuredContent = JsonSerializer.SerializeToElement(new { items = 1 }),
        }), default);
        Assert.Null(withRecord.StructuredContent);
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
