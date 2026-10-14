using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using ModelContextProtocol.Protocol;
using Corvus.Core;
using Corvus.Mcp;

namespace Corvus.Tests;

/// <summary>The frame safety net (S1.7) behind the token budget, and the filter's handling of results that escape it.</summary>
public class ResponseBudgetTests
{
    private static CallToolResult TextResult(int chars) => new() { Content = [new TextContentBlock { Text = new string('x', chars) }] };

    [Fact]
    public void ResultWithinTheFramePassesUnchanged()
    {
        var result = TextResult((int)ResponseBudget.Frame(1_000));
        Assert.Same(result, ResponseBudget.Enforce(result, "t", 1_000, new ResultStore(ResultCacheOptions.MemoryOnly)));
    }

    /// <summary>D2: a read-only result over the frame keeps its head and names the whole result; it is never an error.</summary>
    [Fact]
    public void OversizedSuccessKeepsItsHead()
    {
        var store = new ResultStore(ResultCacheOptions.MemoryOnly);
        var limited = ResponseBudget.Enforce(TextResult(100_000), "decompile_member", 1_000, store);
        Assert.NotEqual(true, limited.IsError);
        var text = ((TextContentBlock)limited.Content[0]).Text;
        Assert.StartsWith(new string('x', 1_000), text);
        var id = System.Text.RegularExpressions.Regex.Match(text, @"read_result id=(r-[0-9a-f]{12})").Groups[1].Value;
        Assert.True(text.Length <= ResponseBudget.Frame(1_000));
        Assert.Equal(100_000, store.Read(id).Text.Length);
    }

    [Fact]
    public void EachPartHasItsOwnFrame()
    {
        var items = JsonSerializer.SerializeToElement(new { items = Enumerable.Range(0, 900).Select(i => $"item {i}").ToArray() });
        long structured = items.GetRawText().Length;
        int tokens = (int)((structured - ResponseBudget.Slack) / 4) + 1;
        var result = new CallToolResult { Content = [new TextContentBlock { Text = new string('x', (int)ResponseBudget.Frame(tokens)) }], StructuredContent = items };
        Assert.Same(result, ResponseBudget.Enforce(result, "search_strings", tokens, new ResultStore(ResultCacheOptions.MemoryOnly)));
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
        var store = new ResultStore(ResultCacheOptions.MemoryOnly);
        var huge = new ToolError(ErrorCode.Conflict, "compilation failed: " + string.Concat(Enumerable.Range(0, 5_000).Select(i => $"error {i}; ")), "fix the code")
        {
            Details = new { errors = 5_000 },
        };
        var limited = ResponseBudget.Enforce(ErrorResult.From(huge, "patch_method_csharp"), "patch_method_csharp", 1_000, store);
        Assert.True(ResponseBudget.Size(limited) < 2 * ResponseBudget.Frame(1_000));
        var json = McpProtocolTests.ErrorJson(limited);
        Assert.Equal("conflict", json.GetProperty("code").GetString());
        Assert.StartsWith("compilation failed: error 0; ", json.GetProperty("message").GetString());
        var id = json.GetProperty("details").GetProperty("resultId").GetString()!;
        Assert.Equal($"read_result id={id} shows the full error", json.GetProperty("next").GetString());
        Assert.Contains("error 4999; ", store.Read(id).Text);
        Assert.Contains("Next: fix the code", store.Read(id).Text);

        var small = ErrorResult.From(new ToolError(ErrorCode.NotFound, "no such type"), "decompile_member");
        Assert.Same(small, ResponseBudget.Enforce(small, "decompile_member", 1_000, store));
    }

    [Fact]
    public async Task FilterBoundsThrownErrorsAndStripsStructuredContentFromErrors()
    {
        var services = new ServiceCollection().AddSingleton(new ServerOptions()).AddSingleton(new ResultStore(ResultCacheOptions.MemoryOnly));
        using var provider = services.BuildServiceProvider();
        var request = new CallToolRequestParams { Name = "t" };

        var thrown = await CallFilter.Run(request, null, provider, _ => throw new ToolError(ErrorCode.Failed, new string('e', 50_000)), default);
        Assert.Contains("kept as r-", McpProtocolTests.ErrorJson(thrown).GetProperty("message").GetString());

        var withRecord = await CallFilter.Run(request, null, provider, _ => ValueTask.FromResult(new CallToolResult
        {
            IsError = true,
            Content = [new TextContentBlock { Text = "failed" }],
            StructuredContent = JsonSerializer.SerializeToElement(new { items = 1 }),
        }), default);
        Assert.Null(withRecord.StructuredContent);
    }
}
