using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using ModelContextProtocol.Protocol;
using Corvus.Core;
using Corvus.Mcp;

namespace Corvus.Tests;

public class ResponseBudgetTests
{
    private static CallToolResult TextResult(int chars) => new() { Content = [new TextContentBlock { Text = new string('x', chars) }] };

    [Fact]
    public void ResultWithinBudgetPassesUnchanged()
    {
        var options = new ServerOptions { MaxOutputChars = 10_000 };
        var result = TextResult(10_000 + ResponseBudget.Slack);
        Assert.Same(result, ResponseBudget.Enforce(result, "t", options, new ResultStore(ResultCacheOptions.MemoryOnly), null));
    }

    [Fact]
    public void OversizedResultIsKeptAndPagedThroughReadResult()
    {
        var options = new ServerOptions { MaxOutputChars = 10_000 };
        var store = new ResultStore(ResultCacheOptions.MemoryOnly);
        var limited = ResponseBudget.Enforce(TextResult(100_000), "decompile_type", options, store, null);
        Assert.True(limited.IsError);
        var text = ((TextContentBlock)limited.Content[0]).Text;
        Assert.StartsWith("Error (limit_exceeded) in decompile_type: the result is 100,000 characters", text);
        var id = ResultStore.IdOf(new string('x', 100_000));
        Assert.Contains($"read_result id={id}", text);
        var json = McpProtocolTests.ErrorJson(limited);
        Assert.Equal(id, json.GetProperty("details").GetProperty("resultId").GetString());
        Assert.Equal(100_000, json.GetProperty("details").GetProperty("chars").GetInt64());

        var tools = new Corvus.Tools.SessionTools(null!, null!, options, store);
        var page = tools.ReadResult(id);
        Assert.StartsWith($"[{id}: decompile_type result, text, 100,000 chars]", page);
        // one line of letters: the default page holds the longest prefix within 6,000 estimated tokens
        int next = int.Parse(System.Text.RegularExpressions.Regex.Match(page, @"\[More: offset=(\d+)\]$").Groups[1].Value);
        Assert.InRange(TokenEstimate.Of(new string('x', next)), 5_900, 6_000);
        Assert.EndsWith("[End: 100,000 chars]", tools.ReadResult(id.ToUpperInvariant(), offset: 90_000));
        Assert.StartsWith("Error (not_found)", Assert.Throws<ToolError>(() => tools.ReadResult("r-000000000000")).Render(null));
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
        Assert.Same(result, ResponseBudget.Enforce(result, "decompile_type", options, new ResultStore(ResultCacheOptions.MemoryOnly), request));
    }

    [Fact]
    public void StructuredContentCounts()
    {
        var options = new ServerOptions { MaxOutputChars = 2_000 };
        var big = JsonSerializer.SerializeToElement(new { items = Enumerable.Range(0, 5_000).Select(i => $"item {i}").ToArray() });
        var result = new CallToolResult { Content = [new TextContentBlock { Text = "{}" }], StructuredContent = big };
        var limited = ResponseBudget.Enforce(result, "search_strings", options, new ResultStore(ResultCacheOptions.MemoryOnly), null);
        Assert.True(limited.IsError);
    }

    /// <summary>simplify_methods applied its edit and then reported limit_exceeded, which reads as if nothing had changed.</summary>
    [Fact]
    public void OversizedResultOfAToolThatChangesStateStaysASuccess()
    {
        var options = new ServerOptions { MaxOutputChars = 10_000 };
        var store = new ResultStore(ResultCacheOptions.MemoryOnly);
        var limited = ResponseBudget.Enforce(TextResult(100_000), "simplify_methods", options, store, null);
        Assert.NotEqual(true, limited.IsError);
        var text = ((TextContentBlock)limited.Content[0]).Text;
        Assert.StartsWith(new string('x', 10_000) + "\n\n[The call completed.", text);
        var id = ResultStore.IdOf(new string('x', 100_000));
        Assert.Contains($"read_result id={id}", text);
        Assert.True(ResponseBudget.Size(limited) <= ResponseBudget.Budget(options, null));
        Assert.Equal(100_000, store.Read(id).Text.Length);
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
        var store = new ResultStore(ResultCacheOptions.MemoryOnly);
        var huge = new ToolError(ErrorCode.Conflict, "compilation failed: " + string.Concat(Enumerable.Range(0, 5_000).Select(i => $"error {i}; ")), "fix the code")
        {
            Details = new { errors = 5_000 },
        };
        var limited = ResponseBudget.Enforce(ErrorResult.From(huge, "patch_method_csharp"), "patch_method_csharp", options, store, null);
        Assert.True(ResponseBudget.Size(limited) < ResponseBudget.Budget(options, null));
        var json = McpProtocolTests.ErrorJson(limited);
        Assert.Equal("conflict", json.GetProperty("code").GetString());
        Assert.StartsWith("compilation failed: error 0; ", json.GetProperty("message").GetString());
        var id = json.GetProperty("details").GetProperty("resultId").GetString()!;
        Assert.Matches("^r-[0-9a-f]{12}$", id);
        Assert.Equal($"read_result id={id} shows the full error", json.GetProperty("next").GetString());
        Assert.Contains("error 4999; ", store.Read(id).Text);
        Assert.Contains("Next: fix the code", store.Read(id).Text);

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
