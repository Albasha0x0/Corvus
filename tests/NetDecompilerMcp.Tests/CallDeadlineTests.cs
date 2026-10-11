using Microsoft.Extensions.DependencyInjection;
using ModelContextProtocol.Protocol;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Mcp;

namespace NetDecompilerMcp.Tests;

/// <summary>The call deadline: tools not marked long-running end with a timeout error after DeadlineFactor x --timeout.</summary>
public class CallDeadlineTests
{
    private static ServiceProvider Services() =>
        new ServiceCollection().AddSingleton(new ServerOptions { TimeoutSeconds = 1 }).AddSingleton<ResultStore>().BuildServiceProvider();

    private static ValueTask<CallToolResult> Run(ServiceProvider services, string tool, Func<CancellationToken, Task<CallToolResult>> work, CancellationToken client = default) =>
        CallFilter.Run(new CallToolRequestParams { Name = tool }, null, services, ct => new ValueTask<CallToolResult>(work(ct)), client);

    private static readonly CallToolResult Done = new() { Content = [new TextContentBlock { Text = "done" }] };

    [Fact]
    public void LongRunningToolsHaveNoDeadline()
    {
        var options = new ServerOptions { TimeoutSeconds = 180 };
        Assert.Null(CallFilter.Deadline("export_project", options));
        Assert.Equal(TimeSpan.FromSeconds(180 * CallFilter.DeadlineFactor), CallFilter.Deadline("decompile_type", options));
    }

    [Fact]
    public async Task CallsPastTheDeadlineEndWithATimeout()
    {
        using var services = Services();
        var release = new TaskCompletionSource();
        var cooperative = Run(services, "decompile_type", async ct => { await Task.Delay(Timeout.Infinite, ct); return Done; }).AsTask();
        var ignoring = Run(services, "search_strings", async _ => { await release.Task; return Done; }).AsTask();
        var quick = Run(services, "get_type_info", async ct => { await Task.Delay(10, ct); return Done; }).AsTask();

        Assert.Equal("done", ((TextContentBlock)(await quick).Content[0]).Text);
        var timedOut = McpProtocolTests.ErrorJson(await cooperative);
        Assert.Equal("timeout", timedOut.GetProperty("code").GetString());
        Assert.True(timedOut.GetProperty("retryable").GetBoolean());
        Assert.False(timedOut.GetProperty("details").GetProperty("stillRunning").GetBoolean());
        // The work never ends until released below: an answer at all is the deadline's (the minute only guards against a hang).
        var abandoned = McpProtocolTests.ErrorJson(await ignoring.WaitAsync(TimeSpan.FromMinutes(1)));
        Assert.Equal("timeout", abandoned.GetProperty("code").GetString());
        Assert.True(abandoned.GetProperty("details").GetProperty("stillRunning").GetBoolean());
        release.SetResult();
    }

    [Fact]
    public async Task ClientCancellationIsNotATimeout()
    {
        using var services = Services();
        using var cts = new CancellationTokenSource(100);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            Run(services, "decompile_type", async ct => { await Task.Delay(Timeout.Infinite, ct); return Done; }, cts.Token).AsTask());
    }

    [Fact]
    public async Task ServerSideCancellationIsACancelledError()
    {
        using var services = Services();
        var result = await Run(services, "get_type_info", _ => throw new OperationCanceledException());
        var json = McpProtocolTests.ErrorJson(result);
        Assert.Equal("cancelled", json.GetProperty("code").GetString());
        Assert.True(json.GetProperty("retryable").GetBoolean());
    }

    [Fact]
    public async Task ToolTimeoutErrorsKeepTheirPartialResult()
    {
        using var services = Services();
        var result = await Run(services, "search_il", ct =>
            throw new ToolError(ErrorCode.Timeout, "search timed out") { Partial = new { matches = 3 } });
        Assert.Equal(3, McpProtocolTests.ErrorJson(result).GetProperty("partial").GetProperty("matches").GetInt32());
    }
}
