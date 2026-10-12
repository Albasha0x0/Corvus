using Microsoft.Extensions.DependencyInjection;
using ModelContextProtocol.Protocol;
using Corvus.Core;
using Corvus.Mcp;

namespace Corvus.Tests;

/// <summary>The call deadline: tools not marked long-running end with a timeout error after DeadlineFactor x --timeout.</summary>
public class CallDeadlineTests
{
    private static ServiceProvider Services(int timeoutSeconds = 1) =>
        new ServiceCollection().AddSingleton(new ServerOptions { TimeoutSeconds = timeoutSeconds }).AddSingleton<ResultStore>().BuildServiceProvider();

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
    [Trait("Speed", "Slow")]
    public async Task WorkLeftRunningPastTheDeadlineIsBoundedAndCounted()
    {
        using var services = Services();
        var leftovers = LeftoverWork.For(services.GetRequiredService<ServerOptions>());
        leftovers.Max = 1;
        var release = new TaskCompletionSource();
        var abandoned = McpProtocolTests.ErrorJson(await Run(services, "search_strings", async _ => { await release.Task; return Done; }).AsTask().WaitAsync(TimeSpan.FromMinutes(1)));
        Assert.True(abandoned.GetProperty("details").GetProperty("stillRunning").GetBoolean());
        Assert.Equal(1, leftovers.Running);

        // at the cap a call waits until its deadline, then is refused as busy with a retry hint
        var started = false;
        var refused = McpProtocolTests.ErrorJson(await Run(services, "get_type_info", _ => { started = true; return Task.FromResult(Done); }));
        Assert.False(started);
        Assert.Equal("provider_unavailable", refused.GetProperty("code").GetString());
        Assert.True(refused.GetProperty("retryable").GetBoolean());
        Assert.True(refused.GetProperty("details").GetProperty("retryAfterMs").GetInt64() > 0);
        Assert.Equal(1, refused.GetProperty("details").GetProperty("leftoverCalls").GetInt32());
        Assert.NotEqual(true, (await Run(services, "server_status", _ => Task.FromResult(Done))).IsError);

        // a waiting call starts as soon as the leftover finishes
        var waiting = Run(services, "get_type_info", _ => Task.FromResult(Done)).AsTask();
        await Task.Delay(100);
        Assert.False(waiting.IsCompleted);
        release.SetResult();
        Assert.NotEqual(true, (await waiting.WaitAsync(TimeSpan.FromMinutes(1))).IsError);
        Assert.Equal(0, leftovers.Running);
        Assert.Equal(1, leftovers.Total);
    }

    [Fact]
    public async Task WorkLeftRunningAfterAClientCancelIsCounted()
    {
        using var services = Services(timeoutSeconds: 3600);
        var leftovers = LeftoverWork.For(services.GetRequiredService<ServerOptions>());
        var release = new TaskCompletionSource();
        using var cts = new CancellationTokenSource();
        var call = Run(services, "search_strings", async _ => { await release.Task; return Done; }, cts.Token).AsTask();
        await cts.CancelAsync();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => call.WaitAsync(TimeSpan.FromMinutes(1)));
        Assert.Equal(1, leftovers.Running);
        release.SetResult();
        for (var clock = System.Diagnostics.Stopwatch.StartNew(); leftovers.Running > 0 && clock.Elapsed < TimeSpan.FromMinutes(1);) await Task.Delay(10);
        Assert.Equal(0, leftovers.Running);
        Assert.Equal(1, leftovers.Total);
    }

    [Fact]
    public async Task ClientCancellationIsNotATimeout()
    {
        // A deadline out of reach: with timers for both, a busy pool could run the deadline's first.
        using var services = Services(timeoutSeconds: 3600);
        using var cts = new CancellationTokenSource();
        var call = Run(services, "decompile_type", async ct => { await Task.Delay(Timeout.Infinite, ct); return Done; }, cts.Token).AsTask();
        await cts.CancelAsync();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => call);
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

    [Fact]
    public async Task AWriterBehindALongReaderAnswersByItsDeadline_NamingTheHolder()
    {
        using var services = Services();
        using var workspace = new AssemblyWorkspace();
        var release = new TaskCompletionSource();
        using var reading = new ManualResetEventSlim();
        // export_project is long-running: no deadline of its own; it holds the shared lock until released (up to 2 minutes).
        var reader = Run(services, "export_project", _ => Task.Run(() => workspace.Read(() =>
        {
            reading.Set();
            release.Task.Wait(TimeSpan.FromMinutes(2));
            return Done;
        }), CancellationToken.None)).AsTask();
        reading.Wait();
        var watch = System.Diagnostics.Stopwatch.StartNew();
        var writer = await Run(services, "rename_symbol", ct => Task.Run(() => workspace.Write(() => Done), ct)).AsTask().WaitAsync(TimeSpan.FromMinutes(1));
        var deadline = CallFilter.Deadline("rename_symbol", services.GetRequiredService<ServerOptions>())!.Value;
        Assert.True(watch.Elapsed < deadline + TimeSpan.FromSeconds(2), $"answered after {watch.Elapsed}");
        var json = McpProtocolTests.ErrorJson(writer);
        Assert.Equal("timeout", json.GetProperty("code").GetString());
        Assert.StartsWith("export_project (shared, running ", json.GetProperty("details").GetProperty("blockedBy").GetString());
        Assert.Contains("held by export_project", json.GetProperty("message").GetString());
        Assert.Contains(workspace.LockUsers(), u => u is { Tool: "export_project", Write: false, Waiting: false });
        release.SetResult();
        Assert.NotEqual(true, (await reader).IsError);
        Assert.Empty(workspace.LockUsers());
    }
}
