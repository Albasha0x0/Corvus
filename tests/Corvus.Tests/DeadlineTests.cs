using System.Diagnostics;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using ModelContextProtocol.Protocol;
using Corvus.Core;
using Corvus.Mcp;

namespace Corvus.Tests;

/// <summary>The effective deadline (STANDARDS S9.1) and joined identical calls.</summary>
public sealed class DeadlineTests
{
    private static ServiceProvider Services(ServerOptions options) =>
        new ServiceCollection().AddSingleton(options).AddSingleton<ResultStore>().BuildServiceProvider();

    private static readonly CallToolResult Done = new() { Content = [new TextContentBlock { Text = "done" }] };

    private static Dictionary<string, JsonElement> Args(string json) => JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(json)!;

    private static ValueTask<CallToolResult> Run(ServiceProvider services, string tool, Func<CancellationToken, Task<CallToolResult>> work,
        Dictionary<string, JsonElement>? arguments = null, CancellationToken client = default, string? clientName = null) =>
        CallFilter.Run(new CallToolRequestParams { Name = tool, Arguments = arguments }, null, services, ct => new ValueTask<CallToolResult>(work(ct)), client, clientName);

    [Fact]
    public void Effective_IsTheSmallerOfServerAndClientLessMargin()
    {
        var options = new ServerOptions { TimeoutSeconds = 180 };
        ClientLimits Client(string? id) => ClientProfiles.Resolve(new ServerOptions { TimeoutSeconds = 180, Client = id }, null);
        Assert.Equal(TimeSpan.FromSeconds(360), Deadlines.Effective(false, options, Client(null)));
        Assert.Equal(TimeSpan.FromSeconds(55), Deadlines.Effective(false, options, Client("codex")));
        Assert.Equal(TimeSpan.FromSeconds(235), Deadlines.Effective(false, options, Client("claude-desktop")));
        Assert.Equal(TimeSpan.FromSeconds(360), Deadlines.Effective(false, options, Client("gemini-cli")));
        // Long-running tools have no server deadline, but still stop for the client.
        Assert.Null(Deadlines.Effective(true, options, Client("claude-code")));
        Assert.Equal(TimeSpan.FromSeconds(595), Deadlines.Effective(true, options, Client("gemini-cli")));
        Assert.Equal(TimeSpan.FromSeconds(1), Deadlines.Effective(true, options, Client(null) with { DeadlineSeconds = 3 }));
        Assert.Null(CallFilter.Deadline("export_project", options));
    }

    /// <summary>A long-running tool that ignores its token, with a client that waits <paramref name="clientSeconds"/>.</summary>
    private static async Task<(TimeSpan Elapsed, JsonElement Error)> SlowCallUnder(int clientSeconds, string tool)
    {
        using var services = Services(new ServerOptions { ClientTimeoutSeconds = clientSeconds });
        var release = new TaskCompletionSource();
        var clock = Stopwatch.StartNew();
        var result = await Run(services, tool, async _ => { await release.Task; return Done; }).AsTask().WaitAsync(TimeSpan.FromMinutes(1));
        var elapsed = clock.Elapsed;
        release.SetResult();
        return (elapsed, McpProtocolTests.ErrorJson(result));
    }

    [Fact]
    public async Task AShortClientDeadline_IsAnsweredWithAMarginLeft()
    {
        var (elapsed, error) = await SlowCallUnder(6, "export_project");
        Assert.True(elapsed <= TimeSpan.FromSeconds(2), $"answered after {elapsed}");
        Assert.Equal("timeout", error.GetProperty("code").GetString());
        Assert.True(error.GetProperty("details").GetProperty("stillRunning").GetBoolean());
        Assert.False(error.GetProperty("details").GetProperty("partial").GetBoolean());
        Assert.Equal(ClientProfiles.ClientTimeoutOption, error.GetProperty("details").GetProperty("deadlineSource").GetString());
        Assert.Contains("the client waits 6 s", error.GetProperty("message").GetString());
    }

    [Fact]
    [Trait("Speed", "Slow")]
    public async Task AFakeTenSecondClient_GetsItsAnswerFiveSecondsEarly()
    {
        var (elapsed, error) = await SlowCallUnder(10, "export_project");
        Assert.True(elapsed <= TimeSpan.FromSeconds(5.2), $"answered after {elapsed}");
        Assert.True(elapsed >= TimeSpan.FromSeconds(3), $"answered after {elapsed}");
        Assert.True(error.GetProperty("details").GetProperty("stillRunning").GetBoolean());
    }

    [Fact]
    public async Task IdenticalReadOnlyCalls_JoinOneRun()
    {
        using var services = Services(new ServerOptions { TimeoutSeconds = 3600 });
        int runs = 0;
        var release = new TaskCompletionSource();
        async Task<CallToolResult> Work(CancellationToken _)
        {
            Interlocked.Increment(ref runs);
            await release.Task;
            return new CallToolResult { Content = [new TextContentBlock { Text = "shared" }] };
        }
        // Argument order and spacing do not matter.
        var first = Run(services, "search_strings", Work, Args("""{"pattern":"a","limit":5}""")).AsTask();
        var second = Run(services, "search_strings", Work, Args("""{ "limit": 5, "pattern": "a" }""")).AsTask();
        var other = Run(services, "search_strings", Work, Args("""{"pattern":"b","limit":5}""")).AsTask();
        await Task.Delay(100);
        Assert.Equal(2, runs);
        release.SetResult();
        var results = await Task.WhenAll(first, second, other);
        Assert.All(results, r => Assert.Equal("shared", ((TextContentBlock)r.Content[0]).Text));
        Assert.NotSame(results[0], results[1]);
        Assert.NotSame(results[0].Content[0], results[1].Content[0]);
        Assert.Equal(0, CallJoin.For(services.GetRequiredService<ServerOptions>()).Running);
    }

    [Fact]
    public async Task EditingCallsNeverJoin()
    {
        Assert.Null(CallJoin.Key("rename_symbol", false, Args("""{"symbol":"a"}""")));
        Assert.Null(CallJoin.Key("server_status", true, null));
        Assert.Equal(CallJoin.Key("get_il", true, Args("""{"a":{"y":1,"x":[2,3]}}""")), CallJoin.Key("get_il", true, Args("""{"a":{"x":[2,3],"y":1}}""")));
        Assert.NotEqual(CallJoin.Key("get_il", true, Args("""{"a":{"x":[3,2]}}""")), CallJoin.Key("get_il", true, Args("""{"a":{"x":[2,3]}}""")));

        using var services = Services(new ServerOptions { TimeoutSeconds = 3600 });
        int runs = 0;
        var release = new TaskCompletionSource();
        async Task<CallToolResult> Work(CancellationToken _) { Interlocked.Increment(ref runs); await release.Task; return Done; }
        var a = Run(services, "rename_symbol", Work, Args("""{"symbol":"a"}""")).AsTask();
        var b = Run(services, "rename_symbol", Work, Args("""{"symbol":"a"}""")).AsTask();
        await Task.Delay(100);
        Assert.Equal(2, runs);
        release.SetResult();
        await Task.WhenAll(a, b);
    }

    [Fact]
    public async Task ACallLeftAtTheClientDeadline_IsPickedUpByTheSameCallAgain()
    {
        using var services = Services(new ServerOptions { TimeoutSeconds = 3600, ClientTimeoutSeconds = 6 });
        int runs = 0;
        var release = new TaskCompletionSource();
        async Task<CallToolResult> Work(CancellationToken _)
        {
            Interlocked.Increment(ref runs);
            await release.Task;
            return new CallToolResult { Content = [new TextContentBlock { Text = "finished" }] };
        }
        var arguments = Args("""{"pattern":"slow"}""");
        var left = McpProtocolTests.ErrorJson(await Run(services, "search_strings", Work, arguments).AsTask().WaitAsync(TimeSpan.FromMinutes(1)));
        Assert.True(left.GetProperty("details").GetProperty("stillRunning").GetBoolean());
        Assert.Contains("same arguments", left.GetProperty("next").GetString());
        var leftovers = LeftoverWork.For(services.GetRequiredService<ServerOptions>());
        Assert.Equal(1, leftovers.Running);

        var again = Run(services, "search_strings", Work, arguments).AsTask();
        release.SetResult();
        Assert.Equal("finished", ((TextContentBlock)(await again.WaitAsync(TimeSpan.FromMinutes(1))).Content[0]).Text);
        Assert.Equal(1, runs);
        Assert.Equal(1, leftovers.Total);
    }

    [Fact]
    public async Task AJoinedRunStops_OnlyWhenEveryCallerCancelled()
    {
        using var services = Services(new ServerOptions { TimeoutSeconds = 3600 });
        var stopped = new TaskCompletionSource();
        async Task<CallToolResult> Work(CancellationToken ct)
        {
            // Not a token registration: the delay's own callback can end this method and unregister it first.
            try { await Task.Delay(Timeout.Infinite, ct); }
            finally { stopped.TrySetResult(); }
            return Done;
        }
        using var one = new CancellationTokenSource();
        using var two = new CancellationTokenSource();
        var arguments = Args("""{"pattern":"x"}""");
        var a = Run(services, "search_strings", Work, arguments, one.Token).AsTask();
        var b = Run(services, "search_strings", Work, arguments, two.Token).AsTask();
        await one.CancelAsync();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => a.WaitAsync(TimeSpan.FromMinutes(1)));
        Assert.False(stopped.Task.IsCompleted);
        await two.CancelAsync();
        await stopped.Task.WaitAsync(TimeSpan.FromMinutes(1));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => b.WaitAsync(TimeSpan.FromMinutes(1)));
    }
}
