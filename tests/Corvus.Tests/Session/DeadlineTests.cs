using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using ModelContextProtocol.Protocol;
using Corvus.Core;
using Corvus.Mcp;

namespace Corvus.Tests;

/// <summary>The effective deadline (STANDARDS S9.1) and joined identical calls.</summary>
public sealed class DeadlineTests
{
    private static ServiceProvider Services(ServerOptions options, TimeProvider? time = null) =>
        new ServiceCollection().AddSingleton(options).AddSingleton<ResultStore>().AddSingleton(time ?? TimeProvider.System).BuildServiceProvider();

    private static readonly CallToolResult Done = new() { Content = [new TextContentBlock { Text = "done" }] };

    private static Dictionary<string, JsonElement> Args(string json) => JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(json)!;

    private static ValueTask<CallToolResult> Run(ServiceProvider services, string tool, Func<CancellationToken, Task<CallToolResult>> work,
        Dictionary<string, JsonElement>? arguments = null, CancellationToken client = default, string? clientName = null) =>
        CallFilter.Run(new CallToolRequestParams { Name = tool, Arguments = arguments }, null, services, ct => new ValueTask<CallToolResult>(work(ct)), client, clientName);

    // Regression: push run 9388ad88 failed Calls_past_the_deadline_end_with_a_timeout
    // when a collection dropped the grace delay's test-clock timer.
    [Fact]
    public void A_stop_delay_on_a_test_clock_fires_after_a_collection()
    {
        var clock = new Microsoft.Extensions.Time.Testing.FakeTimeProvider();
        var delay = StopTimers.Delay(TimeSpan.FromSeconds(1), clock);
        GC.Collect();
        GC.WaitForPendingFinalizers();
        GC.Collect();
        clock.Advance(TimeSpan.FromSeconds(2));
        Assert.True(delay.IsCompleted);
    }

    [Fact]
    public void Effective_is_the_smaller_of_server_and_client_less_margin()
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
        var clock = new ArmedClock();
        using var services = Services(new ServerOptions { ClientTimeoutSeconds = clientSeconds }, clock);
        var release = new TaskCompletionSource();
        var call = Run(services, tool, async _ => { await release.Task; return Done; }).AsTask();
        var elapsed = await clock.RunUntilAsync(call);
        release.SetResult();
        return (elapsed, McpProtocolTests.ErrorJson(await call));
    }

    [Fact]
    public async Task A_short_client_deadline_is_answered_with_a_margin_left()
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
    public async Task A_fake_ten_second_client_gets_its_answer_five_seconds_early()
    {
        var (elapsed, error) = await SlowCallUnder(10, "export_project");
        Assert.True(elapsed <= TimeSpan.FromSeconds(5.2), $"answered after {elapsed}");
        Assert.True(elapsed >= TimeSpan.FromSeconds(3), $"answered after {elapsed}");
        Assert.True(error.GetProperty("details").GetProperty("stillRunning").GetBoolean());
    }

    [Fact]
    public async Task Identical_read_only_calls_join_one_run()
    {
        using var services = Services(new ServerOptions { TimeoutSeconds = 3600 });
        int runs = 0;
        var release = new TaskCompletionSource();
        var twoRunning = new TaskCompletionSource();
        async Task<CallToolResult> Work(CancellationToken _)
        {
            if (Interlocked.Increment(ref runs) == 2) twoRunning.TrySetResult();
            await release.Task;
            return new CallToolResult { Content = [new TextContentBlock { Text = "shared" }] };
        }
        // Argument order and spacing do not matter.
        var first = Run(services, "search_strings", Work, Args("""{"pattern":"a","limit":5}""")).AsTask();
        var second = Run(services, "search_strings", Work, Args("""{ "limit": 5, "pattern": "a" }""")).AsTask();
        var other = Run(services, "search_strings", Work, Args("""{"pattern":"b","limit":5}""")).AsTask();
        await twoRunning.Task.WaitAsync(TimeSpan.FromMinutes(1));
        release.SetResult();
        var results = await Task.WhenAll(first, second, other);
        Assert.Equal(2, runs);
        Assert.All(results, r => Assert.Equal("shared", ((TextContentBlock)r.Content[0]).Text));
        Assert.NotSame(results[0], results[1]);
        Assert.NotSame(results[0].Content[0], results[1].Content[0]);
        Assert.Equal(0, CallJoin.For(services.GetRequiredService<ServerOptions>()).Running);
    }

    /// <summary>A call of <paramref name="tool"/> that stays running until released, answered at the soft time on a fake clock.</summary>
    private sealed class SoftRun : IDisposable
    {
        private readonly string _tool;

        public readonly ArmedClock Clock = new();
        public readonly AssemblyWorkspace Workspace = new();
        public readonly TaskCompletionSource Release = new();
        public static Dictionary<string, JsonElement> Arguments => Args("""{"path":"a.dll"}""");
        public int Runs;
        public readonly ServiceProvider Services;

        public SoftRun(string tool)
        {
            _tool = tool;
            Services = new ServiceCollection().AddSingleton(new ServerOptions { TimeoutSeconds = 3600 }).AddSingleton<ResultStore>()
                .AddSingleton<TimeProvider>(Clock).AddSingleton(Workspace).BuildServiceProvider();
        }

        /// <summary>The notices queued so far, waiting up to a minute for the first.</summary>
        public async Task<List<string>> NoticesAsync()
        {
            using var limit = new CancellationTokenSource(TimeSpan.FromMinutes(1));
            List<string> notices = [];
            while (notices.Count == 0)
            {
                await Task.Delay(10, limit.Token);
                notices = Workspace.DrainNotices();
            }
            return notices;
        }

        public readonly TaskCompletionSource Started = new();

        /// <summary>
        /// Fires the call's timers once its argument check is done; a repeat has
        /// no start signal, so it gets a short real wait.
        /// </summary>
        public async Task<TimeSpan> AnswerAsync(Task call)
        {
            if (Runs == 0) await Started.Task.WaitAsync(TimeSpan.FromMinutes(1));
            else await Task.Delay(200);
            return await Clock.RunUntilAsync(call);
        }

        /// <summary>Releases the run after a short real wait, so a repeat started before has attached to it.</summary>
        public async Task ReleaseAfterAttachAsync()
        {
            await Task.Delay(200);
            Release.SetResult();
        }

        public ValueTask<CallToolResult> Call() => DeadlineTests.Run(Services, _tool, async _ =>
        {
            Interlocked.Increment(ref Runs);
            Started.TrySetResult();
            await Release.Task;
            return Done;
        }, Arguments);

        public void Dispose() { Services.Dispose(); Workspace.Dispose(); }
    }

    [Fact]
    public async Task A_long_running_call_answers_running_and_the_repeat_picks_the_run_up()
    {
        using var run = new SoftRun("compare_assemblies");
        var first = run.Call().AsTask();
        var elapsed = await run.AnswerAsync(first);
        Assert.True(elapsed <= Deadlines.Soft, $"answered after {elapsed}");
        var error = McpProtocolTests.ErrorJson(await first);
        Assert.StartsWith("running:", error.GetProperty("message").GetString());
        Assert.True(error.GetProperty("retryable").GetBoolean());
        Assert.True(error.GetProperty("details").GetProperty("stillRunning").GetBoolean());
        Assert.Equal("soft", error.GetProperty("details").GetProperty("deadlineSource").GetString());
        Assert.StartsWith("repeat the same call", error.GetProperty("next").GetString());
        Assert.Equal(1, CallJoin.For(run.Services.GetRequiredService<ServerOptions>()).Running);

        var repeat = run.Call().AsTask();
        await run.ReleaseAfterAttachAsync();
        Assert.StartsWith("done", ((TextContentBlock)(await repeat).Content[0]).Text);
        Assert.Equal(1, run.Runs);
    }

    [Fact]
    public async Task A_long_running_call_that_finishes_before_the_soft_time_answers_directly()
    {
        using var run = new SoftRun("compare_assemblies");
        run.Release.SetResult();
        Assert.StartsWith("done", ((TextContentBlock)(await run.Call().AsTask()).Content[0]).Text);
        Assert.Empty(run.Workspace.DrainNotices());
    }

    [Fact]
    public async Task A_ceiling_below_the_soft_time_is_reported_as_the_ceiling()
    {
        using var run = new SoftRun("compare_assemblies");
        run.Services.GetRequiredService<ServerOptions>().CallCeiling = TimeSpan.FromSeconds(10);
        var first = run.Call().AsTask();
        await run.AnswerAsync(first);
        var error = McpProtocolTests.ErrorJson(await first);
        Assert.Equal("ceiling", error.GetProperty("details").GetProperty("deadlineSource").GetString());
        Assert.Contains(ServerOptions.MaxCallMinutesVariable, error.GetProperty("message").GetString());
        run.Release.SetResult();
    }

    [Fact]
    public async Task A_repeat_that_collects_the_result_leaves_no_notice()
    {
        using var run = new SoftRun("compare_assemblies");
        var first = run.Call().AsTask();
        await run.AnswerAsync(first);
        await first;
        var repeat = run.Call().AsTask();
        await run.ReleaseAfterAttachAsync();
        Assert.StartsWith("done", ((TextContentBlock)(await repeat).Content[0]).Text);
        await Task.Delay(50);
        Assert.Empty(run.Workspace.DrainNotices());
    }

    [Fact]
    public async Task A_failed_run_queues_one_notice_with_the_first_line_of_its_error()
    {
        using var run = new SoftRun("compare_assemblies");
        await run.AnswerAsync(run.Call().AsTask());
        run.Release.SetException(new InvalidOperationException("bad input.\nsecond line"));
        var notice = Assert.Single(await run.NoticesAsync());
        Assert.Equal("compare_assemblies failed after its running answer (bad input). Next: repeat the same call to read the error.", notice);
    }

    [Fact]
    public async Task A_cancelled_run_queues_one_notice_naming_the_cancel()
    {
        using var run = new SoftRun("compare_assemblies");
        await run.AnswerAsync(run.Call().AsTask());
        run.Release.SetCanceled();
        var notice = Assert.Single(await run.NoticesAsync());
        Assert.StartsWith("compare_assemblies was cancelled after its running answer.", notice);
    }

    [Fact]
    public async Task A_run_that_outlived_its_callers_queues_one_notice_at_its_end()
    {
        using var run = new SoftRun("compare_assemblies");
        var first = run.Call().AsTask();
        await run.AnswerAsync(first);
        await first;
        var second = run.Call().AsTask();
        await run.AnswerAsync(second);
        await second;
        Assert.Empty(run.Workspace.DrainNotices());
        run.Release.SetResult();
        var notices = await run.NoticesAsync();
        var notice = Assert.Single(notices);
        Assert.Equal("compare_assemblies finished after its running answer. Next: repeat the same call.", notice);
        Assert.Equal(1, run.Runs);
    }

    [Fact]
    public async Task A_repeated_load_assembly_joins_the_first_load()
    {
        Assert.NotNull(CallJoin.Key("load_assembly", false, Args("""{"path":"a.dll"}""")));
        Assert.NotNull(CallJoin.Key("load_session", false, Args("""{"path":"a.json"}""")));
        Assert.Null(CallJoin.Key("unload_assembly", false, Args("""{"path":"a.dll"}""")));
        using var run = new SoftRun("load_assembly");
        var first = run.Call().AsTask();
        await run.AnswerAsync(first);
        Assert.Equal("timeout", McpProtocolTests.ErrorJson(await first).GetProperty("code").GetString());
        var repeat = run.Call().AsTask();
        await run.ReleaseAfterAttachAsync();
        Assert.StartsWith("done", ((TextContentBlock)(await repeat).Content[0]).Text);
        Assert.Equal(1, run.Runs);
    }

    [Fact]
    public async Task Editing_calls_never_join()
    {
        Assert.Null(CallJoin.Key("rename_symbol", false, Args("""{"symbol":"a"}""")));
        Assert.Null(CallJoin.Key("server_status", true, null));
        Assert.Equal(CallJoin.Key("get_il", true, Args("""{"a":{"y":1,"x":[2,3]}}""")), CallJoin.Key("get_il", true, Args("""{"a":{"x":[2,3],"y":1}}""")));
        Assert.NotEqual(CallJoin.Key("get_il", true, Args("""{"a":{"x":[3,2]}}""")), CallJoin.Key("get_il", true, Args("""{"a":{"x":[2,3]}}""")));

        using var services = Services(new ServerOptions { TimeoutSeconds = 3600 });
        int runs = 0;
        var release = new TaskCompletionSource();
        var twoRunning = new TaskCompletionSource();
        async Task<CallToolResult> Work(CancellationToken _)
        {
            if (Interlocked.Increment(ref runs) == 2) twoRunning.TrySetResult();
            await release.Task;
            return Done;
        }
        var a = Run(services, "rename_symbol", Work, Args("""{"symbol":"a"}""")).AsTask();
        var b = Run(services, "rename_symbol", Work, Args("""{"symbol":"a"}""")).AsTask();
        await twoRunning.Task.WaitAsync(TimeSpan.FromMinutes(1));
        release.SetResult();
        await Task.WhenAll(a, b);
        Assert.Equal(2, runs);
    }

    [Fact]
    public async Task A_call_left_at_the_client_deadline_is_picked_up_by_the_same_call_again()
    {
        var clock = new ArmedClock();
        using var services = Services(new ServerOptions { TimeoutSeconds = 3600, ClientTimeoutSeconds = 6 }, clock);
        int runs = 0;
        var release = new TaskCompletionSource();
        async Task<CallToolResult> Work(CancellationToken _)
        {
            Interlocked.Increment(ref runs);
            await release.Task;
            return new CallToolResult { Content = [new TextContentBlock { Text = "finished" }] };
        }
        var arguments = Args("""{"pattern":"slow"}""");
        var first = Run(services, "search_strings", Work, arguments).AsTask();
        // Within the client's deadline: the shared run's own stop, an hour out, must not end it.
        await clock.RunUntilAsync(first, within: TimeSpan.FromSeconds(6));
        var left = McpProtocolTests.ErrorJson(await first);
        Assert.True(left.GetProperty("details").GetProperty("stillRunning").GetBoolean());
        Assert.Contains("repeat the same call", left.GetProperty("next").GetString());
        var leftovers = LeftoverWork.For(services.GetRequiredService<ServerOptions>());
        Assert.Equal(1, leftovers.Running);

        // The clock stands still from here: the call can only end by picking up the finished run.
        var again = Run(services, "search_strings", Work, arguments).AsTask();
        release.SetResult();
        Assert.Equal("finished", ((TextContentBlock)(await again.WaitAsync(TimeSpan.FromMinutes(1))).Content[0]).Text);
        Assert.Equal(1, runs);
        Assert.Equal(1, leftovers.Total);
    }

    [Fact]
    public async Task A_joined_run_stops_only_when_every_caller_cancelled()
    {
        var clock = new ArmedClock();
        using var services = Services(new ServerOptions { TimeoutSeconds = 3600 }, clock);
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
        // Only the grace after the cancel fires; the server deadline an hour out never does.
        await clock.RunUntilAsync(a, within: TimeSpan.FromMinutes(1));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => a);
        Assert.False(stopped.Task.IsCompleted);
        await two.CancelAsync();
        await stopped.Task.WaitAsync(TimeSpan.FromMinutes(1));
        await clock.RunUntilAsync(b, within: TimeSpan.FromMinutes(1));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => b);
    }
}
