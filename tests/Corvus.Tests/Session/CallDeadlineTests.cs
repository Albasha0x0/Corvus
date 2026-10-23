using Microsoft.Extensions.DependencyInjection;
using ModelContextProtocol.Protocol;
using Corvus.Core;
using Corvus.Mcp;
using Corvus.Native.Annotations;
using Corvus.Services;

namespace Corvus.Tests;

/// <summary>The call deadline: tools not marked long-running end with a timeout error after DeadlineFactor x --timeout.</summary>
public class CallDeadlineTests
{
    private static ServiceProvider Services(int timeoutSeconds = 1, TimeProvider? time = null) =>
        new ServiceCollection().AddSingleton(new ServerOptions { TimeoutSeconds = timeoutSeconds }).AddSingleton<ResultStore>()
            .AddSingleton(time ?? TimeProvider.System).BuildServiceProvider();

    private static ValueTask<CallToolResult> Run(ServiceProvider services, string tool, Func<CancellationToken, Task<CallToolResult>> work, CancellationToken client = default) =>
        CallFilter.Run(new CallToolRequestParams { Name = tool }, null, services, ct => new ValueTask<CallToolResult>(work(ct)), client);

    private static readonly CallToolResult Done = new() { Content = [new TextContentBlock { Text = "done" }] };

    [Fact]
    public void LongRunningToolsHaveNoDeadline()
    {
        var options = new ServerOptions { TimeoutSeconds = 180 };
        Assert.Null(CallFilter.Deadline("export_project", options));
        Assert.Equal(TimeSpan.FromSeconds(180 * CallFilter.DeadlineFactor), CallFilter.Deadline("decompile_member", options));
    }

    [Fact]
    public async Task CallsPastTheDeadlineEndWithATimeout()
    {
        var clock = new ArmedClock();
        using var services = Services(time: clock);
        var release = new TaskCompletionSource();
        var cooperative = Run(services, "decompile_member", async ct => { await Task.Delay(Timeout.Infinite, ct); return Done; }).AsTask();
        var ignoring = Run(services, "search_strings", async _ => { await release.Task; return Done; }).AsTask();
        var quick = Run(services, "get_type_info", _ => Task.FromResult(Done)).AsTask();

        Assert.Equal("done", ((TextContentBlock)(await quick).Content[0]).Text);
        var deadline = CallFilter.Deadline("decompile_member", services.GetRequiredService<ServerOptions>())!.Value;
        // Only the stop fires here, so the grace period cannot end before the cooperative work has stopped.
        var early = CallFilter.Early(deadline);
        Assert.Equal(early, await clock.RunUntilAsync(cooperative, within: early));
        var timedOut = McpProtocolTests.ErrorJson(await cooperative);
        Assert.Equal("timeout", timedOut.GetProperty("code").GetString());
        Assert.True(timedOut.GetProperty("retryable").GetBoolean());
        Assert.False(timedOut.GetProperty("details").GetProperty("stillRunning").GetBoolean());
        Assert.False(timedOut.GetProperty("details").TryGetProperty("retryAfterMs", out _));
        // The work never ends until released below: an answer at all is the deadline's.
        Assert.True(await clock.RunUntilAsync(ignoring) <= deadline);
        var abandoned = McpProtocolTests.ErrorJson(await ignoring);
        Assert.Equal("timeout", abandoned.GetProperty("code").GetString());
        Assert.True(abandoned.GetProperty("details").GetProperty("stillRunning").GetBoolean());
        Assert.Equal((long)LeftoverWork.RetryAfter.TotalMilliseconds, abandoned.GetProperty("details").GetProperty("retryAfterMs").GetInt64());
        release.SetResult();
    }

    [Fact]
    public async Task Time_spent_before_the_call_runs_counts_against_its_deadline()
    {
        var spent = TimeSpan.FromMilliseconds(700);
        var clock = new LateReceipt(spent);
        using var services = Services(time: clock);
        await Run(services, "decompile_member", _ => Task.FromResult(Done));
        var deadline = CallFilter.Deadline("decompile_member", services.GetRequiredService<ServerOptions>())!.Value;
        Assert.Equal(CallFilter.Early(deadline) - spent, clock.FirstTimer);
    }

    [Fact]
    public async Task A_call_whose_stop_passes_before_its_tool_starts_reports_that_nothing_runs()
    {
        // Receipt to the pre-call step takes longer than the stop time, as a cold start on a loaded machine can (46dd5e3b).
        var deadline = CallFilter.Deadline("decompile_member", new ServerOptions { TimeoutSeconds = 1 })!.Value;
        var clock = new LateReceipt(CallFilter.Early(deadline) + TimeSpan.FromMilliseconds(100));
        using var workspace = new AssemblyWorkspace();
        using var services = new ServiceCollection().AddSingleton(new ServerOptions { TimeoutSeconds = 1 }).AddSingleton<ResultStore>()
            .AddSingleton<TimeProvider>(clock).AddSingleton(workspace).BuildServiceProvider();
        bool started = false;
        var result = await Run(services, "decompile_member", _ => { started = true; return Task.FromResult(Done); });
        var error = McpProtocolTests.ErrorJson(result);
        Assert.Equal("timeout", error.GetProperty("code").GetString());
        Assert.False(error.GetProperty("details").GetProperty("stillRunning").GetBoolean());
        Assert.False(started);
    }

    /// <summary>A clock that moves <paramref name="spent"/> right after the call reads its receipt time.</summary>
    private sealed class LateReceipt(TimeSpan spent) : TimeProvider
    {
        private readonly Microsoft.Extensions.Time.Testing.FakeTimeProvider _time = new();
        private bool _received;

        public TimeSpan? FirstTimer { get; private set; }

        public override long GetTimestamp()
        {
            long now = _time.GetTimestamp();
            if (!_received) { _received = true; _time.Advance(spent); }
            return now;
        }

        public override long TimestampFrequency => _time.TimestampFrequency;
        public override DateTimeOffset GetUtcNow() => _time.GetUtcNow();

        public override ITimer CreateTimer(TimerCallback callback, object? state, TimeSpan dueTime, TimeSpan period)
        {
            FirstTimer ??= dueTime;
            return _time.CreateTimer(callback, state, dueTime, period);
        }
    }

    [Fact]
    public async Task WorkLeftRunningPastTheDeadlineIsBoundedAndCounted()
    {
        var clock = new ArmedClock();
        using var services = Services(time: clock);
        var leftovers = LeftoverWork.For(services.GetRequiredService<ServerOptions>());
        leftovers.Max = 1;
        var release = new TaskCompletionSource();
        var first = Run(services, "search_strings", async _ => { await release.Task; return Done; }).AsTask();
        await clock.RunUntilAsync(first);
        var abandoned = McpProtocolTests.ErrorJson(await first);
        Assert.True(abandoned.GetProperty("details").GetProperty("stillRunning").GetBoolean());
        Assert.Equal(1, leftovers.Running);

        // at the cap a call waits until its deadline, then is refused as busy with a retry hint
        var started = false;
        var refusing = Run(services, "get_type_info", _ => { started = true; return Task.FromResult(Done); }).AsTask();
        await clock.RunUntilAsync(refusing);
        var refused = McpProtocolTests.ErrorJson(await refusing);
        Assert.False(started);
        Assert.Equal("provider_unavailable", refused.GetProperty("code").GetString());
        Assert.True(refused.GetProperty("retryable").GetBoolean());
        Assert.True(refused.GetProperty("details").GetProperty("retryAfterMs").GetInt64() > 0);
        Assert.Equal(1, refused.GetProperty("details").GetProperty("leftoverCalls").GetInt32());
        Assert.NotEqual(true, (await Run(services, "server_status", _ => Task.FromResult(Done))).IsError);

        // a waiting call starts as soon as the leftover finishes; the clock stands still, so its deadline cannot end it
        var waiting = Run(services, "get_type_info", _ => Task.FromResult(Done)).AsTask();
        await clock.ArmedAsync();
        Assert.False(waiting.IsCompleted);
        release.SetResult();
        Assert.NotEqual(true, (await waiting.WaitAsync(TimeSpan.FromMinutes(1))).IsError);
        Assert.Equal(0, leftovers.Running);
        Assert.Equal(1, leftovers.Total);
    }

    [Fact]
    public async Task WorkLeftRunningAfterAClientCancelIsCounted()
    {
        var clock = new ArmedClock();
        using var services = Services(timeoutSeconds: 3600, time: clock);
        var leftovers = LeftoverWork.For(services.GetRequiredService<ServerOptions>());
        var release = new TaskCompletionSource();
        using var cts = new CancellationTokenSource();
        var call = Run(services, "search_strings", async _ => { await release.Task; return Done; }, cts.Token).AsTask();
        await cts.CancelAsync();
        // Only the grace period after the cancel fires, not the hour-long deadline.
        await clock.RunUntilAsync(call, within: CallFilter.DeadlineGrace);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => call);
        Assert.Equal(1, leftovers.Running);
        release.SetResult();
        for (var watch = System.Diagnostics.Stopwatch.StartNew(); leftovers.Running > 0 && watch.Elapsed < TimeSpan.FromMinutes(1);) await Task.Delay(10);
        Assert.Equal(0, leftovers.Running);
        Assert.Equal(1, leftovers.Total);
    }

    [Fact]
    public async Task ClientCancellationIsNotATimeout()
    {
        // A deadline out of reach: with timers for both, a busy pool could run the deadline's first.
        using var services = Services(timeoutSeconds: 3600);
        using var cts = new CancellationTokenSource();
        var call = Run(services, "decompile_member", async ct => { await Task.Delay(Timeout.Infinite, ct); return Done; }, cts.Token).AsTask();
        await cts.CancelAsync();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => call);
    }

    [Fact]
    public async Task ServerSideCancellationIsACancelledError()
    {
        // The clock never moves, so the deadline cannot be what cancelled the call.
        using var services = Services(time: new ArmedClock());
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
        var clock = new ArmedClock();
        using var services = Services(time: clock);
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
        var writing = Run(services, "rename_symbol", ct => Task.Run(() => workspace.Write(() => Done), ct)).AsTask();
        var deadline = CallFilter.Deadline("rename_symbol", services.GetRequiredService<ServerOptions>())!.Value;
        // The stop must find the writer queued on the lock: a stop before its work starts names no holder.
        await Task.Run(async () => { while (!workspace.LockUsers().Any(u => u is { Write: true, Waiting: true })) await Task.Delay(5); })
            .WaitAsync(TimeSpan.FromMinutes(1));
        // Only the stop fires: the writer sees it between lock waits, so the grace period cannot end first.
        var elapsed = await clock.RunUntilAsync(writing, within: CallFilter.Early(deadline));
        Assert.True(elapsed <= deadline, $"answered after {elapsed}");
        var json = McpProtocolTests.ErrorJson(await writing);
        Assert.Equal("timeout", json.GetProperty("code").GetString());
        Assert.StartsWith("export_project (shared, running ", json.GetProperty("details").GetProperty("blockedBy").GetString());
        Assert.Contains("held by export_project", json.GetProperty("message").GetString());
        Assert.Contains(workspace.LockUsers(), u => u is { Tool: "export_project", Write: false, Waiting: false });
        release.SetResult();
        Assert.NotEqual(true, (await reader).IsError);
        Assert.Empty(workspace.LockUsers());
    }

    [Fact]
    public async Task A_finished_call_answers_while_another_call_holds_the_workspace_lock()
    {
        using var dir = new TempDir();
        var copy = dir.File("Fixture.dll");
        File.Copy(Env.FixturePath, copy);
        using var env = new Env(copy);
        var ws = env.Workspace;
        var journal = new EditJournal(ws, new AnnotationStore(dir.File("annotations")), env.History);
        using var services = new ServiceCollection().AddSingleton(new ServerOptions { TimeoutSeconds = 3600 }).AddSingleton<ResultStore>()
            .AddSingleton(TimeProvider.System).AddSingleton(ws).AddSingleton<RecentCalls>().AddSingleton(journal).BuildServiceProvider();
        env.Edit(() => env.Edits.StubMethod(env.One("Secret::Validate"), "true"));
        journal.Sync();
        using var holding = new ManualResetEventSlim();
        using var release = new ManualResetEventSlim();
        // Another call keeps the exclusive lock until released (up to 2 minutes).
        var holder = Task.Run(() => ws.Write(() => { holding.Set(); release.Wait(TimeSpan.FromMinutes(2)); return 0; }));
        holding.Wait();
        Task<CallToolResult> Call(string tool, Func<CancellationToken, ValueTask<CallToolResult>> work) =>
            CallFilter.Run(new CallToolRequestParams { Name = tool, Arguments = new Dictionary<string, System.Text.Json.JsonElement>
                { ["path"] = System.Text.Json.JsonSerializer.SerializeToElement(copy) } }, null, services, work, default).AsTask();
        // An argument error and a success of edit tools: neither changed anything, so neither waits for the holder.
        var error = await Call("add_members_csharp", _ => throw new ToolError(ErrorCode.InvalidArgument, "missing required parameter 'type'."))
            .WaitAsync(TimeSpan.FromMinutes(1));
        var success = await Call("rename_symbol", _ => new ValueTask<CallToolResult>(Done)).WaitAsync(TimeSpan.FromMinutes(1));
        Assert.False(holder.IsCompleted);
        Assert.Equal("invalid_argument", McpProtocolTests.ErrorJson(error).GetProperty("code").GetString());
        Assert.NotEqual(true, success.IsError);
        // The input is still named as the loaded target, from the targets published before the hold.
        foreach (var result in new[] { error, success })
            Assert.Equal(env.Fixture.Id, (string?)result.Meta![ToolOutput.ProvenanceKey]!["input"]![0]!["id"]);
        release.Set();
        await holder.WaitAsync(TimeSpan.FromMinutes(1));
        var file = Assert.Single(Directory.GetFiles(journal.Root, "*" + EditJournal.EditsSuffix));
        Assert.Single(EditHistoryService.ReadScript(file).Edits);
    }
}
