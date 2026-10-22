
using System.Text.Json.Nodes;
using Corvus.Core;
using Corvus.Native.Providers;
using Corvus.Native.Providers.Ghidra;
using Corvus.Native.Providers.Ida;

namespace Corvus.Tests;

/// <summary><see cref="WorkerConnection"/> against an in-process worker: serial and concurrent requests, cancellation by request, kill fallback.</summary>
public class WorkerConnectionTests
{
    /// <summary>A request time limit where the limit is not under test: a starved pool can delay a reply by seconds.</summary>
    private static readonly TimeSpan NoLimit = TimeSpan.FromMinutes(10);
    private static readonly WorkerConnectionOptions Concurrent = new() { Concurrent = true, CancelGrace = TimeSpan.FromSeconds(10) };

    /// <summary>
    /// The error of the first of at most 5 tries whose request reached the worker's input before its time limit ran out;
    /// the last try's error when none did.
    /// </summary>
    private static async Task<ToolError> TimedOutAfterTheWrite(Func<Task<ToolError>> attempt)
    {
        for (int i = 1; ; i++)
        {
            var e = await attempt();
            // A try whose request was not written before the limit missed the precondition, not a check: it is retried.
            if (!e.Message.Contains(" The request had not been written to the worker.") || i == 5) return e;
        }
    }

    [Fact]
    public async Task Concurrent_requests_complete_out_of_order()
    {
        using var worker = new FakeWorkerProcess();
        using var c = worker.Connect(Concurrent);
        var slow = c.RequestAsync("hold", new JsonObject { ["tag"] = "slow" }, NoLimit, default);
        var fast = c.RequestAsync("echo", new JsonObject { ["tag"] = "fast" }, NoLimit, default);
        Assert.Equal("fast", (await fast).GetProperty("tag").GetString());
        Assert.False(slow.IsCompleted);
        worker.Release();
        Assert.Equal("slow", (await slow).GetProperty("tag").GetString());
        Assert.True(worker.MaxInFlight >= 2);
    }

    [Fact]
    public async Task Concurrent_requests_reach_the_worker_in_the_order_sent()
    {
        using var worker = new FakeWorkerProcess();
        using var c = worker.Connect(Concurrent);
        await Task.WhenAll(Enumerable.Range(0, 200).Select(i => c.RequestAsync("echo", new JsonObject { ["n"] = i }, NoLimit, default)).ToList());
        Assert.Equal(Enumerable.Range(1, 200).Select(i => (long)i), worker.Received);
    }

    [Fact]
    public async Task Serial_connection_runs_one_request_at_a_time()
    {
        using var worker = new FakeWorkerProcess();
        using var c = worker.Connect(null);
        await Task.WhenAll(Enumerable.Range(0, 4).Select(i => c.RequestAsync("sleep", new JsonObject { ["ms"] = 30 }, NoLimit, default)));
        Assert.Equal(1, worker.MaxInFlight);
    }

    [Fact]
    public async Task Cancelled_request_is_stopped_by_the_worker_which_keeps_running()
    {
        using var worker = new FakeWorkerProcess();
        using var c = worker.Connect(Concurrent);
        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(200));
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => c.RequestAsync("hold", null, NoLimit, cts.Token));
        Assert.True(c.IsAlive);
        Assert.Equal(1, worker.Cancelled);
        Assert.Equal(7, (await c.RequestAsync("echo", new JsonObject { ["v"] = 7 }, NoLimit, default)).GetProperty("v").GetInt32());
    }

    [Fact]
    public async Task Timed_out_request_is_cancelled_and_reported_as_timeout()
    {
        using var worker = new FakeWorkerProcess();
        using var c = worker.Connect(Concurrent);
        var e = await Assert.ThrowsAsync<ToolError>(() => c.RequestAsync("sleep", new JsonObject { ["ms"] = 60_000 }, TimeSpan.FromMilliseconds(200), default));
        Assert.Equal(ErrorCode.Timeout, e.Code);
        Assert.Contains("cancelled", e.Message);
        Assert.True(c.IsAlive);
    }

    [Fact]
    public async Task A_worker_that_exits_reports_what_it_wrote_to_stderr()
    {
        using var worker = new FakeWorkerProcess();
        using var c = worker.Connect(Concurrent);
        var e = await Assert.ThrowsAsync<ToolError>(() => c.RequestAsync("exit_with_message", new JsonObject { ["message"] = "license check failed" }, NoLimit, default));
        Assert.Equal(ErrorCode.ProviderUnavailable, e.Code);
        Assert.Contains("license check failed", e.Message);
    }

    // Regression for the macOS and Linux failures of A_worker_that_crashes_is_named_and_the_next_call_starts_a_new_one.
    [Fact]
    public async Task A_worker_whose_pipes_close_before_its_exit_is_named_with_its_exit_code_and_stderr()
    {
        using var worker = new FakeWorkerProcess();
        using var c = worker.Connect(Concurrent);
        var e = await Assert.ThrowsAsync<ToolError>(() => c.RequestAsync("exit_late", new JsonObject { ["message"] = "fatal: stack overflow" }, NoLimit, default));
        Assert.Equal(ErrorCode.ProviderUnavailable, e.Code);
        Assert.Contains("test worker exited with code 1 (0x00000001) while handling 'exit_late'.", e.Message);
        Assert.Contains("fatal: stack overflow", e.Message);
    }

    [Fact]
    public async Task A_worker_stopped_for_time_names_what_it_was_doing()
    {
        int? asked = null, id = null;
        var e = await TimedOutAfterTheWrite(async () =>
        {
            using var worker = new FakeWorkerProcess();
            id = worker.Id;
            using var c = worker.Connect(Concurrent with { CancelGrace = TimeSpan.FromMilliseconds(200), StallReport = pids => { asked = pids[0]; return "main thread in analysis"; } });
            return await Assert.ThrowsAsync<ToolError>(() => c.RequestAsync("stubborn", null, TimeSpan.FromMilliseconds(200), default));
        });
        Assert.Contains("the worker was stopped. Progress events: 0. Last worker message: ", e.Message);
        Assert.Contains("ago.\nworker state:\nmain thread in analysis", e.Message);
        Assert.Equal(id, asked);

        using var silent = new FakeWorkerProcess();
        using var s = silent.Connect(new WorkerConnectionOptions { StallReport = _ => "class search" });
        e = await Assert.ThrowsAsync<ToolError>(() => s.WaitReadyAsync(TimeSpan.FromMilliseconds(200), default));
        Assert.Contains("did not start within", e.Message);
        Assert.Contains("worker state:\nclass search", e.Message);
    }

    [Fact]
    public async Task A_timeout_reads_the_worker_before_it_cancels_the_request()
    {
        var cancelsAtReport = -1;
        var e = await TimedOutAfterTheWrite(async () =>
        {
            using var worker = new FakeWorkerProcess();
            using var c = worker.Connect(Concurrent with { StallReport = _ => { cancelsAtReport = Volatile.Read(ref worker.Cancelled); return "request thread in frame"; } });
            return await Assert.ThrowsAsync<ToolError>(() => c.RequestAsync("hold", null, TimeSpan.FromMilliseconds(200), default));
        });
        Assert.Equal(0, cancelsAtReport);
        Assert.Contains("the request was cancelled. Progress events: 0.", e.Message);
        Assert.Contains("worker state:\nrequest thread in frame", e.Message);
        Assert.DoesNotContain("Worker log", e.Message);
    }

    [Fact]
    public async Task A_timeout_names_the_workers_log_line_and_progress_reports_for_the_request()
    {
        using var worker = new FakeWorkerProcess();
        using var c = worker.Connect(Concurrent with { CancelGrace = TimeSpan.FromMilliseconds(200) });
        var logged = c.RequestAsync("stubborn", null, TimeSpan.FromSeconds(3), default);
        var unlogged = c.RequestAsync("stubborn", null, TimeSpan.FromSeconds(3), default);
        worker.Log(WorkerProtocol.RequestLogPrefix + "1 stubborn: started");
        worker.Emit(new JsonObject { ["event"] = "progress", ["id"] = 1L, ["stage"] = "" });
        var e = await Assert.ThrowsAsync<ToolError>(() => logged);
        Assert.Contains("Progress events: 1. Worker log: corvus request 1 stubborn: started.", e.Message);
        e = await Assert.ThrowsAsync<ToolError>(() => unlogged);
        Assert.Contains("Progress events: 0. Worker log: no line for this request read yet.", e.Message);
    }

    [Fact]
    public async Task A_stall_report_that_read_nothing_says_the_worker_state_is_unknown()
    {
        foreach (var (answer, shown) in new[] { (WorkerConnection.StateUnknown + "jcmd Thread.print failed", "jcmd Thread.print failed"), ((string?)null, "the report read nothing") })
        {
            using var worker = new FakeWorkerProcess();
            using var c = worker.Connect(Concurrent with { CancelGrace = TimeSpan.FromMilliseconds(200), StallReport = _ => answer });
            var e = await Assert.ThrowsAsync<ToolError>(() => c.RequestAsync("stubborn", null, TimeSpan.FromMilliseconds(200), default));
            Assert.Contains("\nworker state unknown: " + shown, e.Message);
        }
    }

    [Fact]
    public void A_thread_dump_summary_keeps_the_heap_line_and_running_Ghidra_threads()
    {
        const string threads = """
            "main" #1 prio=5 os_prio=0 tid=0x1 nid=0x2 runnable
               java.lang.Thread.State: RUNNABLE
                    at ghidra.app.plugin.core.analysis.AutoAnalysisManager.startAnalysis(AutoAnalysisManager.java:700)
                    at corvus.Worker.open(Worker.java:120)

            "idle pool" #20 prio=5 waiting on condition
               java.lang.Thread.State: WAITING (parking)
                    at ghidra.util.worker.Worker.run(Worker.java:10)

            "GC Thread#0" os_prio=2 runnable
            """;
        var summary = JavaThreadDump.Summary(threads, " garbage-first heap   total 1048576K, used 1040000K [0x0, 0x1)\n  region size 1024K");
        Assert.StartsWith("heap: garbage-first heap   total 1048576K, used 1040000K", summary);
        Assert.Contains("\"main\" #1", summary);
        Assert.Contains("  at ghidra.app.plugin.core.analysis.AutoAnalysisManager.startAnalysis", summary);
        Assert.DoesNotContain("idle pool", summary);
    }

    [Fact]
    public async Task Request_that_ignores_cancel_kills_the_worker()
    {
        using var worker = new FakeWorkerProcess();
        using var c = worker.Connect(Concurrent with { CancelGrace = TimeSpan.FromMilliseconds(200) });
        var other = c.RequestAsync("sleep", new JsonObject { ["ms"] = 60_000 }, NoLimit, default);
        var e = await Assert.ThrowsAsync<ToolError>(() => c.RequestAsync("stubborn", null, TimeSpan.FromMilliseconds(200), default));
        Assert.Equal(ErrorCode.Timeout, e.Code);
        Assert.Contains("stopped", e.Message);
        Assert.False(c.IsAlive);
        // Requests still running when the worker is stopped fail as well.
        Assert.Equal(ErrorCode.ProviderUnavailable, (await Assert.ThrowsAsync<ToolError>(() => other)).Code);
    }

    [Fact]
    public async Task Serial_connection_kills_on_timeout()
    {
        using var worker = new FakeWorkerProcess();
        using var c = worker.Connect(null);
        var e = await Assert.ThrowsAsync<ToolError>(() => c.RequestAsync("sleep", new JsonObject { ["ms"] = 60_000 }, TimeSpan.FromMilliseconds(200), default));
        Assert.Equal(ErrorCode.Timeout, e.Code);
        Assert.False(c.IsAlive);
        Assert.Equal(0, worker.Cancelled);
    }

    [Fact]
    public async Task Serial_connection_with_grace_cancels_in_the_worker_and_keeps_it()
    {
        using var worker = new FakeWorkerProcess();
        using var c = worker.Connect(new WorkerConnectionOptions { CancelGrace = TimeSpan.FromSeconds(10) });
        var e = await Assert.ThrowsAsync<ToolError>(() => c.RequestAsync("sleep", new JsonObject { ["ms"] = 60_000 }, TimeSpan.FromMilliseconds(200), default));
        Assert.Equal(ErrorCode.Timeout, e.Code);
        Assert.True(c.IsAlive);
        Assert.Equal(1, worker.Cancelled);
        // Cancelled once the worker has the request: a token cancelled sooner ends the wait for the serial gate instead.
        using var cts = new CancellationTokenSource();
        var second = c.RequestAsync("sleep", new JsonObject { ["ms"] = 60_000 }, NoLimit, cts.Token);
        Assert.True(SpinWait.SpinUntil(() => worker.Received.Count == 2, TimeSpan.FromMinutes(1)));
        cts.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => second);
        Assert.True(c.IsAlive);
        Assert.Equal(2, worker.Cancelled);
        Assert.Empty(c.Running);
        Assert.Equal(3, (await c.RequestAsync("echo", new JsonObject { ["v"] = 3 }, NoLimit, default)).GetProperty("v").GetInt32());
    }

    [Fact]
    public async Task Timed_out_request_answered_within_the_grace_returns_its_partial_result()
    {
        using var worker = new FakeWorkerProcess();
        using var c = worker.Connect(new WorkerConnectionOptions { CancelGrace = TimeSpan.FromSeconds(10) });
        var r = await c.RequestAsync("partial", null, TimeSpan.FromMilliseconds(200), default);
        Assert.Equal("cancelled", r.GetProperty("partial").GetString());
        Assert.Equal(42, r.GetProperty("next").GetInt32());
        Assert.True(c.IsAlive);
    }

    [Fact]
    public async Task Requests_carry_their_time_limit_and_show_while_running()
    {
        using var worker = new FakeWorkerProcess();
        using var c = worker.Connect(Concurrent);
        Assert.Equal(90, (await c.RequestAsync("timeout", null, TimeSpan.FromSeconds(90), default)).GetProperty("timeout").GetDouble());
        var running = c.RequestAsync("hold", null, NoLimit, default);
        Assert.Equal("hold", Assert.Single(c.Running).Op);
        worker.Release();
        await running;
        Assert.Empty(c.Running);
    }

    [Fact]
    public async Task Function_lists_cut_short_continue_from_the_cursor()
    {
        static Task<System.Text.Json.JsonElement> Json(string text) => Task.FromResult(System.Text.Json.JsonDocument.Parse(text).RootElement.Clone());
        var starts = new List<uint?>();
        var list = await WorkerRows.FunctionsPaged(start =>
        {
            starts.Add(start);
            return Json(start == null ? """{"rows":[[16,32,"a",0]],"partial":"deadline","next":32}""" : """[[32,48,"b",0]]""");
        });
        Assert.Equal(["a", "b"], list.Select(f => f.Name));
        Assert.Equal([null, 32u], starts);
        var e = await Assert.ThrowsAsync<ToolError>(() => WorkerRows.FunctionsPaged(_ => Json("""{"rows":[],"partial":"deadline","next":0}""")));
        Assert.Equal(ErrorCode.Timeout, e.Code);
    }

    [Fact]
    public async Task Worker_errors_map_to_tool_errors()
    {
        using var worker = new FakeWorkerProcess();
        using var c = worker.Connect(Concurrent);
        var e = await Assert.ThrowsAsync<ToolError>(() => c.RequestAsync("missing", null, NoLimit, default));
        Assert.Equal(ErrorCode.NotFound, e.Code);
    }

    [Fact]
    public void A_crash_of_Ghidras_decompiler_names_IDA_and_the_disassembly()
    {
        var next = GhidraProvider.Remediation(ErrorCode.Failed, "decompiling FUN_140230ba0 failed: Exception while decompiling 140230ba0: Decompiler process died");
        Assert.Contains("engine=ida", next);
        Assert.Contains("disassemble", next);
    }

    [Fact]
    public void An_open_out_of_time_names_the_open_limit_and_a_request_its_own()
    {
        foreach (var next in new[] { IdaProvider.Remediation(ErrorCode.Timeout, "open"), GhidraProvider.Remediation(ErrorCode.Timeout, "open") })
            Assert.Contains(ServerOptions.EngineOpenTimeoutVariable, next);
        foreach (var next in new[] { IdaProvider.Remediation(ErrorCode.Timeout, "decompile"), GhidraProvider.Remediation(ErrorCode.Timeout, "decompile") })
        {
            Assert.Contains(ServerOptions.EngineRequestTimeoutVariable, next);
            Assert.DoesNotContain("keeps running", next); // the worker may have been stopped
        }
    }
}
