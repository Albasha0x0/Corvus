
using System.Diagnostics;
using System.Text.Json.Nodes;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Native.Providers;

namespace NetDecompilerMcp.Tests;

/// <summary><see cref="WorkerConnection"/> against an in-process worker: serial and concurrent requests, cancellation by request, kill fallback.</summary>
public class WorkerConnectionTests
{
    private static readonly WorkerConnectionOptions Concurrent = new() { Concurrent = true, CancelGrace = TimeSpan.FromSeconds(10) };

    [Fact]
    public async Task Concurrent_requests_complete_out_of_order()
    {
        using var worker = new FakeWorkerProcess();
        using var c = worker.Connect(Concurrent);
        var slow = c.RequestAsync("sleep", new JsonObject { ["ms"] = 400, ["tag"] = "slow" }, TimeSpan.FromSeconds(10), default);
        var fast = c.RequestAsync("sleep", new JsonObject { ["ms"] = 10, ["tag"] = "fast" }, TimeSpan.FromSeconds(10), default);
        var first = await Task.WhenAny(slow, fast);
        Assert.Same(fast, first);
        Assert.Equal("fast", (await fast).GetProperty("tag").GetString());
        Assert.Equal("slow", (await slow).GetProperty("tag").GetString());
        Assert.True(worker.MaxInFlight >= 2);
    }

    [Fact]
    public async Task Serial_connection_runs_one_request_at_a_time()
    {
        using var worker = new FakeWorkerProcess();
        using var c = worker.Connect(null);
        await Task.WhenAll(Enumerable.Range(0, 4).Select(i => c.RequestAsync("sleep", new JsonObject { ["ms"] = 30 }, TimeSpan.FromSeconds(10), default)));
        Assert.Equal(1, worker.MaxInFlight);
    }

    [Fact]
    public async Task Cancelled_request_is_stopped_by_the_worker_which_keeps_running()
    {
        using var worker = new FakeWorkerProcess();
        using var c = worker.Connect(Concurrent);
        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(200));
        var clock = Stopwatch.StartNew();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => c.RequestAsync("sleep", new JsonObject { ["ms"] = 60_000 }, TimeSpan.FromMinutes(1), cts.Token));
        Assert.True(clock.Elapsed < TimeSpan.FromSeconds(5));
        Assert.True(c.IsAlive);
        Assert.Equal(1, worker.Cancelled);
        Assert.Equal(7, (await c.RequestAsync("echo", new JsonObject { ["v"] = 7 }, TimeSpan.FromSeconds(5), default)).GetProperty("v").GetInt32());
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
    public async Task Request_that_ignores_cancel_kills_the_worker()
    {
        using var worker = new FakeWorkerProcess();
        using var c = worker.Connect(Concurrent with { CancelGrace = TimeSpan.FromMilliseconds(200) });
        var other = c.RequestAsync("sleep", new JsonObject { ["ms"] = 60_000 }, TimeSpan.FromMinutes(1), default);
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
    public async Task Worker_errors_map_to_tool_errors()
    {
        using var worker = new FakeWorkerProcess();
        using var c = worker.Connect(Concurrent);
        var e = await Assert.ThrowsAsync<ToolError>(() => c.RequestAsync("missing", null, TimeSpan.FromSeconds(5), default));
        Assert.Equal(ErrorCode.NotFound, e.Code);
    }
}
