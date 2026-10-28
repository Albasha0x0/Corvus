using System.Diagnostics;
using System.Text.Json.Nodes;
using Corvus.Core;
using Corvus.Native.Providers;
using Corvus.Native.Providers.Worker;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary><c>corvus worker</c> processes: a request round-trips, a crash and a memory-limit hit are named, and the next call gets a fresh worker.</summary>
public sealed class WorkerHostTests(ITestOutputHelper output)
{
    private static readonly TimeSpan Limit = TimeSpan.FromSeconds(60);

    /// <summary>A pool whose workers register the fixture ops.</summary>
    private static WorkerPool Pool(long memoryLimitBytes = 0) => new(new WorkerPoolOptions
    {
        Enabled = true,
        MemoryLimitBytes = memoryLimitBytes,
        Start = WorkerPool.OwnCommand() with { Environment = new Dictionary<string, string?> { [WorkerHost.FixtureOpsVariable] = "1" } },
    });

    private static async Task<int> Ping(WorkerPool pool) =>
        (await pool.RunAsync("test", "ping", null, Limit, CancellationToken.None)).GetProperty("pid").GetInt32();

    [Fact]
    public async Task A_request_round_trips_through_a_worker_process()
    {
        using (var off = new WorkerPool(new WorkerPoolOptions { Enabled = false }))
            Assert.Equal(ErrorCode.ProviderUnavailable,
                (await Assert.ThrowsAsync<ToolError>(() => off.RunAsync("test", "ping", null, Limit, CancellationToken.None))).Code);

        using var pool = Pool();
        var started = Stopwatch.StartNew();
        var result = await pool.RunAsync("test", "ping", new JsonObject { ["echo"] = "café \"line\"\n2" }, Limit, CancellationToken.None);
        var start = started.Elapsed;
        Assert.NotEqual(Environment.ProcessId, result.GetProperty("pid").GetInt32());
        Assert.Equal("café \"line\"\n2", result.GetProperty("echo").GetString());

        started.Restart();
        for (int i = 0; i < 100; i++) Assert.Equal(result.GetProperty("pid").GetInt32(), await Ping(pool));
        output.WriteLine($"start and first call {start.TotalMilliseconds:0} ms; then {started.Elapsed.TotalMilliseconds / 100:0.00} ms per call");
    }

    [Fact]
    public async Task A_worker_that_crashes_is_named_and_the_next_call_starts_a_new_one()
    {
        using var pool = Pool();
        var first = await Ping(pool);
        var e = await Assert.ThrowsAsync<ToolError>(() => pool.RunAsync("test", "fixture_exit", null, Limit, CancellationToken.None));
        Assert.Equal(ErrorCode.ProviderUnavailable, e.Code);
        Assert.Contains("test worker exited with code", e.Message);
        Assert.Contains("'fixture_exit'", e.Message);
        Assert.NotEqual(first, await Ping(pool));
    }

    [Fact]
    public async Task A_crash_fails_only_the_request_that_caused_it_and_the_others_run_again_alone()
    {
        using var dir = new TempDir();
        var release = dir.File("release");
        using var pool = Pool();
        var first = await Ping(pool);
        var waiting = pool.RunAsync("test", "fixture_wait", new JsonObject { ["release"] = release }, Limit, CancellationToken.None);
        while (pool.RunningRequests == 0) await Task.Delay(20);
        var e = await Assert.ThrowsAsync<ToolError>(() => pool.RunAsync("test", "fixture_exit", null, Limit, CancellationToken.None, file: "input.bin"));
        Assert.Equal((ErrorCode.ProviderUnavailable, false), (e.Code, e.Retryable));
        Assert.StartsWith("Run alone after the test worker ended, the request ended its worker again: test worker exited with code", e.Message);
        File.WriteAllText(release, "");
        var survived = (await waiting).GetProperty("pid").GetInt32();
        Assert.NotEqual(first, survived);
        Assert.NotEqual(first, await Ping(pool));
    }

    [Fact]
    public async Task A_worker_start_is_stopped_on_idle_time_not_on_wall_time()
    {
        // The command spins for 600 ms of CPU time and then waits without ever sending the ready event.
        using var pool = new WorkerPool(new WorkerPoolOptions
        {
            Enabled = true,
            MemoryLimitBytes = 0,
            StartTimeout = TimeSpan.FromMilliseconds(300),
            Start = new ChildProcessStart(FakeTool.Executable, ["spin", "600"]),
        });
        var e = await Assert.ThrowsAsync<ToolError>(() => pool.RunAsync("test", "ping", null, Limit, CancellationToken.None));
        Assert.Equal(ErrorCode.Timeout, e.Code);
        Assert.Matches("while starting|its overall limit of 0.9 s", e.Message);
    }

    // Native allocation passes no GC limit: on macOS only the footprint watchdog stops it.
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task A_worker_past_its_memory_limit_is_named_and_the_next_call_starts_a_new_one(bool native)
    {
        using var pool = Pool(300L << 20);
        var first = await Ping(pool);
        var e = await Assert.ThrowsAsync<ToolError>(() => pool.RunAsync("test", "fixture_allocate", new JsonObject { ["native"] = native }, Limit,
            CancellationToken.None, file: "input.bin"));
        Assert.Equal((ErrorCode.LimitExceeded, false), (e.Code, e.Retryable));
        Assert.Contains($"reached its memory limit of 300 MB ({WorkerPool.MemoryVariable}) while running 'fixture_allocate' on input.bin", e.Message);
        Assert.NotEqual(first, await Ping(pool));
    }

    // Regression (48563dd9): a worker whose allocation failed answered nothing and timed out after 60 s. The fixture waits forever after the failure.
    [Fact]
    public async Task A_worker_that_hangs_at_its_memory_limit_is_ended_and_named()
    {
        if (!OperatingSystem.IsWindows()) return;
        using var pool = Pool(300L << 20);
        var watch = System.Diagnostics.Stopwatch.StartNew();
        var e = await Assert.ThrowsAsync<ToolError>(() => pool.RunAsync("test", "fixture_allocate", new JsonObject { ["native"] = true, ["hang"] = true },
            Limit, CancellationToken.None));
        Assert.Equal((ErrorCode.LimitExceeded, false), (e.Code, e.Retryable));
        Assert.True(watch.Elapsed < TimeSpan.FromSeconds(20), $"ended after {watch.Elapsed.TotalSeconds:0.0} s");
    }
}
