using System.Text.Json.Nodes;
using Corvus.Core;
using Corvus.Native.Providers;

namespace Corvus.Tests;

/// <summary><see cref="WorkerSessionBase"/> over in-process workers: journal replay, restart budget, damaged database, concurrency.</summary>
public sealed class WorkerSessionBaseTests : IDisposable
{
    private readonly TempDir _tmp = new();

    public void Dispose() => _tmp.Dispose();

    private async Task<TestSession> Open(bool concurrent = false, bool savedDatabase = false, bool damaged = false, int maxRestarts = 3)
    {
        var input = _tmp.File("image.bin");
        if (!File.Exists(input)) File.WriteAllBytes(input, [1, 2, 3]);
        var s = new TestSession(new AnalysisCache(_tmp.File("cache-" + Guid.NewGuid().ToString("N"))), concurrent, maxRestarts)
        {
            HasDatabase = savedDatabase,
            Damaged = damaged,
        };
        await s.OpenAsync(input, null, default);
        return s;
    }

    private static JsonObject Set(string key, string value) => new() { ["key"] = key, ["value"] = value };
    private static JsonObject Get(string key) => new() { ["key"] = key };

    [Fact]
    public async Task A_transient_start_failure_starts_a_new_worker_a_bounded_number_of_times()
    {
        var input = _tmp.File("image.bin");
        File.WriteAllBytes(input, [1, 2, 3]);
        await using (var s = new TestSession(new AnalysisCache(_tmp.File("cache-a")), false, 3) { TransientFailures = WorkerSessionBase.TransientStartRetries })
        {
            await s.OpenAsync(input, null, default);
            Assert.Equal(WorkerSessionBase.TransientStartRetries + 1, s.Starts);
        }
        await using (var s = new TestSession(new AnalysisCache(_tmp.File("cache-b")), false, 3) { TransientFailures = WorkerSessionBase.TransientStartRetries + 1 })
        {
            var e = await Assert.ThrowsAsync<ToolError>(() => s.OpenAsync(input, null, default));
            Assert.Contains("transient race", e.Message);
            Assert.Equal(WorkerSessionBase.TransientStartRetries + 1, s.Starts);
        }
    }

    [Fact]
    public async Task Journaled_changes_are_replayed_after_a_crash()
    {
        await using var s = await Open();
        await s.CallAsync("set", Set("a", "1"), default, journal: true);
        Assert.Equal(ErrorCode.ProviderUnavailable, (await Assert.ThrowsAsync<ToolError>(() => s.CallAsync("crash", new JsonObject(), default))).Code);
        Assert.Equal("1", (await s.CallAsync("get", Get("a"), default)).GetProperty("value").GetString());
        Assert.Equal(2, s.Starts);
    }

    [Fact]
    public async Task The_generation_holds_over_reads_and_advances_on_changes_and_restarts()
    {
        await using var s = await Open();
        long g = s.Generation;
        await s.CallAsync("get", Get("a"), default);
        await s.CallAsync("echo", new JsonObject(), default);
        Assert.Equal(g, s.Generation);
        await s.CallAsync("set", Set("a", "1"), default, journal: true);
        Assert.True(s.Generation > g);
        g = s.Generation;
        await Assert.ThrowsAsync<ToolError>(() => s.CallAsync("crash", new JsonObject(), default));
        await s.CallAsync("get", Get("a"), default); // restarts the worker
        Assert.True(s.Generation > g);
    }

    [Fact]
    public async Task A_call_s_time_limit_reaches_the_worker()
    {
        await using var s = await Open();
        Assert.Equal(120, (await s.CallAsync("timeout", new JsonObject(), default)).GetProperty("timeout").GetDouble());
        using (EngineRequestLimit.Use(TimeSpan.FromSeconds(7)))
            Assert.Equal(7, (await s.CallAsync("timeout", new JsonObject(), default)).GetProperty("timeout").GetDouble());
        Assert.Null(EngineRequestLimit.Current);
    }

    [Fact]
    public async Task State_shows_the_running_request_the_queue_and_restarts_without_asking_the_worker()
    {
        await using var s = await Open();
        Assert.Equal("idle", s.State().State);
        await s.CallAsync("set", Set("a", "1"), default, journal: true);
        // The running request holds in the worker until the test releases it, so the state is read while it runs.
        var running = s.CallAsync("hold", new JsonObject(), default);
        var waiting = s.CallAsync("get", Get("a"), default);
        EngineSessionState? busy = null;
        Assert.True(SpinWait.SpinUntil(() => (busy = s.State()) is { BusyOp: "hold", Queued: 1, BusySeconds: > 0 }, TimeSpan.FromMinutes(1)),
            $"state: {busy}");
        Assert.Equal(("busy", "hold", 1, 1), (busy!.State, busy.BusyOp, busy.Queued, busy.Unsaved));
        Assert.NotNull(busy.WorkerPid);
        s.Current!.Release();
        await running;
        await waiting;
        Assert.Equal(("idle", 0), (s.State().State, s.State().Queued));
        await Assert.ThrowsAsync<ToolError>(() => s.CallAsync("crash", new JsonObject(), default));
        await s.CallAsync("get", Get("a"), default);
        Assert.Equal(1, s.State().Restarts);
    }

    [Fact]
    public async Task A_save_clears_the_journal()
    {
        await using var s = await Open();
        await s.CallAsync("set", Set("a", "1"), default, journal: true);
        await s.SaveAsync();
        await Assert.ThrowsAsync<ToolError>(() => s.CallAsync("crash", new JsonObject(), default));
        Assert.Null((await s.CallAsync("get", Get("a"), default)).GetProperty("value").GetString());
    }

    [Fact]
    public async Task A_long_journal_is_saved_and_cleared()
    {
        await using var s = await Open();
        s.SaveThreshold = 3;
        await s.CallAsync("set", Set("a", "1"), default, journal: true);
        await s.CallAsync("set", Set("b", "2"), default, journal: true);
        Assert.Equal(2, s.UnsavedCount);
        await s.CallAsync("set", Set("c", "3"), default, journal: true);
        Assert.Equal(0, s.UnsavedCount);
    }

    [Fact]
    public async Task Failed_restarts_beyond_the_budget_close_the_session()
    {
        await using var s = await Open(maxRestarts: 1);
        s.FailStarts = true;
        await Assert.ThrowsAsync<ToolError>(() => s.CallAsync("crash", new JsonObject(), default));
        await Assert.ThrowsAsync<ToolError>(() => s.CallAsync("echo", new JsonObject(), default));
        Assert.False(s.IsOpen);
        Assert.True(s.Forgotten);
        Assert.Equal(ErrorCode.NotLoaded, (await Assert.ThrowsAsync<ToolError>(() => s.CallAsync("echo", new JsonObject(), default))).Code);
    }

    [Fact]
    public async Task A_damaged_saved_database_is_rebuilt_once()
    {
        await using var s = await Open(savedDatabase: true, damaged: true);
        Assert.Equal(1, s.Deleted);
        Assert.False(s.ReusedDatabase);
        Assert.Equal(2, s.Starts);
    }

    [Fact]
    public async Task Concurrent_sessions_overlap_reads_and_serialize_writes()
    {
        // Each request holds in the worker until the test releases it, so arrivals show the overlap, not timing.
        await using var c = await Open(concurrent: true);
        var reads = Enumerable.Range(0, 4).Select(_ => c.CallAsync("hold", new JsonObject(), default)).ToArray();
        Assert.True(SpinWait.SpinUntil(() => c.Current!.Received.Count == 4, TimeSpan.FromMinutes(1)), $"reads received: {c.Current!.Received.Count}");
        c.Current.Release();
        await Task.WhenAll(reads);
        Assert.Equal(4, c.Current.MaxInFlight);

        // The two requests counted as queued wait in the session, so the worker has the first one only.
        await using var serial = await Open(concurrent: false);
        var writes = Enumerable.Range(0, 3).Select(_ => serial.CallAsync("hold", new JsonObject(), default)).ToArray();
        Assert.True(SpinWait.SpinUntil(() => serial.Current!.Received.Count == 1 && serial.State().Queued == 2, TimeSpan.FromMinutes(1)),
            $"writes received: {serial.Current!.Received.Count}, queued: {serial.State().Queued}");
        Assert.Single(serial.Current.Received);
        serial.Current.Release();
        await Task.WhenAll(writes);
        Assert.Equal(1, serial.Current.MaxInFlight);
    }

    [Fact]
    public async Task Concurrent_session_cancels_a_request_without_restarting()
    {
        await using var s = await Open(concurrent: true);
        var worker = s.Worker;
        using var cts = new CancellationTokenSource(200);
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => s.CallAsync("sleep", new JsonObject { ["ms"] = 60_000 }, cts.Token));
        Assert.Same(worker, s.Worker);
        await s.CallAsync("echo", new JsonObject(), default);
        Assert.Equal(1, s.Starts);
    }

    private sealed class TestSession(AnalysisCache cache, bool concurrent, int maxRestarts) : WorkerSessionBase(new NativeOpenOptions())
    {
        public bool HasDatabase;
        public bool Damaged;
        public bool FailStarts;
        public int TransientFailures;
        public int SaveThreshold = int.MaxValue;
        public int Starts;
        public int Deleted;
        public bool Forgotten;
        public FakeWorkerProcess? Current;

        public override string ProviderId => "test";
        protected override string EngineName => "test engine";
        protected override TimeSpan ShutdownGrace => TimeSpan.FromSeconds(2);
        protected override int MaxRestarts => maxRestarts;
        protected override bool ConcurrentRequests => concurrent;
        protected override int JournalSaveThreshold => SaveThreshold;
        protected override bool DatabaseExists => HasDatabase;
        protected override bool ReadsOnly(string op) => op is "get" or "echo";

        protected override CacheEntry AcquireEntry(string imagePath, string? sha256) => cache.Acquire(ProviderId, imagePath, sha256);
        protected override void PrepareOpen() { }
        protected override void DeleteDatabase() { Deleted++; HasDatabase = false; }
        protected override JsonObject CloseArgs(bool save) => new();
        protected override void Forget() => Forgotten = true;
        protected override bool TransientStartFailure(ToolError error) => error.Message.Contains("transient race", StringComparison.Ordinal);

        protected override async Task StartWorkerAndOpenCoreAsync(CancellationToken cancellationToken)
        {
            Starts++;
            if (FailStarts) throw new ToolError(ErrorCode.ProviderUnavailable, "engine did not start");
            if (TransientFailures-- > 0) throw new ToolError(ErrorCode.ProviderUnavailable, "worker exited: transient race");
            Current = new FakeWorkerProcess(ready: true);
            var worker = Current.Connect(concurrent ? new WorkerConnectionOptions { Concurrent = true, CancelGrace = TimeSpan.FromSeconds(10) } : null);
            SetWorker(worker);
            await worker.WaitReadyAsync(TimeSpan.FromSeconds(5), cancellationToken);
            ReusedDatabase = HasDatabase;
            if (HasDatabase && Damaged) throw new ToolError(ErrorCode.Failed, "database damaged");
            HasDatabase = true;
        }
    }
}
