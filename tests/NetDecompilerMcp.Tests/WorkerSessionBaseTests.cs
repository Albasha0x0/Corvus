using System.Text.Json.Nodes;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Native.Providers;

namespace NetDecompilerMcp.Tests;

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
    public async Task Journaled_changes_are_replayed_after_a_crash()
    {
        await using var s = await Open();
        await s.CallAsync("set", Set("a", "1"), default, journal: true);
        Assert.Equal(ErrorCode.ProviderUnavailable, (await Assert.ThrowsAsync<ToolError>(() => s.CallAsync("crash", new JsonObject(), default))).Code);
        Assert.Equal("1", (await s.CallAsync("get", Get("a"), default)).GetProperty("value").GetString());
        Assert.Equal(2, s.Starts);
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
        await using var c = await Open(concurrent: true);
        await Task.WhenAll(Enumerable.Range(0, 4).Select(_ => c.CallAsync("sleep", new JsonObject { ["ms"] = 150 }, default)));
        Assert.True(c.Current!.MaxInFlight >= 2, $"reads in flight: {c.Current.MaxInFlight}");

        await using var serial = await Open(concurrent: false);
        await Task.WhenAll(Enumerable.Range(0, 3).Select(_ => serial.CallAsync("sleep", new JsonObject { ["ms"] = 50 }, default)));
        Assert.Equal(1, serial.Current!.MaxInFlight);
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

        protected override CacheEntry AcquireEntry(string imagePath, string? sha256) => cache.Acquire(ProviderId, imagePath, sha256);
        protected override void PrepareOpen() { }
        protected override void DeleteDatabase() { Deleted++; HasDatabase = false; }
        protected override JsonObject CloseArgs(bool save) => new();
        protected override void Forget() => Forgotten = true;

        protected override async Task StartWorkerAndOpenCoreAsync(CancellationToken cancellationToken)
        {
            Starts++;
            if (FailStarts) throw new ToolError(ErrorCode.ProviderUnavailable, "engine did not start");
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
