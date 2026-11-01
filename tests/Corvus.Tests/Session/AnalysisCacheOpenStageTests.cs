using System.Text.Json.Nodes;
using Corvus.Core;
using Corvus.Native.Providers;

namespace Corvus.Tests;

/// <summary>A second session on a held entry is told the holder's open stage and the seconds left.</summary>
public sealed class AnalysisCacheOpenStageTests : IDisposable
{
    private readonly TempDir _tmp = new();

    public void Dispose() => _tmp.Dispose();

    private string Input()
    {
        var path = _tmp.File("image.bin");
        if (!File.Exists(path)) File.WriteAllBytes(path, new byte[4096]);
        return path;
    }

    private AnalysisCache Cache() =>
        new(_tmp.File("cache"), maxBytes: long.MaxValue, maxAge: TimeSpan.FromDays(1)) { AutoEvict = false };

    [Fact]
    public void A_second_acquire_names_the_open_stage_and_remaining_seconds()
    {
        var cache = Cache();
        using var first = cache.Acquire("ida", Input(), null);
        AnalysisCache.WriteProgress(first.Directory, "analysis", DateTime.UtcNow.AddSeconds(-10), 100, fromHistory: true);

        var error = Assert.Throws<ToolError>(() => cache.Acquire("ida", Input(), null));

        Assert.Equal(ErrorCode.Conflict, error.Code);
        Assert.Contains("in analysis for 10 s of about 100 s expected from earlier opens", error.Message);
        Assert.Contains("Retry in about 90 s", error.Remediation);
        Assert.Equal(TimeSpan.FromSeconds(90), error.RetryAfter);
    }

    [Fact]
    public void A_default_rate_estimate_names_its_basis()
    {
        var cache = Cache();
        using var first = cache.Acquire("ida", Input(), null);
        AnalysisCache.WriteProgress(first.Directory, "analysis", DateTime.UtcNow.AddSeconds(-10), 100, fromHistory: false);

        var error = Assert.Throws<ToolError>(() => cache.Acquire("ida", Input(), null));

        Assert.Contains("expected from the default rate", error.Message);
    }

    [Fact]
    public void An_overrun_names_the_expected_seconds_and_the_retry_delay()
    {
        var cache = Cache();
        using var first = cache.Acquire("ida", Input(), null);
        AnalysisCache.WriteProgress(first.Directory, "analysis", DateTime.UtcNow.AddSeconds(-200), 100, fromHistory: true);

        var error = Assert.Throws<ToolError>(() => cache.Acquire("ida", Input(), null));

        Assert.Contains("past the expected 100 s; retry in 5 s", error.Remediation);
        Assert.Equal(TimeSpan.FromSeconds(5), error.RetryAfter);
    }

    [Fact]
    public void A_cleared_open_stage_leaves_the_plain_conflict()
    {
        var cache = Cache();
        using var first = cache.Acquire("ida", Input(), null);
        AnalysisCache.WriteProgress(first.Directory, "analysis", DateTime.UtcNow, 100);
        AnalysisCache.ClearProgress(first.Directory);

        var error = Assert.Throws<ToolError>(() => cache.Acquire("ida", Input(), null));

        Assert.DoesNotContain("expected", error.Message);
        Assert.Equal(AnalysisCache.LockRetryAfter, error.RetryAfter);
    }

    [Fact]
    public void A_stage_without_expected_seconds_names_the_stage_and_keeps_the_default_retry()
    {
        var cache = Cache();
        using var first = cache.Acquire("ida", Input(), null);
        AnalysisCache.WriteProgress(first.Directory, "load", DateTime.UtcNow.AddSeconds(-2), null);

        var error = Assert.Throws<ToolError>(() => cache.Acquire("ida", Input(), null));

        Assert.Contains("in load for 2 s.", error.Message);
        Assert.DoesNotContain("expected", error.Message);
        Assert.Equal(AnalysisCache.LockRetryAfter, error.RetryAfter);
    }

    [Fact]
    public void A_stage_file_of_another_process_is_ignored()
    {
        var cache = Cache();
        using var first = cache.Acquire("ida", Input(), null);
        var other = Environment.ProcessId + 1;
        File.WriteAllText(Path.Combine(first.Directory, ".progress"),
            $$"""{"Pid":{{other}},"Stage":"analysis","Started":"{{DateTime.UtcNow:O}}","ExpectedSeconds":100,"FromHistory":true}""");

        var error = Assert.Throws<ToolError>(() => cache.Acquire("ida", Input(), null));

        Assert.DoesNotContain("analysis for", error.Message);
    }

    [Fact]
    public void A_malformed_stage_file_leaves_the_plain_conflict()
    {
        var cache = Cache();
        using var first = cache.Acquire("ida", Input(), null);
        File.WriteAllText(Path.Combine(first.Directory, ".progress"), "{ not json");

        var error = Assert.Throws<ToolError>(() => cache.Acquire("ida", Input(), null));

        Assert.Equal(ErrorCode.Conflict, error.Code);
        Assert.Equal(AnalysisCache.LockRetryAfter, error.RetryAfter);
    }

    [Fact]
    public async Task An_open_writes_its_stage_for_a_second_session_and_removes_it_when_it_ends()
    {
        await using var session = new StageSession(Cache(), Input(), new NativeOpenOptions { ExpectedSeconds = 600, ExpectedFromHistory = true });
        await session.OpenAsync(Input(), null, default);

        Assert.Contains("in analysis for", session.SeenByCompetitor);
        Assert.Contains("of about 600 s expected from earlier opens", session.SeenByCompetitor);
        Assert.False(File.Exists(Path.Combine(session.Dir, ".progress")));
    }

    [Fact]
    public async Task A_load_stage_quotes_no_expected_seconds()
    {
        await using var session = new StageSession(Cache(), Input(), new NativeOpenOptions { ExpectedSeconds = 600 }) { Stage = "load" };
        await session.OpenAsync(Input(), null, default);

        Assert.Contains("in load for", session.SeenByCompetitor);
        Assert.DoesNotContain("expected", session.SeenByCompetitor);
    }

    [Fact]
    public async Task A_cancelled_open_removes_its_stage_file()
    {
        await using var session = new StageSession(Cache(), Input(), new NativeOpenOptions { ExpectedSeconds = 600 }) { Cancel = true };
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => session.OpenAsync(Input(), null, default));

        Assert.False(File.Exists(Path.Combine(session.Dir, ".progress")));
    }

    [Fact]
    public async Task A_stage_noted_after_the_open_ended_writes_no_file()
    {
        await using var session = new StageSession(Cache(), Input(), new NativeOpenOptions { ExpectedSeconds = 600 });
        await session.OpenAsync(Input(), null, default);
        session.NoteStage("analysis");

        Assert.False(File.Exists(Path.Combine(session.Dir, ".progress")));
    }

    private sealed class StageSession(AnalysisCache cache, string input, NativeOpenOptions options) : WorkerSessionBase(options)
    {
        public string Stage = "analysis";
        public bool Cancel;
        public string SeenByCompetitor = "";

        public string Dir => Entry!.Directory;
        public override string ProviderId => "test";
        protected override string EngineName => "test engine";
        protected override bool DatabaseExists => false;
        protected override TimeSpan ShutdownGrace => TimeSpan.FromSeconds(2);
        protected override int MaxRestarts => 0;

        public void NoteStage(string stage) => StartStage(stage);

        protected override CacheEntry AcquireEntry(string imagePath, string? sha256) => cache.Acquire(ProviderId, imagePath, sha256);
        protected override void PrepareOpen() { }
        protected override void DeleteDatabase() { }
        protected override JsonObject CloseArgs(bool save) => new();
        protected override void Forget() { }

        protected override async Task StartWorkerAndOpenCoreAsync(CancellationToken cancellationToken)
        {
            StartStage(Stage);
            SeenByCompetitor = Assert.Throws<ToolError>(() => cache.Acquire(ProviderId, input, null)).Message;
            if (Cancel) throw new OperationCanceledException();
            var worker = new FakeWorkerProcess(ready: true).Connect(null);
            SetWorker(worker);
            await worker.WaitReadyAsync(TimeSpan.FromSeconds(5), cancellationToken);
        }
    }
}
