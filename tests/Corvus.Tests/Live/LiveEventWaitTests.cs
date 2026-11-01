using System.Diagnostics;
using Corvus.Core;
using Corvus.Services;
using Corvus.Tools;

namespace Corvus.Tests;

/// <summary>live_events waitSeconds on a scripted backend.</summary>
public sealed class LiveEventWaitTests : IDisposable
{
    private const ulong Base = 0x7ff6_1000_0000;
    private static readonly string Sqlite = RealPackages.File("SQLitePCLRaw.lib.e_sqlite3", "2.1.11", "runtimes", "win-x64", "native", "e_sqlite3.dll");
    private readonly AssemblyWorkspace _workspace = new();
    private readonly LiveSessionService _service;
    private readonly LiveSessionTools _tools;

    public LiveEventWaitTests()
    {
        _service = new LiveSessionService(_workspace, new NativeCodeService(_workspace, SharedCodeIndex.Options()))
        {
            Backend = new ScriptedLiveBackend(Sqlite, Base, 0x200000),
        };
        _tools = new LiveSessionTools(new ServerOptions { AllowLive = true, AllowLiveAttach = true }, _service);
    }

    public void Dispose()
    {
        _service.Dispose();
        _workspace.Dispose();
    }

    [Fact]
    public async Task Waiting_for_events_returns_when_one_is_appended_not_at_the_bound()
    {
        await _tools.LiveSession("attach", program: "99994242");
        var s = _service.Get("live-1");
        var cursor = s.Sequence + 1;
        var clock = Stopwatch.StartNew();
        var waiting = _tools.LiveEvents("live-1", cursor: cursor.ToString(), kind: "output", waitSeconds: 60);
        await Task.Delay(100);
        Assert.False(waiting.IsCompleted);
        s.Add("output", null, null, "ready");
        var page = await waiting;
        Assert.Contains("ready", page);
        Assert.True(clock.Elapsed < TimeSpan.FromSeconds(30), page);
    }

    [Fact]
    public async Task An_event_page_is_saved_as_json_and_an_existing_path_is_refused_before_the_wait()
    {
        await _tools.LiveSession("attach", program: "99994242");
        _service.Get("live-1").Add("output", null, null, "ready");
        var path = Path.Combine(Path.GetTempPath(), $"ev-{Guid.NewGuid():N}.json");
        try
        {
            _ = Corvus.Mcp.ToolOutput.Collect();
            Assert.Contains("saved: ", await _tools.LiveEvents("live-1", kind: "output", outputPath: path));
            using var json = System.Text.Json.JsonDocument.Parse(File.ReadAllText(path));
            Assert.Equal("live-1", json.RootElement.GetProperty("session").GetString());
            var clock = Stopwatch.StartNew();
            var error = await Assert.ThrowsAsync<ToolError>(() => _tools.LiveEvents("live-1", kind: "exit", waitSeconds: 60, outputPath: path));
            Assert.Equal(ErrorCode.Conflict, error.Code);
            Assert.True(clock.Elapsed < TimeSpan.FromSeconds(20));
        }
        finally { File.Delete(path); }
    }

    [Fact]
    public async Task Waiting_for_events_past_the_bound_names_the_next_call()
    {
        await _tools.LiveSession("attach", program: "99994242");
        var cursor = _service.Get("live-1").Sequence + 1;
        var page = await _tools.LiveEvents("live-1", cursor: cursor.ToString(), kind: "output", waitSeconds: 1);
        Assert.Contains("No events within 1 s", page);
        Assert.Contains($"cursor={cursor} kind=output waitSeconds=1", page);
    }

    [Fact]
    public async Task Waiting_for_events_ignores_events_that_fail_the_filter()
    {
        await _tools.LiveSession("attach", program: "99994242");
        var s = _service.Get("live-1");
        var waiting = _tools.LiveEvents("live-1", cursor: (s.Sequence + 1).ToString(), kind: "output", waitSeconds: 60);
        s.Add("error", null, null, "other kind");
        await Task.Delay(200);
        Assert.False(waiting.IsCompleted);
        s.Add("output", null, null, "match");
        Assert.Contains("match", await waiting);
    }

    [Fact]
    public async Task Waiting_for_events_returns_when_the_session_ends()
    {
        await _tools.LiveSession("attach", program: "99994242");
        var waiting = _tools.LiveEvents("live-1", cursor: (_service.Get("live-1").Sequence + 1).ToString(), kind: "output", waitSeconds: 60);
        await Task.Delay(100);
        await _tools.LiveSession("close", session: "live-1");
        var page = await waiting.WaitAsync(TimeSpan.FromSeconds(30));
        Assert.Contains("Session closed; no events", page);
        Assert.DoesNotContain("Call again", page);
    }

    [Fact]
    public async Task Waiting_for_events_stops_when_the_token_is_cancelled()
    {
        await _tools.LiveSession("attach", program: "99994242");
        using var cts = new CancellationTokenSource();
        var waiting = _tools.LiveEvents("live-1", kind: "output", waitSeconds: 60, cancellationToken: cts.Token);
        await Task.Delay(100);
        cts.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => waiting.WaitAsync(TimeSpan.FromSeconds(30)));
    }

    [Fact]
    public async Task Zero_waitSeconds_returns_at_once_with_no_events()
    {
        await _tools.LiveSession("attach", program: "99994242");
        var page = await _tools.LiveEvents("live-1", cursor: (_service.Get("live-1").Sequence + 1).ToString(), kind: "output");
        Assert.Contains("No events.", page);
    }
}
