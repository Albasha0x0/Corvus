using System.Text.Json.Nodes;
using Corvus.Core;
using Corvus.Services;
using Corvus.Tools;
using Microsoft.Extensions.Time.Testing;

namespace Corvus.Tests;

/// <summary>Notices, the idle limit and held stops of a session on a scripted backend.</summary>
public sealed class LiveNoticeTests : LiveSessionTestBase
{
    [Fact]
    public async Task A_stop_queues_one_notice_naming_the_wait_call()
    {
        await _tools.LiveSession("attach", program: "99994242");
        await _tools.LiveBreak("live-1", "set", at: "e_sqlite3!sqlite3_open");
        _backend.Hit("s1", 77, Base + 0x1010);
        _backend.Hit("s1", 78, Base + 0x1010);
        await _tools.LiveBreak("live-1", wait: true, waitSeconds: 10);
        var notices = _workspace.DrainNotices().Where(n => n.StartsWith("live-1: thread")).ToList();
        Assert.Single(notices);
        Assert.Contains("live_break session=live-1 wait=true", notices[0]);
    }

    [Fact]
    public async Task An_exit_queues_a_notice_naming_the_wait_call()
    {
        await _tools.LiveSession("attach", program: "99994242");
        _backend.Worker!.Emit(new JsonObject { ["event"] = "exit", ["reason"] = "process-terminated" });
        // CI run 41624347552 (ubuntu): the wait returned before the notice was
        // queued.
        await _tools.LiveBreak("live-1", wait: true, waitSeconds: 10);
        var notice = Assert.Single(_workspace.DrainNotices(), n => n.Contains("process-terminated"));
        Assert.Contains("Next: live_break session=live-1 wait=true", notice);
    }

    [Fact]
    public async Task Two_waits_return_the_same_held_stop_until_it_continues()
    {
        await _tools.LiveSession("attach", program: "99994242");
        await _tools.LiveBreak("live-1", "set", at: "e_sqlite3!sqlite3_open");
        _backend.Hit("s1", 77, Base + 0x1010);
        _backend.Hit("s1", 78, Base + 0x1010);
        var first = await _tools.LiveBreak("live-1", wait: true, waitSeconds: 10);
        // The second stop event can reach the session after the first wait returns.
        var second = await _tools.LiveBreak("live-1", wait: true, waitSeconds: 10);
        for (int i = 0; i < 100 && !second.Contains("held: thread 78"); i++)
        {
            await Task.Delay(50);
            second = await _tools.LiveBreak("live-1", wait: true, waitSeconds: 10);
        }
        Assert.Contains("thread 77 stopped at s1", first);
        Assert.Contains("thread 77 stopped at s1", second);
        Assert.Contains("held: thread 78 at s1", second);
        await _tools.LiveBreak("live-1", "continue", thread: "77");
        Assert.Contains("thread 78 stopped at s1", await _tools.LiveBreak("live-1", wait: true, waitSeconds: 10));
    }

    [Fact]
    public async Task A_wait_with_no_stop_names_a_longer_wait()
    {
        await _tools.LiveSession("attach", program: "99994242");
        var text = await _tools.LiveBreak("live-1", wait: true, waitSeconds: 1);
        Assert.Contains("Next: live_break session=live-1 wait=true waitSeconds=4", text);
    }

    [Fact]
    public async Task A_call_restarts_the_idle_limit_and_status_does_not()
    {
        var clock = new FakeTimeProvider();
        _service.Time = clock;
        await _tools.LiveSession("spawn", program: Sqlite);
        var s = _service.Get("live-1");
        clock.Advance(TimeSpan.FromMinutes(20));
        Assert.Contains("closes after 30 min unused, 10 min left", await _tools.LiveSession("status", session: "live-1"));
        await _tools.LiveBreak("live-1");
        Assert.Contains("30 min left", await _tools.LiveSession("status", session: "live-1"));
        clock.Advance(TimeSpan.FromMinutes(29));
        for (var i = 0; i < 20; i++) await Task.Delay(20);
        Assert.False(s.Closed);
    }

    [Fact]
    public async Task The_idle_limit_closes_the_session_and_ends_a_started_program()
    {
        var clock = new FakeTimeProvider();
        _service.Time = clock;
        await _tools.LiveSession("spawn", program: Sqlite);
        var s = _service.Get("live-1");
        clock.Advance(TimeSpan.FromMinutes(31));
        for (var i = 0; i < 500 && s.Ended == null; i++) await Task.Delay(20);
        Assert.Equal("idle", s.CloseReason);
        Assert.True(_backend.LastCloseEnd);
        Assert.StartsWith("ended when the session closed (idle)", s.Ended);
        var notice = Assert.Single(_workspace.DrainNotices(), n => n.Contains("min unused"));
        Assert.Contains("was ended. Next: live_events session=live-1", notice);
    }

    [Fact]
    public async Task A_wait_in_progress_keeps_the_session_open_past_the_idle_limit()
    {
        var clock = new FakeTimeProvider();
        _service.Time = clock;
        await _tools.LiveSession("spawn", program: Sqlite);
        var s = _service.Get("live-1");
        using var cancel = new CancellationTokenSource();
        var wait = s.NextStopAsync(TimeSpan.FromSeconds(300), cancel.Token);
        clock.Advance(TimeSpan.FromMinutes(31));
        for (var i = 0; i < 20; i++) await Task.Delay(20);
        Assert.False(s.Closed);
        cancel.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => wait);
    }
}
