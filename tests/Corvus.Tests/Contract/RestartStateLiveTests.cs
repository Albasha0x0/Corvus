using Corvus.Core;
using Corvus.Services;
using Corvus.Tools;

namespace Corvus.Tests;

/// <summary>
/// The live tools answer an ended server's sessions and runs from their
/// recording, and refuse those that were never kept.
/// </summary>
public sealed class RestartStateLiveTests : LiveSessionTestBase
{
    private async Task<Dictionary<string, string>> Reads(LiveSessionTools tools)
    {
        async Task<string> Answer(Func<Task<string>> call)
        {
            try { return await call(); }
            catch (ToolError e) { return $"Error ({ToolError.CodeName(e.Code)}): {e.Message}\nNext: {e.Remediation}"; }
        }
        return new(StringComparer.Ordinal)
        {
            ["live_events"] = await Answer(() => tools.LiveEvents("live-1")),
            ["live_coverage"] = await Answer(() => tools.LiveCoverage(action: "report", run: "cov-1")),
            ["live_timeline"] = await Answer(() => tools.LiveTimeline(action: "report", run: "tl-1")),
            ["live_console"] = await Answer(() => tools.LiveConsole(action: "status", run: "con-1")),
        };
    }

    // Runs and sessions belong to the process, so the next one names the list call.
    [Fact]
    public async Task A_run_or_session_of_an_ended_process_is_refused_with_the_call_that_lists_them()
    {
        // A real event trace needs an elevated run; the process id is not one.
        _service.ActivitySource = new ScriptedActivitySource();
        await _tools.LiveSession("attach", program: "99994242");
        await _tools.LiveCoverage("live-1", "start", match: "sqlite3_open");
        await _tools.LiveTimeline("live-1", "start");
        var first = await Reads(_tools);
        Assert.All(first.Where(p => p.Key is "live_coverage" or "live_timeline"), p => Assert.DoesNotContain("Error (", p.Value));

        using var second = new LiveSessionService(_workspace, new NativeCodeService(_workspace, SharedCodeIndex.Options())) { Backend = new ScriptedLiveBackend(Sqlite, Base, 0x200000) };
        var restarted = await Reads(new LiveSessionTools(new ServerOptions { AllowLive = true, AllowLiveAttach = true, AllowLiveSpawn = true, LiveAllowAny = true }, second));
        Assert.All(restarted, p => Assert.StartsWith("Error (not_found)", p.Value));
        Assert.Contains("Next: live_session action=list", restarted["live_events"]);
        foreach (var tool in new[] { "live_coverage", "live_timeline", "live_console" })
            Assert.Contains($"Next: {tool} action=list", restarted[tool]);
    }

    // A server's recording is complete once the server has closed its sessions.
    [Fact]
    public async Task Events_timeline_coverage_and_console_of_an_ended_server_answer_as_saved_runs()
    {
        using var dir = new TempDir();
        var recordings = dir.File("recordings");
        var program = dir.File("prompt.exe");
        File.WriteAllBytes(program, [0x4D, 0x5A]);
        var source = new ScriptedActivitySource();
        var host = new ScriptedConsoleHost();
        var options = new ServerOptions { AllowLive = true, AllowLiveAttach = true, AllowLiveSpawn = true, LiveAllowAny = true };
        var first = new LiveSessionService(_workspace, new NativeCodeService(_workspace, SharedCodeIndex.Options()))
        {
            Backend = new ScriptedLiveBackend(Sqlite, Base, 0x200000), ActivitySource = source, ConsoleHost = host, Kept = new LiveRecordings(() => recordings),
        };
        var tools = new LiveSessionTools(options, first);
        await tools.LiveSession("attach", program: "99994242");
        await tools.LiveCoverage("live-1", "start", match: "sqlite3_open");
        await tools.LiveTimeline("live-1", "start");
        source.Send("file", "orders.txt");
        await tools.LiveConsole("start", program: program);
        host.Last!.Show("name?" + "\r\n");
        host.Last.Exit(0);
        for (var waited = System.Diagnostics.Stopwatch.StartNew(); first.GetConsole("con-1").State == "running" && waited.Elapsed < TimeSpan.FromMinutes(1);) await Task.Delay(10);
        first.Dispose();

        using var second = new LiveSessionService(_workspace, new NativeCodeService(_workspace, SharedCodeIndex.Options())) { Kept = new LiveRecordings(() => recordings) };
        var restarted = new LiveSessionTools(options, second);

        var events = await restarted.LiveEvents("live-1");
        Assert.Contains("saved run of ended session live-1", events);
        Assert.Contains("Next: live_session action=attach program=", events);
        Assert.Contains("session closed (server exit)", events);

        var timeline = await restarted.LiveTimeline(action: "report", run: "tl-1");
        Assert.Contains("saved run of ended session live-1", timeline);
        Assert.Contains("orders.txt", timeline);
        Assert.Contains("tl-1 live-1", await restarted.LiveTimeline());

        var coverage = await restarted.LiveCoverage(action: "report", run: "cov-1", show: "all");
        Assert.Contains("saved run of ended session live-1", coverage);
        Assert.Contains("sqlite3_open", coverage);
        Assert.Contains("cov-1 live-1", await restarted.LiveCoverage());

        var transcript = await restarted.LiveConsole(action: "transcript", run: "con-1");
        Assert.Contains("saved run of ended session con-1", transcript);
        Assert.Contains("#1 name?", transcript);
        Assert.Contains("Next: live_console action=start program=", transcript);
        Assert.Contains("con-1 prompt.exe pid 4242: saved (0)", await restarted.LiveConsole());
    }

    // The first server kept live-1; the second attaches before any read.
    [Fact]
    public async Task A_new_session_after_a_restart_does_not_take_a_kept_session_id()
    {
        using var dir = new TempDir();
        var recordings = dir.File("recordings");
        var options = new ServerOptions { AllowLive = true, AllowLiveAttach = true, AllowLiveSpawn = true, LiveAllowAny = true };
        var first = new LiveSessionService(_workspace, new NativeCodeService(_workspace, SharedCodeIndex.Options()))
        {
            Backend = new ScriptedLiveBackend(Sqlite, Base, 0x200000), Kept = new LiveRecordings(() => recordings),
        };
        await new LiveSessionTools(options, first).LiveSession("attach", program: "99994242");
        first.Dispose();

        using var second = new LiveSessionService(_workspace, new NativeCodeService(_workspace, SharedCodeIndex.Options()))
        {
            Backend = new ScriptedLiveBackend(Sqlite, Base, 0x200000), Kept = new LiveRecordings(() => recordings),
        };
        var tools = new LiveSessionTools(options, second);
        var attached = await tools.LiveSession("attach", program: "99994242");
        Assert.Contains("live-2", attached);
        Assert.Contains("saved run of ended session live-1", await tools.LiveEvents("live-1"));
    }

    // A held session id wins over a kept one.
    [Fact]
    public async Task A_session_id_this_server_holds_is_answered_from_the_live_session()
    {
        using var dir = new TempDir();
        var recordings = dir.File("recordings");
        Directory.CreateDirectory(Path.Combine(recordings, "20260101000000000-1-0001", "live-1"));
        File.WriteAllText(Path.Combine(recordings, "20260101000000000-1-0001", "live-1", "session.json"),
            System.Text.Json.JsonSerializer.Serialize(new LiveSavedHeader("live-1", "scripted", "old", false, 1, DateTime.UtcNow, DateTime.UtcNow, "closed", null, "start", 0)));
        using var service = new LiveSessionService(_workspace, new NativeCodeService(_workspace, SharedCodeIndex.Options()))
        {
            Backend = new ScriptedLiveBackend(Sqlite, Base, 0x200000), Kept = new LiveRecordings(() => recordings),
        };
        var tools = new LiveSessionTools(new ServerOptions { AllowLive = true, AllowLiveAttach = true, LiveAllowAny = true }, service);
        await tools.LiveSession("attach", program: "99994242");
        Assert.DoesNotContain("saved run", await tools.LiveEvents("live-2"));
        Assert.Null(service.SavedSession("live-2"));
    }

    // A recording is looked up by session id, so a path-like id never reaches the file system.
    [Fact]
    public async Task A_session_id_that_is_a_path_is_refused_as_not_found()
    {
        using var dir = new TempDir();
        using var service = new LiveSessionService(_workspace, new NativeCodeService(_workspace, SharedCodeIndex.Options())) { Kept = new LiveRecordings(() => dir.File("recordings")) };
        var tools = new LiveSessionTools(new ServerOptions { AllowLive = true, AllowLiveAttach = true }, service);
        var error = await Assert.ThrowsAsync<ToolError>(() => tools.LiveEvents(Path.Combine("..", "live-1")));
        Assert.Equal(ErrorCode.NotFound, error.Code);
    }

    // The folders of earlier starts are bounded.
    [Fact]
    public void Recordings_of_earlier_servers_are_removed_past_the_kept_count()
    {
        using var dir = new TempDir();
        var recordings = dir.File("recordings");
        for (int i = 0; i < LiveRecordings.KeptServers + 5; i++)
        {
            using var server = new LiveRecordings(() => recordings);
            server.Keep("live-1", "tl-1", () => new { Id = "tl-1" }).Seal();
        }
        Assert.Equal(LiveRecordings.KeptServers, Directory.GetDirectories(recordings).Length);
    }
}
