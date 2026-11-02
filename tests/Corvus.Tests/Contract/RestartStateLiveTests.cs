using Corvus.Core;
using Corvus.Services;
using Corvus.Tools;

namespace Corvus.Tests;

/// <summary>The live tools refuse a session or run of an ended process with the call that lists them.</summary>
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
        await _tools.LiveSession("attach", program: "99994242");
        await _tools.LiveCoverage("live-1", "start", match: "sqlite3_open");
        // Activity traces are collected on Windows only.
        if (OperatingSystem.IsWindows())
            await _tools.LiveTimeline("live-1", "start");
        var first = await Reads(_tools);
        Assert.All(first.Where(p => p.Key is "live_coverage" || p.Key is "live_timeline" && OperatingSystem.IsWindows()), p => Assert.DoesNotContain("Error (", p.Value));

        using var second = new LiveSessionService(_workspace, new NativeCodeService(_workspace, SharedCodeIndex.Options())) { Backend = new ScriptedLiveBackend(Sqlite, Base, 0x200000) };
        var restarted = await Reads(new LiveSessionTools(new ServerOptions { AllowLive = true, AllowLiveAttach = true, AllowLiveSpawn = true, LiveAllowAny = true }, second));
        Assert.All(restarted, p => Assert.StartsWith("Error (not_found)", p.Value));
        Assert.Contains("Next: live_session action=list", restarted["live_events"]);
        foreach (var tool in new[] { "live_coverage", "live_timeline", "live_console" })
            Assert.Contains($"Next: {tool} action=list", restarted[tool]);
    }
}
