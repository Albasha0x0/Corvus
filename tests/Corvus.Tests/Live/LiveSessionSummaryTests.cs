using Corvus.Core;
using Corvus.Tools;

namespace Corvus.Tests;

/// <summary>What close, status and list report about the open sessions, on a scripted backend.</summary>
public sealed class LiveSessionSummaryTests : LiveSessionTestBase
{
    private static LiveSessionTools.LiveSessionReport Report(OutputCall call) =>
        Assert.IsType<LiveSessionTools.LiveSessionReport>(call.Record);

    [Fact]
    public async Task Close_returns_a_one_line_summary_without_the_module_list()
    {
        await _tools.LiveSession("attach", program: "99994242");
        var call = OutputCall.Begin(new OutputCall("live_session", 6_000, null));
        var text = await _tools.LiveSession("close", session: "live-1");
        var report = Report(call);
        OutputCall.Begin(null!);
        Assert.Single(text.TrimEnd().Split('\n'));
        Assert.Contains("live-1 (scripted): 99994242 pid 99994242, closed after", text);
        Assert.Contains("events (closed by request)", text);
        Assert.DoesNotContain("modules", text);
        Assert.Empty(report.Modules);
    }

    [Fact]
    public async Task Status_and_close_list_the_open_sessions_as_list_does()
    {
        await _tools.LiveSession("attach", program: "99994242");
        var call = OutputCall.Begin(new OutputCall("live_session", 6_000, null));
        await _tools.LiveSession("status", session: "live-1");
        var status = Report(call);
        await _tools.LiveSession("close", session: "live-1");
        var closed = Report(call);
        OutputCall.Begin(null!);
        Assert.Equal(["live-1"], status.Sessions.Select(r => r.Session));
        Assert.Empty(closed.Sessions);
    }

    [Fact]
    public async Task A_closed_session_leaves_the_list_and_its_events_stay_readable()
    {
        await _tools.LiveSession("attach", program: "99994242");
        await _tools.LiveSession("close", session: "live-1");
        Assert.Equal("No sessions.\n", await _tools.LiveSession("list"));
        Assert.Contains("session closed (closed by request)", await _tools.LiveEvents("live-1", kind: "exit"));
    }

    [Fact]
    public async Task Attach_by_name_keeps_the_name_as_program_and_the_pid_apart()
    {
        var call = OutputCall.Begin(new OutputCall("live_session", 6_000, null));
        await _tools.LiveSession("attach", program: "sample.exe");
        var report = Report(call);
        OutputCall.Begin(null!);
        Assert.Equal("sample.exe", report.Program);
        Assert.Equal(ScriptedLiveBackend.Pid, report.ProcessId);
    }
}
