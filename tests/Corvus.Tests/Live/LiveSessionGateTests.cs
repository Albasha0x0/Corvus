using Corvus.Core;
using Corvus.Mcp;
using Corvus.Services;
using Corvus.Tools;

namespace Corvus.Tests;

/// <summary>The session tools are registered everywhere and refuse calls until the server starts with their opt-in flags.</summary>
public class LiveSessionGateTests
{
    private static LiveSessionTools Tools(bool live = false, bool spawn = false, bool attach = false, string? allow = null)
    {
        var workspace = new AssemblyWorkspace();
        var service = new LiveSessionService(workspace, new NativeCodeService(workspace, SharedCodeIndex.Options()))
        {
            Backend = new ScriptedLiveBackend("app.exe", 0, 1) { Missing = "no session backend" },
        };
        var options = new ServerOptions { AllowLive = live, AllowLiveSpawn = spawn, AllowLiveAttach = attach };
        if (allow != null) options.LiveAllow.Add(allow);
        return new(options, service);
    }

    [Fact]
    public async Task Every_session_tool_refuses_without_allow_live()
    {
        var tools = Tools();
        foreach (var call in new Func<Task<string>>[]
                 {
                     () => tools.LiveSession("attach", program: "app.exe"), () => tools.LiveBreak("live-1"), () => tools.LiveWatchCalls("live-1"), () => tools.LiveRead("live-1"),
                     () => tools.LiveEvents("live-1"), () => tools.LiveScriptCalls("live-1"), () => tools.LiveCoverage("live-1"), () => tools.LiveTimeline("live-1"), () => tools.LiveConsole(),
                 })
        {
            var e = await Assert.ThrowsAsync<ToolError>(call);
            Assert.Equal(ErrorCode.Unsupported, e.Code);
            Assert.Contains("--allow-live-", e.Remediation);
        }
    }

    [Fact]
    public async Task Starting_a_program_also_needs_allow_live_spawn()
    {
        var e = await Assert.ThrowsAsync<ToolError>(() => Tools(live: true).LiveSession("spawn", program: "app.exe"));
        Assert.Equal(ErrorCode.Unsupported, e.Code);
        Assert.Contains(ServerOptions.AllowLiveSpawnOption, e.Remediation);
        var console = await Assert.ThrowsAsync<ToolError>(() => Tools(live: true).LiveConsole("start", program: "app.exe"));
        Assert.Contains(ServerOptions.AllowLiveSpawnOption, console.Remediation);
        // Past the gates: the backend's own answer.
        Assert.Equal(ErrorCode.ProviderUnavailable, (await Assert.ThrowsAsync<ToolError>(() => Tools(live: true, attach: true).LiveSession("attach", program: "app.exe"))).Code);
    }

    [Fact]
    public async Task A_device_spawn_refused_by_a_program_list_names_live_allow_any()
    {
        // Regression: the hint said to drop --live-allow, which refuses a spawn too.
        var e = await Assert.ThrowsAsync<ToolError>(() => Tools(live: true, spawn: true, allow: Path.GetTempPath()).LiveSession("spawn", program: "com.example.app", device: "emulator-5554"));
        Assert.Equal(ErrorCode.AccessDenied, e.Code);
        Assert.Equal($"ask the user to start the server with {ServerOptions.LiveAllowOption} * (any program) to open a device session", e.Remediation);
    }

    [Fact]
    public void Server_status_names_the_flags_that_turn_them_on()
    {
        var registered = ToolAvailability.SessionTools.ToHashSet();
        var off = ToolAvailability.Of(registered, [], idaScripting: false, isWindows: true);
        Assert.Equal(ToolAvailability.SessionTools.Order(StringComparer.Ordinal), off.Select(u => u.Tool).Order(StringComparer.Ordinal));
        Assert.All(off, u => Assert.Contains(ServerOptions.AllowLiveOption, u.Remediation));
        var live = ToolAvailability.Of(registered, [], idaScripting: false, isWindows: true, allowLive: true);
        Assert.Equal([("live_session", "action=spawn"), ("live_session", "action=attach"), ("live_console", "action=start"), ("live_script", (string?)null)], live.Select(u => (u.Tool, u.Mode)));
        Assert.Contains(ServerOptions.AllowLiveAttachOption, live[1].Remediation);
        Assert.Contains(ServerOptions.LiveScriptingOption, live[3].Remediation);
        Assert.Empty(ToolAvailability.Of(registered, [], idaScripting: false, isWindows: true, allowLive: true, allowLiveSpawn: true, liveScripting: true, allowLiveAttach: true));
        var unlisted = ToolAvailability.Of(registered, [], idaScripting: false, isWindows: true, allowLive: true, allowLiveSpawn: true, liveScripting: true, allowLiveAttach: true, liveStartList: false);
        Assert.Equal([("live_session", "action=spawn"), ("live_console", "action=start")], unlisted.Select(u => (u.Tool, u.Mode)));
        Assert.All(unlisted, u => Assert.Contains(ServerOptions.LiveAllowOption, u.Remediation));
    }

    [Fact]
    public async Task The_window_view_is_refused_without_allow_window_capture()
    {
        var workspace = new AssemblyWorkspace();
        using var service = new LiveSessionService(workspace, new NativeCodeService(workspace, SharedCodeIndex.Options()));
        using var dumps = new MinidumpService();
        var tools = new LiveProcessTools(new LiveProcessService(dumps), service, new ServerOptions());
        var e = await Assert.ThrowsAsync<ToolError>(() => tools.InspectProcess($"{Environment.ProcessId}", view: "windows"));
        Assert.Equal(ErrorCode.Unsupported, e.Code);
        Assert.StartsWith($"ask the user to start the server with {ServerOptions.AllowWindowCaptureOption}", e.Remediation);
    }
}
