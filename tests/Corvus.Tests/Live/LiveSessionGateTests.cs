using Corvus.Core;
using Corvus.Mcp;
using Corvus.Tools;

namespace Corvus.Tests;

/// <summary>The session tools are registered everywhere and refuse calls until the server starts with their opt-in flags.</summary>
public class LiveSessionGateTests
{
    private static LiveSessionTools Tools(bool live = false, bool spawn = false) => new(new ServerOptions { AllowLive = live, AllowLiveSpawn = spawn });

    [Fact]
    public async Task Every_session_tool_refuses_without_allow_live()
    {
        var tools = Tools();
        foreach (var call in new Func<Task<string>>[]
                 {
                     () => tools.LiveSession("attach", program: "app.exe"), () => tools.LiveBreak("live-1"), () => tools.LiveRead("live-1"), () => tools.LiveEvents("live-1"),
                 })
        {
            var e = await Assert.ThrowsAsync<ToolError>(call);
            Assert.Equal(ErrorCode.Unsupported, e.Code);
            Assert.Contains("--allow-live (or CORVUS_ALLOW_LIVE=1)", e.Remediation);
        }
    }

    [Fact]
    public async Task Starting_a_program_also_needs_allow_live_spawn()
    {
        var e = await Assert.ThrowsAsync<ToolError>(() => Tools(live: true).LiveSession("spawn", program: "app.exe"));
        Assert.Equal(ErrorCode.Unsupported, e.Code);
        Assert.Contains(ServerOptions.AllowLiveSpawnOption, e.Remediation);
        // past the gates: no session backend yet
        Assert.Equal(ErrorCode.ProviderUnavailable, (await Assert.ThrowsAsync<ToolError>(() => Tools(live: true).LiveSession("attach", program: "app.exe"))).Code);
    }

    [Fact]
    public void Server_status_names_the_flags_that_turn_them_on()
    {
        var registered = ToolAvailability.SessionTools.ToHashSet();
        var off = ToolAvailability.Of(registered, [], idaScripting: false, isWindows: true);
        Assert.Equal(ToolAvailability.SessionTools.Order(StringComparer.Ordinal), off.Select(u => u.Tool).Order(StringComparer.Ordinal));
        Assert.All(off, u => Assert.Contains(ServerOptions.AllowLiveOption, u.Remediation));
        var spawn = Assert.Single(ToolAvailability.Of(registered, [], idaScripting: false, isWindows: true, allowLive: true));
        Assert.Equal(("live_session", "action=spawn"), (spawn.Tool, spawn.Mode));
        Assert.Empty(ToolAvailability.Of(registered, [], idaScripting: false, isWindows: true, allowLive: true, allowLiveSpawn: true));
    }
}
