using Corvus.Core;
using Corvus.Services;
using Corvus.Tools;

namespace Corvus.Tests;

/// <summary>Child processes on a scripted backend: held at their start, listed, attached as a session of their own, let go, resumed at close.</summary>
public sealed class LiveChildrenTests : IDisposable
{
    private const ulong Base = 0x7ff6_1000_0000;
    private static readonly string Sqlite = RealPackages.File("SQLitePCLRaw.lib.e_sqlite3", "2.1.11", "runtimes", "win-x64", "native", "e_sqlite3.dll");
    private readonly AssemblyWorkspace _workspace = new();
    private readonly LiveSessionService _service;
    private readonly ScriptedLiveBackend _backend;
    private readonly LiveSessionTools _tools;

    public LiveChildrenTests()
    {
        _backend = new ScriptedLiveBackend(Sqlite, Base, 0x200000);
        _service = new LiveSessionService(_workspace, new NativeCodeService(_workspace, new ServerOptions())) { Backend = _backend };
        _tools = new LiveSessionTools(new ServerOptions { AllowLive = true, AllowLiveSpawn = true }, _service);
    }

    public void Dispose()
    {
        _service.Dispose();
        _workspace.Dispose();
    }

    private async Task<string> Until(Func<Task<string>> call, string text)
    {
        var last = "";
        for (int i = 0; i < 100 && !(last = await call()).Contains(text, StringComparison.Ordinal); i++) await Task.Delay(20);
        Assert.Contains(text, last);
        return last;
    }

    [Fact]
    public async Task A_held_child_is_listed_attached_started_through_the_parent_and_the_rest_resumed_at_close()
    {
        await _tools.LiveSession("spawn", program: Sqlite, childNames: ["child.exe"]);
        Assert.Equal("child.exe", (string?)_backend.LastOpen!["children"]!["names"]![0]);
        var parent = _backend.Worker!;
        _backend.Child(parent, 5001, @"C:\app\child.exe", held: true);
        _backend.Child(parent, 5002, @"C:\app\helper.exe", held: false);
        _backend.Child(parent, 5003, @"C:\app\child.exe", held: true);

        var children = await Until(() => _tools.LiveSession("children", session: "live-1"), "pid 5003");
        Assert.Contains("follows child processes named child.exe: 3 started, 2 held", children);
        Assert.Contains(@"pid 5001 held: C:\app\child.exe --role ""two words""", children);
        Assert.Contains("pid 5002 resumed:", children);
        Assert.Contains("held at its start: live_session action=attach_child or release_child program=5001",
            await _tools.LiveEvents("live-1", kind: "child"));

        var child = await _tools.LiveSession("attach_child", session: "live-1", program: "5001");
        Assert.Contains("live-2 (scripted): 5001 pid 5001, suspended", child);
        Assert.Contains("(held by live-1)", child);
        Assert.Contains("is attached in live-2", (await Refused(() => _tools.LiveSession("release_child", session: "live-1", program: "5001"))).Message);
        Assert.Empty(_backend.ChildResumes);

        Assert.Contains("program started", await _tools.LiveBreak("live-2", "continue"));
        Assert.Equal([5001], _backend.ChildResumes);
        Assert.Contains("live-2 (scripted): 5001 pid 5001, running", await _tools.LiveSession("status", session: "live-2"));
        Assert.Contains("pid 5001 attached in live-2", await _tools.LiveSession("children", session: "live-1"));

        await _tools.LiveSession("close", session: "live-1");
        Assert.Equal([5001, 5003], _backend.ChildResumes);
        Assert.Contains("live-2 (scripted): 5001 pid 5001, running", await _tools.LiveSession("status", session: "live-2"));
    }

    [Fact]
    public async Task A_child_released_runs_unobserved_and_one_whose_session_closes_before_it_starts_is_held_again()
    {
        await _tools.LiveSession("spawn", program: Sqlite, childNames: ["*"]);
        Assert.Empty(_backend.LastOpen!["children"]!["names"]!.AsArray());
        var parent = _backend.Worker!;
        _backend.Child(parent, 5001, @"C:\app\child.exe", held: true);
        _backend.Child(parent, 5004, @"C:\app\worker.exe", held: true);
        await Until(() => _tools.LiveSession("children", session: "live-1"), "pid 5004");

        Assert.Contains("follows child processes: 2 started, 1 held", await _tools.LiveSession("release_child", session: "live-1", program: "5004"));
        Assert.Equal([5004], _backend.ChildResumes);
        Assert.Contains("holds no child process 77", (await Refused(() => _tools.LiveSession("attach_child", session: "live-1", program: "77"))).Message);

        await _tools.LiveSession("attach_child", session: "live-1", program: "5001");
        await _tools.LiveSession("close", session: "live-2");
        Assert.Contains("pid 5001 held:", await _tools.LiveSession("children", session: "live-1"));
        Assert.Equal([5004], _backend.ChildResumes);
    }

    [Fact]
    public async Task On_linux_the_gate_lets_the_child_go_stopped_and_the_child_session_starts_it_itself()
    {
        var backend = new ScriptedLiveBackend(Sqlite, Base, 0x200000) { Platform = "linux" };
        using var service = new LiveSessionService(_workspace, new NativeCodeService(_workspace, new ServerOptions())) { Backend = backend };
        var tools = new LiveSessionTools(new ServerOptions { AllowLive = true, AllowLiveSpawn = true }, service);
        await tools.LiveSession("spawn", program: Sqlite, childNames: ["*"]);
        backend.Child(backend.Worker!, 5001, "/app/child", held: true);
        await Until(() => tools.LiveSession("children", session: "live-1"), "pid 5001 held");

        Assert.Contains("live-2 (scripted): 5001 pid 5001, suspended", await tools.LiveSession("attach_child", session: "live-1", program: "5001"));
        Assert.Equal([-5001], backend.ChildResumes);
        Assert.Equal(true, (bool?)backend.LastOpen!["stopped"]);
        Assert.Contains("program started", await tools.LiveBreak("live-2", "continue"));
        Assert.Equal([-5001], backend.ChildResumes);
        await tools.LiveSession("close", session: "live-1");
        Assert.Equal([-5001], backend.ChildResumes);
    }

    [Fact]
    public async Task Without_childNames_the_session_asks_for_no_child_gating()
    {
        await _tools.LiveSession("spawn", program: Sqlite);
        Assert.Null(_backend.LastOpen!["children"]);
        var report = await _tools.LiveSession("children", session: "live-1");
        Assert.Contains("does not follow child processes", report);
        Assert.DoesNotContain("follows child processes", await _tools.LiveSession("status", session: "live-1"));
    }

    private static async Task<ToolError> Refused(Func<Task<string>> call) => await Assert.ThrowsAsync<ToolError>(call);
}
