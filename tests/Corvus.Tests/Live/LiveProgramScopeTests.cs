using System.Diagnostics;
using Corvus.Core;
using Corvus.Services;
using Corvus.Tools;

namespace Corvus.Tests;

/// <summary>--allow-live-attach and --live-allow: attaching needs its own switch, and both attach and spawn stay inside the listed programs.</summary>
public sealed class LiveProgramScopeTests : IDisposable
{
    private readonly TempDir _dir = new();
    private readonly AssemblyWorkspace _workspace = new();
    private readonly LiveSessionService _service;
    private readonly ScriptedLiveBackend _backend = new("app.exe", 0, 1);

    public LiveProgramScopeTests() => _service = new LiveSessionService(_workspace, new NativeCodeService(_workspace, new ServerOptions())) { Backend = _backend };

    public void Dispose()
    {
        _service.Dispose();
        _workspace.Dispose();
        _dir.Dispose();
    }

    private LiveSessionTools Tools(bool attach = true, params string[] allow)
    {
        var options = new ServerOptions { AllowLive = true, AllowLiveSpawn = true, AllowLiveAttach = attach };
        options.LiveAllow.AddRange(allow);
        return new LiveSessionTools(options, _service);
    }

    private string Program(string folder, string name = "tool.exe")
    {
        var path = Path.Combine(_dir.Path, folder, name);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        File.WriteAllBytes(path, [0x4D, 0x5A]);
        return path;
    }

    private static async Task<ToolError> Refused(Func<Task<string>> call, ErrorCode code = ErrorCode.Unsupported)
    {
        var e = await Assert.ThrowsAsync<ToolError>(call);
        Assert.Equal(code, e.Code);
        return e;
    }

    [Fact]
    public async Task Attaching_needs_allow_live_attach()
    {
        var e = await Refused(() => Tools(attach: false).LiveSession("attach", program: "4242"));
        Assert.Contains(ServerOptions.AllowLiveAttachOption, e.Remediation);
        Assert.Null(_backend.LastOpen);
        await Tools(attach: true).LiveSession("attach", program: "4242"); // without --live-allow the program passes unchanged
        Assert.Contains("4242", _backend.LastOpen!.ToJsonString());
    }

    [Fact]
    public async Task Spawn_inside_a_listed_folder_hands_the_backend_the_full_path()
    {
        var inside = Program("allowed");
        await Tools(allow: Path.Combine(_dir.Path, "allowed")).LiveSession("spawn", program: inside);
        Assert.Equal(inside, (string?)_backend.LastOpen!["spawn"]);
    }

    [Fact]
    public async Task Spawn_outside_the_list_is_refused_before_the_backend()
    {
        var allowed = Path.Combine(_dir.Path, "app");
        Program("app");
        var sibling = Program("app2");                                      // a folder that only shares the prefix
        var climbed = Path.Combine(allowed, "..", "other", "tool.exe");     // .. leaves the folder
        Program("other");
        foreach (var program in new[] { sibling, climbed })
        {
            var e = await Refused(() => Tools(allow: allowed).LiveSession("spawn", program: program));
            Assert.Contains(ServerOptions.LiveAllowOption, e.Remediation);
        }
        var console = await Refused(() => Tools(allow: allowed).LiveConsole("start", program: sibling));
        Assert.Contains(ServerOptions.LiveAllowOption, console.Remediation);
        await Refused(() => Tools(allow: allowed).LiveSession("spawn", program: Path.Combine(allowed, "missing.exe")), ErrorCode.NotFound);
        Assert.Null(_backend.LastOpen);
    }

    [Fact]
    public void A_listed_file_allows_only_itself()
    {
        var file = Program("one");
        var other = Program("one", "other.exe");
        Assert.True(LiveProgramScope.Contains([file], file));
        Assert.False(LiveProgramScope.Contains([file], other));
        Assert.True(LiveProgramScope.Contains([Path.GetDirectoryName(file)!], other));
    }

    [Fact]
    public async Task Attach_is_checked_on_the_process_image_path()
    {
        var self = Environment.ProcessId;
        var image = LiveProgramScope.ImagePath(self);
        Assert.NotNull(image);
        var e = await Refused(() => Tools(allow: _dir.Path).LiveSession("attach", program: self.ToString()));
        Assert.Contains(image!, e.Message);
        Assert.Null(_backend.LastOpen);

        await Tools(allow: Path.GetDirectoryName(image)!).LiveSession("attach", program: self.ToString());
        Assert.Contains(self.ToString(), _backend.LastOpen!.ToJsonString());
    }

    [Fact]
    public async Task Attach_by_name_needs_a_process_inside_the_list()
    {
        using var current = Process.GetCurrentProcess();
        var named = await Refused(() => Tools(allow: _dir.Path).LiveSession("attach", program: current.ProcessName));
        Assert.Contains("none inside", named.Message);
        await Refused(() => Tools(allow: _dir.Path).LiveSession("attach", program: "corvus-no-such-process"), ErrorCode.NotFound);
        Assert.Null(_backend.LastOpen);
    }

    [Fact]
    public void The_options_read_the_switch_and_full_paths_of_the_list()
    {
        var o = ServerOptions.Parse([ServerOptions.AllowLiveAttachOption, ServerOptions.LiveAllowOption, "programs", ServerOptions.LiveAllowOption, _dir.Path]);
        Assert.True(o.AllowLiveAttach);
        Assert.Equal([Path.GetFullPath("programs"), _dir.Path], o.LiveAllow);
    }
}
