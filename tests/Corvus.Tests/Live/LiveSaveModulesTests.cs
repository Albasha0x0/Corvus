using Corvus.Core;
using Corvus.Services;
using Corvus.Tools;

namespace Corvus.Tests;

public class LiveSaveModulesTests
{
    [Fact]
    public async Task save_modules_writes_the_session_program_image()
    {
        if (!OperatingSystem.IsWindows()) return;
        // The session holds a running system program; the scripted backend only names it.
        using var child = System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "findstr.exe"), "x")
            { RedirectStandardInput = true, UseShellExecute = false, CreateNoWindow = true })!;
        var workspace = new AssemblyWorkspace();
        var service = new LiveSessionService(workspace, new NativeCodeService(workspace, SharedCodeIndex.Options()))
        {
            Backend = new ScriptedLiveBackend("findstr.exe", 0x10000, 0x1000) { ProcessId = child.Id },
        };
        var tools = new LiveSessionTools(new ServerOptions { AllowLive = true, AllowLiveAttach = true }, service);
        var dir = Path.Combine(Path.GetTempPath(), "corvus-test-" + Guid.NewGuid().ToString("N"));
        try
        {
            await tools.LiveSession("attach", program: child.Id.ToString());
            var text = await tools.LiveSession("save_modules", session: "live-1", outputPath: dir, modules: "findstr.exe");
            Assert.Contains("the program keeps running", text);
            var file = Assert.Single(Directory.GetFiles(dir));
            Assert.Equal("MZ", System.Text.Encoding.ASCII.GetString(File.ReadAllBytes(file), 0, 2));
            Assert.False(child.HasExited);
            Assert.Equal(ErrorCode.Conflict, (await Assert.ThrowsAsync<ToolError>(() => tools.LiveSession("save_modules", session: "live-1", outputPath: dir))).Code);
        }
        finally
        {
            service.Dispose();
            child.Kill();
            if (Directory.Exists(dir)) Directory.Delete(dir, true);
        }
    }

    [Fact]
    public async Task save_modules_is_refused_without_the_live_option()
    {
        var workspace = new AssemblyWorkspace();
        var service = new LiveSessionService(workspace, new NativeCodeService(workspace, SharedCodeIndex.Options()))
        {
            Backend = new ScriptedLiveBackend("app.exe", 0, 1),
        };
        var tools = new LiveSessionTools(new ServerOptions(), service);
        var e = await Assert.ThrowsAsync<ToolError>(() => tools.LiveSession("save_modules", session: "live-1"));
        Assert.Equal(ErrorCode.Unsupported, e.Code);
        Assert.Contains("--allow-live-", e.Remediation);
    }
}
