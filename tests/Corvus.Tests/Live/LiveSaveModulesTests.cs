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

    [Fact]
    public async Task save_modules_code_writes_the_executable_regions_no_image_backs()
    {
        if (!OperatingSystem.IsWindows()) return;
        using var child = StartChild();
        // An executable page the child never mapped from a file.
        var region = NativeMethods.Allocate(child, 0x1000, 0x40);
        NativeMethods.Write(child, region, [0x90, 0x90, 0xC3, 0x42]);
        var (service, tools) = Open(child);
        var dir = Path.Combine(Path.GetTempPath(), "corvus-test-" + Guid.NewGuid().ToString("N"));
        try
        {
            var text = await tools.LiveSession("save_modules", session: "live-1", outputPath: dir, modules: "code");
            Assert.Contains($"code-{region:X}.bin", text);
            var bytes = File.ReadAllBytes(Path.Combine(dir, $"code-{region:X}.bin"));
            Assert.Equal([0x90, 0x90, 0xC3, 0x42], bytes[..4]);
        }
        finally
        {
            service.Dispose();
            child.Kill();
            if (Directory.Exists(dir)) Directory.Delete(dir, true);
        }
    }

    [Fact]
    public async Task save_modules_names_code_that_differs_from_the_file()
    {
        if (!OperatingSystem.IsWindows()) return;
        using var child = StartChild();
        // The first byte of the entry point is rewritten in the child's memory
        // only.
        NativeMethods.Patch(child, (ulong)child.MainModule!.EntryPointAddress, 0xCC);
        var (service, tools) = Open(child);
        var dir = Path.Combine(Path.GetTempPath(), "corvus-test-" + Guid.NewGuid().ToString("N"));
        try
        {
            var text = await tools.LiveSession("save_modules", session: "live-1", outputPath: dir, modules: "findstr.exe");
            Assert.True(text.Contains("code differs"), text);
            Assert.Contains("code ranges differing from the file", text);
        }
        finally
        {
            service.Dispose();
            child.Kill();
            if (Directory.Exists(dir)) Directory.Delete(dir, true);
        }
    }

    [Fact]
    public async Task save_modules_reports_unchanged_code_as_same()
    {
        if (!OperatingSystem.IsWindows()) return;
        using var child = StartChild();
        var (service, tools) = Open(child);
        var dir = Path.Combine(Path.GetTempPath(), "corvus-test-" + Guid.NewGuid().ToString("N"));
        try
        {
            var text = await tools.LiveSession("save_modules", session: "live-1", outputPath: dir, modules: "findstr.exe");
            Assert.Contains("code same", text);
            Assert.DoesNotContain("code ranges differing", text);
        }
        finally
        {
            service.Dispose();
            child.Kill();
            if (Directory.Exists(dir)) Directory.Delete(dir, true);
        }
    }

    [System.Runtime.Versioning.SupportedOSPlatform("windows")]
    private static System.Diagnostics.Process StartChild()
    {
        var child = System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(Path.Combine(Environment.SystemDirectory, "findstr.exe"), "x")
            { RedirectStandardInput = true, UseShellExecute = false, CreateNoWindow = true })!;
        // Loader worker threads wait before the entry point runs, so only the
        // main thread waiting on input, seen twice, is past the entry point a
        // test rewrites.
        int waits = 0;
        for (int i = 0; i < 200 && waits < 2; i++)
        {
            Thread.Sleep(50);
            try
            {
                child.Refresh();
                var main = child.Threads.Cast<System.Diagnostics.ProcessThread>().MinBy(t => t.StartTime);
                waits = child.MainModule != null && main?.ThreadState == System.Diagnostics.ThreadState.Wait ? waits + 1 : 0;
            }
            catch (Exception ex) when (ex is System.ComponentModel.Win32Exception or InvalidOperationException) { waits = 0; }
        }
        return child;
    }

    private static (LiveSessionService Service, LiveSessionTools Tools) Open(System.Diagnostics.Process child)
    {
        var workspace = new AssemblyWorkspace();
        var service = new LiveSessionService(workspace, new NativeCodeService(workspace, SharedCodeIndex.Options()))
        {
            Backend = new ScriptedLiveBackend("findstr.exe", 0x10000, 0x1000) { ProcessId = child.Id },
        };
        var tools = new LiveSessionTools(new ServerOptions { AllowLive = true, AllowLiveAttach = true }, service, new MinidumpService());
        tools.LiveSession("attach", program: child.Id.ToString()).GetAwaiter().GetResult();
        return (service, tools);
    }

    private static class NativeMethods
    {
        [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
        private static extern nint VirtualAllocEx(nint process, nint address, nuint size, uint type, uint protect);

        [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool VirtualProtectEx(nint process, nint address, nuint size, uint protect, out uint old);

        [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool WriteProcessMemory(nint process, nint address, byte[] buffer, nuint size, out nuint written);

        public static ulong Allocate(System.Diagnostics.Process p, uint size, uint protect)
        {
            var at = VirtualAllocEx(p.Handle, 0, size, 0x3000, protect);
            Assert.NotEqual(0, at);
            return (ulong)at;
        }

        public static void Write(System.Diagnostics.Process p, ulong address, byte[] bytes) =>
            Assert.True(WriteProcessMemory(p.Handle, (nint)address, bytes, (nuint)bytes.Length, out _));

        public static void Patch(System.Diagnostics.Process p, ulong address, byte value)
        {
            Assert.True(VirtualProtectEx(p.Handle, (nint)address, 1, 0x40, out var old));
            Write(p, address, [value]);
            VirtualProtectEx(p.Handle, (nint)address, 1, old, out _);
        }
    }
}
