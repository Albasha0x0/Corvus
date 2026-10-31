using System.Diagnostics;
using System.Globalization;
using System.Runtime.InteropServices;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Corvus.Native.Dump.Managed;
using Corvus.Services;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>regionFilter=unbacked on a running program and on its dump: one program allocating executable memory, one plain .NET program.</summary>
[Trait("Speed", "Slow")]
[Permit("live")]
[Collection(ExternalToolEnvironmentCollection.Name)]
public sealed class DumpUnbackedRealTests(ITestOutputHelper output) : IDisposable
{
    private const string AllocatorSource = """
        #include <windows.h>
        #include <stdio.h>
        #include <string.h>

        int main(int argc, char** argv)
        {
            unsigned char* p = (unsigned char*)VirtualAlloc(NULL, 4096, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
            if (!p) return 2;
            if (argc > 1 && !strcmp(argv[1], "pe")) memcpy(p, GetModuleHandleA(NULL), 0x400);
            else { p[0] = 0x90; p[1] = 0x90; p[2] = 0xC3; }
            printf("READY %llu\n", (unsigned long long)(ULONG_PTR)p);
            fflush(stdout);
            for (;;) Sleep(INFINITE);
        }
        """;

    private const string DotnetSource = """
        using System;
        using System.Reflection.Emit;
        using System.Runtime.CompilerServices;

        namespace Probe;

        public static class Program
        {
            [MethodImpl(MethodImplOptions.NoInlining)]
            private static int Work(int n)
            {
                int sum = 0;
                for (int i = 0; i < n; i++) sum += i;
                return sum;
            }

            public static void Main()
            {
                var generated = new DynamicMethod("Generated", typeof(int), [typeof(int)]);
                var il = generated.GetILGenerator();
                il.Emit(OpCodes.Ldarg_0);
                il.Emit(OpCodes.Ldc_I4_1);
                il.Emit(OpCodes.Add);
                il.Emit(OpCodes.Ret);
                var add = (Func<int, int>)generated.CreateDelegate(typeof(Func<int, int>));
                Console.WriteLine("READY " + add(Work(1000)));
                Console.Out.Flush();
                Console.ReadLine();
            }
        }
        """;

    private readonly TempDir _dir = new();
    private readonly List<Process> _started = [];

    public void Dispose()
    {
        foreach (var p in _started)
            try { p.Kill(); } catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception) { }
        _dir.Dispose();
    }

    [DllImport("dbghelp.dll", SetLastError = true)]
    private static extern bool MiniDumpWriteDump(IntPtr process, int processId, IntPtr file, int type, IntPtr exception, IntPtr user, IntPtr callback);

    // Full memory, full memory info, thread info, data segments, unloaded modules.
    private const int FullDump = 0x2 | 0x800 | 0x1000 | 0x4 | 0x20;

    private static readonly object DbgHelpGate = new();

    private string WriteDump(Process process, string name)
    {
        var path = _dir.File(name);
        using (var file = new FileStream(path, FileMode.Create, FileAccess.ReadWrite))
        {
            bool ok;
            lock (DbgHelpGate) ok = MiniDumpWriteDump(process.Handle, process.Id, file.SafeFileHandle.DangerousGetHandle(), FullDump, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
            Assert.True(ok, $"MiniDumpWriteDump failed: {Marshal.GetLastWin32Error()}");
        }
        return path;
    }

    private static bool CanBuildNative() => OperatingSystem.IsWindows() && RuntimeInformation.ProcessArchitecture == Architecture.X64 && VisualStudio.HasVcVars;

    private (Process Process, ulong Address) StartAllocator(params string[] args)
    {
        var exe = LiveTarget.WinX64.Build(_dir, "allocator", AllocatorSource);
        var psi = new ProcessStartInfo(exe) { RedirectStandardOutput = true, RedirectStandardInput = true, UseShellExecute = false, CreateNoWindow = true };
        foreach (var a in args) psi.ArgumentList.Add(a);
        var process = Process.Start(psi)!;
        _started.Add(process);
        var line = process.StandardOutput.ReadLine();
        Assert.StartsWith("READY ", line);
        return (process, ulong.Parse(line!["READY ".Length..], CultureInfo.InvariantCulture));
    }

    private async Task<List<MinidumpService.UnbackedRegion>> LiveRows(Process process, string? yara = null)
    {
        using var dumps = new MinidumpService();
        var report = await new LiveProcessService(dumps).Inspect(process.Id.ToString(CultureInfo.InvariantCulture), "regions", null, 0, 1000, "unbacked", 64, null, 60, default, null, yara);
        Assert.True(report.Detached);
        Assert.Equal(report.HandlesOpened, report.HandlesClosed);
        return [.. report.Items!.Cast<MinidumpService.UnbackedRegion>()];
    }

    private async Task<MinidumpService.UnbackedPage> DumpRows(string dump)
    {
        using var dumps = new MinidumpService();
        var (_, page) = await dumps.UnbackedMemory(dump, 0, 1000, null, new DacRequest(), default);
        foreach (var n in page.Notes) output.WriteLine(n);
        return page;
    }

    [Fact]
    public async Task A_program_that_allocates_executable_memory_has_exactly_that_region_unbacked()
    {
        if (!CanBuildNative()) return;
        var (process, address) = StartAllocator();
        var live = Assert.Single(await LiveRows(process));
        Assert.Equal($"0x{address:X}", live.Base);
        Assert.Equal("unbacked", live.Backing);
        Assert.False(live.Noteworthy);
        var page = await DumpRows(WriteDump(process, "allocator.dmp"));
        var region = Assert.Single(page.Rows);
        Assert.Equal($"0x{address:X}", region.Base);
        Assert.Equal("none", region.Header);
        Assert.False(region.Noteworthy);
        Assert.Equal("PAGE_EXECUTE_READWRITE", region.Protection);
    }

    [Fact]
    public async Task A_PE_image_copied_into_executable_memory_is_noteworthy_live_and_in_its_dump()
    {
        if (!CanBuildNative()) return;
        var (process, address) = StartAllocator("pe");
        var live = Assert.Single(await LiveRows(process));
        Assert.Equal(($"0x{address:X}", "pe", true), (live.Base, live.Header, live.Noteworthy));
        var region = Assert.Single((await DumpRows(WriteDump(process, "allocator-pe.dmp"))).Rows);
        Assert.Equal(($"0x{address:X}", "pe", true), (region.Base, region.Header, region.Noteworthy));
    }

    [Fact]
    public async Task A_plain_dotnet_program_has_nothing_noteworthy_and_its_code_heaps_are_labelled_jit()
    {
        if (!OperatingSystem.IsWindows() || RuntimeInformation.ProcessArchitecture != Architecture.X64) return;
        var dll = _dir.File("Probe.dll");
        File.WriteAllBytes(dll, Roslyn.Compile("Probe", DotnetSource, new CSharpCompilationOptions(OutputKind.ConsoleApplication, optimizationLevel: OptimizationLevel.Debug)));
        File.WriteAllText(_dir.File("Probe.runtimeconfig.json"), System.Text.Json.JsonSerializer.Serialize(new
        {
            runtimeOptions = new { tfm = $"net{Environment.Version.Major}.0", framework = new { name = "Microsoft.NETCore.App", version = Environment.Version.ToString() } },
        }));
        var psi = new ProcessStartInfo("dotnet") { RedirectStandardOutput = true, RedirectStandardInput = true, UseShellExecute = false, CreateNoWindow = true };
        psi.ArgumentList.Add(dll);
        var process = Process.Start(psi)!;
        _started.Add(process);
        Assert.StartsWith("READY ", process.StandardOutput.ReadLine());

        var page = await DumpRows(WriteDump(process, "probe.dmp"));
        foreach (var r in page.Rows) output.WriteLine($"{r.Base} {r.Size} {r.Backing} {r.Header} {r.Detail}");
        Assert.DoesNotContain(page.Rows, r => r.Noteworthy == true);
        Assert.Contains(page.Rows, r => r.Backing == "jit");
        Assert.DoesNotContain(page.Notes, n => n.Contains("not labelled", StringComparison.Ordinal));

        var live = await LiveRows(process);
        Assert.DoesNotContain(live, r => r.Noteworthy == true);
        Assert.Contains(live, r => r.Backing == "jit");
    }
}
