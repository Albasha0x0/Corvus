using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using Microsoft.Win32.SafeHandles;
using ModelContextProtocol.Client;
using ModelContextProtocol.Protocol;
using Corvus.Services;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>
/// Real crash dumps written at run time: an MSVC-built program (x64 and x86, with its PDB) crashes on purpose and is
/// dumped by this process through MiniDumpWriteDump (with the child's exception pointers) or dumps itself from its
/// unhandled-exception filter; a hung child and a .NET process are dumped too. cdb (Windows SDK debuggers), when
/// installed, is the oracle for the faulting frames and the module list. Skipped without the MSVC build tools.
/// </summary>
[Trait("Speed", "Slow")]
[Permit("reference-tool")]
public sealed class MinidumpRealTests(ITestOutputHelper output)
{
    private const string Source = """
        #include <windows.h>
        #include <dbghelp.h>
        #include <stdio.h>
        #include <string.h>
        #include <stdexcept>
        #pragma comment(lib, "dbghelp.lib")

        static char g_dump[MAX_PATH];
        volatile int g_sink;
        static int* volatile g_target = nullptr;

        static LONG WINAPI Filter(EXCEPTION_POINTERS* ep)
        {
            if (g_dump[0])
            {
                HANDLE f = CreateFileA(g_dump, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
                MINIDUMP_EXCEPTION_INFORMATION mei = { GetCurrentThreadId(), ep, FALSE };
                MiniDumpWriteDump(GetCurrentProcess(), GetCurrentProcessId(), f,
                    (MINIDUMP_TYPE)(MiniDumpWithThreadInfo | MiniDumpWithHandleData | MiniDumpWithUnloadedModules | MiniDumpWithFullMemoryInfo), &mei, NULL, NULL);
                CloseHandle(f);
                TerminateProcess(GetCurrentProcess(), 3);
            }
            printf("CRASH %lu %llu\n", GetCurrentThreadId(), (unsigned long long)(ULONG_PTR)ep);
            fflush(stdout);
            for (;;) Sleep(INFINITE);
        }

        extern "C" __declspec(noinline) void crash_here(int* p, int v) { *p = v; g_sink = v; }

        extern "C" __declspec(noinline) void level2(int* p, int depth)
        {
            char buffer[64];
            for (int i = 0; i < 64; i++) buffer[i] = (char)(i * depth + g_sink);
            crash_here(p, depth + 42);
            g_sink += buffer[(depth + g_sink) & 63];
        }

        extern "C" __declspec(noinline) void level1(int* p) { level2(p, (int)(GetTickCount() & 1) + 1); g_sink++; }

        extern "C" __declspec(noinline) void wait_forever(void)
        {
            printf("READY\n");
            fflush(stdout);
            for (;;) Sleep(INFINITE);
        }

        __declspec(noinline) void thrower(int n) { if (n > 0) throw std::runtime_error("boom"); }

        int main(int argc, char** argv)
        {
            if (argc > 2) strcpy_s(g_dump, sizeof g_dump, argv[2]);
            SetUnhandledExceptionFilter(Filter);
            if (argc > 1 && !strcmp(argv[1], "hang")) wait_forever();
            if (argc > 1 && !strcmp(argv[1], "cpp")) thrower(argc);
            level1(g_target);
            return 0;
        }
        """;

    private static readonly string[] CrashFrames = ["crash_here", "level2", "level1", "main"];

    // ---- dbghelp ----

    [StructLayout(LayoutKind.Sequential, Pack = 4)]
    private struct MinidumpExceptionInformation
    {
        public uint ThreadId;
        public IntPtr ExceptionPointers;
        public int ClientPointers;
    }

    [DllImport("dbghelp.dll", SetLastError = true)]
    private static extern bool MiniDumpWriteDump(IntPtr process, uint processId, SafeFileHandle file, uint type, ref MinidumpExceptionInformation exception, IntPtr user, IntPtr callback);

    [DllImport("dbghelp.dll", SetLastError = true)]
    private static extern bool MiniDumpWriteDump(IntPtr process, uint processId, SafeFileHandle file, uint type, IntPtr exception, IntPtr user, IntPtr callback);

    private const uint Normal = 0x1000 | 0x4 | 0x20 | 0x800; // thread info, handles, unloaded modules, full memory info
    private const uint Full = Normal | 0x2;
    private static readonly object DbgHelpGate = new();

    private static void WriteDump(Process process, string path, uint type, uint? threadId = null, ulong pointers = 0)
    {
        using var file = File.OpenHandle(path, FileMode.Create, FileAccess.ReadWrite);
        bool ok;
        lock (DbgHelpGate)
        {
            if (threadId is { } tid)
            {
                var info = new MinidumpExceptionInformation { ThreadId = tid, ExceptionPointers = checked((IntPtr)(long)pointers), ClientPointers = 1 };
                ok = MiniDumpWriteDump(process.Handle, (uint)process.Id, file, type, ref info, IntPtr.Zero, IntPtr.Zero);
            }
            else ok = MiniDumpWriteDump(process.Handle, (uint)process.Id, file, type, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
        }
        Assert.True(ok, $"MiniDumpWriteDump failed: {Marshal.GetLastWin32Error()}");
    }

    // ---- the sample ----

    private static string? Build(TempDir dir, string arch)
    {
        if (!OperatingSystem.IsWindows()) return null;
        var vcvars = VisualStudio.VcVarsAll();
        if (vcvars == null) return null;
        File.WriteAllText(dir.File("crash.cpp"), Source);
        var psi = new ProcessStartInfo("cmd.exe")
        {
            WorkingDirectory = dir.Path,
            Arguments = $"/s /c \"\"{vcvars}\" {arch} >nul && cl /nologo /O2 /Oy- /Zi /EHsc /MT crash.cpp /link /DEBUG /INCREMENTAL:NO /OUT:crash.exe\"",
        };
        var (code, log) = Tools.Run(psi, 300_000);
        Assert.True(code == 0 && File.Exists(dir.File("crash.exe")), log);
        return dir.File("crash.exe");
    }

    private static Process Start(string exe, params string[] args)
    {
        var psi = new ProcessStartInfo(exe) { RedirectStandardOutput = true, RedirectStandardInput = true, UseShellExecute = false, CreateNoWindow = true };
        foreach (var a in args) psi.ArgumentList.Add(a);
        return Process.Start(psi)!;
    }

    private static string ReadLine(Process p)
    {
        var line = p.StandardOutput.ReadLineAsync();
        Assert.True(line.Wait(TimeSpan.FromSeconds(30)), "the child did not report in time");
        return line.Result ?? "";
    }

    private static void Kill(Process p)
    {
        try { p.Kill(true); p.WaitForExit(5000); }
        catch (InvalidOperationException) { }
    }

    /// <summary>Crashes the sample and dumps it from this process with the child's exception pointers.</summary>
    private static string CrashAndDump(string exe, string dump, uint type)
    {
        using var p = Start(exe, "av");
        try
        {
            var m = Regex.Match(ReadLine(p), @"^CRASH (\d+) (\d+)");
            Assert.True(m.Success);
            WriteDump(p, dump, type, uint.Parse(m.Groups[1].Value), ulong.Parse(m.Groups[2].Value));
        }
        finally { Kill(p); }
        return dump;
    }

    /// <summary>The sample writes its own dump from its unhandled-exception filter.</summary>
    private static string SelfDump(string exe, string mode, string dump)
    {
        using var p = Start(exe, mode, dump);
        Assert.True(p.WaitForExit(60_000), "the sample did not exit");
        Assert.True(File.Exists(dump), $"no dump written (exit code {p.ExitCode})");
        return dump;
    }

    private static List<string?> Functions(MinidumpService.StackReport s) => s.Items.Select(f => f.Function).ToList();

    private void Print(MinidumpService.StackReport s)
    {
        foreach (var f in s.Items) output.WriteLine($"{f.Index,2} {f.Address} {f.Symbol} [{f.SymbolSource}] {f.Method}{((f.Basis == "inferred") ? " (heuristic)" : "")} {f.Note}");
        output.WriteLine($"stop: {s.Stop}");
        foreach (var n in s.Notes) output.WriteLine("  " + n);
    }

    private static void AssertSubsequence(IReadOnlyList<string?> actual, IReadOnlyList<string> expected)
    {
        int at = 0;
        foreach (var name in actual)
            if (at < expected.Count && name == expected[at]) at++;
        Assert.True(at == expected.Count, $"expected {string.Join(" > ", expected)} in {string.Join(" > ", actual)}");
    }

    [Fact]
    public async Task X64AccessViolationIsNamedAndUnwound()
    {
        using var dir = new TempDir();
        if (Build(dir, "x64") is not { } exe) return;
        var dump = CrashAndDump(exe, dir.File("av.dmp"), Normal);
        using var service = new MinidumpService();
        var sw = Stopwatch.StartNew();
        var summary = await service.Summarize(dump, null, default);
        output.WriteLine($"summary in {sw.ElapsedMilliseconds} ms: {summary.Counts!.Modules} modules, {summary.Counts.Threads} threads");
        var e = summary.Exception!;
        output.WriteLine($"{e.Name}: {e.Description} at {e.Symbol} [{e.SymbolSource}]: {e.Instruction} ({e.InstructionSource})");
        Assert.Equal("EXCEPTION_ACCESS_VIOLATION", e.Name);
        Assert.StartsWith("access violation writing 0x0000000000000000", e.Description);
        Assert.Equal("crash.exe", e.Module);
        Assert.StartsWith("crash!crash_here", e.Symbol);
        Assert.Equal("pdb", e.SymbolSource);
        Assert.StartsWith("mov", e.Instruction);
        Assert.Contains("[r", e.Instruction);
        var modules = service.Modules(dump, null, 0, 1000).Rows;
        var main = modules.Single(m => m.Name == "crash.exe");
        Assert.Equal("matches", main.LocalImage);
        Assert.EndsWith("crash.pdb", main.PdbName);
        Assert.Contains(modules, m => m.Name.Equals("ntdll.dll", StringComparison.OrdinalIgnoreCase) && m.LocalImage == "matches");
        Assert.True(summary.FaultingThread!.Faulting);
        Assert.Empty(summary.Issues!);

        sw.Restart();
        var stack = await service.Stack(dump, null, true, 256, 0, 256, null, default);
        output.WriteLine($"stack in {sw.ElapsedMilliseconds} ms");
        Print(stack);
        Assert.Equal(CrashFrames, Functions(stack).Take(4));
        Assert.All(stack.Items.Take(4), f => Assert.Equal("pdb", f.SymbolSource));
        Assert.Contains(stack.Items, f => f.Function == "BaseThreadInitThunk");
        Assert.Contains(stack.Items, f => f.Function == "RtlUserThreadStart");
        Assert.Equal(0, stack.ScannedFrames);
        Assert.Equal("end_of_stack", stack.Stop);

        var memory = await service.ReadMemory(dump, e.Address, 16, true, default);
        Assert.Equal(16, memory.Length);
        Assert.StartsWith(e.Instruction![(e.Instruction!.LastIndexOf('(') + 1)..^1], memory.Code);

        CompareWithCdb(dump, dir.Path, summary, stack);
    }

    [Fact]
    public async Task FullMemoryDumpUnwindsWithoutTheImageFile()
    {
        using var dir = new TempDir();
        if (Build(dir, "x64") is not { } exe) return;
        var dump = CrashAndDump(exe, dir.File("full.dmp"), Full);
        File.Move(exe, dir.File("renamed.bin"));
        using var service = new MinidumpService();
        var summary = await service.Summarize(dump, null, default);
        Assert.Equal("missing", service.Modules(dump, null, 0, 1000).Rows.Single(m => m.Name == "crash.exe").LocalImage);
        Assert.True(summary.Counts!.FullMemory);
        var stack = await service.Stack(dump, null, true, 256, 0, 256, null, default);
        Print(stack);
        Assert.Equal(CrashFrames, Functions(stack).Take(4));
        Assert.Contains(stack.Notes, n => n.StartsWith("crash.exe: image dump_memory", StringComparison.Ordinal));
        Assert.Equal(0, stack.ScannedFrames);
    }

    [Fact]
    public async Task X86SelfDumpWalksTheFramePointerChain()
    {
        using var dir = new TempDir();
        if (Build(dir, "x86") is not { } exe) return;
        var dump = SelfDump(exe, "av", dir.File("x86.dmp"));
        // Without the PDB there is no frame data: the frames come from the EBP chain.
        var pdb = dir.File("crash.pdb");
        Directory.CreateDirectory(dir.File("hidden"));
        File.Move(pdb, dir.File(Path.Combine("hidden", "crash.pdb")));
        MinidumpService.StackReport chain;
        using (var service = new MinidumpService()) chain = await service.Stack(dump, null, true, 128, 0, 128, null, default);
        Print(chain);
        File.Move(dir.File(Path.Combine("hidden", "crash.pdb")), pdb);
        using var named = new MinidumpService();
        var stack = await named.Stack(dump, null, true, 128, 0, 128, null, default);
        Assert.Equal(CrashFrames, Functions(stack).Take(4));
        Assert.Equal(stack.Items.Take(5).Select(f => f.Address), chain.Items.Take(5).Select(f => f.Address));
        Assert.Equal(["frame_pointer", "frame_pointer", "frame_pointer"], chain.Items.Skip(1).Take(3).Select(f => f.Method));
    }

    [Fact]
    public async Task X86_self_dump_walks_the_pdb_frame_data()
    {
        using var dir = new TempDir();
        if (Build(dir, "x86") is not { } exe) return;
        var dump = SelfDump(exe, "av", dir.File("x86.dmp"));
        using var service = new MinidumpService();
        var summary = await service.Summarize(dump, null, default);
        Assert.Equal("x86", summary.System!.Architecture);
        Assert.All(service.Modules(dump, null, 0, 1000).Rows, m => Assert.Equal("matches", m.LocalImage));
        Assert.Equal("access violation writing 0x00000000 (a null or near-null pointer)", summary.Exception!.Description);
        Assert.StartsWith("crash!crash_here", summary.Exception.Symbol);
        var stack = await service.Stack(dump, null, true, 128, 0, 128, null, default);
        Print(stack);
        Assert.Equal(CrashFrames, Functions(stack).Take(4));
        Assert.Equal(["frame_data", "frame_data", "frame_data"], stack.Items.Skip(1).Take(3).Select(f => f.Method));
        Assert.Contains(stack.Items, f => f.Function == "BaseThreadInitThunk"); // SysWOW64 images for a 32-bit process
        CompareWithCdb(dump, dir.Path, summary, stack);
    }

    [Fact]
    public async Task CppExceptionNamesTheThrownType()
    {
        using var dir = new TempDir();
        if (Build(dir, "x64") is not { } exe) return;
        var dump = SelfDump(exe, "cpp", dir.File("cpp.dmp"));
        using var service = new MinidumpService();
        var summary = await service.Summarize(dump, null, default);
        var e = summary.Exception!;
        output.WriteLine($"{e.Name}: {e.Description}; types {string.Join(", ", e.ThrownTypes!)}; at {e.Symbol}");
        Assert.Equal("0xE06D7363", e.Code);
        Assert.Equal("std::runtime_error", e.ThrownTypes!.FirstOrDefault());
        Assert.Contains("std::exception", e.ThrownTypes!);
        var stack = await service.Stack(dump, null, true, 128, 0, 128, null, default);
        Print(stack);
        AssertSubsequence(Functions(stack), ["RaiseException", "thrower", "main"]);
    }

    [Fact]
    public async Task HungProcessDumpShowsTheWaitingThread()
    {
        using var dir = new TempDir();
        if (Build(dir, "x64") is not { } exe) return;
        using var p = Start(exe, "hang");
        string dump = dir.File("hang.dmp");
        try
        {
            Assert.Equal("READY", ReadLine(p));
            Thread.Sleep(200);
            WriteDump(p, dump, Normal);
        }
        finally { Kill(p); }
        using var service = new MinidumpService();
        var summary = await service.Summarize(dump, null, default);
        Assert.Null(summary.Exception);
        Assert.Contains(summary.Notes!, n => n.StartsWith("No exception stream", StringComparison.Ordinal));
        var stack = await service.Stack(dump, null, true, 128, 0, 128, null, default);
        Print(stack);
        AssertSubsequence(Functions(stack), ["wait_forever", "main", "BaseThreadInitThunk", "RtlUserThreadStart"]);
        Assert.Equal(0, stack.ScannedFrames);
    }

    [Fact]
    public async Task ManagedProcessFramesAreIdentified()
    {
        if (!OperatingSystem.IsWindows()) return;
        using var dir = new TempDir();
        var psi = new ProcessStartInfo("dotnet") { RedirectStandardInput = true, RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false, CreateNoWindow = true };
        psi.ArgumentList.Add(typeof(Corvus.Core.AssemblyWorkspace).Assembly.Location);
        using var p = Process.Start(psi)!;
        string dump = dir.File("managed.dmp");
        try
        {
            Thread.Sleep(2500); // the server is up and waits for input
            WriteDump(p, dump, Normal);
        }
        finally { Kill(p); }
        using var service = new MinidumpService();
        var summary = await service.Summarize(dump, null, default);
        Assert.Equal(".NET (CoreCLR)", summary.Process!.Runtime);
        output.WriteLine($"DAC {summary.Managed!.Dac.Status}: {summary.Managed.Dac.Detail}; heap {summary.Managed.Heap}");
        int managed = 0, frames = 0, heuristic = 0, decoded = 0;
        var sw = Stopwatch.StartNew();
        for (int i = 0; i < summary.Counts!.Threads; i++)
        {
            var stack = await service.Stack(dump, $"#{i}", true, 128, 0, 128, null, default);
            frames += stack.Items.Count;
            heuristic += stack.ScannedFrames;
            managed += stack.Items.Count(f => f.Kind == "managed");
            decoded += stack.Items.Count(f => f.SymbolSource == "clr" && f.Token != null);
            if (i == 0) Print(stack);
        }
        output.WriteLine($"{summary.Counts!.Threads} threads, {frames} frames ({heuristic} heuristic, {managed} managed, {decoded} decoded) in {sw.ElapsedMilliseconds} ms");
        Assert.True(managed > 0, "no managed frame identified");
        if (summary.Managed.Dac.Status == "loaded") Assert.True(decoded > 0, "the DAC loaded but no managed frame was decoded");
    }

    /// <summary>Three crashes of two kinds (ASLR moves the image between runs) make two buckets.</summary>
    [Fact]
    public async Task RealCrashesBucketBySignature()
    {
        using var dir = new TempDir();
        if (Build(dir, "x64") is not { } exe) return;
        var dumps = Directory.CreateDirectory(dir.File("dumps")).FullName;
        CrashAndDump(exe, Path.Combine(dumps, "av1.dmp"), Normal);
        CrashAndDump(exe, Path.Combine(dumps, "av2.dmp"), Normal);
        SelfDump(exe, "cpp", Path.Combine(dumps, "cpp.dmp"));
        using var service = new MinidumpService { BucketCache = dir.File("cache") };
        var r = await service.Bucket(dumps, false, null, 3, null, false, true, 10, null, 0, 10, null, default);
        foreach (var b in r.Items) output.WriteLine($"{b.Count} {b.Signature}");
        Assert.Equal(2, r.Total);
        var av = r.Items[0];
        Assert.Equal(2, av.Count);
        Assert.StartsWith("0xC0000005 | crash!crash_here | crash!level2 > crash!level1 > crash!main", av.Signature);
        Assert.StartsWith("0xE06D7363 | crash!thrower", r.Items[1].Signature); // the raising frames are skipped
    }

    /// <summary>Through the server: a loaded image's user name wins over the PDB name in dump_stack.</summary>
    [Fact]
    public async Task UserNamesOfALoadedImageNameTheFrames()
    {
        using var dir = new TempDir();
        if (Build(dir, "x64") is not { } exe) return;
        var dump = CrashAndDump(exe, dir.File("av.dmp"), Normal);
        await using var client = await McpProtocolTests.StartServerAsync();
        async Task<string> Call(string tool, Dictionary<string, object?> args)
        {
            var r = await client.CallToolAsync(tool, args);
            var text = string.Join("\n", r.Content.OfType<TextContentBlock>().Select(c => c.Text));
            Assert.True(r.IsError != true, text);
            return text;
        }
        await Call("load_assembly", new() { ["path"] = exe });
        await Call("rename_native", new() { ["dryRun"] = false, ["image"] = "crash.exe", ["address"] = "level1", ["name"] = "UserLevelOne" });
        var stack = await client.CallToolAsync("dump_stack", new Dictionary<string, object?> { ["dump"] = dump });
        Assert.True(stack.IsError != true);
        var frames = stack.StructuredContent!.Value.GetProperty("items").EnumerateArray()
            .Select(f => (Function: f.TryGetProperty("function", out var n) ? n.GetString() : null, Source: f.TryGetProperty("symbolSource", out var s) ? s.GetString() : null)).ToList();
        Assert.Contains(("UserLevelOne", "user"), frames);
        Assert.Contains(("level2", "pdb"), frames);
    }

    // ---- cdb ----

    private static string? Cdb()
    {
        if (Environment.GetEnvironmentVariable("CORVUS_CDB") is { Length: > 0 } custom && File.Exists(custom)) return custom;
        var pf86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
        if (pf86.Length == 0) return null;
        var path = Path.Combine(pf86, "Windows Kits", "10", "Debuggers", "x64", "cdb.exe");
        return File.Exists(path) ? path : null;
    }

    /// <summary>cdb's faulting frames (.ecxr; kc) and module list (lm) against ours.</summary>
    private void CompareWithCdb(string dump, string symbols, MinidumpService.DumpReport summary, MinidumpService.StackReport stack)
    {
        if (Cdb() is not { } cdb) { output.WriteLine("cdb not installed: oracle skipped"); return; }
        var psi = new ProcessStartInfo(cdb) { UseShellExecute = false };
        foreach (var a in new[] { "-z", dump, "-y", symbols, "-c", ".ecxr;kc 8;lm;q" }) psi.ArgumentList.Add(a);
        psi.Environment["_NT_SYMBOL_PATH"] = symbols;
        psi.Environment.Remove("_NT_ALT_SYMBOL_PATH");
        var (code, log) = Tools.Run(psi, 180_000);
        Assert.True(code == 0, log);
        int site = log.IndexOf("Reading initial command", StringComparison.Ordinal);
        Assert.True(site >= 0, log);
        var frames = Regex.Matches(log[site..], @"^(?:[0-9a-f]{2} )?(\w+)!([^\s:]+)\r?$", RegexOptions.Multiline).Take(8)
            .Select(m => (Module: m.Groups[1].Value, Function: m.Groups[2].Value)).ToList();
        output.WriteLine("cdb: " + string.Join(" > ", frames.Select(f => $"{f.Module}!{f.Function}")));
        Assert.True(frames.Count >= 4, log);
        Assert.Equal(frames.Take(4).Select(f => $"{f.Module}!{f.Function}"), stack.Items.Take(4).Select(f => $"crash!{f.Function}"));
        int lm = log.IndexOf("start ", site, StringComparison.Ordinal);
        var modules = Regex.Matches(log[Math.Max(lm, 0)..], @"^([0-9a-f]{8}(?:`[0-9a-f]{8})?) [0-9a-f]{8}(?:`[0-9a-f]{8})?\s+(\S+)", RegexOptions.Multiline)
            .Select(m => (Base: Convert.ToUInt64(m.Groups[1].Value.Replace("`", ""), 16), Name: m.Groups[2].Value)).ToList();
        output.WriteLine($"cdb lm: {modules.Count} modules, ours: {summary.Counts!.Modules}");
        Assert.Equal(summary.Counts!.Modules, modules.Count);
        var ours = new MinidumpService().Modules(dump, null, 0, 1000).Rows.ToDictionary(m => Convert.ToUInt64(m.Base[2..], 16));
        foreach (var (b, name) in modules)
        {
            Assert.True(ours.TryGetValue(b, out var m), $"cdb lists {name} at {b:X}, we do not");
            Assert.Equal(name, Path.GetFileNameWithoutExtension(m!.Name), StringComparer.OrdinalIgnoreCase);
        }
    }
}
