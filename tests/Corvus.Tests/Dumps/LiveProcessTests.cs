using System.Diagnostics;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Corvus.Core;
using Corvus.Native.Dump;
using Corvus.Native.Live;
using Corvus.Services;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>
/// inspect_process: the read-only guarantee (access masks, no write-capable API bound) and a real inspection of a child
/// process this test owns (findstr waiting on its input, 64-bit and 32-bit), checked to be unchanged afterwards: the
/// bytes of its writable image sections, its threads' suspend counts, and that it still answers. Skipped off Windows.
/// </summary>
public sealed class LiveProcessTests(ITestOutputHelper output)
{
    [Fact]
    public void Handles_are_query_and_read_only_and_no_write_capable_api_is_bound()
    {
        Assert.Equal(0x0410u, LiveProcess.ProcessAccess);   // PROCESS_QUERY_INFORMATION | PROCESS_VM_READ
        Assert.Equal(0x0048u, LiveProcess.ThreadAccess);    // THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION
        string[] forbidden =
        [
            "WriteProcessMemory", "VirtualProtectEx", "VirtualAllocEx", "VirtualFreeEx", "SuspendThread", "ResumeThread", "Wow64SuspendThread",
            "SetThreadContext", "Wow64SetThreadContext", "CreateRemoteThread", "CreateRemoteThreadEx", "QueueUserAPC", "DebugActiveProcess",
            "DebugBreakProcess", "NtSuspendProcess", "NtResumeProcess", "TerminateProcess", "TerminateThread", "DuplicateHandle", "MiniDumpWriteDump",
            "OpenProcessToken", "AdjustTokenPrivileges",
        ];
        var bound = typeof(LiveProcess).Assembly.GetTypes()
            .Where(t => t.Namespace == "Corvus.Native.Live")
            .SelectMany(t => t.GetMethods(BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic))
            .Select(m => m.GetCustomAttribute<DllImportAttribute>() is { } d ? d.EntryPoint ?? m.Name : null)
            .Where(n => n != null).ToList();
        Assert.NotEmpty(bound);
        Assert.DoesNotContain(bound, n => forbidden.Any(f => n!.StartsWith(f, StringComparison.Ordinal)));
    }

    [Fact]
    public async Task Selection_errors_are_typed()
    {
        using var dumps = new MinidumpService();
        var service = new LiveProcessService(dumps);
        async Task<ToolError> Fails(string process, string? view = null) =>
            await Assert.ThrowsAsync<ToolError>(() => service.Inspect(process, view, null, 0, 1, null, 1, null, 5, default));
        if (!OperatingSystem.IsWindows())
        {
            Assert.Equal(ErrorCode.ProviderUnavailable, (await Fails("1")).Code);
            return;
        }
        Assert.Equal(ErrorCode.NotFound, (await Fails("no-such-process-" + Guid.NewGuid().ToString("N")[..8])).Code);
        Assert.Equal(ErrorCode.InvalidArgument, (await Fails("0")).Code);
        Assert.Equal(ErrorCode.InvalidArgument, (await Fails(Environment.ProcessId.ToString())).Code);
        Assert.Equal(ErrorCode.InvalidArgument, (await Fails("1", "bogus")).Code);
        // the System process (pid 4) exists and is never readable from user mode
        var system = await Fails("4");
        Assert.True(system.Code is ErrorCode.AccessDenied or ErrorCode.NotFound, system.Code.ToString());
    }

    public static TheoryData<string> Bitness => new() { "System32", "SysWOW64" };

    [Theory]
    [MemberData(nameof(Bitness))]
    [Trait("Speed", "Slow")]
    public async Task Inspecting_a_child_leaves_it_unchanged_and_running(string systemFolder)
    {
        if (!OperatingSystem.IsWindows() || RuntimeInformation.ProcessArchitecture != Architecture.X64) return;
        var exe = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), systemFolder, "findstr.exe");
        if (!File.Exists(exe)) { output.WriteLine($"{exe} not present: skipped"); return; }
        using var child = Process.Start(new ProcessStartInfo(exe, "x")
        {
            RedirectStandardInput = true, RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true,
        })!;
        try
        {
            await Send(child, "x-before");
            // findstr settles after its first line (its output buffer is first touched then): wait until its writable data is
            // stable; empty until the loader lists its image (a loaded machine started it later), and two empty reads are not stable
            var before = Snapshot(child.Id);
            for (var settle = Stopwatch.StartNew(); settle.Elapsed < TimeSpan.FromSeconds(30);)
            {
                await Task.Delay(100);
                var again = Snapshot(child.Id);
                if (again.Writable.Count > 0 && again.Writable.SequenceEqual(before.Writable)) break;
                before = again;
            }
            Assert.NotEmpty(before.Writable);

            var clock = Stopwatch.StartNew();
            using var dumps = new MinidumpService();
            var service = new LiveProcessService(dumps);
            string pid = child.Id.ToString();
            var summary = await service.Inspect(pid, "summary", null, 0, 50, null, 64, null, 60, default);
            var modules = (await service.Inspect(pid, "modules", null, 0, 1000, null, 64, null, 60, default)).Items!.Cast<MinidumpService.ModuleSummary>().ToList();
            var regions = await service.Inspect(pid, "regions", null, 0, 1000, "writable", 64, null, 60, default);
            var threads = await service.Inspect(pid, "threads", null, 0, 50, null, 64, null, 60, default);
            var rows = threads.Items!.Cast<LiveProcessService.ThreadRow>().ToList();
            output.WriteLine($"{systemFolder}: {summary.Counts!.Modules} modules, {regions.Total}/{summary.Counts.RegionsTotal} writable regions, {summary.Counts.Threads} threads, " +
                             $"handles {threads.HandlesOpened}/{threads.HandlesClosed}, {clock.ElapsedMilliseconds} ms");

            foreach (var r in new[] { summary, regions, threads })
            {
                Assert.True(r.Detached);
                Assert.Equal(r.HandlesOpened, r.HandlesClosed);
                Assert.True(r.StillRunning);
                Assert.Equal(systemFolder == "SysWOW64" ? "x86" : "x64", r.Architecture);
                Assert.Equal(systemFolder == "SysWOW64", r.Wow64);
            }
            Assert.True(threads.HandlesOpened >= 1 + rows.Count);
            Assert.Equal("findstr.exe", summary.MainModule!.Name, ignoreCase: true);
            Assert.Contains(modules, m => m.Name.Equals("findstr.exe", StringComparison.OrdinalIgnoreCase) && m.LocalImage == "matches");
            Assert.Contains(modules, m => m.Name.Equals("ntdll.dll", StringComparison.OrdinalIgnoreCase));
            Assert.NotEmpty(regions.Items!);
            Assert.All(rows, t => Assert.Equal(0u, t.SuspendCount));
            // the main thread waits in a read of its input: the stack runs from an ntdll system call stub up into findstr
            List<MinidumpService.StackFrame>? main = null;
            foreach (var t in rows)
            {
                var stack = await service.Inspect(pid, "stacks", t.Id.ToString(), 0, 64, null, 64, null, 60, default);
                var frames = stack.Items!.Cast<MinidumpService.StackFrame>().ToList();
                output.WriteLine($"  thread {t.Id} suspend={t.SuspendCount} {t.Location} [{stack.StackStop}] " + string.Join(" <- ", frames.Take(6).Select(f => f.Symbol)));
                Assert.True(stack.Detached);
                if (main == null && frames.Any(f => f.Module?.Equals("findstr.exe", StringComparison.OrdinalIgnoreCase) == true)) main = frames;
            }
            Assert.NotNull(main);
            Assert.StartsWith("ntdll!Nt", main[0].Symbol);
            Assert.All(main.TakeWhile(f => f.Basis != "inferred"), f => Assert.NotNull(f.Module));

            var after = Snapshot(child.Id);
            Assert.Equal(before.Writable, after.Writable);
            Assert.Equal(before.Suspended, after.Suspended);
            Assert.Equal(0, after.Suspended);
            Assert.False(child.HasExited);
            // still working after the inspection: it takes more input and, at end of input, writes every matching line and exits normally
            await child.StandardInput.WriteLineAsync("x-after");
            child.StandardInput.Close();
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            var text = await child.StandardOutput.ReadToEndAsync(timeout.Token);
            await child.WaitForExitAsync(timeout.Token);
            Assert.Equal(["x-before", "x-after"], text.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries));
            Assert.Equal(0, child.ExitCode);
        }
        finally
        {
            try { child.Kill(); } catch (InvalidOperationException) { }
        }
    }

    [Fact]
    public async Task Cancellation_is_honored_before_attaching()
    {
        if (!OperatingSystem.IsWindows()) return;
        using var dumps = new MinidumpService();
        var service = new LiveProcessService(dumps);
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => service.Inspect("4", null, null, 0, 1, null, 1, null, 5, cts.Token));
    }

    /// <summary>Writes a line to findstr and waits until all its threads wait again (findstr buffers its output on a pipe).</summary>
    private static async Task Send(Process child, string line)
    {
        await child.StandardInput.WriteLineAsync(line);
        await child.StandardInput.FlushAsync();
        var clock = Stopwatch.StartNew();
        int quiet = 0;
        while (clock.ElapsedMilliseconds < 5000 && quiet < 3)
        {
            await Task.Delay(20);
            child.Refresh();
            quiet = child.Threads.Cast<ProcessThread>().All(t => t.ThreadState == System.Diagnostics.ThreadState.Wait) ? quiet + 1 : 0;
        }
    }

    /// <summary>SHA-256 of each writable committed region of the child's image modules, and how many of its threads are suspended.</summary>
    private static (List<string> Writable, int Suspended) Snapshot(int pid)
    {
        using var live = LiveProcess.Attach(pid);
        var hashes = new List<string>();
        foreach (var r in live.Regions())
        {
            if (r.State != 0x1000 || r.Type != 0x1000000 || (r.Protect & 0xCC) == 0 || (r.Protect & 0x100) != 0) continue;
            if (live.ModuleAt(r.Base) is not { } m || !m.FileName.Equals("findstr.exe", StringComparison.OrdinalIgnoreCase)) continue;
            var bytes = new byte[r.Size];
            int n = live.ReadMemory(r.Base, bytes);
            hashes.Add($"{r.Base:X}:{n}:{Convert.ToHexString(SHA256.HashData(bytes.AsSpan(0, n)))}");
        }
        int suspended = 0;
        using var process = Process.GetProcessById(pid);
        process.Refresh();
        foreach (ProcessThread t in process.Threads)
            if (t.ThreadState == System.Diagnostics.ThreadState.Wait && t.WaitReason == ThreadWaitReason.Suspended) suspended++;
        foreach (var t in live.Threads())
            if (live.ReadThread(t.Id, context: false).SuspendCount is > 0) suspended++;
        return (hashes, suspended);
    }
}

/// <summary>
/// Every process of this session inspected with stacks: each call either succeeds with every handle closed or fails
/// with a typed error (access denied, exited); prints the runner numbers (processes, frames, named frames, time).
/// </summary>
[Trait("Speed", "Slow")]
public sealed class LiveProcessSweepTests(ITestOutputHelper output)
{
    [Fact]
    public async Task Every_process_of_the_session_is_inspected_or_refused_with_a_typed_error()
    {
        if (!OperatingSystem.IsWindows() || RuntimeInformation.ProcessArchitecture != Architecture.X64) return;
        using var dumps = new MinidumpService();
        var service = new LiveProcessService(dumps);
        using var self = Process.GetCurrentProcess();
        int session = self.SessionId, ok = 0, threads = 0, frames = 0, named = 0, heuristic = 0;
        var errors = new Dictionary<string, int>();
        var clock = Stopwatch.StartNew();
        long slowest = 0;
        string slowestName = "";
        var all = Process.GetProcesses();
        // bounded: the first 40 by id (about 10 s)
        var targets = all.Where(p => p.SessionId == session && p.Id != Environment.ProcessId).Select(p => (p.Id, p.ProcessName)).OrderBy(p => p.Id).Take(40).ToList();
        foreach (var p in all) p.Dispose();
        foreach (var (pid, name) in targets)
        {
            try
            {
                var r = await service.Inspect(pid.ToString(), "stacks", null, 0, 64, null, 64, null, 30, default);
                Assert.True(r.Detached, $"{name} ({pid}): {r.HandlesOpened} opened, {r.HandlesClosed} closed");
                ok++;
                threads++;
                foreach (var f in r.Items!.Cast<MinidumpService.StackFrame>())
                {
                    frames++;
                    if (f.Function != null) named++;
                    if (f.Basis == "inferred") heuristic++;
                }
                if (r.ElapsedMs > slowest) (slowest, slowestName) = (r.ElapsedMs, name);
            }
            catch (ToolError e)
            {
                var key = ToolError.CodeName(e.Code);
                errors[key] = errors.GetValueOrDefault(key) + 1;
                output.WriteLine($"{name} ({pid}): {key}: {e.Message}");
                Assert.True(e.Code is ErrorCode.AccessDenied or ErrorCode.NotFound, $"{name} ({pid}): {e.Code} {e.Message}");
            }
        }
        output.WriteLine($"{targets.Count} processes in session {session}: {ok} inspected, errors: {string.Join(", ", errors.Select(kv => $"{kv.Key} {kv.Value}"))}; " +
                         $"{threads} threads, {frames} frames, {named} named ({(frames > 0 ? named * 100 / frames : 0)}%), {heuristic} heuristic; " +
                         $"{clock.ElapsedMilliseconds} ms total, slowest {slowestName} {slowest} ms");
        Assert.True(ok > 0);
    }
}
