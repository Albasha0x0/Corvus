using System.Runtime.InteropServices;
using Corvus.Core;
using Corvus.Native.Diagnostics;
using Corvus.Native.Dump;
using Corvus.Services;

namespace Corvus.Tests;

/// <summary>
/// Snapshot writes: one the running program disturbs (it changed a list or a region during the read) is written again; a
/// program still starting is written once its loader has run; a Linux core written at a stop gives the stopped thread the
/// stop's registers and signal; a program waiting in vfork for a child that has not run its program is refused instead of
/// holding gcore, and is left running.
/// </summary>
public sealed class ProcessSnapshotTests
{
    [Fact]
    public void A_write_the_program_changed_is_tried_again()
    {
        var errors = new Queue<int>([unchecked((int)0x80070018), unchecked((int)0x8007012B), 0]);
        ProcessSnapshot.Attempts(7, () => errors.Dequeue());
        Assert.Empty(errors);

        int calls = 0;
        var changed = Assert.Throws<ToolError>(() => ProcessSnapshot.Attempts(7, () => { calls++; return unchecked((int)0x8007012B); }));
        Assert.Equal(ProcessSnapshot.WriteTries, calls);
        Assert.Contains("the program changed while it was read", changed.Message);

        calls = 0;
        var other = Assert.Throws<ToolError>(() => ProcessSnapshot.Attempts(7, () => { calls++; return unchecked((int)0x80070070); }));
        Assert.Equal(1, calls);
        Assert.Equal(ErrorCode.IoError, other.Code);
        Assert.Contains("disk space", other.Remediation);
    }

    [Fact]
    public async Task A_core_written_at_a_stop_gives_the_stopped_thread_the_stops_registers_and_signal()
    {
        using var dir = new TempDir();
        var path = dir.File("stop.core");
        File.WriteAllBytes(path, SyntheticCore.Core(arm64: false));
        var p = SyntheticCore.Points(arm64: false);
        // thread 1002 waits elsewhere; the stop saw it at the crash point with thread 1001's stack
        var registers = new Dictionary<string, ulong> { ["rip"] = SyntheticCore.Base + p.Crash, ["rsp"] = SyntheticCore.X, ["rbp"] = SyntheticCore.X + 48, ["r12"] = 0xC12 };
        ProcessSnapshot.MarkStop(path, new ProcessSnapshot.Stop(1002, "x64", registers));

        using (var core = CoreFile.FromBytes(File.ReadAllBytes(path), "stop.core"))
        {
            Assert.Empty(core.Issues);
            Assert.Equal((1002u, 5), (core.FaultingThread!.Id, core.FaultingThread.Signal));
            Assert.Equal(0, core.ThreadById(1001)!.Signal);
            Assert.Equal(new ElfCoreSignal(5, 1, 0, SyntheticCore.Base + p.Crash, null), core.Signal);
        }
        using var service = new MinidumpService();
        var r = await service.Stack(path, "exception", true, 64, 0, 64, null, CancellationToken.None);
        Assert.Equal(1002u, r.ThreadId);
        Assert.Equal(["crash::null()", "B", "A", "M"], r.Items.Select(f => f.Function));
    }

    [Fact]
    public void A_vfork_wait_is_read_from_the_thread_state_and_wait_channel()
    {
        Assert.Equal('D', ProcessSnapshot.StateOf("19 (vf (copy)) D 1 19 1 34816"));
        Assert.Equal('\0', ProcessSnapshot.StateOf(null));
        Assert.True(ProcessSnapshot.IsVforkWait("kernel_clone"));
        Assert.True(ProcessSnapshot.IsVforkWait("_do_fork"));
        Assert.False(ProcessSnapshot.IsVforkWait("futex_wait_queue"));
        Assert.False(ProcessSnapshot.IsVforkWait(null));
    }

    /// <summary>vforker: prints its pid, then vforks a child that stops itself before it runs sleep 3, and waits for it.</summary>
    private const string Vforker = """
        #include <signal.h>
        #include <stdio.h>
        #include <unistd.h>
        #include <sys/wait.h>
        int main(void)
        {
            printf("%d\n", getpid());
            fflush(stdout);
            pid_t pid = vfork();
            if (pid == 0) { kill(getpid(), SIGSTOP); execl("/bin/sleep", "sleep", "3", (char*)0); _exit(127); }
            waitpid(pid, 0, 0);
            return 0;
        }
        """;

    [Trait("Speed", "Slow")]
    [LiveTargetFact("linux-x64")]
    public Task A_program_in_vfork_is_refused_and_left_running_on_linux_x64() => VforkRefused(LiveTarget.LinuxX64);

    [Trait("Speed", "Slow")]
    [LiveTargetFact("linux-x86")]
    public Task A_program_in_vfork_is_refused_and_left_running_on_linux_x86() => VforkRefused(LiveTarget.LinuxX86);

    private static async Task VforkRefused(LiveTarget target)
    {
        using var dir = new TempDir();
        var exe = target.Build(dir, "vforker", Vforker);
        using var parent = System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(exe) { RedirectStandardOutput = true })!;
        try
        {
            var pid = int.Parse((await parent.StandardOutput.ReadLineAsync())!, System.Globalization.CultureInfo.InvariantCulture);
            int? waiting = null;
            for (int i = 0; i < 50 && (waiting = ProcessSnapshot.InVfork(pid)) == null; i++) await Task.Delay(100);
            Assert.Equal(pid, waiting);
            int child = int.Parse(File.ReadAllText($"/proc/{pid}/task/{pid}/children").Trim(), System.Globalization.CultureInfo.InvariantCulture);

            var sw = System.Diagnostics.Stopwatch.StartNew();
            var refused = Assert.Throws<ToolError>(() => ProcessSnapshot.Write(pid, dir.File("held.core"), false, CancellationToken.None));
            Assert.Equal(ErrorCode.Timeout, refused.Code);
            Assert.Contains("waits in vfork", refused.Message);
            Assert.InRange(sw.Elapsed, ProcessSnapshot.VforkWait, ProcessSnapshot.VforkWait + TimeSpan.FromSeconds(20));
            Assert.Equal('D', ProcessSnapshot.State(pid, pid));
            Assert.False(File.Exists(dir.File("held.core")));

            // A gcore already attaching when the vfork wait is seen is ended,
            // and the program is not left in group stop.
            var ended = Assert.Throws<ToolError>(() => ProcessSnapshot.WriteCore(pid, dir.File("attached.core"), CancellationToken.None, null, waitOutVfork: false));
            Assert.Contains("waits in vfork", ended.Message);
            await Task.Delay(500);
            Assert.Equal('D', ProcessSnapshot.State(pid, pid));

            // A child that runs its program within the wait lets the snapshot
            // be written.
            _ = Task.Delay(2000).ContinueWith(_ => System.Diagnostics.Process.Start("kill", ["-CONT", child.ToString(System.Globalization.CultureInfo.InvariantCulture)]));
            Assert.True(ProcessSnapshot.Write(pid, dir.File("after.core"), false, CancellationToken.None) > 0);
            Assert.True(parent.WaitForExit(10_000), "the program did not run on after the snapshots");
        }
        finally
        {
            if (!parent.HasExited) parent.Kill(true);
        }
    }

    [Fact]
    public void A_program_still_starting_is_written_once_its_loader_has_run()
    {
        if (!OperatingSystem.IsWindows()) return;
        using var dir = new TempDir();
        // Regression: a snapshot right after a process started failed three times with ERROR_PARTIAL_COPY.
        // The process is created suspended (its loader has not run) and resumed 500 ms later.
        var si = new StartupInfo { cb = Marshal.SizeOf<StartupInfo>() };
        Assert.True(CreateProcessW(Path.Combine(Environment.SystemDirectory, "findstr.exe"), "findstr x\0".ToCharArray(), IntPtr.Zero, IntPtr.Zero, false,
            0x4 | 0x08000000, IntPtr.Zero, null, ref si, out var pi), "CreateProcess");
        try
        {
            using var resume = new Timer(_ => _ = ResumeThread(pi.Thread), null, 500, Timeout.Infinite);
            Assert.True(ProcessSnapshot.Write(pi.ProcessId, dir.File("start.dmp"), false, CancellationToken.None) > 0);
        }
        finally
        {
            TerminateProcess(pi.Process, 0);
            CloseHandle(pi.Thread);
            CloseHandle(pi.Process);
        }
    }

    [Fact]
    public void A_loader_that_never_runs_is_refused_after_the_wait()
    {
        var wait = ProcessSnapshot.LoaderWait;
        ProcessSnapshot.LoaderWait = TimeSpan.FromMilliseconds(100);
        try
        {
            var refused = Assert.Throws<ToolError>(() => ProcessSnapshot.AwaitLoader(7, () => false, CancellationToken.None));
            Assert.Equal(ErrorCode.Timeout, refused.Code);
            Assert.Contains("Process 7 has not started", refused.Message);
            Assert.Contains("live_break action=continue", refused.Remediation);
            var answers = new Queue<bool?>([false, false, true]);
            ProcessSnapshot.AwaitLoader(7, () => answers.Dequeue(), CancellationToken.None);
            Assert.Empty(answers);
            // An unreadable PEB is unknown, not a loader that has not run.
            ProcessSnapshot.AwaitLoader(7, () => null, CancellationToken.None);
        }
        finally { ProcessSnapshot.LoaderWait = wait; }
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct StartupInfo
    {
        public int cb;
        public string? Reserved, Desktop, Title;
        public int X, Y, XSize, YSize, XCountChars, YCountChars, FillAttribute, Flags;
        public short ShowWindow, Reserved2;
        public IntPtr Reserved3, StdInput, StdOutput, StdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ProcessInformation
    {
        public IntPtr Process, Thread;
        public int ProcessId, ThreadId;
    }

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool CreateProcessW(string application, char[] commandLine, IntPtr processAttributes, IntPtr threadAttributes, bool inherit,
        uint flags, IntPtr environment, string? directory, ref StartupInfo startup, out ProcessInformation info);

    [DllImport("kernel32.dll")]
    private static extern uint ResumeThread(IntPtr thread);

    [DllImport("kernel32.dll")]
    private static extern bool TerminateProcess(IntPtr process, uint code);

    [DllImport("kernel32.dll")]
    private static extern bool CloseHandle(IntPtr handle);
}
