using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;
using static Corvus.Native.Providers.WindowsJob;

namespace Corvus.Native.Providers;

/// <summary>What to run: executable, arguments (quoted as needed) and environment overrides (null value removes).</summary>
public sealed record ChildProcessStart(string FileName, IReadOnlyList<string> Arguments)
{
    public string? WorkingDirectory { get; init; }
    public IReadOnlyDictionary<string, string?> Environment { get; init; } = new Dictionary<string, string?>();
    /// <summary>Most committed memory of the whole tree in bytes (Windows: the job's limit; allocations past it fail); null: none.</summary>
    public long? MemoryLimitBytes { get; init; }
    /// <summary>
    /// Also applies <see cref="MemoryLimitBytes"/> outside Windows: RLIMIT_DATA on Linux (allocations past it fail), a
    /// watchdog on the physical footprint on macOS (the tree is ended). Off: no limit there, as for engine workers.
    /// </summary>
    public bool MemoryLimitOnPosix { get; init; }
}

/// <summary>
/// A child process with redirected stdio whose whole process tree is stopped by <see cref="Kill"/> and by
/// <see cref="Dispose"/>. On Windows the process is created suspended inside a Job Object with
/// JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, so it cannot start a child outside the job, and the tree also dies when this
/// process exits for any reason (the job handle is closed by the OS). Elsewhere a shell parent runs the child and kills
/// it (and its process group) within a second of this process ending, killed outright included.
/// </summary>
public abstract class ChildProcess : IDisposable
{
    public abstract int Id { get; }
    public abstract Stream StandardInput { get; }
    public abstract Stream StandardOutput { get; }
    public abstract Stream StandardError { get; }
    public abstract bool HasExited { get; }
    /// <summary>Exit code once exited, otherwise null.</summary>
    public abstract int? ExitCode { get; }
    /// <summary>Completes when the process (not necessarily its children) has exited.</summary>
    public abstract Task Exited { get; }
    /// <summary>Ids of the processes in the tree that are still running (Windows: the job's processes).</summary>
    public abstract IReadOnlyList<int> TreeProcessIds();
    /// <summary>Stops the process and its children. Safe to call more than once.</summary>
    public abstract void Kill();
    /// <summary>The memory limit in bytes when the tree's peak usage reached it (allocations failed), else null.</summary>
    public virtual long? MemoryLimitReached() => null;

    /// <summary>
    /// CPU time the tree has used so far (user plus kernel), or null when it cannot be read. The base sums the running
    /// processes of <see cref="TreeProcessIds"/>, so it can fall when one exits; null when none could be read.
    /// </summary>
    public virtual TimeSpan? TreeCpuTime()
    {
        TimeSpan total = TimeSpan.Zero;
        bool read = false;
        foreach (var id in TreeProcessIds())
            try
            {
                using var process = Process.GetProcessById(id);
                total += process.TotalProcessorTime;
                read = true;
            }
            catch (Exception ex) when (ex is ArgumentException or InvalidOperationException or System.ComponentModel.Win32Exception or NotSupportedException) { }
        return read ? total : null;
    }

    public abstract void Dispose();

    public static ChildProcess Start(ChildProcessStart start)
    {
        ChildProcess child = OperatingSystem.IsWindows() ? WindowsJobProcess.Launch(start) : PosixGroupProcess.Launch(start);
        Running[child] = (Path.GetFileName(start.FileName), DateTimeOffset.UtcNow);
        child.Exited.ContinueWith(_ => Running.TryRemove(child, out var _), CancellationToken.None, TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
        return child;
    }

    private static readonly System.Collections.Concurrent.ConcurrentDictionary<ChildProcess, (string Program, DateTimeOffset Started)> Running = new();

    /// <summary>Children of this process still running (workers, helpers, external tools): id, program file name and start time.</summary>
    public static IReadOnlyList<(int Id, string Program, DateTimeOffset Started)> Live() =>
        [.. Running.Where(r => !r.Key.HasExited).Select(r => (r.Key.Id, r.Value.Program, r.Value.Started)).OrderBy(r => r.Started)];

    /// <summary>Runs an output reader on a thread of its own: a reader waiting for a starved pool loses the output.</summary>
    public static Thread StartReader(Action read)
    {
        var thread = new Thread(() => read()) { IsBackground = true, Name = "child output" };
        thread.Start();
        return thread;
    }

    /// <summary>
    /// Waits for the readers to reach the end of the output, which comes once the whole tree has closed it; true when they did
    /// before <paramref name="timeout"/> measured from <paramref name="started"/>.
    /// </summary>
    public static bool JoinReaders(IEnumerable<Thread> readers, Stopwatch started, TimeSpan timeout) =>
        readers.All(t => t.Join(timeout == Timeout.InfiniteTimeSpan ? Timeout.InfiniteTimeSpan
            : timeout - started.Elapsed is var left && left > TimeSpan.Zero ? left : TimeSpan.Zero));

    /// <summary>Windows command-line quoting of one argument (CommandLineToArgvW rules).</summary>
    public static string QuoteArgument(string arg)
    {
        if (arg.Length > 0 && arg.IndexOfAny([' ', '\t', '\n', '\v', '"']) < 0) return arg;
        var sb = new StringBuilder("\"");
        for (int i = 0; i < arg.Length; i++)
        {
            int slashes = 0;
            while (i < arg.Length && arg[i] == '\\') { slashes++; i++; }
            if (i == arg.Length) { sb.Append('\\', slashes * 2); break; }
            if (arg[i] == '"') sb.Append('\\', slashes * 2 + 1).Append('"');
            else sb.Append('\\', slashes).Append(arg[i]);
        }
        return sb.Append('"').ToString();
    }
}

internal sealed class PosixGroupProcess : ChildProcess
{
    private readonly Process _process;
    private readonly Task _exited;
    /// <summary>The worker itself (the shell's child): the id status reports and the process group Kill ends.</summary>
    private readonly int _workerId;
    private readonly Lock _gate = new();
    private bool _disposed, _disposedExited;
    private int? _disposedExitCode;

    private readonly long? _footprintLimit;
    private volatile bool _limitHit;

    private PosixGroupProcess(Process process, long? footprintLimit)
    {
        _process = process;
        _exited = process.WaitForExitAsync();
        _workerId = ReadWorkerId(process.StandardOutput.BaseStream) ?? process.Id;
        _footprintLimit = footprintLimit;
        // macOS does not enforce RLIMIT_DATA or RLIMIT_AS, so the footprint is
        // read on a thread of its own: a starved pool would read it late.
        if (footprintLimit is { } limit)
            new Thread(() => WatchFootprint(limit)) { IsBackground = true, Name = "child footprint " + _workerId }.Start();
    }

    /// <summary>Ends the tree once the worker's physical footprint (what macOS itself limits a process by) passes <paramref name="limit"/>.</summary>
    private void WatchFootprint(long limit)
    {
        // rusage_info_v2: a 16-byte uuid, then 64-bit fields; ri_phys_footprint is the eighth.
        const int footprintOffset = 72;
        var info = new byte[256];
        while (!_exited.Wait(100))
        {
            // Without the call the managed heap limit the caller sets still holds.
            try { if (ProcPidRusage(_workerId, 2, info) != 0) continue; }
            catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException) { return; }
            if (BitConverter.ToInt64(info, footprintOffset) <= limit) continue;
            _limitHit = true;
            Kill();
            return;
        }
    }

    [DllImport("libc", EntryPoint = "proc_pid_rusage")]
    private static extern int ProcPidRusage(int pid, int flavor, byte[] buffer);

    public override long? MemoryLimitReached() => _limitHit ? _footprintLimit : null;

    /// <summary>
    /// Runs "$@" with this shell as its parent, so its id is not reused while the watcher looks at it. setsid makes the child
    /// lead a process group of its own (as a background child it leads none, so setsid does not fork); set -m is the fallback
    /// only, as dash turns job control off without a controlling terminal. Its first output line is its id, written before it execs. Background
    /// jobs of a non-interactive shell read /dev/null, hence stdin through fd 3; the shell's own stderr (job notices) is
    /// dropped, the child's goes through fd 4. The watcher kills the child's group and the child once process $1 is gone.
    /// A non-empty CORVUS_CHILD_DATA_KB becomes the child's RLIMIT_DATA, and is not passed on.
    /// </summary>
    internal const string WatchScript = """
        w=$1; shift
        exec 3<&0 4>&2
        if command -v setsid >/dev/null 2>&1; then g=setsid; else g=; set -m 2>/dev/null; fi
        $g /bin/sh -c 'echo "$$"; if [ -n "$CORVUS_CHILD_DATA_KB" ]; then ulimit -d "$CORVUS_CHILD_DATA_KB" || exit 126; fi; unset CORVUS_CHILD_DATA_KB; exec "$@"' corvus-worker "$@" 0<&3 2>&4 3<&- 4>&- &
        c=$!
        set +m
        exec 3<&- 4>&- 2>/dev/null
        (while kill -0 "$w" && kill -0 "$c"; do sleep 0.25 || sleep 1; done
         kill -0 "$w" || { kill -9 -"$c"; kill -9 "$c"; }) </dev/null >/dev/null 2>&1 &
        s=$!
        wait "$c"; e=$?
        kill "$s"
        exit $e
        """;

    /// <summary>The id line the script writes first, read a byte at a time so none of the child's output is consumed.</summary>
    private static int? ReadWorkerId(Stream stdout)
    {
        Span<byte> one = stackalloc byte[1];
        int id = 0, digits = 0;
        while (stdout.Read(one) == 1 && one[0] != (byte)'\n')
        {
            if (one[0] is < (byte)'0' or > (byte)'9' || ++digits > 9) return null;
            id = id * 10 + (one[0] - '0');
        }
        return digits > 0 ? id : null;
    }

    public static PosixGroupProcess Launch(ChildProcessStart start) => Launch(start, Environment.ProcessId);

    /// <param name="watchPid">The process whose end ends the child (tests pass a stand-in for this one).</param>
    internal static PosixGroupProcess Launch(ChildProcessStart start, int watchPid)
    {
        var psi = new ProcessStartInfo("/bin/sh")
        {
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
            WorkingDirectory = start.WorkingDirectory ?? "",
        };
        foreach (var a in (string[])["-c", WatchScript, "corvus-child", watchPid.ToString(System.Globalization.CultureInfo.InvariantCulture), Resolve(start)])
            psi.ArgumentList.Add(a);
        foreach (var a in start.Arguments) psi.ArgumentList.Add(a);
        foreach (var (k, v) in start.Environment)
        {
            if (v == null) psi.Environment.Remove(k);
            else psi.Environment[k] = v;
        }
        long? limit = start.MemoryLimitOnPosix && start.MemoryLimitBytes is > 0 ? start.MemoryLimitBytes : null;
        if (limit is { } bytes && OperatingSystem.IsLinux())
            psi.Environment["CORVUS_CHILD_DATA_KB"] = (bytes >> 10).ToString(System.Globalization.CultureInfo.InvariantCulture);
        return new PosixGroupProcess(Process.Start(psi) ?? throw new Win32Exception("process did not start"), OperatingSystem.IsMacOS() ? limit : null);
    }

    /// <summary>The executable's full path, searched as Process.Start does; a missing one throws here as it would without the shell.</summary>
    private static string Resolve(ChildProcessStart start)
    {
        var name = start.FileName;
        string? path;
        if (name.Contains('/')) path = Path.GetFullPath(name);
        else
        {
            var search = start.Environment.TryGetValue("PATH", out var p) && p != null ? p : Environment.GetEnvironmentVariable("PATH") ?? "";
            path = new[] { Path.GetDirectoryName(Environment.ProcessPath), Directory.GetCurrentDirectory() }.Concat(search.Split(':'))
                .Where(d => !string.IsNullOrEmpty(d)).Select(d => Path.Combine(d!, name)).FirstOrDefault(File.Exists);
        }
        if (path == null || !File.Exists(path)) throw new Win32Exception(2, $"An error occurred trying to start process '{name}': No such file or directory");
        if (!OperatingSystem.IsWindows() && (File.GetUnixFileMode(path) & (UnixFileMode.UserExecute | UnixFileMode.GroupExecute | UnixFileMode.OtherExecute)) == 0)
            throw new Win32Exception(13, $"An error occurred trying to start process '{name}': Permission denied");
        return path;
    }

    public override int Id => _workerId;
    public override Stream StandardInput => _process.StandardInput.BaseStream;
    public override Stream StandardOutput => _process.StandardOutput.BaseStream;
    public override Stream StandardError => _process.StandardError.BaseStream;
    public override bool HasExited { get { lock (_gate) return _disposed ? _disposedExited : _process.HasExited; } }
    public override int? ExitCode { get { lock (_gate) return _disposed ? _disposedExitCode : _process.HasExited ? _process.ExitCode : null; } }
    public override Task Exited => _exited;
    public override IReadOnlyList<int> TreeProcessIds() => HasExited ? [] : [_workerId];

    [DllImport("libc", EntryPoint = "kill", SetLastError = true)]
    private static extern int SysKill(int pid, int signal);

    public override void Kill()
    {
        try
        {
            // a group keeps its id while members remain, so the group kill is safe after the worker itself ended
            _ = SysKill(-_workerId, 9);
            if (!HasExited) _ = SysKill(_workerId, 9);
        }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException) { }
        try { _process.Kill(entireProcessTree: true); } catch (Exception ex) when (ex is InvalidOperationException or Win32Exception) { }
    }

    public override void Dispose()
    {
        Kill();
        lock (_gate)
        {
            if (_disposed) return;
            // Process throws once disposed; the exit is kept, as WindowsJobProcess keeps it, for callers that still ask.
            _disposedExited = _process.WaitForExit(2000);
            _disposedExitCode = _disposedExited ? _process.ExitCode : null;
            _disposed = true;
            _process.Dispose();
        }
    }
}

internal sealed class WindowsJobProcess : ChildProcess
{
    private readonly SafeFileHandle _job;
    private readonly SafeProcessHandle _processHandle;
    private readonly int _id;
    private readonly FileStream _stdin, _stdout, _stderr;
    private readonly TaskCompletionSource _exited = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly ProcessWaitHandle _waitHandle;
    private int _disposed;
    /// <summary>The exit thread and Dispose; the last to finish closes the process handle, never closed under a pending wait.</summary>
    private int _handleUsers = 2;

    private readonly long? _memoryLimit;
    private readonly SafeFileHandle? _port;
    private volatile bool _limitHit;

    private WindowsJobProcess(SafeFileHandle job, SafeProcessHandle process, int id, SafeFileHandle stdin, SafeFileHandle stdout, SafeFileHandle stderr,
        long? memoryLimit, SafeFileHandle? port)
    {
        _job = job;
        _memoryLimit = memoryLimit;
        _port = port;
        _processHandle = process;
        _id = id;
        _stdin = new FileStream(stdin, FileAccess.Write, 1);
        _stdout = new FileStream(stdout, FileAccess.Read, 1);
        _stderr = new FileStream(stderr, FileAccess.Read, 1);
        _waitHandle = new ProcessWaitHandle(process);
        ExitThreadStarting?.Invoke(id);
        // A thread of its own, not a pool wait: a starved pool would report the exit seconds late.
        new Thread(() =>
        {
            _waitHandle.WaitOne();
            _exited.TrySetResult();
            ReleaseHandles();
        }) { IsBackground = true, Name = "child exit " + id }.Start();
        if (port != null) new Thread(() => WatchMemoryLimit(port)) { IsBackground = true, Name = "child memory " + id }.Start();
    }

    // A worker whose allocations fail can hang instead of exiting, so the job is ended at the limit, as the footprint
    // watchdog ends it on macOS (CI on 48563dd9: a 60 s timeout instead of limit_exceeded).
    private void WatchMemoryLimit(SafeFileHandle port)
    {
        try
        {
            while (Volatile.Read(ref _disposed) == 0 && !_limitHit)
            {
                if (!GetQueuedCompletionStatus(port, out var message, out _, out _, 250) || message != JobMessageJobMemoryLimit) continue;
                _limitHit = true;
                Kill();
            }
        }
        catch (ObjectDisposedException) { }
    }

    public override int Id => _id;
    public override Stream StandardInput => _stdin;
    public override Stream StandardOutput => _stdout;
    public override Stream StandardError => _stderr;
    public override Task Exited => _exited.Task;
    public override bool HasExited => _exited.Task.IsCompleted || (GetExitCodeProcess(_processHandle, out var c) && c != StillActive);

    public override int? ExitCode => GetExitCodeProcess(_processHandle, out var code) && code != StillActive ? unchecked((int)code) : null;

    // The job's accounting keeps the time of processes that already exited, so it never falls.
    public override TimeSpan? TreeCpuTime()
    {
        if (_job.IsClosed) return null;
        // JOBOBJECT_BASIC_ACCOUNTING_INFORMATION, 48 bytes (the call wants the exact size), starts with TotalUserTime and
        // TotalKernelTime in 100 ns units.
        const int size = 48;
        var buffer = Marshal.AllocHGlobal(size);
        try
        {
            if (!QueryInformationJobObject(_job, JobObjectBasicAccountingInformation, buffer, size, out _)) return null;
            return TimeSpan.FromTicks(Marshal.ReadInt64(buffer, 0) + Marshal.ReadInt64(buffer, 8));
        }
        catch (ObjectDisposedException) { return null; }
        finally { Marshal.FreeHGlobal(buffer); }
    }

    public override IReadOnlyList<int> TreeProcessIds()
    {
        if (_job.IsClosed) return [];
        // JOBOBJECT_BASIC_PROCESS_ID_LIST: two DWORDs then ULONG_PTR ids.
        const int capacity = 256;
        var size = 8 + IntPtr.Size * capacity;
        var buffer = Marshal.AllocHGlobal(size);
        try
        {
            if (!QueryInformationJobObject(_job, JobObjectBasicProcessIdList, buffer, (uint)size, out _)) return [];
            var count = Marshal.ReadInt32(buffer, 4);
            var ids = new int[Math.Min(count, capacity)];
            for (int i = 0; i < ids.Length; i++) ids[i] = (int)Marshal.ReadIntPtr(buffer, 8 + i * IntPtr.Size);
            return ids;
        }
        finally { Marshal.FreeHGlobal(buffer); }
    }

    public override void Kill()
    {
        if (!_job.IsClosed) TerminateJobObject(_job, 1);
    }

    public override long? MemoryLimitReached()
    {
        if (_memoryLimit is not { } limit || _port is not { IsClosed: false } port) return null;
        // The job posts JOB_OBJECT_MSG_JOB_MEMORY_LIMIT when an allocation would pass the limit (and fails); read here too,
        // so a death seen before the watcher wakes still names the limit.
        lock (port)
            while (!_limitHit && GetQueuedCompletionStatus(port, out var message, out _, out _, 0))
                _limitHit = message == JobMessageJobMemoryLimit;
        return _limitHit ? limit : null;
    }

    public override void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
        Kill();
        _job.Dispose(); // KILL_ON_JOB_CLOSE: anything left in the job dies here
        if (_port != null) lock (_port) _port.Dispose();
        foreach (var s in new Stream[] { _stdin, _stdout, _stderr })
        {
            try { s.Dispose(); } catch (IOException) { }
        }
        // Termination is asynchronous; observe the exit before Dispose returns.
        if (_waitHandle.WaitOne(2000)) _exited.TrySetResult();
        ReleaseHandles();
    }

    private void ReleaseHandles()
    {
        if (Interlocked.Decrement(ref _handleUsers) != 0) return;
        _waitHandle.Dispose();
        _processHandle.Dispose();
    }

    /// <summary>
    /// Process.Start lets its child inherit every inheritable handle of this process, and the child ends of our pipes are
    /// inheritable from CreatePipe until they are closed after CreateProcess; a server started meanwhile would hold our
    /// child's output open, so its reader never saw the end. Both take Process.Start's own lock (a private field; a lock
    /// of our own should a runtime rename it).
    /// </summary>
    internal static readonly object CreateLock =
        typeof(Process).GetField("s_createProcessLock", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static)?.GetValue(null) ?? new object();

    /// <summary>Test hook: runs while the child ends are inheritable.</summary>
    internal static Action<ChildProcessStart>? PipesCreated;

    /// <summary>Test hook: runs on the launching thread just before the child's exit thread starts.</summary>
    internal static Action<int>? ExitThreadStarting;

    public static WindowsJobProcess Launch(ChildProcessStart start)
    {
        // The lock covers only the window in which the child ends are inheritable; starting the exit thread waits for
        // the thread to run, which on a loaded machine took up to 0.6 s and queued every other launch behind it.
        Started started;
        lock (CreateLock) started = LaunchLocked(start);
        return new WindowsJobProcess(started.Job, started.Process, GetProcessId(started.Process), started.Stdin, started.Stdout, started.Stderr,
            start.MemoryLimitBytes is > 0 ? start.MemoryLimitBytes : null, started.Port);
    }

    /// <summary>A running child's handles: its job, process, the parent ends of its pipes, and the job's port if any.</summary>
    private readonly record struct Started(SafeFileHandle Job, SafeProcessHandle Process, SafeFileHandle Stdin, SafeFileHandle Stdout, SafeFileHandle Stderr,
        SafeFileHandle? Port);

    private static Started LaunchLocked(ChildProcessStart start)
    {
        var job = CreateJobObjectW(IntPtr.Zero, null);
        if (job.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error(), "CreateJobObject failed");
        SafeFileHandle? inRead = null, inWrite = null, outRead = null, outWrite = null, errRead = null, errWrite = null, port = null;
        IntPtr attributes = IntPtr.Zero, handleList = IntPtr.Zero;
        var info = default(PROCESS_INFORMATION);
        try
        {
            var limits = new JOBOBJECT_EXTENDED_LIMIT_INFORMATION
            {
                BasicLimitInformation = new JOBOBJECT_BASIC_LIMIT_INFORMATION
                {
                    LimitFlags = KillOnJobClose | DieOnUnhandledException | (start.MemoryLimitBytes is > 0 ? JobMemory : 0),
                },
                JobMemoryLimit = checked((UIntPtr)(ulong)Math.Max(0, start.MemoryLimitBytes ?? 0)),
            };
            if (!SetInformationJobObject(job, JobObjectExtendedLimitInformation, ref limits, (uint)Marshal.SizeOf<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>()))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "SetInformationJobObject failed");
            if (start.MemoryLimitBytes is > 0)
            {
                port = CreateIoCompletionPort(new IntPtr(-1), IntPtr.Zero, UIntPtr.Zero, 1);
                if (port.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error(), "CreateIoCompletionPort failed");
                var association = new JOBOBJECT_ASSOCIATE_COMPLETION_PORT { CompletionKey = IntPtr.Zero, CompletionPort = port.DangerousGetHandle() };
                if (!SetInformationJobObject(job, JobObjectAssociateCompletionPortInformation, ref association, (uint)Marshal.SizeOf<JOBOBJECT_ASSOCIATE_COMPLETION_PORT>()))
                    throw new Win32Exception(Marshal.GetLastWin32Error(), "SetInformationJobObject (completion port) failed");
            }

            CreateInheritablePipe(out inRead, out inWrite, childEndIsRead: true);
            CreateInheritablePipe(out outRead, out outWrite, childEndIsRead: false);
            CreateInheritablePipe(out errRead, out errWrite, childEndIsRead: false);
            PipesCreated?.Invoke(start);

            // Only the three child pipe ends are inherited, not every inheritable handle of this process
            // (such as the stdio pipes of an MCP stdio transport).
            IntPtr listSize = IntPtr.Zero;
            InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref listSize);
            attributes = Marshal.AllocHGlobal(listSize);
            if (!InitializeProcThreadAttributeList(attributes, 1, 0, ref listSize))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "InitializeProcThreadAttributeList failed");
            handleList = Marshal.AllocHGlobal(IntPtr.Size * 3);
            Marshal.WriteIntPtr(handleList, 0, inRead.DangerousGetHandle());
            Marshal.WriteIntPtr(handleList, IntPtr.Size, outWrite.DangerousGetHandle());
            Marshal.WriteIntPtr(handleList, IntPtr.Size * 2, errWrite.DangerousGetHandle());
            if (!UpdateProcThreadAttribute(attributes, 0, ProcThreadAttributeHandleList, handleList, IntPtr.Size * 3, IntPtr.Zero, IntPtr.Zero))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "UpdateProcThreadAttribute failed");

            var si = new STARTUPINFOEX();
            si.StartupInfo.cb = Marshal.SizeOf<STARTUPINFOEX>();
            si.StartupInfo.dwFlags = StartfUseStdHandles;
            si.StartupInfo.hStdInput = inRead.DangerousGetHandle();
            si.StartupInfo.hStdOutput = outWrite.DangerousGetHandle();
            si.StartupInfo.hStdError = errWrite.DangerousGetHandle();
            si.lpAttributeList = attributes;

            var commandLine = new StringBuilder(QuoteArgument(start.FileName));
            foreach (var a in start.Arguments) commandLine.Append(' ').Append(QuoteArgument(a));
            var flags = CreateSuspended | CreateNoWindow | CreateUnicodeEnvironment | ExtendedStartupInfoPresent;
            if (!CreateProcessW(start.FileName, commandLine.Append('\0').ToString().ToCharArray(), IntPtr.Zero, IntPtr.Zero, true, flags,
                    BuildEnvironment(start.Environment), start.WorkingDirectory, ref si, out info))
                throw new Win32Exception(Marshal.GetLastWin32Error(), $"CreateProcess failed for {start.FileName}");

            var process = new SafeProcessHandle(info.hProcess, ownsHandle: true);
            using var thread = new SafeFileHandle(info.hThread, ownsHandle: true);
            info = default;
            if (!AssignProcessToJobObject(job, process))
            {
                var error = Marshal.GetLastWin32Error();
                TerminateProcess(process, 1);
                process.Dispose();
                throw new Win32Exception(error, "AssignProcessToJobObject failed");
            }
            if (ResumeThread(thread) == uint.MaxValue)
            {
                var error = Marshal.GetLastWin32Error();
                TerminateJobObject(job, 1);
                process.Dispose();
                throw new Win32Exception(error, "ResumeThread failed");
            }
            var started = new Started(job, process, inWrite, outRead, errRead, port);
            inWrite = outRead = errRead = null;
            return started;
        }
        catch
        {
            if (info.hProcess != IntPtr.Zero) { TerminateProcess(new SafeProcessHandle(info.hProcess, true), 1); CloseHandle(info.hThread); }
            job.Dispose();
            port?.Dispose();
            inWrite?.Dispose(); outRead?.Dispose(); errRead?.Dispose();
            throw;
        }
        finally
        {
            // The parent's copies of the child ends must be closed, or reads never see EOF when the child exits.
            inRead?.Dispose(); outWrite?.Dispose(); errWrite?.Dispose();
            if (attributes != IntPtr.Zero) { DeleteProcThreadAttributeList(attributes); Marshal.FreeHGlobal(attributes); }
            if (handleList != IntPtr.Zero) Marshal.FreeHGlobal(handleList);
        }
    }

    private static void CreateInheritablePipe(out SafeFileHandle read, out SafeFileHandle write, bool childEndIsRead)
    {
        var sa = new SECURITY_ATTRIBUTES { nLength = Marshal.SizeOf<SECURITY_ATTRIBUTES>(), bInheritHandle = true };
        if (!CreatePipe(out read, out write, ref sa, 0))
            throw new Win32Exception(Marshal.GetLastWin32Error(), "CreatePipe failed");
        var parentEnd = childEndIsRead ? write : read;
        if (!SetHandleInformation(parentEnd, HandleFlagInherit, 0))
            throw new Win32Exception(Marshal.GetLastWin32Error(), "SetHandleInformation failed");
    }

    private static string BuildEnvironment(IReadOnlyDictionary<string, string?> overrides)
    {
        var env = new SortedDictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (System.Collections.DictionaryEntry e in System.Environment.GetEnvironmentVariables())
            env[(string)e.Key] = (string?)e.Value ?? "";
        foreach (var (k, v) in overrides)
        {
            if (v == null) env.Remove(k);
            else env[k] = v;
        }
        var sb = new StringBuilder();
        foreach (var (k, v) in env) sb.Append(k).Append('=').Append(v).Append('\0');
        return sb.Append('\0').ToString();
    }

    private const uint StillActive = 259;
    private const int JobObjectBasicAccountingInformation = 1;
    private const int JobObjectBasicProcessIdList = 3;
    private const int JobObjectAssociateCompletionPortInformation = 7;
    private const uint JobMessageJobMemoryLimit = 10;
    private const uint JobMemory = 0x200;
    private const uint DieOnUnhandledException = 0x400;
    private const uint CreateNoWindow = 0x08000000;
    private const uint CreateUnicodeEnvironment = 0x400;
    private const uint HandleFlagInherit = 1;
    private static readonly IntPtr ProcThreadAttributeHandleList = 0x20002;

    [StructLayout(LayoutKind.Sequential)]
    private struct SECURITY_ATTRIBUTES { public int nLength; public IntPtr lpSecurityDescriptor; public bool bInheritHandle; }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern SafeFileHandle CreateIoCompletionPort(IntPtr file, IntPtr existingPort, UIntPtr key, uint threads);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetQueuedCompletionStatus(SafeFileHandle port, out uint bytes, out UIntPtr key, out IntPtr overlapped, uint milliseconds);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool QueryInformationJobObject(SafeFileHandle job, int infoClass, IntPtr info, uint length, out uint returned);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CreatePipe(out SafeFileHandle read, out SafeFileHandle write, ref SECURITY_ATTRIBUTES sa, uint size);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetHandleInformation(SafeFileHandle handle, uint mask, uint flags);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool CreateProcessW(string application, char[] commandLine, IntPtr processAttributes, IntPtr threadAttributes,
        bool inheritHandles, uint flags, string environment, string? currentDirectory, ref STARTUPINFOEX startupInfo, out PROCESS_INFORMATION info);
}
