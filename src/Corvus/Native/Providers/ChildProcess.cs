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
    /// <summary>Applies <see cref="MemoryLimitBytes"/> off Windows too: RLIMIT_DATA on Linux, a footprint watchdog on macOS; when off, no limit applies there, as for engine workers.</summary>
    public bool MemoryLimitOnPosix { get; init; }
}

/// <summary>A child process with redirected stdio whose tree ends on <see cref="Kill"/>, <see cref="Dispose"/> or this process's exit (Windows job object; elsewhere a watching shell).</summary>
/// <remarks>On Windows the process starts suspended in a KILL_ON_JOB_CLOSE job, so it cannot start a child outside the
/// job. Elsewhere the shell kills the child's group within a second of this process ending, even when killed outright.</remarks>
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

    /// <summary>User plus kernel CPU time of the running tree processes (can fall when one exits); null when none could be read.</summary>
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

    /// <summary>Kills the process tree and waits up to <see cref="TreeExitWait"/> for every process of it to exit.</summary>
    public abstract void Dispose();

    /// <summary>How long <see cref="Dispose"/> waits for the killed tree; a tree still running then is reported on stderr.</summary>
    internal static readonly TimeSpan TreeExitWait = TimeSpan.FromSeconds(10);

    /// <summary>Writes the stderr warning for a tree still running <paramref name="waited"/> after it was killed.</summary>
    private protected static void ReportTreeRunning(int id, TimeSpan waited) =>
        Console.Error.WriteLine($"Process tree {id} still running {waited.TotalSeconds:0.0} s after kill; its files may stay open.");

    /// <summary>Starts <paramref name="start"/>; a bare program name is found as <see cref="ProgramPath"/> finds it; throws Win32Exception when it is not found or relative.</summary>
    public static ChildProcess Start(ChildProcessStart start)
    {
        var path = start.Environment.TryGetValue("PATH", out var p) && p != null ? p : Environment.GetEnvironmentVariable("PATH");
        start = start with { FileName = ProgramPath(start.FileName, path) };
        ChildProcess child = OperatingSystem.IsWindows() ? WindowsJobProcess.Launch(start) : PosixGroupProcess.Launch(start);
        Running[child] = (Path.GetFileName(start.FileName), DateTimeOffset.UtcNow);
        child.Exited.ContinueWith(_ => Running.TryRemove(child, out var _), CancellationToken.None, TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
        return child;
    }

    private static readonly System.Collections.Concurrent.ConcurrentDictionary<ChildProcess, (string Program, DateTimeOffset Started)> Running = new();

    /// <summary>The full path of <paramref name="name"/>: kept when fully qualified; a bare name is looked up in this program's folder,
    /// then in the fully qualified entries of <paramref name="path"/> (with PATHEXT on Windows); throws Win32Exception for a relative path or no match.</summary>
    /// <remarks>The current folder is never searched: Windows CreateProcess completes a bare application name against it.</remarks>
    internal static string ProgramPath(string name, string? path)
    {
        if (Path.IsPathFullyQualified(name)) return name;
        if (name.IndexOfAny(['/', '\\']) >= 0 || Path.IsPathRooted(name))
            throw new Win32Exception(2, $"An error occurred trying to start process '{name}': a relative program path is not started");
        string[] extensions = OperatingSystem.IsWindows() && !Path.HasExtension(name)
            ? ["", .. (Environment.GetEnvironmentVariable("PATHEXT") ?? ".COM;.EXE;.BAT;.CMD").Split(';', StringSplitOptions.RemoveEmptyEntries)]
            : [""];
        var folders = new[] { Path.GetDirectoryName(Environment.ProcessPath) }.Concat((path ?? "").Split(Path.PathSeparator))
            .Where(d => !string.IsNullOrEmpty(d) && Path.IsPathFullyQualified(d));
        return folders.SelectMany(d => extensions.Select(e => Path.Combine(d!, name + e))).FirstOrDefault(File.Exists)
               ?? throw new Win32Exception(2, $"An error occurred trying to start process '{name}': No such file or directory");
    }

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

    /// <summary>True when the readers reach end of output (the whole tree closed it) within <paramref name="timeout"/> of <paramref name="started"/>.</summary>
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
        // macOS enforces neither RLIMIT_DATA nor RLIMIT_AS, so a thread of its own reads the footprint; a starved
        // pool would read it late.
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

    /// <summary>Runs "$@" as a process group leader with this shell as parent, so its id is not reused while watched; prints its id first and kills the group once process $1 is gone.</summary>
    // Stdin goes through fd 3, as a non-interactive shell's background jobs read /dev/null; the child's stderr goes
    // through fd 4; a non-empty CORVUS_CHILD_DATA_KB sets RLIMIT_DATA and is not passed on.
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
        var path = start.FileName;
        if (!File.Exists(path)) throw new Win32Exception(2, $"An error occurred trying to start process '{name}': No such file or directory");
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
            // A group keeps its id while members remain, so the group kill is safe after the worker ended.
            _ = SysKill(-_workerId, 9);
            if (!HasExited) _ = SysKill(_workerId, 9);
        }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException) { }
        try { _process.Kill(entireProcessTree: true); } catch (Exception ex) when (ex is InvalidOperationException or Win32Exception) { }
    }

    /// <summary>True while a process of the worker's group runs; false when none or unknown. Linux skips zombies, which a container without init never reaps.</summary>
    private bool GroupRunning()
    {
        if (OperatingSystem.IsLinux())
        {
            try
            {
                foreach (var dir in Directory.EnumerateDirectories("/proc"))
                {
                    if (!int.TryParse(Path.GetFileName(dir), out _)) continue;
                    string stat;
                    try { stat = File.ReadAllText(Path.Combine(dir, "stat")); }
                    catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { continue; }
                    // Fields after the command: state, parent, process group.
                    var fields = stat[(stat.LastIndexOf(')') + 2)..].Split(' ');
                    if (fields.Length > 2 && fields[0] != "Z" && fields[2] == _workerId.ToString(System.Globalization.CultureInfo.InvariantCulture)) return true;
                }
                return false;
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return false; }
        }
        try { return SysKill(-_workerId, 0) == 0; }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException) { return false; }
    }

    public override void Dispose()
    {
        Kill();
        lock (_gate)
        {
            if (_disposed) return;
            // Process throws once disposed, so the exit is kept for callers that still ask.
            var clock = Stopwatch.StartNew();
            _disposedExited = _process.WaitForExit(TreeExitWait);
            // Other group members exit on their own time after the same signal.
            while (GroupRunning() && clock.Elapsed < TreeExitWait) Thread.Sleep(20);
            if (!_disposedExited || GroupRunning()) ReportTreeRunning(_workerId, clock.Elapsed);
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
    // Read before the process handle closes, so a caller asking after Dispose still gets it.
    private long _exitCode = long.MinValue;

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
            if (GetExitCodeProcess(_processHandle, out var code)) Interlocked.Exchange(ref _exitCode, unchecked((int)code));
            _exited.TrySetResult();
            ReleaseHandles();
        }) { IsBackground = true, Name = "child exit " + id }.Start();
        if (port != null) new Thread(() => WatchMemoryLimit(port)) { IsBackground = true, Name = "child memory " + id }.Start();
    }

    // A worker whose allocations fail can hang, so the job ends at the limit (CI on 48563dd9: 60 s timeout, not limit_exceeded).
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
    public override bool HasExited => _exited.Task.IsCompleted || LiveExitCode() != null;

    public override int? ExitCode => Interlocked.Read(ref _exitCode) is var c && c != long.MinValue ? (int)c : LiveExitCode();

    /// <summary>The exit code read from the handle; null while running or once the handle is closed.</summary>
    private int? LiveExitCode()
    {
        try { return GetExitCodeProcess(_processHandle, out var code) && code != StillActive ? unchecked((int)code) : null; }
        catch (ObjectDisposedException) { return null; }
    }

    // The job's accounting keeps the time of processes that already exited, so it never falls.
    public override TimeSpan? TreeCpuTime()
    {
        if (_job.IsClosed) return null;
        // JOBOBJECT_BASIC_ACCOUNTING_INFORMATION: exactly 48 bytes; TotalUserTime and TotalKernelTime first, in 100 ns.
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
        // Drains JOB_OBJECT_MSG_JOB_MEMORY_LIMIT here too, so a death seen before the watcher wakes names the limit.
        lock (port)
            while (!_limitHit && GetQueuedCompletionStatus(port, out var message, out _, out _, 0))
                _limitHit = message == JobMessageJobMemoryLimit;
        return _limitHit ? limit : null;
    }

    public override void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
        Kill();
        // Termination is asynchronous: wait for the job so its files are closed before the caller reuses them.
        var clock = Stopwatch.StartNew();
        var exited = _waitHandle.WaitOne(TreeExitWait);
        if (exited) _exited.TrySetResult();
        while (exited && ActiveProcesses() > 0 && clock.Elapsed < TreeExitWait) Thread.Sleep(20);
        if (!exited || ActiveProcesses() > 0) ReportTreeRunning(_id, clock.Elapsed);
        // KILL_ON_JOB_CLOSE: anything left in the job dies here.
        _job.Dispose();
        if (_port != null) lock (_port) _port.Dispose();
        foreach (var s in new Stream[] { _stdin, _stdout, _stderr })
        {
            try { s.Dispose(); } catch (IOException) { }
        }
        ReleaseHandles();
    }

    /// <summary>Processes of the job not yet exited (JOBOBJECT_BASIC_ACCOUNTING_INFORMATION.ActiveProcesses); 0 when it cannot be read.</summary>
    private int ActiveProcesses()
    {
        if (_job.IsClosed) return 0;
        const int size = 48;
        var buffer = Marshal.AllocHGlobal(size);
        try { return QueryInformationJobObject(_job, JobObjectBasicAccountingInformation, buffer, size, out _) ? Marshal.ReadInt32(buffer, 40) : 0; }
        finally { Marshal.FreeHGlobal(buffer); }
    }

    private void ReleaseHandles()
    {
        if (Interlocked.Decrement(ref _handleUsers) != 0) return;
        _waitHandle.Dispose();
        _processHandle.Dispose();
    }

    /// <summary>Process.Start's private create lock (own lock if renamed), so its child never inherits our inheritable pipe ends.</summary>
    internal static readonly object CreateLock =
        typeof(Process).GetField("s_createProcessLock", System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static)?.GetValue(null) ?? new object();

    /// <summary>Test hook: runs while the child ends are inheritable.</summary>
    internal static Action<ChildProcessStart>? PipesCreated;

    /// <summary>Test hook: runs on the launching thread just before the child's exit thread starts.</summary>
    internal static Action<int>? ExitThreadStarting;

    public static WindowsJobProcess Launch(ChildProcessStart start)
    {
        // Lock only while child ends are inheritable: starting the exit thread took up to 0.6 s on a loaded machine.
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

            // Inherit only the three child pipe ends, not the MCP stdio transport's pipes.
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
