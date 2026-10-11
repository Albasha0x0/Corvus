using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace NetDecompilerMcp.Native.Providers;

/// <summary>What to run: executable, arguments (quoted as needed) and environment overrides (null value removes).</summary>
public sealed record ChildProcessStart(string FileName, IReadOnlyList<string> Arguments)
{
    public string? WorkingDirectory { get; init; }
    public IReadOnlyDictionary<string, string?> Environment { get; init; } = new Dictionary<string, string?>();
    /// <summary>Most committed memory of the whole tree in bytes (Windows: the job's limit; allocations past it fail); null: none.</summary>
    public long? MemoryLimitBytes { get; init; }
}

/// <summary>
/// A child process with redirected stdio whose whole process tree is stopped by <see cref="Kill"/> and by
/// <see cref="Dispose"/>. On Windows the process is created suspended inside a Job Object with
/// JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, so it cannot start a child outside the job, and the tree also dies when this
/// process exits for any reason (the job handle is closed by the OS). Elsewhere the child is expected to call
/// setsid() (the workers do) and the process group is killed.
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
    public abstract void Dispose();

    public static ChildProcess Start(ChildProcessStart start) =>
        OperatingSystem.IsWindows() ? WindowsJobProcess.Launch(start) : PosixGroupProcess.Launch(start);

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

    private PosixGroupProcess(Process process)
    {
        _process = process;
        _exited = process.WaitForExitAsync();
    }

    public static PosixGroupProcess Launch(ChildProcessStart start)
    {
        var psi = new ProcessStartInfo(start.FileName)
        {
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
            WorkingDirectory = start.WorkingDirectory ?? "",
        };
        foreach (var a in start.Arguments) psi.ArgumentList.Add(a);
        foreach (var (k, v) in start.Environment)
        {
            if (v == null) psi.Environment.Remove(k);
            else psi.Environment[k] = v;
        }
        return new PosixGroupProcess(Process.Start(psi) ?? throw new Win32Exception("process did not start"));
    }

    public override int Id => _process.Id;
    public override Stream StandardInput => _process.StandardInput.BaseStream;
    public override Stream StandardOutput => _process.StandardOutput.BaseStream;
    public override Stream StandardError => _process.StandardError.BaseStream;
    public override bool HasExited => _process.HasExited;
    public override int? ExitCode => _process.HasExited ? _process.ExitCode : null;
    public override Task Exited => _exited;
    public override IReadOnlyList<int> TreeProcessIds() => _process.HasExited ? [] : [_process.Id];

    [DllImport("libc", EntryPoint = "kill", SetLastError = true)]
    private static extern int SysKill(int pid, int signal);

    public override void Kill()
    {
        try { _ = SysKill(-_process.Id, 9); } catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException) { }
        try { _process.Kill(entireProcessTree: true); } catch (Exception ex) when (ex is InvalidOperationException or Win32Exception) { }
    }

    public override void Dispose()
    {
        Kill();
        _process.Dispose();
    }
}

internal sealed class WindowsJobProcess : ChildProcess
{
    private readonly SafeFileHandle _job;
    private readonly SafeProcessHandle _processHandle;
    private readonly int _id;
    private readonly FileStream _stdin, _stdout, _stderr;
    private readonly TaskCompletionSource _exited = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly RegisteredWaitHandle _wait;
    private readonly ProcessWaitHandle _waitHandle;
    private int _disposed;

    private readonly long? _memoryLimit;
    private readonly SafeFileHandle? _port;
    private bool _limitHit;

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
        _wait = ThreadPool.RegisterWaitForSingleObject(_waitHandle, (_, _) => _exited.TrySetResult(), null, Timeout.Infinite, executeOnlyOnce: true);
    }

    public override int Id => _id;
    public override Stream StandardInput => _stdin;
    public override Stream StandardOutput => _stdout;
    public override Stream StandardError => _stderr;
    public override Task Exited => _exited.Task;
    public override bool HasExited => _exited.Task.IsCompleted || (GetExitCodeProcess(_processHandle, out var c) && c != StillActive);

    public override int? ExitCode => GetExitCodeProcess(_processHandle, out var code) && code != StillActive ? unchecked((int)code) : null;

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
        // the job posts JOB_OBJECT_MSG_JOB_MEMORY_LIMIT when an allocation would pass the limit (and fails)
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
        // Termination is asynchronous; observe the exit before the wait registration goes away.
        if (_waitHandle.WaitOne(2000)) _exited.TrySetResult();
        _wait.Unregister(null);
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

    public static WindowsJobProcess Launch(ChildProcessStart start)
    {
        lock (CreateLock) return LaunchLocked(start);
    }

    private static WindowsJobProcess LaunchLocked(ChildProcessStart start)
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
            var child = new WindowsJobProcess(job, process, GetProcessId(process), inWrite, outRead, errRead, start.MemoryLimitBytes is > 0 ? start.MemoryLimitBytes : null, port);
            inWrite = outRead = errRead = null;
            return child;
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

    private sealed class ProcessWaitHandle : WaitHandle
    {
        public ProcessWaitHandle(SafeProcessHandle process) => SafeWaitHandle = new SafeWaitHandle(process.DangerousGetHandle(), ownsHandle: false);
    }

    private const uint StillActive = 259;
    private const int JobObjectBasicProcessIdList = 3;
    private const int JobObjectExtendedLimitInformation = 9;
    private const int JobObjectAssociateCompletionPortInformation = 7;
    private const uint JobMessageJobMemoryLimit = 10;
    private const uint KillOnJobClose = 0x2000;
    private const uint JobMemory = 0x200;
    private const uint DieOnUnhandledException = 0x400;
    private const uint CreateSuspended = 0x4;
    private const uint CreateNoWindow = 0x08000000;
    private const uint CreateUnicodeEnvironment = 0x400;
    private const uint ExtendedStartupInfoPresent = 0x80000;
    private const int StartfUseStdHandles = 0x100;
    private const uint HandleFlagInherit = 1;
    private static readonly IntPtr ProcThreadAttributeHandleList = 0x20002;

    [StructLayout(LayoutKind.Sequential)]
    private struct SECURITY_ATTRIBUTES { public int nLength; public IntPtr lpSecurityDescriptor; public bool bInheritHandle; }

    [StructLayout(LayoutKind.Sequential)]
    private struct JOBOBJECT_BASIC_LIMIT_INFORMATION
    {
        public long PerProcessUserTimeLimit, PerJobUserTimeLimit;
        public uint LimitFlags;
        public UIntPtr MinimumWorkingSetSize, MaximumWorkingSetSize;
        public uint ActiveProcessLimit;
        public UIntPtr Affinity;
        public uint PriorityClass, SchedulingClass;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct IO_COUNTERS { public ulong ReadOperationCount, WriteOperationCount, OtherOperationCount, ReadTransferCount, WriteTransferCount, OtherTransferCount; }

    [StructLayout(LayoutKind.Sequential)]
    private struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION
    {
        public JOBOBJECT_BASIC_LIMIT_INFORMATION BasicLimitInformation;
        public IO_COUNTERS IoInfo;
        public UIntPtr ProcessMemoryLimit, JobMemoryLimit, PeakProcessMemoryUsed, PeakJobMemoryUsed;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct STARTUPINFO
    {
        public int cb;
        public string? lpReserved, lpDesktop, lpTitle;
        public int dwX, dwY, dwXSize, dwYSize, dwXCountChars, dwYCountChars, dwFillAttribute, dwFlags;
        public short wShowWindow, cbReserved2;
        public IntPtr lpReserved2, hStdInput, hStdOutput, hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct STARTUPINFOEX { public STARTUPINFO StartupInfo; public IntPtr lpAttributeList; }

    [StructLayout(LayoutKind.Sequential)]
    private struct PROCESS_INFORMATION { public IntPtr hProcess, hThread; public int dwProcessId, dwThreadId; }

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern SafeFileHandle CreateJobObjectW(IntPtr attributes, string? name);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetInformationJobObject(SafeFileHandle job, int infoClass, ref JOBOBJECT_EXTENDED_LIMIT_INFORMATION info, uint length);

    [StructLayout(LayoutKind.Sequential)]
    private struct JOBOBJECT_ASSOCIATE_COMPLETION_PORT { public IntPtr CompletionKey, CompletionPort; }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetInformationJobObject(SafeFileHandle job, int infoClass, ref JOBOBJECT_ASSOCIATE_COMPLETION_PORT info, uint length);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern SafeFileHandle CreateIoCompletionPort(IntPtr file, IntPtr existingPort, UIntPtr key, uint threads);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetQueuedCompletionStatus(SafeFileHandle port, out uint bytes, out UIntPtr key, out IntPtr overlapped, uint milliseconds);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool QueryInformationJobObject(SafeFileHandle job, int infoClass, IntPtr info, uint length, out uint returned);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool AssignProcessToJobObject(SafeFileHandle job, SafeProcessHandle process);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool TerminateJobObject(SafeFileHandle job, uint exitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool TerminateProcess(SafeProcessHandle process, uint exitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CreatePipe(out SafeFileHandle read, out SafeFileHandle write, ref SECURITY_ATTRIBUTES sa, uint size);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetHandleInformation(SafeFileHandle handle, uint mask, uint flags);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool InitializeProcThreadAttributeList(IntPtr list, int count, int flags, ref IntPtr size);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool UpdateProcThreadAttribute(IntPtr list, uint flags, IntPtr attribute, IntPtr value, IntPtr size, IntPtr previous, IntPtr returnSize);

    [DllImport("kernel32.dll")]
    private static extern void DeleteProcThreadAttributeList(IntPtr list);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool CreateProcessW(string application, char[] commandLine, IntPtr processAttributes, IntPtr threadAttributes,
        bool inheritHandles, uint flags, string environment, string? currentDirectory, ref STARTUPINFOEX startupInfo, out PROCESS_INFORMATION info);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint ResumeThread(SafeFileHandle thread);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern int GetProcessId(SafeProcessHandle process);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetExitCodeProcess(SafeProcessHandle process, out uint exitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);
}
