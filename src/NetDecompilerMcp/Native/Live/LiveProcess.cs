using System.Buffers.Binary;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Native.Dump;
using NetDecompilerMcp.Native.Pe;

namespace NetDecompilerMcp.Native.Live;

/// <summary>A thread of the process as the system thread snapshot lists it.</summary>
public sealed record LiveThreadEntry(uint Id, int BasePriority);

/// <summary>What was read about one thread; fields that could not be read are null and <see cref="Error"/> says why.</summary>
public sealed record LiveThread(
    uint Id, string? Name, uint? SuspendCount, int? Priority, int? BasePriority, ulong? Teb, ulong? StartAddress,
    ulong? StackLow, ulong? StackHigh, DumpContext? Context, string? Error);

/// <summary>
/// A running Windows process read without changing it. The process handle has PROCESS_QUERY_INFORMATION |
/// PROCESS_VM_READ and nothing else; each thread is opened for one capture with THREAD_GET_CONTEXT |
/// THREAD_QUERY_INFORMATION and closed right after. Modules come from the loader list (EnumProcessModulesEx, which reads
/// the target's memory), regions from VirtualQueryEx, threads from the system thread snapshot (no handle to the target),
/// registers from GetThreadContext / Wow64GetThreadContext on the running thread (no suspension: a snapshot that may be
/// slightly stale for a thread running user code). Nothing is written, no thread is suspended, created or resumed, no
/// debugger is attached. Disposing closes the process handle; <see cref="HandlesOpened"/> and <see cref="HandlesClosed"/>
/// count every handle to the target.
/// </summary>
public sealed class LiveProcess : IProcessMemory, IDisposable
{
    /// <summary>The access mask of the process handle.</summary>
    public const uint ProcessAccess = LiveNative.PROCESS_QUERY_INFORMATION | LiveNative.PROCESS_VM_READ;
    /// <summary>The access mask of each thread handle.</summary>
    public const uint ThreadAccess = LiveNative.THREAD_GET_CONTEXT | LiveNative.THREAD_QUERY_INFORMATION;

    private const int MaxModules = MinidumpLimits.MaxModules;
    private const int Page = 0x1000;

    private readonly SafeKernelHandle _process;
    private readonly NativeArch _serverArch;
    private int _opened, _closed;
    private volatile bool _disposed;
    private List<DumpMemoryRegion>? _regions;

    private LiveProcess(SafeKernelHandle process, int pid, NativeArch serverArch)
    {
        _process = process;
        Pid = pid;
        _serverArch = serverArch;
    }

    public int Pid { get; }
    public string? ImagePath { get; private set; }
    public DateTime? StartTimeUtc { get; private set; }
    public NativeArch Arch { get; private set; }
    /// <summary>A 32-bit process on 64-bit Windows.</summary>
    public bool Wow64 { get; private set; }
    public bool Is64Bit => Arch is NativeArch.X64 or NativeArch.Arm64;
    public string Identity => $"live|{Pid}|{StartTimeUtc?.Ticks ?? 0}";
    public IReadOnlyList<DumpModule> Modules { get; private set; } = [];
    public IReadOnlyList<DumpUnloadedModule> UnloadedModules => [];
    /// <summary>Why the module list is incomplete, or null.</summary>
    public string? ModulesNote { get; private set; }
    public int HandlesOpened => Volatile.Read(ref _opened);
    public int HandlesClosed => Volatile.Read(ref _closed);
    /// <summary>Whether register contexts can be read from this server (same architecture, or a WoW64 target of an x64 server).</summary>
    public bool CanReadContexts => _serverArch == Arch || (_serverArch == NativeArch.X64 && Arch == NativeArch.X86 && Wow64);

    /// <summary>
    /// Opens the process for reading. Typed errors: provider_unavailable off Windows, not_found for no such process,
    /// access_denied, unsupported for a 64-bit process seen from a 32-bit server.
    /// </summary>
    public static LiveProcess Attach(int pid, CancellationToken ct = default)
    {
        if (!OperatingSystem.IsWindows())
            throw new ToolError(ErrorCode.ProviderUnavailable, "live process inspection uses the Windows process API; this server is not running on Windows.",
                "inspect a minidump instead (open_minidump), or run the server on Windows") { Details = new { reason = "platform_not_windows" } };
        if (pid <= 0) throw new ToolError(ErrorCode.InvalidArgument, $"{pid} is not a process id.", "pass a process id or a process name");
        if (pid == Environment.ProcessId)
            throw new ToolError(ErrorCode.InvalidArgument, "that is the server's own process.", "pass the id or name of another process");
        ct.ThrowIfCancellationRequested();
        var handle = LiveNative.OpenProcess(ProcessAccess, false, pid);
        if (handle.IsInvalid)
        {
            int error = Marshal.GetLastPInvokeError();
            handle.Dispose();
            throw error switch
            {
                LiveNative.ERROR_ACCESS_DENIED => new ToolError(ErrorCode.AccessDenied,
                    $"Windows denied read access to process {pid} (PROCESS_QUERY_INFORMATION | PROCESS_VM_READ): it runs as another user, elevated, or protected.",
                    "run the server as the same user with the same elevation as the target; protected processes (anti-malware, DRM, system) cannot be read")
                { Details = new { reason = "access_denied", pid } },
                LiveNative.ERROR_INVALID_PARAMETER => new ToolError(ErrorCode.NotFound, $"no running process has id {pid} (it may have exited).", "pass a running process id or a process name")
                { Details = new { reason = "process_not_found", pid } },
                _ => new ToolError(ErrorCode.Failed, $"cannot open process {pid}: {new Win32Exception(error).Message}"),
            };
        }
        var live = new LiveProcess(handle, pid, ServerArch());
        live._opened = 1;
        handle.Closed = () => Interlocked.Increment(ref live._closed);
        try
        {
            live.ReadIdentity();
            live.ReadModules(ct);
            return live;
        }
        catch
        {
            live.Dispose();
            throw;
        }
    }

    private static NativeArch ServerArch() => RuntimeInformation.ProcessArchitecture switch
    {
        Architecture.X64 => NativeArch.X64,
        Architecture.X86 => NativeArch.X86,
        Architecture.Arm64 => NativeArch.Arm64,
        Architecture.Arm => NativeArch.Arm,
        _ => NativeArch.Unknown,
    };

    private void ReadIdentity()
    {
        if (!LiveNative.GetExitCodeProcess(_process, out uint exit) || exit != LiveNative.STILL_ACTIVE)
            throw new ToolError(ErrorCode.NotFound, $"process {Pid} has exited.", "pass a running process") { Details = new { reason = "process_exited", pid = Pid } };
        var buffer = new char[32768];
        uint size = (uint)buffer.Length;
        if (LiveNative.QueryFullProcessImageName(_process, 0, buffer, ref size)) ImagePath = new string(buffer, 0, (int)size);
        if (LiveNative.GetProcessTimes(_process, out long created, out _, out _, out _) && created > 0)
            StartTimeUtc = DateTime.FromFileTimeUtc(created);
        ushort processMachine = 0, nativeMachine = 0;
        bool known;
        try { known = LiveNative.IsWow64Process2(_process, out processMachine, out nativeMachine); }
        catch (EntryPointNotFoundException) { known = false; }
        if (known)
        {
            Wow64 = processMachine != LiveNative.IMAGE_FILE_MACHINE_UNKNOWN;
            Arch = Machine(Wow64 ? processMachine : nativeMachine);
        }
        else
        {
            bool wow = LiveNative.IsWow64Process(_process, out bool w) && w;
            Wow64 = wow;
            Arch = wow ? NativeArch.X86 : Environment.Is64BitOperatingSystem ? NativeArch.X64 : NativeArch.X86;
        }
        if (_serverArch is NativeArch.X86 or NativeArch.Arm && Is64Bit)
            throw new ToolError(ErrorCode.Unsupported, $"process {Pid} is 64-bit and this server runs as a 32-bit process, which cannot read a 64-bit address space.",
                "run the 64-bit build of the server") { Details = new { reason = "bitness_mismatch", target = Arch.ToString(), server = _serverArch.ToString() } };
    }

    private static NativeArch Machine(ushort machine) => machine switch
    {
        LiveNative.IMAGE_FILE_MACHINE_I386 => NativeArch.X86,
        LiveNative.IMAGE_FILE_MACHINE_AMD64 => NativeArch.X64,
        LiveNative.IMAGE_FILE_MACHINE_ARM64 => NativeArch.Arm64,
        LiveNative.IMAGE_FILE_MACHINE_ARMNT => NativeArch.Arm,
        _ => NativeArch.Unknown,
    };

    /// <summary>Whether the process is still running (it may exit while it is read).</summary>
    public bool IsRunning => !_disposed && LiveNative.GetExitCodeProcess(_process, out uint exit) && exit == LiveNative.STILL_ACTIVE;

    private void ReadModules(CancellationToken ct)
    {
        var handles = new nint[1024];
        uint needed = 0;
        bool ok = false;
        // the loader list can change between calls: retry a few times with the size it asks for
        for (int attempt = 0; attempt < 4 && !ok; attempt++)
        {
            ok = LiveNative.EnumProcessModulesEx(_process, handles, (uint)(handles.Length * IntPtr.Size), out needed, LiveNative.LIST_MODULES_ALL);
            if (!ok) { System.Threading.Thread.Sleep(5); continue; }
            int count = (int)(needed / (uint)IntPtr.Size);
            if (count > handles.Length && count <= MaxModules) { handles = new nint[count + 16]; ok = false; }
        }
        if (!ok)
        {
            // a process that is still starting (no loader data yet), or one that just exited
            ModulesNote = $"the module list could not be read: {new Win32Exception(Marshal.GetLastPInvokeError()).Message}";
            return;
        }
        int n = Math.Min((int)(needed / (uint)IntPtr.Size), Math.Min(handles.Length, MaxModules));
        if (needed / (uint)IntPtr.Size > MaxModules) ModulesNote = $"only the first {MaxModules} modules are listed";
        var name = new char[32768];
        var modules = new List<DumpModule>(n);
        for (int i = 0; i < n; i++)
        {
            ct.ThrowIfCancellationRequested();
            if (!LiveNative.GetModuleInformation(_process, handles[i], out var info, (uint)Marshal.SizeOf<LiveNative.MODULEINFO>())) continue;
            uint len = LiveNative.GetModuleFileNameEx(_process, handles[i], name, (uint)name.Length);
            string path = len > 0 ? new string(name, 0, (int)len) : $"module_{(ulong)info.lpBaseOfDll:X}";
            ulong b = (ulong)info.lpBaseOfDll;
            var (stamp, checksum, codeView) = Header(b);
            modules.Add(new DumpModule(b, info.SizeOfImage, checksum, stamp, path, null, null, codeView));
        }
        modules.Sort((a, b) => a.Base.CompareTo(b.Base));
        Modules = modules;
    }

    /// <summary>TimeDateStamp, CheckSum and the CodeView record of a mapped image, from its headers in memory.</summary>
    private (uint Stamp, uint CheckSum, PeCodeView? CodeView) Header(ulong imageBase)
    {
        var head = new byte[Page];
        int n = ReadMemory(imageBase, head);
        if (!DumpImages.TryHeader(head.AsSpan(0, n), out uint stamp, out _, out _)) return (0, 0, null);
        int opt = (int)BinaryPrimitives.ReadUInt32LittleEndian(head.AsSpan(0x3C)) + 24;
        uint checksum = opt + 68 <= n ? BinaryPrimitives.ReadUInt32LittleEndian(head.AsSpan(opt + 64)) : 0;
        bool pe32Plus = BinaryPrimitives.ReadUInt16LittleEndian(head.AsSpan(opt)) == 0x20B;
        int debugDir = opt + (pe32Plus ? 112 : 96) + 6 * 8;
        if (debugDir + 8 > n) return (stamp, checksum, null);
        uint rva = BinaryPrimitives.ReadUInt32LittleEndian(head.AsSpan(debugDir)), size = BinaryPrimitives.ReadUInt32LittleEndian(head.AsSpan(debugDir + 4));
        var entry = new byte[28];
        for (uint at = 0; at + 28 <= size && at < 28 * 32; at += 28)
        {
            if (ReadMemory(imageBase + rva + at, entry) < 28) break;
            if (BinaryPrimitives.ReadUInt32LittleEndian(entry.AsSpan(12)) != 2) continue; // IMAGE_DEBUG_TYPE_CODEVIEW
            uint dataSize = BinaryPrimitives.ReadUInt32LittleEndian(entry.AsSpan(16)), dataRva = BinaryPrimitives.ReadUInt32LittleEndian(entry.AsSpan(20));
            var cv = new byte[Math.Min(dataSize, 0x400u)];
            int got = ReadMemory(imageBase + dataRva, cv);
            if (got >= 24 && BinaryPrimitives.ReadUInt32LittleEndian(cv) == 0x53445352) // "RSDS"
                return (stamp, checksum, new PeCodeView("RSDS", new Guid(cv.AsSpan(4, 16)), BinaryPrimitives.ReadUInt32LittleEndian(cv.AsSpan(20)), Utf8Z(cv.AsSpan(24, got - 24))));
        }
        return (stamp, checksum, null);
    }

    private static string Utf8Z(ReadOnlySpan<byte> b)
    {
        int end = b.IndexOf((byte)0);
        return Encoding.UTF8.GetString(end >= 0 ? b[..end] : b);
    }

    public DumpModule? ModuleAt(ulong address) => ProcessMemoryExtensions.ModuleAt(Modules, address);

    public int ReadMemory(ulong address, Span<byte> destination)
    {
        if (destination.IsEmpty || _disposed) return 0;
        if (TryRead(address, destination) == destination.Length) return destination.Length;
        // a range that crosses an unreadable page: page by page up to the first failure
        int done = 0;
        while (done < destination.Length)
        {
            ulong at = address + (ulong)done;
            int chunk = (int)Math.Min((ulong)(destination.Length - done), Page - (at & (Page - 1)));
            int n = TryRead(at, destination.Slice(done, chunk));
            done += n;
            if (n < chunk) break;
        }
        return done;
    }

    private int TryRead(ulong address, Span<byte> destination)
    {
        if (address > (ulong)nint.MaxValue || address + (ulong)destination.Length < address) return 0;
        try
        {
            return LiveNative.ReadProcessMemory(_process, (nint)address, ref MemoryMarshal.GetReference(destination), destination.Length, out nint read)
                ? (int)read : 0;
        }
        catch (ObjectDisposedException) { return 0; }
    }

    /// <summary>The address space (VirtualQueryEx), read once and cached; bounded by <see cref="MinidumpLimits.MaxMemoryRegions"/>.</summary>
    public IReadOnlyList<DumpMemoryRegion> Regions(CancellationToken ct = default)
    {
        if (_regions != null) return _regions;
        var list = new List<DumpMemoryRegion>();
        ulong address = 0;
        while (list.Count < MinidumpLimits.MaxMemoryRegions && !_disposed)
        {
            if ((list.Count & 0xFF) == 0) ct.ThrowIfCancellationRequested();
            if (address > (ulong)nint.MaxValue) break;
            DumpMemoryRegion region;
            if (IntPtr.Size == 8)
            {
                if (LiveNative.VirtualQueryEx64(_process, (nint)address, out var m, Marshal.SizeOf<LiveNative.MEMORY_BASIC_INFORMATION64>()) == 0) break;
                region = new DumpMemoryRegion(m.BaseAddress, m.AllocationBase, m.AllocationProtect, m.RegionSize, m.State, m.Protect, m.Type);
            }
            else
            {
                if (LiveNative.VirtualQueryEx32(_process, (nint)address, out var m, Marshal.SizeOf<LiveNative.MEMORY_BASIC_INFORMATION32>()) == 0) break;
                region = new DumpMemoryRegion(m.BaseAddress, m.AllocationBase, m.AllocationProtect, m.RegionSize, m.State, m.Protect, m.Type);
            }
            if (region.Size == 0 || region.Base + region.Size <= address) break;
            list.Add(region);
            address = region.Base + region.Size;
        }
        return _regions = list;
    }

    public DumpMemoryRegion? RegionAt(ulong address) => ProcessMemoryExtensions.RegionAt(Regions(), address);

    /// <summary>A mapped module is readable throughout as far as the stack walker is concerned; unreadable pages read as missing.</summary>
    public ulong ReadableExtent(ulong start, ulong size) => size;

    /// <summary>The process's threads from the system thread snapshot (CreateToolhelp32Snapshot TH32CS_SNAPTHREAD), sorted by id.</summary>
    public IReadOnlyList<LiveThreadEntry> Threads(CancellationToken ct = default)
    {
        var list = new List<LiveThreadEntry>();
        using var snapshot = LiveNative.CreateToolhelp32Snapshot(LiveNative.TH32CS_SNAPTHREAD, 0);
        if (snapshot.IsInvalid) return list;
        var entry = new LiveNative.THREADENTRY32 { dwSize = (uint)Marshal.SizeOf<LiveNative.THREADENTRY32>() };
        for (bool more = LiveNative.Thread32First(snapshot, ref entry); more && list.Count < MinidumpLimits.MaxThreads; more = LiveNative.Thread32Next(snapshot, ref entry))
        {
            if ((list.Count & 0xFF) == 0) ct.ThrowIfCancellationRequested();
            if (entry.th32OwnerProcessID == (uint)Pid) list.Add(new LiveThreadEntry(entry.th32ThreadID, entry.tpBasePri));
        }
        list.Sort((a, b) => a.Id.CompareTo(b.Id));
        return list;
    }

    /// <summary>Opens one thread (THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION), reads it, and closes the handle.</summary>
    public LiveThread ReadThread(uint id, bool context)
    {
        if (_disposed) return new LiveThread(id, null, null, null, null, null, null, null, null, null, "the process handle is closed");
        using var thread = LiveNative.OpenThread(ThreadAccess, false, id);
        if (thread.IsInvalid)
        {
            int error = Marshal.GetLastPInvokeError();
            return new LiveThread(id, null, null, null, null, null, null, null, null, null,
                error == LiveNative.ERROR_INVALID_PARAMETER ? "the thread has exited" : $"cannot open the thread: {new Win32Exception(error).Message}");
        }
        Interlocked.Increment(ref _opened);
        thread.Closed = () => Interlocked.Increment(ref _closed);
        string? error2 = null;
        ulong? teb = null;
        int? priority = null, basePriority = null;
        if (LiveNative.NtQueryInformationThread(thread, LiveNative.ThreadBasicInformation, out LiveNative.THREAD_BASIC_INFORMATION basic,
                (uint)Marshal.SizeOf<LiveNative.THREAD_BASIC_INFORMATION>(), out _) >= 0)
        {
            teb = (ulong)basic.TebBaseAddress;
            priority = basic.Priority;
            basePriority = basic.BasePriority;
        }
        ulong? start = LiveNative.NtQueryInformationThread(thread, LiveNative.ThreadQuerySetWin32StartAddress, out nint s, (uint)IntPtr.Size, out _) >= 0 ? (ulong)s : null;
        uint? suspend = LiveNative.NtQueryInformationThread(thread, LiveNative.ThreadSuspendCount, out uint sc, 4, out _) >= 0 ? sc : null;
        string? name = null;
        try
        {
            if (LiveNative.GetThreadDescription(thread, out nint text) >= 0 && text != 0)
            {
                name = Marshal.PtrToStringUni(text);
                LiveNative.LocalFree(text);
                if (string.IsNullOrEmpty(name)) name = null;
            }
        }
        catch (EntryPointNotFoundException) { }
        var (low, high) = teb is { } t ? StackBounds(t) : (null, null);
        DumpContext? ctx = null;
        if (context)
        {
            if (!CanReadContexts) error2 = $"registers of a {Arch} process are not read by a {_serverArch} server";
            else
            {
                ctx = Context(thread, out string? why);
                error2 = why;
            }
        }
        return new LiveThread(id, name, suspend, priority, basePriority, teb, start, low, high, ctx, error2);
    }

    /// <summary>
    /// The stack range from the thread's TEB (NT_TIB StackLimit..StackBase). A WoW64 thread's 32-bit TEB follows its
    /// 64-bit one (WowTebOffset, else +0x2000).
    /// </summary>
    private (ulong?, ulong?) StackBounds(ulong teb)
    {
        if (Wow64 && IntPtr.Size == 8)
        {
            ulong teb32 = teb + 0x2000;
            if (this.TryReadU32(teb + 0x180C, out uint offset) && offset is > 0 and < 0x10000) teb32 = teb + offset;
            return this.TryReadU32(teb32 + 4, out uint b32) && this.TryReadU32(teb32 + 8, out uint l32) && l32 < b32 ? (l32, b32) : (null, null);
        }
        if (IntPtr.Size == 8)
            return this.TryReadU64(teb + 8, out ulong b) && this.TryReadU64(teb + 16, out ulong l) && l < b ? (l, b) : (null, null);
        return this.TryReadU32(teb + 4, out uint b4) && this.TryReadU32(teb + 8, out uint l4) && l4 < b4 ? (l4, b4) : (null, null);
    }

    /// <summary>GetThreadContext (or Wow64GetThreadContext) into an aligned buffer, parsed like a dump's CONTEXT.</summary>
    private DumpContext? Context(SafeKernelHandle thread, out string? error)
    {
        error = null;
        bool wow = Wow64 && _serverArch == NativeArch.X64;
        var arch = Arch;
        int size; int flagsAt; uint flags;
        switch (wow ? NativeArch.X86 : arch)
        {
            case NativeArch.X64: size = 0x4D0; flagsAt = 0x30; flags = 0x10000F; break; // CONTEXT_AMD64 | CONTROL | INTEGER | SEGMENTS | FLOATING_POINT
            case NativeArch.X86: size = 0x2CC; flagsAt = 0; flags = 0x10007; break;     // CONTEXT_i386 | CONTROL | INTEGER | SEGMENTS
            case NativeArch.Arm64: size = 0x390; flagsAt = 0; flags = 0x400003; break;   // CONTEXT_ARM64 | CONTROL | INTEGER
            default: error = $"no register layout for {arch}"; return null;
        }
        nint raw = Marshal.AllocHGlobal(size + 16);
        try
        {
            nint aligned = (raw + 15) & ~(nint)15;
            var zero = new byte[size];
            BinaryPrimitives.WriteUInt32LittleEndian(zero.AsSpan(flagsAt), flags);
            Marshal.Copy(zero, 0, aligned, size);
            bool ok = wow ? LiveNative.Wow64GetThreadContext(thread, aligned) : LiveNative.GetThreadContext(thread, aligned);
            if (!ok)
            {
                error = $"registers not read: {new Win32Exception(Marshal.GetLastPInvokeError()).Message}";
                return null;
            }
            var bytes = new byte[size];
            Marshal.Copy(aligned, bytes, 0, size);
            return DumpContext.Parse(arch, bytes);
        }
        finally { Marshal.FreeHGlobal(raw); }
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _process.Dispose();
    }
}
