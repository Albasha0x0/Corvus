using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace Corvus.Native.Live;

/// <summary>A kernel handle closed with CloseHandle; <see cref="Closed"/> runs once when it is.</summary>
internal sealed class SafeKernelHandle : SafeHandleZeroOrMinusOneIsInvalid
{
    public SafeKernelHandle() : base(true) { }

    public Action? Closed { get; set; }

    protected override bool ReleaseHandle()
    {
        bool ok = LiveNative.CloseHandle(handle);
        Closed?.Invoke();
        return ok;
    }
}

/// <summary>
/// The Win32 calls live inspection makes. Every one of them only queries or reads: there is no entry point here that
/// writes memory, changes protection, suspends, resumes or creates threads, or debugs (see docs/live-inspection.md).
/// </summary>
internal static class LiveNative
{
    // Access rights: the only ones ever requested.
    public const uint PROCESS_VM_READ = 0x0010;
    public const uint PROCESS_QUERY_INFORMATION = 0x0400;
    public const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
    public const uint SYNCHRONIZE = 0x00100000;
    public const uint THREAD_GET_CONTEXT = 0x0008;
    public const uint THREAD_QUERY_INFORMATION = 0x0040;

    public const int ERROR_ACCESS_DENIED = 5;
    public const int ERROR_INVALID_PARAMETER = 87;
    public const uint STILL_ACTIVE = 259;

    public const uint TH32CS_SNAPTHREAD = 0x4;
    public const uint LIST_MODULES_ALL = 0x3;

    public const ushort IMAGE_FILE_MACHINE_UNKNOWN = 0;
    public const ushort IMAGE_FILE_MACHINE_I386 = 0x014C;
    public const ushort IMAGE_FILE_MACHINE_ARMNT = 0x01C4;
    public const ushort IMAGE_FILE_MACHINE_AMD64 = 0x8664;
    public const ushort IMAGE_FILE_MACHINE_ARM64 = 0xAA64;

    public const int ThreadBasicInformation = 0;
    public const int ThreadQuerySetWin32StartAddress = 9;
    public const int ThreadSuspendCount = 35;

    [StructLayout(LayoutKind.Sequential)]
    public struct MEMORY_BASIC_INFORMATION64
    {
        public ulong BaseAddress, AllocationBase;
        public uint AllocationProtect;
        public ushort PartitionId;
        public ushort Alignment1;
        public ulong RegionSize;
        public uint State, Protect, Type, Alignment2;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct MEMORY_BASIC_INFORMATION32
    {
        public uint BaseAddress, AllocationBase, AllocationProtect, RegionSize, State, Protect, Type;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct MODULEINFO { public nint lpBaseOfDll; public uint SizeOfImage; public nint EntryPoint; }

    [StructLayout(LayoutKind.Sequential)]
    public struct THREADENTRY32 { public uint dwSize, cntUsage, th32ThreadID, th32OwnerProcessID; public int tpBasePri, tpDeltaPri; public uint dwFlags; }

    [StructLayout(LayoutKind.Sequential)]
    public struct THREAD_BASIC_INFORMATION { public int ExitStatus; public nint TebBaseAddress, UniqueProcess, UniqueThread, AffinityMask; public int Priority, BasePriority; }

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(nint handle);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern SafeKernelHandle OpenProcess(uint access, bool inherit, int processId);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern uint WaitForSingleObject(SafeKernelHandle handle, uint milliseconds);

    // A file or folder opened with no access, only to ask for its final path (links and short names resolved).
    public const uint FILE_SHARE_ALL = 0x7;
    public const uint OPEN_EXISTING = 3;
    public const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "CreateFileW")]
    public static extern SafeFileHandle OpenForQuery(string path, uint access, uint share, nint security, uint disposition, uint flags, nint template);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "GetFinalPathNameByHandleW")]
    public static extern uint GetFinalPathNameByHandle(SafeFileHandle file, [Out] char[] path, uint size, uint flags);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern SafeKernelHandle OpenThread(uint access, bool inherit, uint threadId);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool ReadProcessMemory(SafeKernelHandle process, nint address, ref byte buffer, nint size, out nint read);

    [DllImport("kernel32.dll", SetLastError = true, EntryPoint = "VirtualQueryEx")]
    public static extern nint VirtualQueryEx64(SafeKernelHandle process, nint address, out MEMORY_BASIC_INFORMATION64 info, nint length);

    [DllImport("kernel32.dll", SetLastError = true, EntryPoint = "VirtualQueryEx")]
    public static extern nint VirtualQueryEx32(SafeKernelHandle process, nint address, out MEMORY_BASIC_INFORMATION32 info, nint length);

    [DllImport("kernel32.dll", SetLastError = true, EntryPoint = "K32EnumProcessModulesEx")]
    public static extern bool EnumProcessModulesEx(SafeKernelHandle process, [Out] nint[] modules, uint bytes, out uint needed, uint filter);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "K32GetModuleFileNameExW")]
    public static extern uint GetModuleFileNameEx(SafeKernelHandle process, nint module, [Out] char[] name, uint size);

    [DllImport("kernel32.dll", SetLastError = true, EntryPoint = "K32GetModuleInformation")]
    public static extern bool GetModuleInformation(SafeKernelHandle process, nint module, out MODULEINFO info, uint size);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool IsWow64Process2(SafeKernelHandle process, out ushort processMachine, out ushort nativeMachine);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool IsWow64Process(SafeKernelHandle process, out bool wow64);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode, EntryPoint = "QueryFullProcessImageNameW")]
    public static extern bool QueryFullProcessImageName(SafeKernelHandle process, uint flags, [Out] char[] name, ref uint size);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool GetProcessTimes(SafeKernelHandle process, out long creation, out long exit, out long kernel, out long user);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool GetExitCodeProcess(SafeKernelHandle process, out uint exitCode);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern SafeKernelHandle CreateToolhelp32Snapshot(uint flags, uint processId);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool Thread32First(SafeKernelHandle snapshot, ref THREADENTRY32 entry);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool Thread32Next(SafeKernelHandle snapshot, ref THREADENTRY32 entry);

    [DllImport("ntdll.dll")]
    public static extern int NtQueryInformationThread(SafeKernelHandle thread, int infoClass, out THREAD_BASIC_INFORMATION info, uint length, out uint returned);

    [DllImport("ntdll.dll")]
    public static extern int NtQueryInformationThread(SafeKernelHandle thread, int infoClass, out nint info, uint length, out uint returned);

    [DllImport("ntdll.dll")]
    public static extern int NtQueryInformationThread(SafeKernelHandle thread, int infoClass, out uint info, uint length, out uint returned);

    [DllImport("kernel32.dll")]
    public static extern int GetThreadDescription(SafeKernelHandle thread, out nint description);

    [DllImport("kernel32.dll")]
    public static extern nint LocalFree(nint memory);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool GetThreadContext(SafeKernelHandle thread, nint context);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool Wow64GetThreadContext(SafeKernelHandle thread, nint context);
}
