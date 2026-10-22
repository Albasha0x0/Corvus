using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace TestFixture.FakeTools;

/// <summary>
/// Puts the current process in a Windows job object that ends every process in it when its last handle closes. Only this
/// process holds the handle, so its exit, however it comes (a crash, a kill, a timeout), ends the processes it started and
/// theirs, unless they left the job. Elsewhere it does nothing.
/// </summary>
public static class KillOnCloseJob
{
    private const int JobObjectExtendedLimitInformation = 9;
    private const uint KillOnJobClose = 0x2000;
    private static SafeFileHandle? _job;

    /// <summary>Enters the job once per process; throws <see cref="Win32Exception"/> when Windows refuses it.</summary>
    public static void EnterCurrentProcess()
    {
        if (!OperatingSystem.IsWindows() || _job != null) return;
        var job = CreateJobObjectW(IntPtr.Zero, null);
        if (job.IsInvalid) throw new Win32Exception();
        var info = new JOBOBJECT_EXTENDED_LIMIT_INFORMATION { BasicLimitInformation = { LimitFlags = KillOnJobClose } };
        if (!SetInformationJobObject(job, JobObjectExtendedLimitInformation, ref info, (uint)Marshal.SizeOf<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>())
            || !AssignProcessToJobObject(job, GetCurrentProcess()))
        {
            var error = new Win32Exception();
            job.Dispose();
            throw error;
        }
        // Kept open for the life of the process: closing it ends the process too.
        _job = job;
    }

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

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern SafeFileHandle CreateJobObjectW(IntPtr attributes, string? name);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetInformationJobObject(SafeFileHandle job, int infoClass, ref JOBOBJECT_EXTENDED_LIMIT_INFORMATION info, uint length);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool AssignProcessToJobObject(SafeFileHandle job, IntPtr process);

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();
}
