using System.Diagnostics;
using System.Runtime.InteropServices;

namespace Corvus.Tests;

/// <summary>Dumps of test servers that did not answer in time, written into the run's stall folder.</summary>
internal static class ServerDump
{
    /// <summary>The stall folder of a push or full run (test.ps1 sets it); unset elsewhere, and then nothing is written.</summary>
    public const string FolderVariable = "CORVUS_STALL_DIR";

    // Each dump holds the server's heap; a few name the cause, more only fill the disk.
    private const int MaxDumps = 3;

    /// <summary>
    /// Writes a dump of each server this process started (dotnet under cmd /c, as the SDK starts it) from
    /// <paramref name="started"/> on and still running; returns the files written, empty when the folder is unset, holds
    /// <see cref="MaxDumps"/> server dumps already, or no server matched. Never throws.
    /// </summary>
    public static IReadOnlyList<string> Write(DateTime started) =>
        Environment.GetEnvironmentVariable(FolderVariable) is { Length: > 0 } folder ? Write(started, folder) : [];

    /// <summary>As above, into <paramref name="folder"/>; <paramref name="shell"/> limits it to the server under that cmd process.</summary>
    internal static IReadOnlyList<string> Write(DateTime started, string folder, int? shell = null)
    {
        var written = new List<string>();
        try
        {
            if (!OperatingSystem.IsWindows()) return written;
            Directory.CreateDirectory(folder);
            int room = MaxDumps - Directory.GetFiles(folder, "server-start-*.dmp").Length;
            foreach (var server in Process.GetProcessesByName("dotnet"))
            {
                using (server)
                {
                    if (room <= 0) break;
                    try
                    {
                        if (server.StartTime < started.AddSeconds(-1) || ParentOf(server.Id) is not { } cmd) continue;
                        if (shell is { } only ? cmd != only : ParentOf(cmd) != Environment.ProcessId) continue;
                        var file = Path.Combine(folder, $"server-start-{server.Id}-{DateTime.Now:yyyyMMdd-HHmmss}.dmp");
                        if (Dump(server.Id, file)) { written.Add(file); room--; }
                    }
                    catch (Exception e) when (e is InvalidOperationException or System.ComponentModel.Win32Exception) { }
                }
            }
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { }
        return written;
    }

    // The runtime's createdump no longer takes another process's id, so dbghelp writes it: private memory, data segments,
    // handles, memory info and thread info, as a heap dump holds for reading .NET stacks.
    private const int HeapDump = 0x200 | 0x1 | 0x4 | 0x800 | 0x1000;

    private static bool Dump(int pid, string file)
    {
        using var process = OpenProcess(0x0400 | 0x0010 | 0x0040 /* QUERY_INFORMATION | VM_READ | DUP_HANDLE */, false, pid);
        if (process.IsInvalid) return false;
        bool done;
        using (var stream = new FileStream(file, FileMode.Create, FileAccess.ReadWrite))
            done = MiniDumpWriteDump(process, pid, stream.SafeFileHandle, HeapDump, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
        if (!done) File.Delete(file);
        return done;
    }

    /// <summary>The parent process id of <paramref name="pid"/>, or null when it cannot be read.</summary>
    private static int? ParentOf(int pid)
    {
        using var process = OpenProcess(0x1000 /* PROCESS_QUERY_LIMITED_INFORMATION */, false, pid);
        if (process.IsInvalid) return null;
        var info = new ProcessBasicInformation();
        return NtQueryInformationProcess(process, 0, ref info, Marshal.SizeOf<ProcessBasicInformation>(), out _) == 0 ? (int)info.InheritedFromUniqueProcessId : null;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ProcessBasicInformation
    {
        public nint ExitStatus, PebBaseAddress, AffinityMask, BasePriority, UniqueProcessId, InheritedFromUniqueProcessId;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern Microsoft.Win32.SafeHandles.SafeProcessHandle OpenProcess(uint access, bool inherit, int pid);

    [DllImport("dbghelp.dll", SetLastError = true)]
    private static extern bool MiniDumpWriteDump(Microsoft.Win32.SafeHandles.SafeProcessHandle process, int processId, Microsoft.Win32.SafeHandles.SafeFileHandle file, int type,
        IntPtr exception, IntPtr user, IntPtr callback);

    [DllImport("ntdll.dll")]
    private static extern int NtQueryInformationProcess(Microsoft.Win32.SafeHandles.SafeProcessHandle process, int infoClass, ref ProcessBasicInformation info, int size, out int returned);
}
