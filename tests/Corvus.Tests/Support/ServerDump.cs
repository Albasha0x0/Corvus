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
    /// Writes a dump of the server process <paramref name="pid"/>; returns the file, or null when the folder is unset, holds
    /// <see cref="MaxDumps"/> server dumps already, the process cannot be read or this is not Windows. Never throws.
    /// </summary>
    public static string? Write(int pid) =>
        Environment.GetEnvironmentVariable(FolderVariable) is { Length: > 0 } folder ? Write(pid, folder) : null;

    /// <summary>As above, into <paramref name="folder"/>.</summary>
    internal static string? Write(int pid, string folder) => Write(pid, folder, out _);

    /// <summary>As above; <paramref name="error"/> is the Win32 error of the last failed attempt, 0 when none failed.</summary>
    internal static string? Write(int pid, string folder, out int error)
    {
        error = 0;
        try
        {
            if (!OperatingSystem.IsWindows()) return null;
            Directory.CreateDirectory(folder);
            if (Directory.GetFiles(folder, "server-start-*.dmp").Length >= MaxDumps) return null;
            var file = Path.Combine(folder, $"server-start-{pid}-{DateTime.Now:yyyyMMdd-HHmmss}.dmp");
            // A process still starting can fail a read (ERROR_PARTIAL_COPY); a few tries over about 1 s keep the dump of
            // a server that failed to start.
            for (int attempt = 0; attempt < DumpAttempts; attempt++)
            {
                if (attempt > 0) Thread.Sleep(DumpRetryDelay);
                if ((error = Dump(pid, file)) == 0) return file;
            }
            return null;
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { return null; }
    }

    private const int DumpAttempts = 3;
    private static readonly TimeSpan DumpRetryDelay = TimeSpan.FromMilliseconds(500);

    // The runtime's createdump no longer takes another process's id, so dbghelp writes it: private memory, data segments,
    // handles, memory info and thread info, as a heap dump holds for reading .NET stacks.
    private const int HeapDump = 0x200 | 0x1 | 0x4 | 0x800 | 0x1000;

    // Returns 0, or the Win32 error of the open or the dump.
    private static int Dump(int pid, string file)
    {
        using var process = OpenProcess(0x0400 | 0x0010 | 0x0040 /* QUERY_INFORMATION | VM_READ | DUP_HANDLE */, false, pid);
        if (process.IsInvalid) return Marshal.GetLastPInvokeError();
        int error = 0;
        using (var stream = new FileStream(file, FileMode.Create, FileAccess.ReadWrite))
            if (!MiniDumpWriteDump(process, pid, stream.SafeFileHandle, HeapDump, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero))
                error = Marshal.GetLastPInvokeError() is var e and not 0 ? e : -1;
        if (error != 0) File.Delete(file);
        return error;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern Microsoft.Win32.SafeHandles.SafeProcessHandle OpenProcess(uint access, bool inherit, int pid);

    [DllImport("dbghelp.dll", SetLastError = true)]
    private static extern bool MiniDumpWriteDump(Microsoft.Win32.SafeHandles.SafeProcessHandle process, int processId, Microsoft.Win32.SafeHandles.SafeFileHandle file, int type,
        IntPtr exception, IntPtr user, IntPtr callback);
}
