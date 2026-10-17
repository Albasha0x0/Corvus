using System.Diagnostics;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using Corvus.Core;

namespace Corvus.Native.Diagnostics;

/// <summary>
/// A snapshot of a running process as a dump file, through the operating system's own writer: MiniDumpWriteDump on
/// Windows (as dotnet-dump and ProcDump write them), GDB's gcore on Linux (an ELF core). The process keeps running.
/// </summary>
public static class ProcessSnapshot
{
    // MiniDumpWithFullMemory | WithHandleData | WithUnloadedModules | WithFullMemoryInfo | WithThreadInfo
    private const uint DumpType = 0x2 | 0x4 | 0x20 | 0x800 | 0x1000;
    private const uint ProcessAccess = 0x0400 | 0x0010 | 0x0040; // PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_DUP_HANDLE (handle data)

    /// <summary>Writes the snapshot of <paramref name="pid"/> to <paramref name="path"/> (a temp file first, then placed); returns its size.</summary>
    public static long Write(int pid, string path, bool overwrite, CancellationToken ct)
    {
        var full = SafeFile.FullPath(path);
        if (File.Exists(full) && !overwrite)
            throw new ToolError(ErrorCode.Conflict, $"{full} exists.", "pass overwrite=true, or another outputPath");
        Directory.CreateDirectory(Path.GetDirectoryName(full)!);
        var partial = full + ".partial";
        try
        {
            if (OperatingSystem.IsWindows()) WriteMinidump(pid, partial);
            else if (OperatingSystem.IsLinux()) WriteCore(pid, partial, ct);
            else throw new ToolError(ErrorCode.ProviderUnavailable, "Snapshots are written on Windows (MiniDumpWriteDump) and Linux (gcore).", "on macOS, lldb's process save-core writes one");
            File.Move(partial, full, overwrite);
            return new FileInfo(full).Length;
        }
        finally
        {
            if (File.Exists(partial)) File.Delete(partial);
        }
    }

    private static void WriteMinidump(int pid, string path)
    {
        var process = OpenProcess(ProcessAccess, false, pid);
        if (process == IntPtr.Zero)
        {
            int error = Marshal.GetLastPInvokeError();
            throw error == 5
                ? new ToolError(ErrorCode.AccessDenied, $"Process {pid} cannot be opened for reading (access denied).", "run the server as the user who started the program")
                : new ToolError(ErrorCode.NotFound, $"Process {pid} cannot be opened (error {error}); it may have exited.", "live_session action=status shows the session's state");
        }
        try
        {
            using var file = new FileStream(path, FileMode.Create, FileAccess.ReadWrite, FileShare.None);
            if (!MiniDumpWriteDump(process, (uint)pid, file.SafeFileHandle, DumpType, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero))
                throw new ToolError(ErrorCode.IoError, $"MiniDumpWriteDump failed for process {pid} (error 0x{Marshal.GetLastPInvokeError():X}).", "check the disk space at the output path");
        }
        finally
        {
            CloseHandle(process);
        }
    }

    /// <summary>gcore names its output &lt;prefix&gt;.&lt;pid&gt;; the file is moved to <paramref name="path"/>.</summary>
    private static void WriteCore(int pid, string path, CancellationToken ct)
    {
        var gcore = Environment.GetEnvironmentVariable("PATH")?.Split(Path.PathSeparator).Select(d => Path.Combine(d, "gcore")).FirstOrDefault(File.Exists)
                    ?? throw new ToolError(ErrorCode.ProviderUnavailable, "gcore (GDB) is not on PATH.", "install GDB (it ships gcore)");
        var prefix = path + ".core";
        using var p = Process.Start(new ProcessStartInfo(gcore) { ArgumentList = { "-o", prefix, pid.ToString(System.Globalization.CultureInfo.InvariantCulture) }, RedirectStandardOutput = true, RedirectStandardError = true })!;
        var stderr = p.StandardError.ReadToEndAsync(ct);
        p.StandardOutput.ReadToEnd();
        if (!p.WaitForExit(TimeSpan.FromMinutes(5))) { p.Kill(true); throw new ToolError(ErrorCode.Timeout, "gcore did not finish within 5 minutes."); }
        var written = $"{prefix}.{pid}";
        if (p.ExitCode != 0 || !File.Exists(written))
            throw new ToolError(ErrorCode.IoError, $"gcore failed (exit {p.ExitCode}): {stderr.Result.Trim()}", "ptrace may be restricted: see /proc/sys/kernel/yama/ptrace_scope");
        File.Move(written, path, true);
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint access, bool inherit, int pid);

    [DllImport("kernel32.dll")]
    private static extern bool CloseHandle(IntPtr handle);

    [DllImport("dbghelp.dll", SetLastError = true)]
    private static extern bool MiniDumpWriteDump(IntPtr process, uint processId, SafeFileHandle file, uint type, IntPtr exception, IntPtr user, IntPtr callback);
}
