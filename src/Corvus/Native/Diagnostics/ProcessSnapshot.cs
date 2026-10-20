using System.Buffers.Binary;
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
    /// <summary>A thread held at a stop: its registers become the dump's exception context, as a debugger's dump at a break records its last event.</summary>
    public sealed record Stop(int ThreadId, byte[] Context, ulong Address);

    // MiniDumpWithFullMemory | WithHandleData | WithUnloadedModules | WithFullMemoryInfo | WithThreadInfo
    private const uint DumpType = 0x2 | 0x4 | 0x20 | 0x800 | 0x1000;
    private const uint ProcessAccess = 0x0400 | 0x0010 | 0x0040; // PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_DUP_HANDLE (handle data)

    /// <summary>Writes the snapshot of <paramref name="pid"/> to <paramref name="path"/> (a temp file first, then placed); returns its size.</summary>
    public static long Write(int pid, string path, bool overwrite, CancellationToken ct, Stop? stop = null)
    {
        var full = SafeFile.FullPath(path);
        if (File.Exists(full) && !overwrite)
            throw new ToolError(ErrorCode.Conflict, $"{full} exists.", "pass overwrite=true, or another outputPath");
        Directory.CreateDirectory(Path.GetDirectoryName(full)!);
        var partial = full + ".partial";
        try
        {
            if (OperatingSystem.IsWindows()) WriteMinidump(pid, partial, stop);
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

    /// <summary>An x64 CONTEXT (control and integer registers) from register values named as Frida and the dump reader name them.</summary>
    public static byte[] ContextX64(IReadOnlyDictionary<string, ulong> registers)
    {
        var c = new byte[0x4D0];
        BinaryPrimitives.WriteUInt32LittleEndian(c.AsSpan(0x30), 0x100003); // CONTEXT_AMD64 | CONTROL | INTEGER
        BinaryPrimitives.WriteUInt16LittleEndian(c.AsSpan(0x38), 0x33); // user-mode cs
        BinaryPrimitives.WriteUInt16LittleEndian(c.AsSpan(0x42), 0x2B); // user-mode ss
        BinaryPrimitives.WriteUInt32LittleEndian(c.AsSpan(0x44), 0x202); // eflags: IF
        string[] order = ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "rip"];
        for (int i = 0; i < order.Length; i++)
            if (registers.TryGetValue(order[i], out var v)) BinaryPrimitives.WriteUInt64LittleEndian(c.AsSpan(0x78 + 8 * i), v);
        return c;
    }

    /// <summary>An x86 CONTEXT (control and integer registers) from register values named as Frida names them.</summary>
    public static byte[] ContextX86(IReadOnlyDictionary<string, ulong> registers)
    {
        var c = new byte[0x2CC];
        BinaryPrimitives.WriteUInt32LittleEndian(c, 0x10003); // CONTEXT_i386 | CONTROL | INTEGER
        BinaryPrimitives.WriteUInt32LittleEndian(c.AsSpan(0xBC), 0x23); // user-mode cs
        BinaryPrimitives.WriteUInt32LittleEndian(c.AsSpan(0xC0), 0x202); // eflags: IF
        BinaryPrimitives.WriteUInt32LittleEndian(c.AsSpan(0xC8), 0x2B); // user-mode ss
        string[] order = ["edi", "esi", "ebx", "edx", "ecx", "eax", "ebp", "eip"];
        for (int i = 0; i < order.Length; i++)
            if (registers.TryGetValue(order[i], out var v)) BinaryPrimitives.WriteUInt32LittleEndian(c.AsSpan(0x9C + 4 * i), (uint)v);
        if (registers.TryGetValue("esp", out var sp)) BinaryPrimitives.WriteUInt32LittleEndian(c.AsSpan(0xC4), (uint)sp);
        return c;
    }

    private static void WriteMinidump(int pid, string path, Stop? stop)
    {
        var process = OpenProcess(ProcessAccess, false, pid);
        if (process == IntPtr.Zero)
        {
            int error = Marshal.GetLastPInvokeError();
            throw error == 5
                ? new ToolError(ErrorCode.AccessDenied, $"Process {pid} cannot be opened for reading (access denied).", "run the server as the user who started the program")
                : new ToolError(ErrorCode.NotFound, $"Process {pid} cannot be opened (error {error}); it may have exited.", "live_session action=status shows the session's state");
        }
        IntPtr block = IntPtr.Zero, exception = IntPtr.Zero;
        if (stop != null)
        {
            // one block, in this process (ClientPointers false): MINIDUMP_EXCEPTION_INFORMATION (pack 4), EXCEPTION_POINTERS,
            // an EXCEPTION_RECORD for a breakpoint at the stop, and the CONTEXT 16-byte aligned; a 64-bit writer copies an x64
            // CONTEXT's size whatever the target, so a WoW64 program's x86 CONTEXT is padded to it
            const int Info = 0, Pointers = 16, Record = 32, Context = 192;
            int size = Context + Math.Max(stop.Context.Length, 0x4D0) + 16;
            block = Marshal.AllocHGlobal(size);
            var bytes = new byte[size];
            long context = ((block.ToInt64() + Context + 15) & ~15L) - block.ToInt64();
            BinaryPrimitives.WriteInt32LittleEndian(bytes.AsSpan(Info), stop.ThreadId);
            BinaryPrimitives.WriteInt64LittleEndian(bytes.AsSpan(Info + 4), block.ToInt64() + Pointers);
            BinaryPrimitives.WriteInt64LittleEndian(bytes.AsSpan(Pointers), block.ToInt64() + Record);
            BinaryPrimitives.WriteInt64LittleEndian(bytes.AsSpan(Pointers + 8), block.ToInt64() + context);
            BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(Record), 0x80000003); // EXCEPTION_BREAKPOINT
            BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(Record + 16), stop.Address);
            stop.Context.CopyTo(bytes, context);
            Marshal.Copy(bytes, 0, block, bytes.Length);
            exception = block;
        }
        try
        {
            using var file = new FileStream(path, FileMode.Create, FileAccess.ReadWrite, FileShare.None);
            if (!MiniDumpWriteDump(process, (uint)pid, file.SafeFileHandle, DumpType, exception, IntPtr.Zero, IntPtr.Zero))
                throw new ToolError(ErrorCode.IoError, $"MiniDumpWriteDump failed for process {pid} (error 0x{Marshal.GetLastPInvokeError():X}).", "check the disk space at the output path");
        }
        finally
        {
            CloseHandle(process);
            if (block != IntPtr.Zero) Marshal.FreeHGlobal(block);
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
        {
            var failure = $"gcore failed (exit {p.ExitCode}): {stderr.Result.Trim()}";
            // gcore is never the program's parent: a refusal is permanent, not a retryable I/O error
            throw Live.PtraceScope.Refusing(started: false) is { } scope ? Live.PtraceScope.Refusal(scope, failure) : new ToolError(ErrorCode.IoError, failure, "check the disk space at the output path");
        }
        File.Move(written, path, true);
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint access, bool inherit, int pid);

    [DllImport("kernel32.dll")]
    private static extern bool CloseHandle(IntPtr handle);

    [DllImport("dbghelp.dll", SetLastError = true)]
    private static extern bool MiniDumpWriteDump(IntPtr process, uint processId, SafeFileHandle file, uint type, IntPtr exception, IntPtr user, IntPtr callback);
}
