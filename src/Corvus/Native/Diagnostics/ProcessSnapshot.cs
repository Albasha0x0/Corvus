using System.Buffers.Binary;
using System.Diagnostics;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using Corvus.Core;

namespace Corvus.Native.Diagnostics;

/// <summary>Writes a running process's dump file with the OS writer (MiniDumpWriteDump, gcore, lldb save-core); the process keeps running.</summary>
public static class ProcessSnapshot
{
    /// <summary>A thread held at a stop; its registers become the dump's exception context or the core thread's, with SIGTRAP.</summary>
    public sealed record Stop(int ThreadId, string Arch, IReadOnlyDictionary<string, ulong> Registers)
    {
        public ulong Address => Registers.GetValueOrDefault(Arch switch { "x64" => "rip", "arm64" => "pc", _ => "eip" });
    }

    // MiniDumpWithFullMemory | WithHandleData | WithUnloadedModules | WithFullMemoryInfo | WithThreadInfo.
    private const uint DumpType = 0x2 | 0x4 | 0x20 | 0x800 | 0x1000;
    // PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_DUP_HANDLE (handle data).
    private const uint ProcessAccess = 0x0400 | 0x0010 | 0x0040;

    /// <summary>Writes the snapshot of <paramref name="pid"/> to <paramref name="path"/> (a temp file first, then placed); returns its size.</summary>
    public static long Write(int pid, string path, bool overwrite, CancellationToken ct, Stop? stop = null)
    {
        var full = SafeFile.Output(path);
        if (File.Exists(full) && !overwrite)
            throw new ToolError(ErrorCode.Conflict, $"{full} exists.", "pass overwrite=true, or another outputPath");
        Directory.CreateDirectory(Path.GetDirectoryName(full)!);
        var partial = full + ".partial";
        try
        {
            if (OperatingSystem.IsWindows()) WriteMinidump(pid, partial, stop, ct);
            else if (OperatingSystem.IsLinux()) WriteCore(pid, partial, ct, stop);
            else if (OperatingSystem.IsMacOS()) WriteMachCore(pid, partial, ct);
            else throw new ToolError(ErrorCode.ProviderUnavailable, "Snapshots are written on Windows (MiniDumpWriteDump), Linux (gcore) and macOS (lldb).");
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

    /// <summary>An ARM64 CONTEXT (control and integer registers) from register values named as Frida names them.</summary>
    public static byte[] ContextArm64(IReadOnlyDictionary<string, ulong> registers)
    {
        var c = new byte[0x390];
        // The flags are CONTEXT_ARM64 | CONTROL | INTEGER.
        BinaryPrimitives.WriteUInt32LittleEndian(c, 0x400003);
        if (registers.TryGetValue("nzcv", out var nzcv)) BinaryPrimitives.WriteUInt32LittleEndian(c.AsSpan(4), (uint)nzcv);
        for (int i = 0; i <= 28; i++)
            if (registers.TryGetValue($"x{i}", out var v)) BinaryPrimitives.WriteUInt64LittleEndian(c.AsSpan(8 + 8 * i), v);
        string[] order = ["fp", "lr", "sp", "pc"];
        for (int i = 0; i < order.Length; i++)
            if (registers.TryGetValue(order[i], out var v)) BinaryPrimitives.WriteUInt64LittleEndian(c.AsSpan(0xF0 + 8 * i), v);
        return c;
    }

    private static void WriteMinidump(int pid, string path, Stop? stop, CancellationToken ct)
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
            // One local block (exception info, pointers, breakpoint record, aligned CONTEXT); a 64-bit writer copies an x64
            // CONTEXT's size, so a WoW64 program's x86 CONTEXT is padded to it.
            var stopContext = stop.Arch switch { "x64" => ContextX64(stop.Registers), "arm64" => ContextArm64(stop.Registers), _ => ContextX86(stop.Registers) };
            const int Info = 0, Pointers = 16, Record = 32, Context = 192;
            int size = Context + Math.Max(stopContext.Length, 0x4D0) + 16;
            block = Marshal.AllocHGlobal(size);
            var bytes = new byte[size];
            long context = ((block.ToInt64() + Context + 15) & ~15L) - block.ToInt64();
            BinaryPrimitives.WriteInt32LittleEndian(bytes.AsSpan(Info), stop.ThreadId);
            BinaryPrimitives.WriteInt64LittleEndian(bytes.AsSpan(Info + 4), block.ToInt64() + Pointers);
            BinaryPrimitives.WriteInt64LittleEndian(bytes.AsSpan(Pointers), block.ToInt64() + Record);
            BinaryPrimitives.WriteInt64LittleEndian(bytes.AsSpan(Pointers + 8), block.ToInt64() + context);
            BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(Record), 0x80000003); // EXCEPTION_BREAKPOINT
            BinaryPrimitives.WriteUInt64LittleEndian(bytes.AsSpan(Record + 16), stop.Address);
            stopContext.CopyTo(bytes, context);
            Marshal.Copy(bytes, 0, block, bytes.Length);
            exception = block;
        }
        try
        {
            // Wait for the loader first: until it has listed the modules, every write fails as a changed program does.
            AwaitLoader(pid, () => LoaderReady(process), LoaderWait, ct);
            Attempts(pid, () =>
            {
                using var file = new FileStream(path, FileMode.Create, FileAccess.ReadWrite, FileShare.None);
                return MiniDumpWriteDump(process, (uint)pid, file.SafeFileHandle, DumpType, exception, IntPtr.Zero, IntPtr.Zero) ? 0 : Marshal.GetLastPInvokeError();
            });
        }
        finally
        {
            CloseHandle(process);
            if (block != IntPtr.Zero) Marshal.FreeHGlobal(block);
        }
    }

    /// <summary>How long a snapshot waits for a starting program's loader before it refuses.</summary>
    internal static readonly TimeSpan LoaderWait = TimeSpan.FromSeconds(10);

    /// <summary>Returns once <paramref name="ready"/> is not false; refuses with Timeout once <paramref name="elapsed"/> reaches <paramref name="wait"/>.</summary>
    internal static void AwaitLoader(int pid, Func<bool?> ready, TimeSpan wait, CancellationToken ct, Func<TimeSpan>? elapsed = null)
    {
        if (elapsed == null)
        {
            var clock = Stopwatch.StartNew();
            elapsed = () => clock.Elapsed;
        }
        while (ready() == false)
        {
            if (elapsed() >= wait)
                throw new ToolError(ErrorCode.Timeout, $"Process {pid} has not started: its loader has not listed its modules within {(wait.TotalSeconds >= 1 ? $"{wait.TotalSeconds:0.#} s" : $"{wait.TotalMilliseconds:0} ms")}.",
                    "run the held program with live_break action=continue, then snapshot again");
            ct.ThrowIfCancellationRequested();
            ct.WaitHandle.WaitOne(20);
        }
    }

    /// <summary>Whether the loader has set up the module list (PEB.Ldr initialized); null when the PEB cannot be read.</summary>
    private static bool? LoaderReady(IntPtr process)
    {
        // PROCESS_BASIC_INFORMATION: PebBaseAddress is its second field.
        var basic = new nint[6];
        if (NtQueryInformationProcess(process, 0, basic, IntPtr.Size * basic.Length, out _) != 0) return null;
        if (!ReadProcessMemory(process, basic[1] + (IntPtr.Size == 8 ? 0x18 : 0x0C), out nint ldr, IntPtr.Size, out _)) return null;
        if (ldr == 0) return false;
        // PEB_LDR_DATA.Initialized follows its 4-byte Length.
        return ReadProcessMemory(process, ldr + 4, out byte initialized, 1, out _) ? initialized != 0 : null;
    }

    // HRESULT_FROM_WIN32 of ERROR_BAD_LENGTH and ERROR_PARTIAL_COPY: the program changed while it was read.
    private static readonly int[] Changed = [unchecked((int)0x80070018), unchecked((int)0x8007012B)];
    internal const int WriteTries = 3;

    /// <summary>Runs <paramref name="write"/> (0, else its error) again while the error says the program changed during the read, up to <see cref="WriteTries"/> times.</summary>
    internal static void Attempts(int pid, Func<int> write)
    {
        for (int i = 1; ; i++)
        {
            int error = write();
            if (error == 0) return;
            if (!Changed.Contains(error))
                throw new ToolError(ErrorCode.IoError, $"MiniDumpWriteDump failed for process {pid} (error 0x{error:X}).", "check the disk space at the output path");
            if (i == WriteTries)
                throw new ToolError(ErrorCode.IoError, $"MiniDumpWriteDump failed for process {pid} {WriteTries} times (error 0x{error:X}): the program changed while it was read.",
                    "try again once the program has settled after start-up");
        }
    }

    private static string? OnPath(string name) => Environment.GetEnvironmentVariable("PATH")?.Split(Path.PathSeparator).Select(d => Path.Combine(d, name)).FirstOrDefault(File.Exists);

    // How long a thread may wait in vfork, before or during the write, until the snapshot is given up.
    internal static readonly TimeSpan VforkWait = TimeSpan.FromSeconds(10);
    private static readonly TimeSpan CoreTimeout = TimeSpan.FromMinutes(5);

    /// <summary>Writes an ELF core with gcore to <paramref name="path"/>; without <paramref name="waitOutVfork"/> gcore starts at once.</summary>
    internal static void WriteCore(int pid, string path, CancellationToken ct, Stop? stop, bool waitOutVfork = true)
    {
        var gcore = OnPath("gcore") ?? throw new ToolError(ErrorCode.ProviderUnavailable, "gcore (GDB) is not on PATH.", "install GDB (it ships gcore)");
        // A vfork thread stops only once its child execs, which can wait on the stopped program, so GDB would hang.
        for (var waited = Stopwatch.StartNew(); waitOutVfork && InVfork(pid) is { } tid; Thread.Sleep(100))
            if (waited.Elapsed >= VforkWait) throw VforkRefusal(pid, tid);
        // A process GDB is killed on stays in group stop; one stopped before the write is left stopped.
        bool stoppedBefore = State(pid, pid) == 'T';
        var prefix = path + ".core";
        using var p = Providers.ChildProcess.Start(new Providers.ChildProcessStart(gcore, ["-o", prefix, pid.ToString(System.Globalization.CultureInfo.InvariantCulture)]));
        p.StandardInput.Dispose();
        var (stdout, stderr) = ReadOutput(p);
        var elapsed = Stopwatch.StartNew();
        TimeSpan? vfork = null;
        while (!p.Exited.Wait(250))
        {
            int? waiting = InVfork(pid);
            vfork = waiting == null ? null : vfork ?? elapsed.Elapsed;
            ToolError? failure = ct.IsCancellationRequested ? new ToolError(ErrorCode.Cancelled, "The snapshot was cancelled; gcore was ended.")
                : waiting is { } tid && elapsed.Elapsed - vfork >= VforkWait ? VforkRefusal(pid, tid)
                : elapsed.Elapsed >= CoreTimeout ? new ToolError(ErrorCode.Timeout, $"gcore did not finish within {CoreTimeout.TotalMinutes:0} minutes.") : null;
            if (failure == null) continue;
            p.Kill();
            p.Exited.Wait();
            if (!stoppedBefore) _ = Kill(pid, SigCont);
            throw failure;
        }
        stdout.Join();
        stderr.Join();
        var written = $"{prefix}.{pid}";
        if (p.ExitCode != 0 || !File.Exists(written))
        {
            var failure = $"gcore failed (exit {p.ExitCode}): {stderr.Text.Trim()}";
            // gcore is never the program's parent, so a ptrace refusal is permanent.
            throw Live.PtraceScope.Refusing(started: false) is { } scope ? Live.PtraceScope.Refusal(scope, failure) : new ToolError(ErrorCode.IoError, failure, "check the disk space at the output path");
        }
        File.Move(written, path, true);
        if (stop != null) MarkStop(path, stop);
    }

    /// <summary>A stream read to its end on a thread of its own; <see cref="Text"/> is complete once joined.</summary>
    private sealed class OutputText
    {
        private readonly Thread _thread;

        public OutputText(Stream stream) => _thread = Providers.ChildProcess.StartReader(() => Text = new StreamReader(stream).ReadToEnd());

        public string Text { get; private set; } = "";

        public void Join() => _thread.Join();
    }

    private static (OutputText Stdout, OutputText Stderr) ReadOutput(Providers.ChildProcess p) => (new(p.StandardOutput), new(p.StandardError));

    private static ToolError VforkRefusal(int pid, int tid) => new(ErrorCode.Timeout,
        $"Thread {tid} of process {pid} waits in vfork, which GDB cannot stop; no snapshot was written.",
        "take the snapshot again once the vfork child has run its program");

    /// <summary>A thread of <paramref name="pid"/> that waits in vfork for its child; null when none does.</summary>
    internal static int? InVfork(int pid)
    {
        string[] tasks;
        try { tasks = Directory.GetDirectories($"/proc/{pid}/task"); }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { return null; }
        foreach (var task in tasks)
            if (int.TryParse(Path.GetFileName(task), out var tid) && State(pid, tid) == 'D' && IsVforkWait(Read($"{task}/wchan")))
                return tid;
        return null;
    }

    /// <summary>Whether a wait channel is the fork path a vfork parent sleeps in until its child execs or exits.</summary>
    internal static bool IsVforkWait(string? wchan) => wchan is "kernel_clone" or "_do_fork" or "do_fork" or "wait_for_vfork_done";

    /// <summary>The state letter of /proc/&lt;pid&gt;/task/&lt;tid&gt;/stat (after the command name); '\0' when it cannot be read.</summary>
    internal static char State(int pid, int tid) => StateOf(Read($"/proc/{pid}/task/{tid}/stat"));

    internal static char StateOf(string? stat) => stat?.LastIndexOf(')') is int at and >= 0 && at + 2 < stat.Length ? stat[at + 2] : '\0';

    private static string? Read(string path)
    {
        try { return File.ReadAllText(path).Trim(); }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { return null; }
    }

    // SIGCONT on Linux.
    private const int SigCont = 18;

    [DllImport("libc", EntryPoint = "kill", SetLastError = true)]
    private static extern int Kill(int pid, int signal);

    // user_regs_struct order (x86-64, i386), as NT_PRSTATUS holds it.
    private static readonly string[] UserRegsX64 = ["r15", "r14", "r13", "r12", "rbp", "rbx", "r11", "r10", "r9", "r8", "rax", "rcx", "rdx", "rsi", "rdi", "", "rip", "", "", "rsp"];
    private static readonly string[] UserRegsX86 = ["ebx", "ecx", "edx", "esi", "edi", "ebp", "eax", "", "", "", "", "", "eip", "", "", "esp"];
    private const int SigTrap = 5, TrapBrkpt = 1;

    /// <summary>Gives the stopped thread of an ELF core the stop's registers and SIGTRAP; every other thread's signal is cleared.</summary>
    internal static void MarkStop(string path, Stop stop)
    {
        using var file = new FileStream(path, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
        Span<byte> header = stackalloc byte[64];
        file.ReadExactly(header);
        bool is64 = header[4] == 2;
        ulong phoff = is64 ? BinaryPrimitives.ReadUInt64LittleEndian(header[32..]) : BinaryPrimitives.ReadUInt32LittleEndian(header[28..]);
        int phentsize = BinaryPrimitives.ReadUInt16LittleEndian(header[(is64 ? 54 : 42)..]), phnum = BinaryPrimitives.ReadUInt16LittleEndian(header[(is64 ? 56 : 44)..]);
        var phdrs = new byte[phentsize * phnum];
        file.Position = (long)phoff;
        file.ReadExactly(phdrs);
        int word = is64 ? 8 : 4, regAt = is64 ? 112 : 72, pidAt = is64 ? 32 : 24;
        var order = stop.Arch == "x64" ? UserRegsX64 : UserRegsX86;
        for (int i = 0; i < phnum; i++)
        {
            var ph = phdrs.AsSpan(i * phentsize, phentsize);
            if (BinaryPrimitives.ReadUInt32LittleEndian(ph) != 4) continue; // PT_NOTE
            long offset = is64 ? (long)BinaryPrimitives.ReadUInt64LittleEndian(ph[8..]) : BinaryPrimitives.ReadUInt32LittleEndian(ph[4..]);
            long size = is64 ? (long)BinaryPrimitives.ReadUInt64LittleEndian(ph[32..]) : BinaryPrimitives.ReadUInt32LittleEndian(ph[16..]);
            var notes = new byte[size];
            file.Position = offset;
            file.ReadExactly(notes);
            // The notes after an NT_PRSTATUS, until the next one, belong to its thread.
            bool stopped = false;
            for (long at = 0; at + 12 <= size;)
            {
                uint nameSize = BinaryPrimitives.ReadUInt32LittleEndian(notes.AsSpan((int)at)), descSize = BinaryPrimitives.ReadUInt32LittleEndian(notes.AsSpan((int)at + 4));
                uint type = BinaryPrimitives.ReadUInt32LittleEndian(notes.AsSpan((int)at + 8));
                long desc = at + 12 + ((nameSize + 3) & ~3u), next = desc + ((descSize + 3) & ~3u);
                if (next > size) break;
                var d = notes.AsSpan((int)desc, (int)descSize);
                if (type == Dump.CoreFile.NtPrstatus && d.Length >= regAt)
                {
                    stopped = BinaryPrimitives.ReadUInt32LittleEndian(d[pidAt..]) == (uint)stop.ThreadId;
                    int signal = stopped ? SigTrap : 0;
                    BinaryPrimitives.WriteInt32LittleEndian(d, signal); // pr_info.si_signo
                    BinaryPrimitives.WriteInt32LittleEndian(d[4..], stopped ? TrapBrkpt : 0); // pr_info.si_code
                    BinaryPrimitives.WriteUInt16LittleEndian(d[12..], (ushort)signal); // pr_cursig
                    for (int r = 0; stopped && r < order.Length; r++)
                        if (order[r].Length > 0 && stop.Registers.TryGetValue(order[r], out var v) && regAt + (r + 1) * word <= d.Length)
                            if (is64) BinaryPrimitives.WriteUInt64LittleEndian(d[(regAt + r * 8)..], v);
                            else BinaryPrimitives.WriteUInt32LittleEndian(d[(regAt + r * 4)..], (uint)v);
                }
                else if (type == Dump.CoreFile.NtSiginfo && d.Length >= 16 + word)
                {
                    d.Clear();
                    if (stopped)
                    {
                        BinaryPrimitives.WriteInt32LittleEndian(d, SigTrap);
                        BinaryPrimitives.WriteInt32LittleEndian(d[8..], TrapBrkpt);
                        if (is64) BinaryPrimitives.WriteUInt64LittleEndian(d[16..], stop.Address); // si_addr
                        else BinaryPrimitives.WriteUInt32LittleEndian(d[12..], (uint)stop.Address);
                    }
                }
                at = next;
            }
            file.Position = offset;
            file.Write(notes);
        }
    }

    /// <summary>lldb attaches, writes the modified memory as a Mach-O core (process save-core) and detaches.</summary>
    private static void WriteMachCore(int pid, string path, CancellationToken ct)
    {
        var lldb = OnPath("lldb") ?? throw new ToolError(ErrorCode.ProviderUnavailable, "lldb is not on PATH.", "install the Xcode command line tools (xcode-select --install)");
        using var p = Providers.ChildProcess.Start(new Providers.ChildProcessStart(lldb, ["--batch", "--no-lldbinit", "-p", pid.ToString(System.Globalization.CultureInfo.InvariantCulture),
            "-o", $"process save-core --style modified-memory \"{path.Replace("\\", "\\\\").Replace("\"", "\\\"")}\"", "-o", "process detach"]));
        p.StandardInput.Dispose();
        var (stdout, stderr) = ReadOutput(p);
        if (!p.Exited.Wait(TimeSpan.FromMinutes(5), CancellationToken.None)) { p.Kill(); throw new ToolError(ErrorCode.Timeout, "lldb did not finish within 5 minutes."); }
        stdout.Join();
        stderr.Join();
        if (File.Exists(path) && new FileInfo(path).Length > 0) return;
        var output = $"{stdout.Text}\n{stderr.Text}".Trim();
        var failure = $"lldb process save-core failed (exit {p.ExitCode}): {output[Math.Max(0, output.Length - 1000)..]}";
        throw output.Contains("attach failed", StringComparison.Ordinal)
            ? new ToolError(ErrorCode.AccessDenied, failure, "lldb attaches to programs signed with the get-task-allow entitlement (debug builds), or run the server as root")
            : new ToolError(ErrorCode.IoError, failure, "check the disk space at the output path");
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint access, bool inherit, int pid);

    [DllImport("kernel32.dll")]
    private static extern bool CloseHandle(IntPtr handle);

    [DllImport("ntdll.dll")]
    private static extern int NtQueryInformationProcess(IntPtr process, int infoClass, [Out] nint[] info, int length, out int returned);

    [DllImport("kernel32.dll")]
    private static extern bool ReadProcessMemory(IntPtr process, nint address, out nint buffer, nint size, out nint read);

    [DllImport("kernel32.dll")]
    private static extern bool ReadProcessMemory(IntPtr process, nint address, out byte buffer, nint size, out nint read);

    [DllImport("dbghelp.dll", SetLastError = true)]
    private static extern bool MiniDumpWriteDump(IntPtr process, uint processId, SafeFileHandle file, uint type, IntPtr exception, IntPtr user, IntPtr callback);
}
