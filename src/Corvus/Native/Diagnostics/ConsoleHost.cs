using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;
using Microsoft.Win32.SafeHandles;
using Corvus.Core;
using Corvus.Native.Providers;
using static Corvus.Native.Providers.WindowsJob;

namespace Corvus.Native.Diagnostics;

/// <summary>Why a program cannot run under a console host on this machine, and the fix.</summary>
public sealed record ConsoleHostUnavailable(string Reason, string Remediation);

/// <summary>A program running under a console host.</summary>
public interface IConsoleProcess : IDisposable
{
    int ProcessId { get; }

    /// <summary>Completes with the exit code once the program has ended and the console has delivered its last output.</summary>
    Task<int> Exited { get; }

    /// <summary>Types <paramref name="text"/> into the console, as a terminal sends keys (\r is Enter).</summary>
    void Write(string text);

    void Resize(int columns, int rows);

    /// <summary>Ends the program; <see cref="Exited"/> completes once the console has closed.</summary>
    void Kill();
}

/// <summary>The operating system's console host: a program started with a console whose screen output reaches the caller.</summary>
public interface IConsoleHost
{
    /// <summary>The host as the platform names it.</summary>
    string Name { get; }

    ConsoleHostUnavailable? Unavailable();

    /// <summary>
    /// Starts <paramref name="program"/> with a <paramref name="columns"/> x <paramref name="rows"/> console; its output, as the
    /// console renders it (text with virtual terminal sequences), reaches <paramref name="output"/> on the reader's thread, in order.
    /// </summary>
    IConsoleProcess Start(string program, IReadOnlyList<string> arguments, int columns, int rows, Action<string> output);
}

public static class ConsoleHosts
{
    public static IConsoleHost ForThisMachine() =>
        OperatingSystem.IsWindows() ? new PseudoConsoleHost() : new UnavailableHost();

    private sealed class UnavailableHost : IConsoleHost
    {
        public string Name => "pseudo terminal (PTY)";

        public ConsoleHostUnavailable? Unavailable() =>
            new("Console runs use the Windows pseudoconsole (ConPTY); the pseudo terminal reader for this platform is not available yet.", "run the program on Windows");

        public IConsoleProcess Start(string program, IReadOnlyList<string> arguments, int columns, int rows, Action<string> output) =>
            throw new ToolError(ErrorCode.ProviderUnavailable, Unavailable()!.Reason, Unavailable()!.Remediation);
    }
}

/// <summary>
/// Virtual terminal output to plain text: control and escape sequences left out, cursor-forward as spaces, \r dropped.
/// Keeps its state across chunks, as a sequence may span two reads.
/// </summary>
public sealed class VirtualTerminalText
{
    private enum State { Text, Escape, Csi, String, StringEscape }
    private State _state;
    private readonly StringBuilder _parameters = new();

    public string Plain(string chunk)
    {
        var text = new StringBuilder(chunk.Length);
        foreach (char c in chunk)
            switch (_state)
            {
                case State.Text:
                    if (c == '\x1b') _state = State.Escape;
                    else if (c is '\n' or '\t' || c >= ' ' && c != '\x7f') text.Append(c);
                    break;
                case State.Escape:
                    if (c == '[') { _state = State.Csi; _parameters.Clear(); }
                    else if (c is ']' or 'P' or 'X' or '^' or '_') _state = State.String;
                    else if (c is < ' ' or > '/') _state = State.Text; // a final byte; 0x20-0x2F are intermediates
                    break;
                case State.Csi:
                    if (c is >= '@' and <= '~')
                    {
                        // ConPTY writes runs of blanks as cursor-forward
                        if (c == 'C') text.Append(' ', int.TryParse(_parameters.ToString(), out int n) && n is > 0 and < 1000 ? n : 1);
                        _state = State.Text;
                    }
                    else _parameters.Append(c);
                    break;
                case State.String:
                    if (c == '\a') _state = State.Text;
                    else if (c == '\x1b') _state = State.StringEscape;
                    break;
                case State.StringEscape:
                    _state = c == '\\' ? State.Text : State.String;
                    break;
            }
        return text.ToString();
    }
}

/// <summary>
/// The Windows pseudoconsole (ConPTY), as Microsoft's terminal samples create it: CreatePseudoConsole over two pipes, the
/// program started with PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE inside a kill-on-close job, so it ends with the server.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class PseudoConsoleHost : IConsoleHost
{
    public string Name => "pseudoconsole (ConPTY)";

    public ConsoleHostUnavailable? Unavailable() =>
        NativeLibrary.TryLoad("kernel32.dll", out var k) && NativeLibrary.TryGetExport(k, "CreatePseudoConsole", out _) ? null
            : new("This Windows has no pseudoconsole (CreatePseudoConsole needs Windows 10 1809 or later).", "run the program on a later Windows");

    public IConsoleProcess Start(string program, IReadOnlyList<string> arguments, int columns, int rows, Action<string> output) =>
        PseudoConsoleProcess.Start(program, arguments, columns, rows, output);
}

[SupportedOSPlatform("windows")]
internal sealed class PseudoConsoleProcess : IConsoleProcess
{
    /// <summary>After the program ends, the console's last frame arrives within this quiet time before the console is closed.</summary>
    private static readonly TimeSpan Settle = TimeSpan.FromMilliseconds(150);
    private readonly SafeFileHandle _job;
    private readonly SafeProcessHandle _process;
    private readonly FileStream _input;
    private readonly FileStream _output;
    private readonly Action<string> _deliver;
    private readonly TaskCompletionSource<int> _exited = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly Thread _reader;
    private IntPtr _console;
    private long _lastOutput = Environment.TickCount64;
    private int _closed;

    private PseudoConsoleProcess(SafeFileHandle job, SafeProcessHandle process, int id, IntPtr console, SafeFileHandle input, SafeFileHandle output, Action<string> deliver)
    {
        (_job, _process, ProcessId, _console, _deliver) = (job, process, id, console, deliver);
        _input = new FileStream(input, FileAccess.Write, 1);
        _output = new FileStream(output, FileAccess.Read, 1);
        _reader = ChildProcess.StartReader(Read);
        var wait = new ProcessWaitHandle(process);
        ThreadPool.RegisterWaitForSingleObject(wait, (_, _) => Task.Run(Ended), null, Timeout.Infinite, executeOnlyOnce: true);
    }

    public int ProcessId { get; }
    public Task<int> Exited => _exited.Task;

    public static PseudoConsoleProcess Start(string program, IReadOnlyList<string> arguments, int columns, int rows, Action<string> output)
    {
        var job = CreateJobObjectW(IntPtr.Zero, null);
        if (job.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error(), "CreateJobObject failed");
        SafeFileHandle? inRead = null, inWrite = null, outRead = null, outWrite = null;
        IntPtr console = IntPtr.Zero, attributes = IntPtr.Zero;
        var info = default(PROCESS_INFORMATION);
        try
        {
            var limits = new JOBOBJECT_EXTENDED_LIMIT_INFORMATION { BasicLimitInformation = new() { LimitFlags = KillOnJobClose } };
            if (!SetInformationJobObject(job, JobObjectExtendedLimitInformation, ref limits, (uint)Marshal.SizeOf<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>()))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "SetInformationJobObject failed");
            // not inheritable: the console host duplicates its ends
            if (!CreatePipe(out inRead, out inWrite, IntPtr.Zero, 0) || !CreatePipe(out outRead, out outWrite, IntPtr.Zero, 0))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "CreatePipe failed");
            int hr = CreatePseudoConsole(new COORD { X = (short)columns, Y = (short)rows }, inRead, outWrite, 0, out console);
            if (hr != 0) throw new Win32Exception(hr, "CreatePseudoConsole failed");

            IntPtr size = IntPtr.Zero;
            InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref size);
            attributes = Marshal.AllocHGlobal(size);
            if (!InitializeProcThreadAttributeList(attributes, 1, 0, ref size))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "InitializeProcThreadAttributeList failed");
            if (!UpdateProcThreadAttribute(attributes, 0, ProcThreadAttributePseudoConsole, console, IntPtr.Size, IntPtr.Zero, IntPtr.Zero))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "UpdateProcThreadAttribute failed");

            var si = new STARTUPINFOEX { lpAttributeList = attributes };
            si.StartupInfo.cb = Marshal.SizeOf<STARTUPINFOEX>();
            // empty standard handles: without them the program inherits the server's redirected stdio instead of the console
            si.StartupInfo.dwFlags = StartfUseStdHandles;
            var commandLine = new StringBuilder(ChildProcess.QuoteArgument(program));
            foreach (var a in arguments) commandLine.Append(' ').Append(ChildProcess.QuoteArgument(a));
            if (!CreateProcessW(program, commandLine.Append('\0').ToString().ToCharArray(), IntPtr.Zero, IntPtr.Zero, false,
                    CreateSuspended | ExtendedStartupInfoPresent, IntPtr.Zero, null, ref si, out info))
                throw new Win32Exception(Marshal.GetLastWin32Error(), $"CreateProcess failed for {program}");
            var process = new SafeProcessHandle(info.hProcess, ownsHandle: true);
            using var thread = new SafeFileHandle(info.hThread, ownsHandle: true);
            info = default;
            if (!AssignProcessToJobObject(job, process) || ResumeThread(thread) == uint.MaxValue)
            {
                var error = Marshal.GetLastWin32Error();
                TerminateProcess(process, 1);
                process.Dispose();
                throw new Win32Exception(error, "starting the program in its job failed");
            }
            var started = new PseudoConsoleProcess(job, process, GetProcessId(process), console, inWrite, outRead, output);
            inWrite = outRead = null;
            console = IntPtr.Zero;
            return started;
        }
        catch
        {
            if (info.hProcess != IntPtr.Zero) { TerminateProcess(new SafeProcessHandle(info.hProcess, true), 1); CloseHandle(info.hThread); }
            if (console != IntPtr.Zero) ClosePseudoConsole(console);
            job.Dispose();
            inWrite?.Dispose(); outRead?.Dispose();
            throw;
        }
        finally
        {
            // the console host holds its own copies of these ends
            inRead?.Dispose(); outWrite?.Dispose();
            if (attributes != IntPtr.Zero) { DeleteProcThreadAttributeList(attributes); Marshal.FreeHGlobal(attributes); }
        }
    }

    private void Read()
    {
        var decoder = new UTF8Encoding(false).GetDecoder();
        var bytes = new byte[8192];
        var chars = new char[8192 + 4];
        try
        {
            for (int n; (n = _output.Read(bytes, 0, bytes.Length)) > 0; )
            {
                Interlocked.Exchange(ref _lastOutput, Environment.TickCount64);
                int count = decoder.GetChars(bytes, 0, n, chars, 0);
                if (count > 0) _deliver(new string(chars, 0, count));
            }
        }
        catch (IOException) { /* the console closed its end */ }
        catch (ObjectDisposedException) { }
    }

    /// <summary>The program ended: the console's last output is read, then the console closes and the reader sees the end.</summary>
    private void Ended()
    {
        var deadline = Environment.TickCount64 + 2_000;
        while (Environment.TickCount64 - Interlocked.Read(ref _lastOutput) < Settle.TotalMilliseconds && Environment.TickCount64 < deadline)
            Thread.Sleep(25);
        CloseConsole();
        _reader.Join(TimeSpan.FromSeconds(5));
        _exited.TrySetResult(GetExitCodeProcess(_process, out uint code) ? unchecked((int)code) : -1);
    }

    private void CloseConsole()
    {
        if (Interlocked.Exchange(ref _closed, 1) != 0) return;
        ClosePseudoConsole(_console);
        _console = IntPtr.Zero;
        _input.Dispose();
    }

    public void Write(string text)
    {
        if (Volatile.Read(ref _closed) != 0) throw new InvalidOperationException("the console is closed");
        var bytes = Encoding.UTF8.GetBytes(text);
        _input.Write(bytes);
        _input.Flush();
    }

    public void Resize(int columns, int rows)
    {
        if (Volatile.Read(ref _closed) != 0) return;
        int hr = ResizePseudoConsole(_console, new COORD { X = (short)columns, Y = (short)rows });
        if (hr != 0) throw new Win32Exception(hr, "ResizePseudoConsole failed");
    }

    public void Kill()
    {
        if (!_job.IsClosed) TerminateJobObject(_job, 1);
    }

    public void Dispose()
    {
        Kill();
        // the process handle stays open under a pending wait
        bool ended = _exited.Task.Wait(TimeSpan.FromSeconds(5));
        CloseConsole();
        _reader.Join(TimeSpan.FromSeconds(2));
        _output.Dispose();
        _job.Dispose();
        if (ended) _process.Dispose();
    }

    private static readonly IntPtr ProcThreadAttributePseudoConsole = 0x20016;

    [StructLayout(LayoutKind.Sequential)]
    private struct COORD { public short X, Y; }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern int CreatePseudoConsole(COORD size, SafeFileHandle input, SafeFileHandle output, uint flags, out IntPtr console);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern int ResizePseudoConsole(IntPtr console, COORD size);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern void ClosePseudoConsole(IntPtr console);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CreatePipe(out SafeFileHandle read, out SafeFileHandle write, IntPtr attributes, uint size);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool CreateProcessW(string? application, char[] commandLine, IntPtr processAttributes, IntPtr threadAttributes, bool inheritHandles,
        uint flags, IntPtr environment, string? directory, ref STARTUPINFOEX startup, out PROCESS_INFORMATION info);
}
