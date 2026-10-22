using System.Diagnostics;
using System.Globalization;
using System.Reflection;
using System.Runtime.InteropServices;
using Xunit.Sdk;

namespace Corvus.Tests;

/// <summary>
/// Takes machine-wide permits for a test class's heavy resource (<see cref="MachinePermits"/>) while the class runs. A
/// class needs one through this attribute on it, an enclosing class or a test method; <see cref="IdaFactAttribute"/> and
/// <see cref="GhidraFactAttribute"/> tests need their engine's without it.
/// </summary>
[AttributeUsage(AttributeTargets.Class | AttributeTargets.Method, AllowMultiple = true)]
public sealed class PermitAttribute(string resource) : Attribute
{
    public string Resource { get; } = resource;
}

/// <summary>
/// Machine-wide permits for heavy resources, shared by every test process on the machine (lanes' runs and the background
/// run alike), so engines and real programs stay bounded however many runs start. A permit is a slot file opened for
/// exclusive use: a process that crashes releases its permits with its handles.
/// </summary>
public static class MachinePermits
{
    /// <summary>Permits per resource.</summary>
    public static readonly IReadOnlyDictionary<string, int> Counts = new Dictionary<string, int>
    {
        ["engine-ida"] = 2, ["engine-ghidra"] = 2, ["live"] = 2, ["reference-tool"] = 4,
    };

    private static readonly TimeSpan Poll = TimeSpan.FromMilliseconds(200);

    /// <summary>
    /// How long a collection waits for its permits without progress (no permit changing hands, no holder finishing a
    /// test) before its tests fail, naming who holds them.
    /// </summary>
    public static readonly TimeSpan WaitLimit = TimeSpan.FromMinutes(10);

    /// <summary>How often a holder reports progress while a test runs, so only a holder that stopped runs out a wait.</summary>
    public static readonly TimeSpan Heartbeat = TimeSpan.FromSeconds(60);
    private static readonly object LogLock = new();

    /// <summary>The folder of the slot files, in the machine's temporary folder rather than the run's own.</summary>
    public static string Folder => Path.Combine(LeakGuard.SharedTemp, "corvus-test-data", "permits");

    /// <summary>
    /// The resources a test collection's runnable cases need, in name order; empty when none does or every case is
    /// skipped. Throws for a resource without a count.
    /// </summary>
    public static IReadOnlyList<string> Needed(IEnumerable<IXunitTestCase> testCases)
    {
        var needed = new SortedSet<string>(StringComparer.Ordinal);
        foreach (var testCase in testCases.Where(t => string.IsNullOrEmpty(t.SkipReason)))
        {
            var method = testCase.Method.ToRuntimeMethod();
            if (method.IsDefined(typeof(IdaFactAttribute))) needed.Add("engine-ida");
            if (method.IsDefined(typeof(GhidraFactAttribute))) needed.Add("engine-ghidra");
            foreach (var permit in method.GetCustomAttributes<PermitAttribute>()) needed.Add(permit.Resource);
            for (var type = testCase.TestMethod.TestClass.Class.ToRuntimeType(); type != null; type = type.DeclaringType)
                foreach (var permit in type.GetCustomAttributes<PermitAttribute>(false)) needed.Add(permit.Resource);
        }
        foreach (var resource in needed.Where(r => !Counts.ContainsKey(r)))
            throw new ArgumentException($"No permit count for '{resource}' (MachinePermits.Counts).");
        return [.. needed];
    }

    /// <summary>
    /// Waits for one permit of each resource, taken in the order given (name order, so two holders never wait on each
    /// other), and returns them as one handle with the time waited. Cancellation releases what was taken and throws; so
    /// does a wait that sees no progress for <see cref="WaitLimit"/>, with a <see cref="TimeoutException"/> naming the
    /// slots and their holders.
    /// </summary>
    public static Task<(PermitHandle Held, TimeSpan Waited)> TakeAsync(IReadOnlyList<string> resources, CancellationToken cancellation = default) =>
        // The perf run holds every permit itself (test.ps1 -Perf), so its own tests take none.
        Environment.GetEnvironmentVariable("CORVUS_PERMITS_HELD") == "1"
            ? Task.FromResult((new PermitHandle(), TimeSpan.Zero))
            : TakeAsync(resources, Folder, Counts, cancellation, WaitLimit, Heartbeat);

    internal static async Task<(PermitHandle Held, TimeSpan Waited)> TakeAsync(IReadOnlyList<string> resources, string folder,
        IReadOnlyDictionary<string, int> counts, CancellationToken cancellation, TimeSpan? limit = null, TimeSpan? heartbeat = null)
    {
        var watch = Stopwatch.StartNew();
        var held = new PermitHandle(heartbeat);
        try
        {
            foreach (var resource in resources)
            {
                var dir = Path.Combine(folder, resource);
                Directory.CreateDirectory(dir);
                var count = counts[resource];
                var quiet = Stopwatch.StartNew();
                var seen = Owners(dir, count);
                FileStream? slot;
                while ((slot = TryTake(dir, count)) == null)
                {
                    // A permit changing hands or a holder's progress restarts the limit; one holder keeping its
                    // permit without either fails the wait.
                    if (Owners(dir, count) is var now && now != seen) (seen, quiet) = (now, Stopwatch.StartNew());
                    else if (quiet.Elapsed > limit)
                        throw new TimeoutException($"No {resource} permit within {limit.Value.TotalMinutes:0.##} min without progress: {Holders(dir, count)}.");
                    await Task.Delay(Poll, cancellation);
                }
                held.Add(slot);
            }
        }
        catch
        {
            held.Dispose();
            throw;
        }
        return (held, watch.Elapsed);
    }

    /// <summary>
    /// Appends a wait to the file CORVUS_PERMIT_LOG names (test.ps1 adds the waits to the run's time record): one
    /// tab-separated line of resources, seconds and collection. Nothing without the variable.
    /// </summary>
    public static void Record(IReadOnlyList<string> resources, TimeSpan waited, string collection)
    {
        if (Environment.GetEnvironmentVariable("CORVUS_PERMIT_LOG") is not { Length: > 0 } log) return;
        var line = string.Join('\t', string.Join(',', resources), waited.TotalSeconds.ToString("0.###", CultureInfo.InvariantCulture), collection);
        lock (LogLock) File.AppendAllLines(log, [line]);
    }

    /// <summary>Each slot file of a resource and who holds it: the process id and command line where Windows reports them.</summary>
    private static string Holders(string dir, int count) => string.Join("; ", Enumerable.Range(0, count).Select(i =>
    {
        var slot = Path.Combine(dir, $"slot-{i}");
        var holders = OperatingSystem.IsWindows() ? FileHolders.Of(slot) : [];
        return holders.Count == 0
            ? $"{slot} is held by another process"
            : $"{slot} is held by " + string.Join(", ", holders.Select(h => $"process {h.Pid}" + (h.CommandLine is { } c ? $" ({c})" : "")));
    }));

    /// <summary>
    /// The owner records of a resource's slots, joined: "pid test token progress" from a test process, "pid script" from
    /// a script. A record a holder is rewriting reads as unknown; a script's record whose process lives reads as new on
    /// every call, since a script reports no progress of its own.
    /// </summary>
    private static string Owners(string dir, int count) => string.Join("|", Enumerable.Range(0, count).Select(i =>
    {
        string record;
        try
        {
            using var reader = new StreamReader(new FileStream(Path.Combine(dir, $"slot-{i}{OwnerSuffix}"), FileMode.Open, FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete));
            record = reader.ReadToEnd();
        }
        catch (FileNotFoundException) { return ""; }
        catch (DirectoryNotFoundException) { return ""; }
        catch (IOException) { return "?"; }
        catch (UnauthorizedAccessException) { return "?"; }
        return record.Split(' ') is [var pid, "script"] && int.TryParse(pid, out var id) && Alive(id) ? record + " " + Stopwatch.GetTimestamp() : record;
    }));

    private static bool Alive(int pid)
    {
        try
        {
            using var process = Process.GetProcessById(pid);
            return !process.HasExited;
        }
        catch (ArgumentException) { return false; }
        // A process this one may not query is still running.
        catch (System.ComponentModel.Win32Exception) { return true; }
        catch (InvalidOperationException) { return false; }
    }

    internal const string OwnerSuffix = ".owner";

    private static FileStream? TryTake(string dir, int count)
    {
        for (var i = 0; i < count; i++)
        {
            try { return new FileStream(Path.Combine(dir, $"slot-{i}"), FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None); }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
        }
        return null;
    }

}

/// <summary>
/// Permits held together. Each slot has an owner record beside it, rewritten on <see cref="Progress"/> and on each
/// heartbeat, which tells a waiter the holder is still alive; disposing releases every slot.
/// </summary>
public sealed class PermitHandle : IDisposable
{
    private readonly List<(FileStream Slot, string Owner)> _slots = [];
    private readonly string _token = Guid.NewGuid().ToString("N");
    private readonly Timer? _heartbeat;
    private long _progress;

    /// <summary>Holds no permit yet; <paramref name="heartbeat"/> null reports progress only through <see cref="Progress"/>.</summary>
    public PermitHandle(TimeSpan? heartbeat = null)
    {
        if (heartbeat is { } every) _heartbeat = new Timer(_ => Progress(), null, every, every);
    }

    internal void Add(FileStream slot)
    {
        lock (_slots)
        {
            _slots.Add((slot, slot.Name + MachinePermits.OwnerSuffix));
            Write(_slots[^1].Owner);
        }
    }

    /// <summary>Reports that the holder finished a unit of work, such as a test; no effect once disposed.</summary>
    public void Progress()
    {
        Interlocked.Increment(ref _progress);
        lock (_slots)
            foreach (var (_, owner) in _slots) Write(owner);
    }

    // A failed write only delays a waiter's restart of its limit.
    private void Write(string owner)
    {
        try
        {
            using var stream = new FileStream(owner, FileMode.Create, FileAccess.Write, FileShare.ReadWrite | FileShare.Delete);
            using var writer = new StreamWriter(stream);
            writer.Write($"{Environment.ProcessId} test {_token} {Interlocked.Read(ref _progress)}");
        }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
    }

    public void Dispose()
    {
        _heartbeat?.Dispose();
        lock (_slots)
        {
            foreach (var (slot, _) in _slots) slot.Dispose();
            _slots.Clear();
        }
    }
}

/// <summary>
/// The processes holding a file open, from the Restart Manager, with their command lines; empty when Windows reports none
/// or refuses the query. A command line is null where the process cannot be opened.
/// </summary>
internal static class FileHolders
{
    public static IReadOnlyList<(int Pid, string? CommandLine)> Of(string path)
    {
        var key = new char[33];
        if (RmStartSession(out var session, 0, key) != 0) return [];
        try
        {
            if (RmRegisterResources(session, 1, [path], 0, IntPtr.Zero, 0, IntPtr.Zero) != 0) return [];
            uint count = 0;
            var result = RmGetList(session, out var needed, ref count, null, out _);
            if (result == 0 || result != MoreData) return [];
            var info = new RM_PROCESS_INFO[needed];
            count = needed;
            if (RmGetList(session, out _, ref count, info, out _) != 0) return [];
            return [.. info.Take((int)count).Select(p => (p.Process.dwProcessId, CommandLine(p.Process.dwProcessId)))];
        }
        finally { _ = RmEndSession(session); }
    }

    private static string? CommandLine(int pid)
    {
        var process = OpenProcess(QueryLimitedInformation, false, pid);
        if (process == IntPtr.Zero) return null;
        try
        {
            // The first call fails with the length it needs.
            _ = NtQueryInformationProcess(process, ProcessCommandLineInformation, IntPtr.Zero, 0, out var length);
            if (length == 0) return null;
            var buffer = Marshal.AllocHGlobal(length);
            try
            {
                if (NtQueryInformationProcess(process, ProcessCommandLineInformation, buffer, length, out _) != 0) return null;
                // A UNICODE_STRING: its length in bytes, then a pointer to its characters.
                var text = Marshal.ReadIntPtr(buffer, IntPtr.Size);
                return Marshal.PtrToStringUni(text, Marshal.ReadInt16(buffer) / 2);
            }
            finally { Marshal.FreeHGlobal(buffer); }
        }
        finally { CloseHandle(process); }
    }

    private const int MoreData = 234;
    private const uint QueryLimitedInformation = 0x1000;
    private const int ProcessCommandLineInformation = 60;

    [StructLayout(LayoutKind.Sequential)]
    private struct RM_UNIQUE_PROCESS
    {
        public int dwProcessId;
        public System.Runtime.InteropServices.ComTypes.FILETIME ProcessStartTime;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct RM_PROCESS_INFO
    {
        public RM_UNIQUE_PROCESS Process;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)] public string strAppName;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 64)] public string strServiceShortName;
        public int ApplicationType;
        public uint AppStatus;
        public uint TSSessionId;
        [MarshalAs(UnmanagedType.Bool)] public bool bRestartable;
    }

    [DllImport("rstrtmgr.dll", CharSet = CharSet.Unicode)]
    private static extern int RmStartSession(out uint session, int flags, [Out] char[] key);

    [DllImport("rstrtmgr.dll")]
    private static extern int RmEndSession(uint session);

    [DllImport("rstrtmgr.dll", CharSet = CharSet.Unicode)]
    private static extern int RmRegisterResources(uint session, uint files, string[] names, uint applications, IntPtr processes, uint services, IntPtr serviceNames);

    [DllImport("rstrtmgr.dll")]
    private static extern int RmGetList(uint session, out uint needed, ref uint count, [In, Out] RM_PROCESS_INFO[]? info, out uint rebootReasons);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint access, bool inherit, int pid);

    [DllImport("kernel32.dll")]
    private static extern bool CloseHandle(IntPtr handle);

    [DllImport("ntdll.dll")]
    private static extern int NtQueryInformationProcess(IntPtr process, int infoClass, IntPtr buffer, int length, out int returned);
}
