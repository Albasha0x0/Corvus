extern alias TraceEventPackage;

using System.Buffers.Binary;
using System.Net;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using TraceEventPackage::Microsoft.Diagnostics.Tracing;
using TraceEventPackage::Microsoft.Diagnostics.Tracing.Session;
using Corvus.Core;

namespace Corvus.Native.Diagnostics;

/// <summary>One activity trace entry: time, category (file, registry, network, process), OS name, and a started child's id.</summary>
public sealed record ActivityEntry(DateTime Time, string Category, string Name, int? ProcessId = null);

/// <summary>Why a trace cannot be collected on this machine, and the fix.</summary>
public sealed record ActivityTraceUnavailable(string Reason, string Remediation);

/// <summary>A running trace of one process.</summary>
public interface IActivityTrace
{
    /// <summary>Delivers what the OS still buffers, then ends the trace.</summary>
    Task StopAsync();
}

/// <summary>The operating system's diagnostics channel for the file, registry, network and process activity of one process.</summary>
public interface IActivityTraceSource
{
    /// <summary>The channel as the platform names it.</summary>
    string Name { get; }

    ActivityTraceUnavailable? Unavailable();

    /// <summary>Starts tracing <paramref name="processId"/>; entries reach <paramref name="record"/> on the reader's thread, in order.</summary>
    IActivityTrace Start(int processId, Action<ActivityEntry> record);
}

public static class ActivityTraceSources
{
    public static IActivityTraceSource ForThisMachine() =>
        OperatingSystem.IsWindows() ? new EventTraceSource() : new UnavailableSource(OperatingSystem.IsMacOS() ? "fs_usage" : "strace");

    private sealed class UnavailableSource(string name) : IActivityTraceSource
    {
        public string Name => name;

        public ActivityTraceUnavailable? Unavailable() =>
            new($"Activity traces are collected through event tracing on Windows; the {name} reader is not available yet.", $"trace the program on Windows, or run it under {name}");

        public IActivityTrace Start(int processId, Action<ActivityEntry> record) =>
            throw new ToolError(ErrorCode.ProviderUnavailable, Unavailable()!.Reason, Unavailable()!.Remediation);
    }
}

/// <summary>A real-time ETW session with the kernel file, registry, network and process providers, filtered to one process.</summary>
[SupportedOSPlatform("windows")]
public sealed class EventTraceSource : IActivityTraceSource
{
    /// <summary>Session names: the prefix, the server's process id and a counter.</summary>
    public const string SessionPrefix = "Corvus-Timeline-";
    private static readonly Guid KernelFile = new("edd08927-9cc4-4e65-b970-c2560fb5c289");
    private static readonly Guid KernelRegistry = new("70eb4f03-c1de-4f73-a051-33d13d5413bd");
    private static readonly Guid KernelNetwork = new("7dd42a49-5329-4832-8dfd-43d979153a88");
    private static readonly Guid KernelProcess = new("22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716");
    private static int _next;

    public string Name => "event tracing (ETW)";

    public ActivityTraceUnavailable? Unavailable() => null;

    public IActivityTrace Start(int processId, Action<ActivityEntry> record)
    {
        RemoveStale();
        var name = $"{SessionPrefix}{Environment.ProcessId}-{Interlocked.Increment(ref _next)}";
        TraceEventSession session;
        try
        {
            session = new TraceEventSession(name) { StopOnDispose = true };
        }
        catch (UnauthorizedAccessException)
        {
            throw new ToolError(ErrorCode.AccessDenied, "An event tracing session needs administrator rights or membership in Performance Log Users.",
                "run the server as an administrator, or add its user to Performance Log Users");
        }
        try
        {
            session.EnableProvider(KernelFile, TraceEventLevel.Informational, 0x80); // KERNEL_FILE_KEYWORD_CREATE
            session.EnableProvider(KernelRegistry, TraceEventLevel.Informational, 0x1000 | 0x2000 | 0x100 | 0x400); // CreateKey, OpenKey, SetValueKey, QueryValueKey
            session.EnableProvider(KernelNetwork, TraceEventLevel.Informational, 0x10 | 0x20); // IPv4, IPv6
            session.EnableProvider(KernelProcess, TraceEventLevel.Informational, 0x10); // WINEVENT_KEYWORD_PROCESS
        }
        catch
        {
            session.Dispose();
            throw;
        }
        var decoder = new ActivityDecoder(processId, DeviceMap.Load(), System.Security.Principal.WindowsIdentity.GetCurrent().User?.Value);
        foreach (var (keyObject, path) in OpenKeys.Read(processId)) decoder.Known(keyObject, path);
        return new Trace(session, decoder, record);
    }

    /// <summary>Stops sessions a server that is no longer running left behind (they outlive their process).</summary>
    private static void RemoveStale()
    {
        try
        {
            foreach (var s in TraceEventSession.GetActiveSessionNames())
            {
                if (!s.StartsWith(SessionPrefix, StringComparison.Ordinal) || s[SessionPrefix.Length..].Split('-')[0] is not { } owner
                    || !int.TryParse(owner, out var pid) || pid == Environment.ProcessId || Alive(pid)) continue;
                TraceEventSession.GetActiveSession(s)?.Stop(noThrow: true);
            }
        }
        catch (Exception e) when (e is UnauthorizedAccessException or COMException) { /* listing needs the same rights as starting */ }
    }

    private static bool Alive(int pid)
    {
        try
        {
            using var p = System.Diagnostics.Process.GetProcessById(pid);
            return !p.HasExited;
        }
        catch (ArgumentException) { return false; }
        catch (InvalidOperationException) { return false; }
    }

    private sealed class Trace : IActivityTrace
    {
        private readonly TraceEventSession _session;
        private readonly Task _pump;
        private long _lastEvent = Environment.TickCount64;
        private readonly int _processId;
        private readonly ManualResetEventSlim _processStopped = new();

        public Trace(TraceEventSession session, ActivityDecoder decoder, Action<ActivityEntry> record)
        {
            _session = session;
            _processId = decoder.ProcessId;
            session.Source.Dynamic.All += e =>
            {
                Volatile.Write(ref _lastEvent, Environment.TickCount64);
                if (e.ProviderGuid == KernelProcess && (int)e.ID == 2 && e.ProcessID == _processId) _processStopped.Set(); // ProcessStop
                if (Decode(decoder, e) is { } entry) record(entry);
            };
            _pump = Task.Factory.StartNew(() => session.Source.Process(), CancellationToken.None, TaskCreationOptions.LongRunning, TaskScheduler.Default);
        }

        public async Task StopAsync()
        {
            try { _session.Flush(); }
            catch (Exception e) when (e is COMException or InvalidOperationException) { /* already stopped */ }
            // The last events can trail a flush by over a second; an ended program's stop event follows them (wait at most 10 s).
            if (!Alive(_processId)) await Task.Run(() => _processStopped.Wait(10_000)).ConfigureAwait(false);
            // Flushed buffers arrive up to 1 s later: wait that long, then for a 400 ms quiet spell, at most 4 s.
            var flushed = Environment.TickCount64;
            while (Environment.TickCount64 - flushed < 4_000
                   && (Environment.TickCount64 - flushed < 1_000 || Environment.TickCount64 - Volatile.Read(ref _lastEvent) < 400))
                await Task.Delay(100).ConfigureAwait(false);
            _session.Dispose();
            await Task.WhenAny(_pump, Task.Delay(5_000)).ConfigureAwait(false);
        }

        private static ActivityEntry? Decode(ActivityDecoder d, TraceEvent e)
        {
            var at = e.TimeStamp.ToUniversalTime();
            var id = (int)e.ID;
            if (e.ProviderGuid == KernelFile)
                return id == 12 && e.ProcessID == d.ProcessId ? d.File(at, e.PayloadByName("FileName") as string, Convert.ToInt32(e.PayloadByName("CreateOptions") ?? 0)) : null;
            if (e.ProviderGuid == KernelRegistry)
            {
                if (e.ProcessID != d.ProcessId) return null;
                int status = Convert.ToInt32(e.PayloadByName("Status") ?? -1);
                return id switch
                {
                    1 or 2 => d.Key(at, status, Convert.ToUInt64(e.PayloadByName("BaseObject") ?? 0UL), Convert.ToUInt64(e.PayloadByName("KeyObject") ?? 0UL),
                        e.PayloadByName("BaseName") as string, e.PayloadByName("RelativeName") as string),
                    5 or 7 => d.Value(at, status, Convert.ToUInt64(e.PayloadByName("KeyObject") ?? 0UL), e.PayloadByName("KeyName") as string, e.PayloadByName("ValueName") as string),
                    _ => null,
                };
            }
            if (e.ProviderGuid == KernelNetwork)
                return e.PayloadByName("PID") is { } pid && Convert.ToInt32(pid) == d.ProcessId ? d.Network(at, id, e.PayloadByName("daddr"), e.PayloadByName("dport")) : null;
            if (e.ProviderGuid == KernelProcess && id == 1 && e.PayloadByName("ParentProcessID") is { } parent && Convert.ToInt32(parent) == d.ProcessId)
                return d.ProcessStart(at, Convert.ToInt32(e.PayloadByName("ProcessID") ?? 0), e.EventData());
            return null;
        }
    }
}

/// <summary>Turns kernel provider payloads into entries: DOS paths, joined HKLM/HKCU keys, endpoints and image names.</summary>
internal sealed class ActivityDecoder(int processId, DeviceMap devices, string? userSid)
{
    /// <summary>Key objects remembered for joining relative names; past this the map starts over.</summary>
    private const int MaxKeys = 100_000;
    private const int FileDirectoryFile = 0x1;
    private readonly Dictionary<ulong, string> _keys = [];
    private readonly HashSet<string> _datagrams = new(StringComparer.Ordinal);

    public int ProcessId => processId;

    /// <summary>A key the process held open before the trace started, by its key object and kernel path.</summary>
    public void Known(ulong keyObject, string path)
    {
        if (keyObject != 0 && path.Length > 0 && _keys.Count < MaxKeys) _keys[keyObject] = path;
    }

    public ActivityEntry? File(DateTime at, string? fileName, int createOptions) =>
        string.IsNullOrEmpty(fileName) || (createOptions & FileDirectoryFile) != 0 ? null : new(at, "file", devices.DosPath(fileName));

    /// <summary>A key opened or created; failed opens are left out.</summary>
    public ActivityEntry? Key(DateTime at, int status, ulong baseObject, ulong keyObject, string? baseName, string? relativeName)
    {
        if (status != 0) return null;
        var rel = relativeName ?? "";
        var parent = _keys.GetValueOrDefault(baseObject) ?? (string.IsNullOrEmpty(baseName) ? null : baseName);
        var full = rel.StartsWith('\\') || parent == null ? rel : rel.Length == 0 ? parent : parent.TrimEnd('\\') + "\\" + rel;
        if (full.Length == 0) return null;
        if (keyObject != 0)
        {
            if (_keys.Count >= MaxKeys) _keys.Clear();
            _keys[keyObject] = full;
        }
        return new(at, "registry", RegistryName(full, userSid));
    }

    /// <summary>A value read or written: its key and name.</summary>
    public ActivityEntry? Value(DateTime at, int status, ulong keyObject, string? keyName, string? valueName)
    {
        if (status != 0) return null;
        var key = _keys.GetValueOrDefault(keyObject) ?? (string.IsNullOrEmpty(keyName) ? null : keyName);
        if (key == null) return null;
        return new(at, "registry", RegistryName(key, userSid) + "\\" + (string.IsNullOrEmpty(valueName) ? "(Default)" : valueName));
    }

    /// <summary>TCP connects and accepts each time; UDP sends and receives once per endpoint.</summary>
    public ActivityEntry? Network(DateTime at, int eventId, object? address, object? port)
    {
        var protocol = eventId switch { 12 or 15 or 28 or 31 => "tcp", 42 or 43 or 58 or 59 => "udp", _ => null };
        if (protocol == null || Endpoint(address, port) is not { } endpoint) return null;
        var name = protocol + " " + endpoint;
        return protocol == "udp" && !_datagrams.Add(name) ? null : new(at, "network", name);
    }

    public ActivityEntry ProcessStart(DateTime at, int childId, byte[] data) =>
        new(at, "process", ImageName(data) is { } image ? devices.DosPath(image) : $"process {childId}", childId);

    /// <summary>An endpoint from the providers' fields: an IPv4 address as a 32-bit value or bytes, both in network byte order, and a port the same.</summary>
    public static string? Endpoint(object? address, object? port)
    {
        IPAddress ip;
        switch (address)
        {
            case int v4: ip = new IPAddress(BitConverter.GetBytes(v4)); break;
            case uint u4: ip = new IPAddress(BitConverter.GetBytes(u4)); break;
            case byte[] { Length: 4 or 16 } bytes: ip = new IPAddress(bytes); break;
            case IPAddress a: ip = a; break;
            default: return null;
        }
        if (port == null) return null;
        var p = BinaryPrimitives.ReverseEndianness((ushort)(Convert.ToInt64(port) & 0xFFFF));
        return new IPEndPoint(ip, p).ToString();
    }

    /// <summary>The ImageName of a ProcessStart event (version 3+), after 48 fixed bytes and the label SID the dynamic parser stops at.</summary>
    public static string? ImageName(byte[] data)
    {
        const int sidAt = 48;
        if (data.Length < sidAt + 8 || data[sidAt] != 1) return null;
        int start = sidAt + 8 + 4 * data[sidAt + 1];
        if (start >= data.Length) return null;
        var chars = MemoryMarshal.Cast<byte, char>(data.AsSpan(start, (data.Length - start) & ~1));
        int end = chars.IndexOf('\0');
        if (end <= 0) return null;
        return new string(chars[..end]);
    }

    /// <summary>A kernel registry path in the notation of Regedit and Process Monitor (HKLM, HKCU, HKU).</summary>
    public static string RegistryName(string path, string? userSid)
    {
        const string machine = @"\REGISTRY\MACHINE", users = @"\REGISTRY\USER";
        if (path.StartsWith(machine, StringComparison.OrdinalIgnoreCase) && (path.Length == machine.Length || path[machine.Length] == '\\'))
            return "HKLM" + path[machine.Length..];
        if (path.StartsWith(users, StringComparison.OrdinalIgnoreCase) && (path.Length == users.Length || path[users.Length] == '\\'))
        {
            var rest = path[users.Length..];
            if (userSid != null)
                foreach (var (hive, shown) in new[] { (userSid + "_Classes", @"HKCU\Software\Classes"), (userSid, "HKCU") })
                    if (rest.StartsWith("\\" + hive, StringComparison.OrdinalIgnoreCase) && (rest.Length == hive.Length + 1 || rest[hive.Length + 1] == '\\'))
                        return shown + rest[(hive.Length + 1)..];
            return "HKU" + rest;
        }
        return path;
    }
}

/// <summary>Registry keys a process held open before the trace, by key object, so later relative opens can be joined.</summary>
[SupportedOSPlatform("windows")]
internal static class OpenKeys
{
    private const int SystemExtendedHandleInformation = 64, KeyNameInformation = 3, EntrySize = 40;
    private const int StatusInfoLengthMismatch = unchecked((int)0xC0000004);
    private const uint ProcessDupHandle = 0x40, DuplicateSameAccess = 0x2;

    /// <summary>Kernel paths (\REGISTRY\MACHINE\...); empty when the handle table or the process cannot be read.</summary>
    public static IReadOnlyList<(ulong Object, string Path)> Read(int processId)
    {
        var keys = new List<(ulong, string)>();
        // The entry layout below is the 64-bit one.
        if (IntPtr.Size != 8) return keys;
        using var probe = Microsoft.Win32.Registry.LocalMachine.OpenSubKey("SOFTWARE");
        var process = OpenProcess(ProcessDupHandle, false, processId);
        if (probe == null || process == IntPtr.Zero) return keys;
        var table = IntPtr.Zero;
        try
        {
            table = HandleTable();
            long count = Marshal.ReadInt64(table);
            // The key type index differs between Windows builds; take it from a key handle of our own.
            ulong own = (ulong)probe.Handle.DangerousGetHandle();
            int self = Environment.ProcessId, keyType = -1;
            for (long i = 0; i < count && keyType < 0; i++)
            {
                var e = table + 16 + (nint)(i * EntrySize);
                if (Marshal.ReadInt64(e, 8) == self && (ulong)Marshal.ReadInt64(e, 16) == own) keyType = (ushort)Marshal.ReadInt16(e, 30);
            }
            if (keyType < 0) return keys;
            var name = Marshal.AllocHGlobal(4096);
            try
            {
                for (long i = 0; i < count; i++)
                {
                    var e = table + 16 + (nint)(i * EntrySize);
                    if (Marshal.ReadInt64(e, 8) != processId || (ushort)Marshal.ReadInt16(e, 30) != keyType) continue;
                    if (!DuplicateHandle(process, Marshal.ReadIntPtr(e, 16),GetCurrentProcess(), out var dup, 0, false, DuplicateSameAccess)) continue;
                    try
                    {
                        // KEY_NAME_INFORMATION: a byte length, then the name.
                        if (NtQueryKey(dup, KeyNameInformation, name, 4096, out _) == 0 && Marshal.ReadInt32(name) is var bytes and > 0 and <= 4092)
                            keys.Add(((ulong)Marshal.ReadInt64(e), Marshal.PtrToStringUni(name + 4, bytes / 2)));
                    }
                    finally { CloseHandle(dup); }
                }
            }
            finally { Marshal.FreeHGlobal(name); }
        }
        catch (Exception e) when (e is OutOfMemoryException or System.ComponentModel.Win32Exception) { /* names stay unjoined */ }
        finally
        {
            if (table != IntPtr.Zero) Marshal.FreeHGlobal(table);
            CloseHandle(process);
        }
        return keys;
    }

    /// <summary>SYSTEM_HANDLE_INFORMATION_EX: a count, a reserved field, then 40-byte entries (object, process id, handle value, access, type index at 30).</summary>
    private static IntPtr HandleTable()
    {
        for (int length = 4 << 20; ; )
        {
            var buffer = Marshal.AllocHGlobal(length);
            int status = NtQuerySystemInformation(SystemExtendedHandleInformation, buffer, length, out int needed);
            if (status == 0) return buffer;
            Marshal.FreeHGlobal(buffer);
            if (status != StatusInfoLengthMismatch || length >= 1 << 30) throw new System.ComponentModel.Win32Exception(status);
            length = Math.Max(length * 2, needed + (1 << 20));
        }
    }

    [DllImport("ntdll.dll")]
    private static extern int NtQuerySystemInformation(int informationClass, IntPtr buffer, int length, out int returned);

    [DllImport("ntdll.dll")]
    private static extern int NtQueryKey(IntPtr key, int informationClass, IntPtr buffer, int length, out int returned);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint access, bool inherit, int processId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool DuplicateHandle(IntPtr sourceProcess, IntPtr source, IntPtr targetProcess, out IntPtr target, uint access, bool inherit, uint options);

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();

    [DllImport("kernel32.dll")]
    private static extern bool CloseHandle(IntPtr handle);
}

/// <summary>NT device names to drive letters (QueryDosDevice), so \Device\HarddiskVolume2\x reads C:\x.</summary>
internal sealed class DeviceMap(IReadOnlyList<(string Device, string Drive)> drives)
{
    [SupportedOSPlatform("windows")]
    public static DeviceMap Load()
    {
        var map = new List<(string, string)>();
        var buffer = new char[1024];
        for (char c = 'A'; c <= 'Z'; c++)
        {
            int n = QueryDosDeviceW($"{c}:", buffer, buffer.Length);
            if (n > 0 && new string(buffer, 0, n).Split('\0')[0] is { Length: > 0 } device) map.Add((device, $"{c}:"));
        }
        return new DeviceMap(map);
    }

    public string DosPath(string path)
    {
        if (path.StartsWith(@"\??\", StringComparison.Ordinal)) return path[4..];
        if (path.StartsWith(@"\Device\Mup\", StringComparison.OrdinalIgnoreCase)) return @"\\" + path[12..];
        foreach (var (device, drive) in drives)
            if (path.StartsWith(device, StringComparison.OrdinalIgnoreCase) && (path.Length == device.Length || path[device.Length] == '\\'))
                return drive + path[device.Length..];
        return path;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern int QueryDosDeviceW(string deviceName, [Out] char[] targetPath, int max);
}
