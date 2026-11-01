using System.Globalization;
using System.Runtime.InteropServices;

namespace Corvus.Native.Providers;

/// <summary>Linux restrictions a worker applies to itself, read back from /proc.</summary>
internal static class LinuxSandbox
{
    /// <summary>Set to 1 in a worker's environment to apply the restrictions at startup.</summary>
    public const string ApplyVariable = "CORVUS_WORKER_LINUX_SANDBOX";

    private const int PR_SET_NO_NEW_PRIVS = 38, RLIMIT_CORE = 4;
    private const int SysLandlockCreateRuleset = 444, SysLandlockRestrictSelf = 446;
    private const int LandlockCreateRulesetVersion = 1;

    private const int MakeChar = 6, MakeSock = 9, MakeFifo = 10, MakeBlock = 11;

    // A reader never creates device nodes, sockets or FIFOs.
    internal const ulong HandledSpecialFiles =
        (1UL << MakeChar) | (1UL << MakeSock) | (1UL << MakeFifo) | (1UL << MakeBlock);

    /// <summary>What this process runs under, as /proc reports it.</summary>
    /// <param name="NoNewPrivs">True when the no_new_privs flag is set; null when unreadable.</param>
    /// <param name="Landlock">The Landlock outcome: "abi N, special files refused", "unsupported" or "failed: errno N".</param>
    /// <param name="CoreLimitBytes">The soft core dump limit in bytes; -1 unlimited; null when unreadable.</param>
    /// <param name="DataLimitBytes">The soft data segment limit in bytes; -1 unlimited; null when unreadable.</param>
    public sealed record Settings(bool? NoNewPrivs, string Landlock, long? CoreLimitBytes, long? DataLimitBytes)
    {
        private static string Bytes(long? value) =>
            value is { } v ? (v < 0 ? "unlimited" : v.ToString(CultureInfo.InvariantCulture)) : "unknown";

        /// <summary>One line for server_status; unknown values read "unknown", never "off".</summary>
        public string Describe() =>
            $"no_new_privs {(NoNewPrivs is { } n ? (n ? "on" : "off") : "unknown")}, landlock {Landlock}, " +
            $"core dump limit {Bytes(CoreLimitBytes)}, data limit {Bytes(DataLimitBytes)}";
    }

    /// <summary>Applies the restrictions and returns what /proc reports; null off Linux.</summary>
    public static Settings? Apply()
    {
        if (!OperatingSystem.IsLinux()) return null;
        try
        {
            var denied = prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
            var deniedErrno = Marshal.GetLastWin32Error();
            var rlimit = new Rlimit(0, 0);
            // A failure shows in the limit read back below.
            _ = setrlimit(RLIMIT_CORE, ref rlimit);
            var landlock = denied != 0 ? $"failed: no_new_privs errno {deniedErrno}" : Landlock();
            return Read(File.ReadAllText("/proc/self/status"), File.ReadAllText("/proc/self/limits"), landlock);
        }
        catch (Exception ex) when (ex is DllNotFoundException or EntryPointNotFoundException or IOException or UnauthorizedAccessException)
        {
            return new Settings(null, "unknown", null, null);
        }
    }

    private static string Landlock()
    {
        var abi = syscall(SysLandlockCreateRuleset, 0, 0, LandlockCreateRulesetVersion);
        if (abi < 1) return "unsupported";
        var attribute = Marshal.AllocHGlobal(8);
        try
        {
            Marshal.WriteInt64(attribute, (long)HandledSpecialFiles);
            var ruleset = syscall(SysLandlockCreateRuleset, attribute, 8, 0);
            if (ruleset < 0) return $"failed: errno {Marshal.GetLastWin32Error()}";
            try
            {
                return syscall(SysLandlockRestrictSelf, (nint)ruleset, 0, 0) == 0
                    ? $"abi {abi}, special files refused"
                    : $"failed: errno {Marshal.GetLastWin32Error()}";
            }
            finally { _ = close((int)ruleset); }
        }
        finally { Marshal.FreeHGlobal(attribute); }
    }

    /// <summary>Settings parsed from /proc status and limits text; a missing field is null.</summary>
    internal static Settings Read(string status, string limits, string landlock) => new(
            NoNewPrivsOf(status),
            landlock,
            SoftLimitOf(limits, "Max core file size"),
            SoftLimitOf(limits, "Max data size"));

    /// <summary>The NoNewPrivs flag of a status text; null when absent or malformed.</summary>
    internal static bool? NoNewPrivsOf(string status)
    {
        foreach (var line in status.Split('\n'))
            if (line.StartsWith("NoNewPrivs:", StringComparison.Ordinal))
                return line[11..].Trim() switch { "1" => true, "0" => false, _ => null };
        return null;
    }

    /// <summary>The soft limit of a limits row; -1 unlimited, null when absent or malformed.</summary>
    internal static long? SoftLimitOf(string limits, string name)
    {
        foreach (var line in limits.Split('\n'))
        {
            if (!line.StartsWith(name, StringComparison.Ordinal)) continue;
            var soft = line[name.Length..].Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (soft.Length == 0) return null;
            if (soft[0] == "unlimited") return -1;
            return long.TryParse(soft[0], NumberStyles.None, CultureInfo.InvariantCulture, out var value) ? value : null;
        }
        return null;
    }

    [StructLayout(LayoutKind.Sequential)]
    private readonly record struct Rlimit(ulong Current, ulong Maximum);

    [DllImport("libc", SetLastError = true)]
    private static extern int prctl(int option, ulong a2, ulong a3, ulong a4, ulong a5);

    [DllImport("libc", SetLastError = true)]
    private static extern int setrlimit(int resource, ref Rlimit limit);

    [DllImport("libc", SetLastError = true)]
    private static extern long syscall(long number, nint a, nint b, nint c);

    [DllImport("libc", SetLastError = true)]
    private static extern int close(int fd);
}
