using System.Diagnostics;

namespace Corvus.Tests;

/// <summary>Private memory this process holds, for streaming budgets.</summary>
internal static class ProcessMemory
{
    /// <summary>
    /// Bytes: resident anonymous pages (RssAnon) on Linux, where PrivateMemorySize64 is VmData, address space that swung
    /// from +9 to +657 MB across runs of one 500 MB stream holding +0 MB; PrivateMemorySize64 (committed private bytes) elsewhere.
    /// </summary>
    public static long Private()
    {
        if (OperatingSystem.IsLinux())
            foreach (var line in File.ReadLines("/proc/self/status"))
                if (line.StartsWith("RssAnon:", StringComparison.Ordinal))
                    return long.Parse(line.AsSpan("RssAnon:".Length).Trim().TrimEnd("kB").Trim(), System.Globalization.CultureInfo.InvariantCulture) * 1024;
        using var process = Process.GetCurrentProcess();
        return process.PrivateMemorySize64;
    }
}
