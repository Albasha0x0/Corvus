using System.Globalization;

namespace Corvus.Native.Providers;

/// <summary>Memory cap of an engine worker's process tree (Windows: its Job Object).</summary>
public static class EngineMemoryLimit
{
    /// <summary>Limit in MB; 0 or off: none. Default: three quarters of the memory available to this process.</summary>
    public const string Variable = "NDM_ENGINE_MEMORY_MB";

    /// <summary>The limit in bytes for a worker: <paramref name="configured"/> (0: none), else <see cref="Variable"/>, else the default.</summary>
    public static long? Resolve(long? configured) =>
        configured is { } c ? (c > 0 ? c : null) : Parse(Environment.GetEnvironmentVariable(Variable), GC.GetGCMemoryInfo().TotalAvailableMemoryBytes);

    /// <summary>A <see cref="Variable"/> value against <paramref name="available"/> bytes; unset or unreadable falls back to the default.</summary>
    public static long? Parse(string? value, long available)
    {
        var v = value?.Trim().ToLowerInvariant();
        if (v is "0" or "off" or "none") return null;
        if (long.TryParse(v, NumberStyles.None, CultureInfo.InvariantCulture, out var mb) && mb > 0) return mb << 20;
        return available > 0 ? available / 4 * 3 : null;
    }
}
