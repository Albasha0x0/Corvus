using System.Collections.Concurrent;

namespace Corvus.Core;

/// <summary>
/// A cache folder's entry count and size for status reports, measured at most every 30 s per folder: walking a large
/// engine cache on every server_status call took about a second, and past the sweep's 20 s limit under load.
/// </summary>
internal static class FolderTally
{
    private const long MaxAgeMs = 30_000;
    private static readonly ConcurrentDictionary<string, (long At, int Entries, long Bytes)> Last = new(StringComparer.OrdinalIgnoreCase);

    public static (int Entries, long Bytes) Of(string folder, Func<(int Entries, long Bytes)> measure)
    {
        long now = Environment.TickCount64;
        if (Last.TryGetValue(folder, out var last) && now - last.At < MaxAgeMs) return (last.Entries, last.Bytes);
        var (entries, bytes) = measure();
        Last[folder] = (now, entries, bytes);
        return (entries, bytes);
    }

    /// <summary>After a change the caller made itself (an eviction): the next report measures again.</summary>
    public static void Forget(string folder) => Last.TryRemove(folder, out _);
}
