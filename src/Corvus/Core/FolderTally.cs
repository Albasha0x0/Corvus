using System.Collections.Concurrent;

namespace Corvus.Core;

/// <summary>A cache folder's entry count and size, measured at most every 30 s in the background; a stale count is served meanwhile.</summary>
internal static class FolderTally
{
    private const long MaxAgeMs = 30_000;
    /// <summary>How long a first report waits for its count before saying it is being counted.</summary>
    private static readonly TimeSpan FirstWait = TimeSpan.FromSeconds(2);
    private static readonly ConcurrentDictionary<string, (long At, int Entries, long Bytes)> Last = new(StringComparer.OrdinalIgnoreCase);
    private static readonly ConcurrentDictionary<string, Task> Measuring = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>The count and size; (-1, -1) while a first count is still being taken.</summary>
    public static (int Entries, long Bytes) Of(string folder, Func<(int Entries, long Bytes)> measure)
    {
        bool known = Last.TryGetValue(folder, out var last);
        if (known && Environment.TickCount64 - last.At < MaxAgeMs) return (last.Entries, last.Bytes);
        if (!Measuring.TryGetValue(folder, out var task))
        {
            Task? created = null;
            // A thread of its own: behind busy pool threads, even a small folder's count missed the first wait.
            created = new Task(() =>
            {
                try
                {
                    var (entries, bytes) = measure();
                    var counted = (Environment.TickCount64, entries, bytes);
                    Last[folder] = counted;
                    // Forgotten while counting: the count predates the change.
                    if (!Measuring.TryGetValue(folder, out var current) || current != created) Last.TryRemove(new(folder, counted));
                }
                finally { Measuring.TryRemove(new(folder, created!)); }
            }, TaskCreationOptions.LongRunning);
            task = Measuring.GetOrAdd(folder, created);
            if (task == created) created.Start(TaskScheduler.Default);
        }
        if (known) return (last.Entries, last.Bytes);
        task.Wait(FirstWait);
        return Last.TryGetValue(folder, out last) ? (last.Entries, last.Bytes) : (-1, -1);
    }

    /// <summary>After a change the caller made itself (an eviction): the next report measures again.</summary>
    public static void Forget(string folder)
    {
        Measuring.TryRemove(folder, out _);
        Last.TryRemove(folder, out _);
    }

    /// <summary>"N entries, M MB" or that the folder is being counted.</summary>
    public static string Text(int entries, long bytes, Func<long, string> megabytes, string noun = "entries") =>
        entries < 0 ? $"{noun} being counted" : $"{entries} {noun}, {megabytes(bytes)}";
}
