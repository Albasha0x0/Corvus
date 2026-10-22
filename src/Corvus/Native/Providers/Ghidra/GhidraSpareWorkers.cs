namespace Corvus.Native.Providers.Ghidra;

/// <summary>
/// Started and initialized Ghidra workers with no program open, one per launch command, so the next open adopts one
/// instead of starting a JVM. A spare is kept while a provider uses its command and for <see cref="Linger"/> after the
/// last one is disposed, so providers that follow one another share it; a spare that fails to start is dropped.
/// </summary>
internal static class GhidraSpareWorkers
{
    private sealed class Slot
    {
        public WorkerConnection? Spare;
        public bool Starting;
        public WorkerConnection? Launched;
        public Task? Start;
        public int Users;
        public Timer? End;
    }

    private static readonly Dictionary<string, Slot> Slots = new(StringComparer.Ordinal);
    private static readonly object Sync = new();

    /// <summary>How long a spare outlives the last provider of its command.</summary>
    internal static readonly TimeSpan Linger = TimeSpan.FromSeconds(60);

    /// <summary>The key of a launch: what the JVM is started with and how its connection cancels.</summary>
    public static string Command(ChildProcessStart start, TimeSpan cancelGrace) =>
        string.Join('\n', [start.FileName, .. start.Arguments, start.WorkingDirectory ?? "", start.MemoryLimitBytes?.ToString() ?? "",
            .. start.Environment.OrderBy(e => e.Key, StringComparer.Ordinal).Select(e => $"{e.Key}={e.Value}"), cancelGrace.Ticks.ToString()]);

    /// <summary>Counts a provider of <paramref name="command"/>; its spare stays until every one has called <see cref="Release"/>.</summary>
    public static void Use(string command)
    {
        lock (Sync)
        {
            var slot = SlotOf(command);
            slot.Users++;
            slot.End?.Dispose();
            slot.End = null;
        }
    }

    /// <summary>Ends the spare of <paramref name="command"/> <paramref name="linger"/> (null: <see cref="Linger"/>) after its last provider releases it.</summary>
    public static void Release(string command, TimeSpan? linger = null)
    {
        lock (Sync)
        {
            if (!Slots.TryGetValue(command, out var slot) || --slot.Users > 0) return;
            slot.End?.Dispose();
            slot.End = new Timer(_ => Expire(command, slot), null, linger ?? Linger, Timeout.InfiniteTimeSpan);
        }
    }

    /// <summary>The ready spare of <paramref name="command"/>, removed from the pool; null when there is none alive.</summary>
    public static WorkerConnection? Take(string command)
    {
        WorkerConnection? spare;
        lock (Sync)
        {
            if (!Slots.TryGetValue(command, out var slot) || slot.Spare == null) return null;
            spare = slot.Spare;
            slot.Spare = null;
        }
        if (spare.IsAlive) return spare;
        spare.Dispose();
        return null;
    }

    /// <summary>
    /// Starts the next spare of <paramref name="command"/> once <paramref name="after"/> is ready or closed, so two JVMs
    /// do not start at once; does nothing while one is kept or starting.
    /// </summary>
    public static void Refill(string command, Func<WorkerConnection> launch, WorkerConnection after, TimeSpan startTimeout)
    {
        Slot slot;
        lock (Sync)
        {
            slot = SlotOf(command);
            if (slot.Spare != null || slot.Starting || slot.Users == 0) return;
            slot.Starting = true;
        }
        var start = Task.Run(async () =>
        {
            WorkerConnection? spare = null;
            try
            {
                await Task.WhenAny(after.Ready, after.Closed).ConfigureAwait(false);
                lock (Sync)
                {
                    // EndAll removed the slot while the open it follows was starting: no spare after the pool ended.
                    if (!Slots.TryGetValue(command, out var current) || current != slot) return;
                    spare = launch();
                    slot.Launched = spare;
                }
                await spare.WaitReadyAsync(startTimeout, CancellationToken.None).ConfigureAwait(false);
            }
            catch (Exception)
            {
                spare?.Dispose();
                spare = null;
            }
            lock (Sync)
            {
                slot.Starting = false;
                slot.Launched = null;
                // Every provider released the command while the spare started, so no one needs it: end it.
                if (spare != null && slot.Users > 0 && Slots.TryGetValue(command, out var current) && current == slot) { slot.Spare = spare; spare = null; }
            }
            spare?.Dispose();
        });
        lock (Sync) slot.Start = start;
    }

    /// <summary>
    /// Ends every spare, the ones still starting included, and waits up to <paramref name="wait"/> for them to exit; the
    /// leak check calls it before it deletes the worker folder and counts processes. <paramref name="command"/> limits it
    /// to one launch command.
    /// </summary>
    public static void EndAll(TimeSpan wait, string? command = null)
    {
        List<WorkerConnection> ended = [];
        List<Task> starts = [];
        lock (Sync)
        {
            foreach (var (key, slot) in Slots.Where(s => command == null || s.Key == command).ToList())
            {
                Slots.Remove(key);
                slot.End?.Dispose();
                if (slot.Spare != null) ended.Add(slot.Spare);
                // A spare still starting is killed too: its start fails and its task disposes it, which waits for the exit.
                if (slot.Launched != null) slot.Launched.Kill("spare ended");
                if (slot.Starting && slot.Start != null) starts.Add(slot.Start);
            }
        }
        foreach (var spare in ended) spare.Kill("spare ended");
        Task.WaitAll([.. ended.Select(s => s.Closed), .. starts], wait);
        foreach (var spare in ended) spare.Dispose();
    }

    private static Slot SlotOf(string command)
    {
        if (!Slots.TryGetValue(command, out var slot)) Slots[command] = slot = new Slot();
        return slot;
    }

    private static void Expire(string command, Slot slot)
    {
        WorkerConnection? spare;
        lock (Sync)
        {
            if (slot.Users > 0 || !Slots.TryGetValue(command, out var current) || current != slot) return;
            slot.End?.Dispose();
            spare = slot.Spare;
            Slots.Remove(command);
        }
        spare?.Dispose();
    }
}
