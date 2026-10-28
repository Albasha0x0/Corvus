namespace Corvus.Mcp;

/// <summary>
/// One-shot timers for a call's stop and grace period that fire on threads of their own, so work that keeps every
/// thread-pool thread busy cannot hold back its own deadline. Any other <see cref="TimeProvider"/> (a test clock) uses
/// its own timers.
/// </summary>
internal static class StopTimers
{
    // An object monitor, not a Lock: the scheduler waits on it with
    // Monitor.Wait.
    private static readonly object Gate = new();
    private static readonly PriorityQueue<Entry, long> Due = new();
    private static Thread? _scheduler;

    private sealed class Entry(Action fire) : IDisposable
    {
        private int _state;

        public bool Pending => Volatile.Read(ref _state) == 0;

        public void Dispose() => Interlocked.Exchange(ref _state, 1);

        public void Run()
        {
            if (Interlocked.Exchange(ref _state, 1) != 0) return;
            // The owner may dispose what the action cancels while it runs.
            try { fire(); }
            catch (ObjectDisposedException) { }
        }
    }

    /// <summary>Runs <paramref name="fire"/> once after <paramref name="delay"/>, at once when it is not positive; disposing the result before then skips it.</summary>
    public static IDisposable After(TimeSpan delay, TimeProvider time, Action fire)
    {
        if (time != TimeProvider.System) return time.CreateTimer(_ => fire(), null, delay > TimeSpan.Zero ? delay : TimeSpan.Zero, Timeout.InfiniteTimeSpan);
        var entry = new Entry(fire);
        if (delay <= TimeSpan.Zero)
        {
            entry.Run();
            return entry;
        }
        lock (Gate)
        {
            Due.Enqueue(entry, Environment.TickCount64 + (long)Math.Ceiling(delay.TotalMilliseconds));
            if (_scheduler == null)
            {
                _scheduler = new Thread(Schedule) { IsBackground = true, Name = "Corvus call stop timers" };
                _scheduler.Start();
            }
            Monitor.PulseAll(Gate);
        }
        return entry;
    }

    /// <summary>A task completed after <paramref name="delay"/>, as <see cref="After"/> times it.</summary>
    public static Task Delay(TimeSpan delay, TimeProvider time)
    {
        var done = new TaskCompletionSource();
        After(delay, time, () => done.TrySetResult());
        return done.Task;
    }

    private static void Schedule()
    {
        lock (Gate)
            while (true)
            {
                if (!Due.TryPeek(out var entry, out var at)) Monitor.Wait(Gate);
                else if (at - Environment.TickCount64 is var wait and > 0) Monitor.Wait(Gate, TimeSpan.FromMilliseconds(wait));
                else
                {
                    Due.Dequeue();
                    // A call that finished in time disposed its entry: no
                    // thread for it.
                    if (!entry.Pending) continue;
                    // A thread per due action: what it continues runs there,
                    // and the next due time is not held back.
                    new Thread(entry.Run) { IsBackground = true, Name = "Corvus call stop" }.Start();
                }
            }
    }
}
