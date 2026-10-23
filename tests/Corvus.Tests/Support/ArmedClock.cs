using System.Threading.Channels;
using Microsoft.Extensions.Time.Testing;

namespace Corvus.Tests;

/// <summary>
/// A fake clock that reports each timer the code under test arms, so a test moves time only once the timer it means
/// to fire exists: no sleeps and no wall-clock waits. Time starts at zero and moves only in <see cref="RunUntilAsync"/>.
/// </summary>
internal sealed class ArmedClock : TimeProvider
{
    private readonly FakeTimeProvider _time = new();
    private readonly DateTimeOffset _start;
    private readonly Channel<DateTimeOffset> _armed = Channel.CreateUnbounded<DateTimeOffset>();

    public ArmedClock() => _start = _time.GetUtcNow();

    /// <summary>How far the clock has moved.</summary>
    public TimeSpan Elapsed => _time.GetUtcNow() - _start;

    public override DateTimeOffset GetUtcNow() => _time.GetUtcNow();
    public override long GetTimestamp() => _time.GetTimestamp();
    public override long TimestampFrequency => _time.TimestampFrequency;
    public override TimeZoneInfo LocalTimeZone => _time.LocalTimeZone;

    public override ITimer CreateTimer(TimerCallback callback, object? state, TimeSpan dueTime, TimeSpan period)
    {
        var timer = _time.CreateTimer(callback, state, dueTime, period);
        if (dueTime != Timeout.InfiniteTimeSpan) _armed.Writer.TryWrite(_time.GetUtcNow() + dueTime);
        return timer;
    }

    /// <summary>
    /// Fires the armed timers in the order they were armed, moving the clock to each one's due time, until
    /// <paramref name="done"/> completes; returns how far the clock has moved. A timer due later than
    /// <paramref name="within"/> of the start is not fired and stays armed for the next run. Fails after a minute
    /// without progress.
    /// </summary>
    public async Task<TimeSpan> RunUntilAsync(Task done, TimeSpan? within = null)
    {
        var later = new List<DateTimeOffset>();
        try
        {
            while (!done.IsCompleted)
            {
                // Waits without taking an item, so a timer armed after done completes is left for the next run.
                var ready = _armed.Reader.WaitToReadAsync().AsTask();
                if (await Task.WhenAny(ready, done).WaitAsync(TimeSpan.FromMinutes(1)) != ready || !_armed.Reader.TryRead(out var due)) continue;
                if (within is { } w && due - _start > w)
                {
                    later.Add(due);
                    continue;
                }
                var now = _time.GetUtcNow();
                if (due > now) _time.Advance(due - now);
            }
        }
        finally
        {
            foreach (var due in later) _armed.Writer.TryWrite(due);
        }
        return Elapsed;
    }

    /// <summary>Moves the clock by <paramref name="by"/>, firing every timer due by then.</summary>
    public void Advance(TimeSpan by) => _time.Advance(by);

    /// <summary>Waits until the next timer is armed (up to a minute) without firing it.</summary>
    public async Task ArmedAsync() => await _armed.Reader.WaitToReadAsync().AsTask().WaitAsync(TimeSpan.FromMinutes(1));
}
