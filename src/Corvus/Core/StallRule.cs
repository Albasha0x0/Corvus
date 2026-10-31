namespace Corvus.Core;

/// <summary>
/// Decides that work has stalled: no progress unit for a window and under 1%
/// of a core used over that window. Work that reports progress or uses CPU is
/// never stalled, however long it runs.
/// </summary>
public sealed class StallRule
{
    /// <summary>Opens the message of a request stopped as stalled.</summary>
    public const string MessagePrefix = "stalled on '";

    private readonly TimeProvider _time;
    private readonly Queue<(long Ticks, TimeSpan Cpu)> _samples = new();
    private long _lastProgress;

    /// <summary>The window of silence and idle CPU after which work is stalled.</summary>
    public TimeSpan Window { get; }

    /// <summary>The last progress unit reported, or null when none was.</summary>
    public string? LastUnit { get; private set; }

    /// <summary>Starts a window now; a null <paramref name="time"/> uses the system clock.</summary>
    public StallRule(TimeSpan window, TimeProvider? time = null)
    {
        if (window <= TimeSpan.Zero) throw new ArgumentOutOfRangeException(nameof(window), "The stall window must be positive.");
        Window = window;
        _time = time ?? TimeProvider.System;
        _lastProgress = _time.GetTimestamp();
    }

    /// <summary>Records progress now and keeps a non-empty <paramref name="unit"/>.</summary>
    public void Progress(string? unit, long? ticks = null)
    {
        _lastProgress = ticks ?? _time.GetTimestamp();
        if (!string.IsNullOrEmpty(unit)) LastUnit = unit;
    }

    /// <summary>Whether the window passed with no progress and under 1% of a core used; null <paramref name="cpu"/> means unreadable.</summary>
    public bool Stalled(TimeSpan? cpu)
    {
        var now = _time.GetTimestamp();
        var silent = _time.GetElapsedTime(_lastProgress, now) >= Window;
        // Sample on every check so the CPU window is covered when silence ends.
        var idle = cpu is not { } c || Idle(c, now);
        return silent && idle;
    }

    /// <summary>Records a CPU sample; true when the window used under 1% of a core.</summary>
    public bool Idle(TimeSpan cpu) => Idle(cpu, _time.GetTimestamp());

    private bool Idle(TimeSpan cpu, long now)
    {
        _samples.Enqueue((now, cpu));
        while (_samples.Count > 1 && _time.GetElapsedTime(_samples.ElementAt(1).Ticks, now) >= Window) _samples.Dequeue();
        var (first, used) = _samples.Peek();
        return _time.GetElapsedTime(first, now) >= Window && cpu - used < Window / 100;
    }

    /// <summary>How the last progress reads in a stall error: the unit, or that none was reported.</summary>
    public string LastUnitText => LastUnit is { } unit ? $"last progress: {unit}" : "no progress unit was reported";
}
