using ModelContextProtocol;

namespace Corvus.Setup;

/// <summary>Writes progress notifications as stderr lines, at most one per interval.</summary>
internal sealed class ProgressLog(TextWriter error, TimeSpan? interval = null, Func<long>? ticks = null)
{
    private readonly long _interval = (interval ?? TimeSpan.FromSeconds(1)).Ticks;
    private readonly Func<long> _ticks = ticks ?? (() => Environment.TickCount64 * TimeSpan.TicksPerMillisecond);
    private readonly object _gate = new();
    private long _last = long.MinValue;
    private string? _writtenKey;
    private (string Key, string Line)? _pending;

    /// <summary>Returns a reporter that labels its lines with the tool name and shares this throttle.</summary>
    public IProgress<ProgressNotificationValue> For(string tool) => new Reporter(this, tool);

    /// <summary>Writes the last report the throttle dropped, so an ended call does not stop on a stale line.</summary>
    public void Flush()
    {
        lock (_gate)
        {
            if (_pending is { } p) Write(p.Key, p.Line);
        }
    }

    private void Report(string tool, ProgressNotificationValue value)
    {
        var final = value.Total is { } t && value.Progress >= t;
        var step = value.Total is { } total ? $"[{value.Progress:0}/{total:0}]" : $"[{value.Progress:0}]";
        var key = $"{tool}: {step}";
        var message = (value.Message ?? "").ReplaceLineEndings(" ");
        var line = $"{key} {message}".TrimEnd();
        lock (_gate)
        {
            // The final step is always written, once.
            if (final ? key == _writtenKey : _last != long.MinValue && _ticks() - _last < _interval)
            {
                if (!final) _pending = (key, line);
                return;
            }
            Write(key, line);
        }
    }

    private void Write(string key, string line)
    {
        _last = _ticks();
        _writtenKey = key;
        _pending = null;
        error.WriteLine(line);
    }

    private sealed class Reporter(ProgressLog log, string tool) : IProgress<ProgressNotificationValue>
    {
        public void Report(ProgressNotificationValue value) => log.Report(tool, value);
    }
}
