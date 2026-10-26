namespace Corvus.Core;

/// <summary>
/// The tool calls this server is running and the latest it finished, for server_status: tool, start, and for a finished
/// call its time and outcome. Bounded: <see cref="Kept"/> finished calls.
/// </summary>
public sealed class CallActivity
{
    public const int Kept = 5;

    /// <summary>One call; <see cref="Milliseconds"/> and <see cref="Outcome"/> are null while it runs.</summary>
    public sealed record Call(long Id, string Tool, DateTimeOffset Started, double? Milliseconds = null, string? Outcome = null);

    private readonly Dictionary<long, Call> _running = [];
    private readonly Queue<Call> _finished = new();
    private long _next;

    /// <summary>Records a call as running; returns its id for <see cref="End"/>.</summary>
    public long Start(string tool)
    {
        lock (_running)
        {
            var id = ++_next;
            _running[id] = new Call(id, tool, DateTimeOffset.UtcNow);
            return id;
        }
    }

    /// <summary>Moves a running call to the finished ones; a second end of the same call is ignored.</summary>
    public void End(long id, double milliseconds, string outcome)
    {
        lock (_running)
        {
            if (!_running.Remove(id, out var call)) return;
            _finished.Enqueue(call with { Milliseconds = milliseconds, Outcome = outcome });
            while (_finished.Count > Kept) _finished.Dequeue();
        }
    }

    /// <summary>The running calls, oldest first, and the finished ones, newest first.</summary>
    public (IReadOnlyList<Call> Running, IReadOnlyList<Call> Finished) Snapshot()
    {
        lock (_running) return ([.. _running.Values.OrderBy(c => c.Id)], [.. _finished.Reverse()]);
    }
}
