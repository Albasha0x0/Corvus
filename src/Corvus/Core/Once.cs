namespace Corvus.Core;

/// <summary>A value built once by the first caller; later callers wait cancellably, unlike Lazy, and see any build error.</summary>
internal sealed class Once<T>
{
    private readonly TaskCompletionSource<T> _done = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private int _claimed;

    /// <summary>Whether the value (or its error) is there.</summary>
    public bool IsDone => _done.Task.IsCompleted;

    /// <param name="ct">The waiter's token; without one, the current tool call's.</param>
    public T Get(Func<T> build, CancellationToken ct = default)
    {
        if (Interlocked.Exchange(ref _claimed, 1) == 0)
        {
            try
            {
                var value = build();
                _done.SetResult(value);
                return value;
            }
            catch (Exception ex)
            {
                _done.SetException(ex);
                throw;
            }
        }
        if (!ct.CanBeCanceled) ct = AssemblyWorkspace.CallToken;
        try { _done.Task.Wait(ct); }
        catch (AggregateException e) when (e.InnerException != null) { System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(e.InnerException).Throw(); }
        return _done.Task.Result;
    }
}

/// <summary>A drop-in for Lazy whose waiters stop when their call is cancelled (<see cref="Once{T}"/>).</summary>
internal sealed class Deferred<T>(Func<T> build)
{
    private readonly Once<T> _once = new();

    public T Value => _once.Get(build);
}
