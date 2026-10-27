using ModelContextProtocol;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;

namespace Corvus.Tools;

/// <summary>Sends progress in order, at most every <see cref="MinInterval"/>, and awaits it before the result; never backwards, and the final and latest skipped updates are always sent.</summary>
internal sealed class OrderedProgress(RequestContext<CallToolRequestParams> context) : IProgress<ProgressNotificationValue>
{
    public static readonly TimeSpan MinInterval = TimeSpan.FromMilliseconds(100);

    private readonly ProgressToken? _token = context?.Params?.ProgressToken;
    private readonly object _sync = new();
    private Task _last = Task.CompletedTask;
    private float _progress = float.MinValue;
    private long _sentAt = long.MinValue;
    private ProgressNotificationValue? _skipped;

    public void Report(ProgressNotificationValue value)
    {
        if (_token is not { } token) return;
        lock (_sync)
            foreach (var update in Next(value, Environment.TickCount64))
                Send(token, update);
    }

    /// <summary>The updates to send for <paramref name="value"/> reported at <paramref name="now"/> (milliseconds); call under the lock.</summary>
    internal IReadOnlyList<ProgressNotificationValue> Next(ProgressNotificationValue value, long now)
    {
        if (value.Progress < _progress) return [];
        bool final = value.Total is { } total && value.Progress >= total;
        _progress = value.Progress;
        if (!final && _sentAt != long.MinValue && now - _sentAt < MinInterval.TotalMilliseconds)
        {
            _skipped = value;
            return [];
        }
        // The final update follows the latest skipped one, so the last phase before the end is never lost.
        ProgressNotificationValue[] send = final && _skipped is { } skipped ? [skipped, value] : [value];
        _skipped = null;
        _sentAt = now;
        return send;
    }

    // The SDK's IProgress is fire-and-forget: a notification can arrive after the response, and the client drops it.
    private void Send(ProgressToken token, ProgressNotificationValue value) =>
        _last = _last.ContinueWith(_ => context.Server.NotifyProgressAsync(token, value), TaskScheduler.Default).Unwrap();

    /// <summary>Runs <paramref name="work"/> and returns its result after all progress notifications are sent.</summary>
    public static async Task<T> Run<T>(RequestContext<CallToolRequestParams> context, Func<IProgress<ProgressNotificationValue>, Task<T>> work)
    {
        var progress = new OrderedProgress(context);
        try
        {
            return await work(progress);
        }
        finally
        {
            Task last;
            lock (progress._sync)
            {
                if (progress._skipped is { } skipped && progress._token is { } token)
                    progress.Send(token, skipped);
                last = progress._last;
            }
            try { await last; }
            catch { /* A failed notification does not fail the tool. */ }
        }
    }
}
