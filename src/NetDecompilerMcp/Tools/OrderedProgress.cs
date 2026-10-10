using ModelContextProtocol;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;

namespace NetDecompilerMcp.Tools;

/// <summary>
/// Sends progress notifications sequentially and awaits them before the tool result. The SDK's IProgress is
/// fire-and-forget, so notifications can arrive after the response and be dropped by the client.
/// Progress never goes backwards, and intermediate updates are sent at most every <see cref="MinInterval"/>;
/// the final update (progress == total) and the latest skipped update are always sent.
/// </summary>
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
        {
            if (value.Progress < _progress) return;
            bool final = value.Total is { } total && value.Progress >= total;
            long now = Environment.TickCount64;
            _progress = value.Progress;
            if (!final && _sentAt != long.MinValue && now - _sentAt < MinInterval.TotalMilliseconds)
            {
                _skipped = value;
                return;
            }
            _skipped = null;
            _sentAt = now;
            Send(token, value);
        }
    }

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
            catch { /* notification failures do not fail the tool */ }
        }
    }
}
