using ModelContextProtocol;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;

namespace NetDecompilerMcp.Tools;

/// <summary>
/// Progress reporting that reaches the client before the tool's result. The SDK's injected IProgress sends each
/// notification fire-and-forget, so a fast tool's response can overtake its progress notifications, and the client drops
/// notifications for a request that already completed. This sends them one after another and lets the tool await them.
/// </summary>
internal sealed class OrderedProgress(RequestContext<CallToolRequestParams> context) : IProgress<ProgressNotificationValue>
{
    private readonly ProgressToken? _token = context.Params?.ProgressToken;
    private readonly object _sync = new();
    private Task _last = Task.CompletedTask;

    public void Report(ProgressNotificationValue value)
    {
        if (_token is not { } token) return; // the client did not ask for progress
        lock (_sync)
            _last = _last.ContinueWith(_ => context.Server.NotifyProgressAsync(token, value), TaskScheduler.Default).Unwrap();
    }

    /// <summary>Runs <paramref name="work"/> and returns its result once every progress notification has been sent.</summary>
    public static async Task<string> Run(RequestContext<CallToolRequestParams> context, Func<IProgress<ProgressNotificationValue>, Task<string>> work)
    {
        var progress = new OrderedProgress(context);
        try
        {
            return await work(progress);
        }
        finally
        {
            Task last;
            lock (progress._sync) last = progress._last;
            try { await last; }
            catch { /* a failed notification must not fail the tool */ }
        }
    }
}
