using ModelContextProtocol;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;

namespace NetDecompilerMcp.Tools;

/// <summary>
/// Sends progress notifications sequentially and awaits them before the tool result. The SDK's IProgress is
/// fire-and-forget, so notifications can arrive after the response and be dropped by the client.
/// </summary>
internal sealed class OrderedProgress(RequestContext<CallToolRequestParams> context) : IProgress<ProgressNotificationValue>
{
    private readonly ProgressToken? _token = context.Params?.ProgressToken;
    private readonly object _sync = new();
    private Task _last = Task.CompletedTask;

    public void Report(ProgressNotificationValue value)
    {
        if (_token is not { } token) return;
        lock (_sync)
            _last = _last.ContinueWith(_ => context.Server.NotifyProgressAsync(token, value), TaskScheduler.Default).Unwrap();
    }

    /// <summary>Runs <paramref name="work"/> and returns its result after all progress notifications are sent.</summary>
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
            catch { /* notification failures do not fail the tool */ }
        }
    }
}
