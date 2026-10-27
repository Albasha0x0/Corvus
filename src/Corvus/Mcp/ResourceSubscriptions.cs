using System.Collections.Concurrent;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Extensions.DependencyInjection;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;
using Corvus.Core;

namespace Corvus.Mcp;

/// <summary>Sends notifications/resources/updated for subscribed URIs after any workspace change.</summary>
// Subscribed by resources/subscribe or a subscriptions/listen stream (2026-07-28), whose updates go on that stream.
// The resource list never changes, so list_changed is not sent; every change notifies all, since a spurious update costs one re-read.
public sealed class ResourceSubscriptions(AssemblyWorkspace workspace, IServiceProvider services)
{
    private const string SubscriptionKey = "io.modelcontextprotocol/subscriptionId";

    private sealed record Stream(McpServer Server, JsonNode? Id, IReadOnlyList<string> Uris);

    private readonly ConcurrentDictionary<string, byte> _uris = new(StringComparer.Ordinal);
    private readonly ConcurrentDictionary<Stream, byte> _streams = new();
    private int _generation = workspace.Generation;

    public void Subscribe(string uri)
    {
        StartWatching();
        _uris[uri] = 0;
    }

    public void Unsubscribe(string uri) => _uris.TryRemove(uri, out _);

    public IReadOnlyCollection<string> Subscribed => _uris.Keys.Concat(_streams.Keys.SelectMany(s => s.Uris)).Distinct(StringComparer.Ordinal).ToList();

    // Changes before the first subscription are not news to it.
    private void StartWatching()
    {
        if (_uris.IsEmpty && _streams.IsEmpty) Interlocked.Exchange(ref _generation, workspace.Generation);
    }

    /// <summary>Tracks open subscriptions/listen streams that ask for resource updates.</summary>
    // The SDK grants resourceSubscriptions but sends no update on the stream itself.
    public McpMessageFilter ListenFilter => next => async (context, ct) =>
    {
        if (context.JsonRpcMessage is not JsonRpcRequest { Method: RequestMethods.SubscriptionsListen } request
            || request.Params?["notifications"]?["resourceSubscriptions"] is not JsonArray { Count: > 0 } wanted)
        {
            await next(context, ct).ConfigureAwait(false);
            return;
        }
        var uris = wanted.Select(u => u is JsonValue v && v.TryGetValue(out string? s) ? s : null).OfType<string>().Distinct(StringComparer.Ordinal).ToList();
        var stream = new Stream(context.Server, JsonSerializer.SerializeToNode(request.Id, McpJsonUtilities.DefaultOptions), uris);
        StartWatching();
        _streams[stream] = 0;
        try { await next(context, ct).ConfigureAwait(false); }
        finally { _streams.TryRemove(stream, out _); }
    };

    /// <summary>Sends updates when the workspace changed since the last check (after each tool call and each file reload).</summary>
    public void Check()
    {
        var now = workspace.Generation;
        if (Interlocked.Exchange(ref _generation, now) == now || (_uris.IsEmpty && _streams.IsEmpty)) return;
        var uris = _uris.Keys.ToList();
        var streams = _streams.Keys.ToList();
        var server = uris.Count > 0 ? services.GetService<McpServer>() : null;
        _ = Task.Run(async () =>
        {
            foreach (var uri in server == null ? [] : uris)
                if (!await Send(() => server!.SendNotificationAsync(NotificationMethods.ResourceUpdatedNotification, new ResourceUpdatedNotificationParams { Uri = uri })))
                    break;
            foreach (var stream in streams)
                foreach (var uri in stream.Uris)
                    if (!await Send(() => stream.Server.SendMessageAsync(new JsonRpcNotification
                        {
                            Method = NotificationMethods.ResourceUpdatedNotification,
                            Params = new JsonObject { ["uri"] = uri, ["_meta"] = new JsonObject { [SubscriptionKey] = stream.Id?.DeepClone() } },
                        })))
                        break;
        });
    }

    private static async Task<bool> Send(Func<Task> send)
    {
        try
        {
            await send().ConfigureAwait(false);
            return true;
        }
        catch (Exception ex) when (ex is IOException or ObjectDisposedException or InvalidOperationException or OperationCanceledException)
        {
            return false;
        }
    }
}
