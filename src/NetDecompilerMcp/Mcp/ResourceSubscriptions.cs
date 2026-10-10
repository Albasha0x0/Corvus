using System.Collections.Concurrent;
using Microsoft.Extensions.DependencyInjection;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;
using NetDecompilerMcp.Core;

namespace NetDecompilerMcp.Mcp;

/// <summary>
/// resources/subscribe: a subscribed URI gets notifications/resources/updated after the workspace changes (a load,
/// unload, reload from disk or edit). The resource list itself never changes, so resources/list_changed is not sent.
/// Any change notifies every subscription: resources are few and a spurious update only costs a re-read.
/// </summary>
public sealed class ResourceSubscriptions(AssemblyWorkspace workspace, IServiceProvider services)
{
    private readonly ConcurrentDictionary<string, byte> _uris = new(StringComparer.Ordinal);
    private int _generation = workspace.Generation;

    public void Subscribe(string uri)
    {
        // Changes before the first subscription are not news to it.
        if (_uris.IsEmpty) Interlocked.Exchange(ref _generation, workspace.Generation);
        _uris[uri] = 0;
    }

    public void Unsubscribe(string uri) => _uris.TryRemove(uri, out _);

    public IReadOnlyCollection<string> Subscribed => _uris.Keys.ToList();

    /// <summary>Sends updates when the workspace changed since the last check (after each tool call and each file reload).</summary>
    public void Check()
    {
        var now = workspace.Generation;
        if (Interlocked.Exchange(ref _generation, now) == now || _uris.IsEmpty) return;
        if (services.GetService<McpServer>() is not { } server) return;
        var uris = _uris.Keys.ToList();
        _ = Task.Run(async () =>
        {
            foreach (var uri in uris)
            {
                try
                {
                    await server.SendNotificationAsync(NotificationMethods.ResourceUpdatedNotification, new ResourceUpdatedNotificationParams { Uri = uri });
                }
                catch (Exception ex) when (ex is IOException or ObjectDisposedException or InvalidOperationException or OperationCanceledException)
                {
                    return; // the session ended
                }
            }
        });
    }
}
