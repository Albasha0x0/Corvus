using System.Text.Json;
using Corvus.Core;
using ModelContextProtocol.Protocol;

namespace Corvus.Tests;

/// <summary>A server with the given files loaded; calls tools over MCP and returns the structured result.</summary>
internal sealed class AgreementServer : IAsyncDisposable
{
    private readonly InProcessServer _server;

    private AgreementServer(InProcessServer server) => _server = server;

    /// <summary>Starts a server that preloads <paramref name="paths"/>.</summary>
    public static async Task<AgreementServer> Open(params string[] paths)
    {
        var options = new ServerOptions { BackgroundIndexing = false, WatchFiles = false };
        options.Preload.AddRange(paths);
        return new AgreementServer(await InProcessServer.StartAsync(options: options));
    }

    /// <summary>Calls a tool and returns its structured result; a tool error fails the test with its text.</summary>
    public async Task<JsonElement> Call(string tool, Dictionary<string, object?> args)
    {
        var r = await _server.Client.CallToolAsync(tool, args);
        var text = string.Concat(r.Content.OfType<TextContentBlock>().Select(b => b.Text));
        Assert.True(r.IsError != true, $"{tool}: {text}");
        Assert.True(r.StructuredContent is not null, $"{tool} returned no structured result: {text}");
        return JsonDocument.Parse(r.StructuredContent!.ToString()!).RootElement;
    }

    public ValueTask DisposeAsync() => _server.DisposeAsync();
}
