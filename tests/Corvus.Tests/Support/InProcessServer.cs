using System.IO.Pipelines;
using Microsoft.Extensions.DependencyInjection;
using ModelContextProtocol.Protocol;
using Microsoft.Extensions.Hosting;
using ModelContextProtocol.Client;
using Corvus.Core;
using Corvus.Mcp;

namespace Corvus.Tests;

/// <summary>A server host over in-process streams with the fixture loaded: the stdio server's catalog and filters without a process start.</summary>
internal sealed class InProcessServer : IAsyncDisposable
{
    private readonly IHost _host;
    private readonly Pipe _toServer = new(), _toClient = new();
    public McpClient Client { get; private set; } = null!;
    public IServiceProvider Services => _host.Services;

    private InProcessServer(ServerOptions options) =>
        _host = ServerHost.Build(options, Guide.Core, server => server.WithStreamServerTransport(_toServer.Reader.AsStream(), _toClient.Writer.AsStream()));

    public static async Task<InProcessServer> StartAsync(string? protocolVersion = null, string? clientName = null, ServerOptions? options = null)
    {
        options ??= new ServerOptions { BackgroundIndexing = false, WatchFiles = false };
        if (options.Preload.Count == 0) options.Preload.Add(Env.FixturePath);
        var server = new InProcessServer(options);
        await server._host.StartAsync();
        // Ids start above those an earlier server kept, so each server keeps its own recordings.
        var kept = new TempDir();
        server.Owned.Add(kept);
        server._host.Services.GetRequiredService<Corvus.Services.LiveSessionService>().Kept = new Corvus.Services.LiveRecordings(() => kept.Path);
        await server._host.Services.GetRequiredService<ServerHost.PreloadRun>().Completed;
        server.Client = await McpClient.CreateAsync(new StreamClientTransport(server._toServer.Writer.AsStream(), server._toClient.Reader.AsStream()),
            new McpClientOptions
            {
                ProtocolVersion = protocolVersion,
                DiscoverProbeTimeout = Timeout.InfiniteTimeSpan,
                ClientInfo = clientName == null ? null : new ModelContextProtocol.Protocol.Implementation { Name = clientName, Version = "1" },
            });
        return server;
    }

    private List<IDisposable> Owned { get; } = [];

    public async ValueTask DisposeAsync()
    {
        await Client.DisposeAsync();
        _toServer.Writer.Complete();
        await _host.StopAsync();
        _host.Dispose();
        foreach (var owned in Owned) owned.Dispose();
    }
}
