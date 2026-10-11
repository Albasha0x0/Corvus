using System.IO.Pipelines;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using ModelContextProtocol.Client;
using ModelContextProtocol.Protocol;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Mcp;
using SdkClient = ModelContextProtocol.Client.McpClient;

namespace NetDecompilerMcp.Setup;

/// <summary>
/// The server in this process over in-memory streams, with an MCP client connected to it: every call takes the same
/// argument checks, budgets and error results as an agent's.
/// </summary>
internal sealed class ToolSession : IAsyncDisposable
{
    public const string ClientName = "net-decompiler-cli";

    private readonly IHost _host;
    private readonly Pipe _toServer;

    private ToolSession(IHost host, Pipe toServer, SdkClient client)
    {
        _host = host;
        _toServer = toServer;
        Client = client;
    }

    public SdkClient Client { get; }

    public static async Task<ToolSession> StartAsync(ServerOptions options, CancellationToken cancellationToken)
    {
        Pipe toServer = new(), toClient = new();
        var host = ServerHost.Build(options, Guide.Core, server =>
        {
            server.WithStreamServerTransport(toServer.Reader.AsStream(), toClient.Writer.AsStream());
            // The CLI owns Ctrl+C: it cancels the call in flight instead of stopping the server under it.
            server.Services.AddSingleton<IHostLifetime, NoLifetime>();
        });
        try
        {
            await host.StartAsync(cancellationToken);
            var client = await SdkClient.CreateAsync(new StreamClientTransport(toServer.Writer.AsStream(), toClient.Reader.AsStream()),
                new McpClientOptions { ClientInfo = new Implementation { Name = ClientName, Version = Installation.Version } },
                cancellationToken: cancellationToken);
            return new ToolSession(host, toServer, client);
        }
        catch
        {
            host.Dispose();
            throw;
        }
    }

    public async ValueTask DisposeAsync()
    {
        await Client.DisposeAsync();
        await _toServer.Writer.CompleteAsync();
        using var stop = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        try { await _host.StopAsync(stop.Token); }
        catch (OperationCanceledException) { /* the process is ending */ }
        _host.Dispose();
    }

    private sealed class NoLifetime : IHostLifetime
    {
        public Task WaitForStartAsync(CancellationToken cancellationToken) => Task.CompletedTask;
        public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
    }
}
