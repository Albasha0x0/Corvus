using System.IO.Pipelines;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using ModelContextProtocol.Client;
using ModelContextProtocol.Protocol;
using Corvus.Core;
using Corvus.Mcp;

namespace Corvus.Tests;

/// <summary>The server host over in-process streams: the same catalog and request filters as the stdio server.</summary>
[Collection(InProcessCatalogCollection.Name)]
public class ServerHostTests
{
    [Fact]
    public void Preload_LoadsNativeImagesToo()
    {
        using var dir = new TempDir();
        var options = new ServerOptions();
        options.Preload.Add(McpProtocolTests.NativeSample(dir));
        options.Preload.Add(Env.FixturePath);
        var workspace = new AssemblyWorkspace();
        ServerHost.Preload(workspace, Microsoft.Extensions.Logging.Abstractions.NullLogger.Instance, options);
        Assert.Single(workspace.Natives);
        Assert.Single(workspace.Assemblies);
    }

    [Fact]
    public async Task StreamTransport_ServesTheCatalogAndTools()
    {
        var options = new ServerOptions { BackgroundIndexing = false, WatchFiles = false };
        options.Preload.Add(Env.FixturePath);
        Pipe toServer = new(), toClient = new();
        using var host = ServerHost.Build(options, "test instructions",
            server => server.WithStreamServerTransport(toServer.Reader.AsStream(), toClient.Writer.AsStream()));
        await host.StartAsync();
        try
        {
            await using var client = await McpClient.CreateAsync(new StreamClientTransport(toServer.Writer.AsStream(), toClient.Reader.AsStream()));
            Assert.Equal("test instructions", client.ServerInstructions);
            var tools = await client.ListToolsAsync();
            var (expected, _) = Catalog.OfThisBuild();
            Assert.Equal(expected.Select(t => t["name"]!.GetValue<string>()).Order(), tools.Select(t => t.Name).Order());

            var listed = await client.CallToolAsync("list_assemblies", new Dictionary<string, object?>());
            Assert.NotEqual(true, listed.IsError);
            Assert.Contains("TestFixture", string.Join("\n", listed.Content.OfType<TextContentBlock>().Select(b => b.Text)));

            // The request filters apply: an unknown argument is an error result, not a protocol failure.
            var bad = await client.CallToolAsync("list_assemblies", new Dictionary<string, object?> { ["bogus"] = 1 });
            Assert.True(bad.IsError);
        }
        finally
        {
            toServer.Writer.Complete();
            await host.StopAsync();
        }
    }
}
