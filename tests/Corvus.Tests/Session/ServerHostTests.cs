using System.IO.Pipelines;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using ModelContextProtocol.Client;
using ModelContextProtocol.Protocol;
using Corvus.Core;
using Corvus.Mcp;

namespace Corvus.Tests;

/// <summary>The server host over in-process streams: the same catalog and request filters as the stdio server.</summary>
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

    /// <summary>--load of a container (.vsix here) loads the assemblies inside, as unpack_container does.</summary>
    [Fact]
    public void Preload_UnpacksAContainer()
    {
        using var dir = new TempDir();
        var vsix = dir.File($"extension-{Guid.NewGuid():N}.vsix");
        File.WriteAllBytes(vsix, ContainerFixtures.Zip(("extension.vsixmanifest", "<PackageManifest/>"u8.ToArray()), ("TestFixture.dll", File.ReadAllBytes(Env.FixturePath))));
        var options = new ServerOptions();
        options.Preload.Add(vsix);
        using var workspace = new AssemblyWorkspace();
        var output = Corvus.Services.Analysis.UnpackService.DefaultOutput(vsix, Blob.Sha256(File.ReadAllBytes(vsix)));
        try
        {
            ServerHost.Preload(workspace, Microsoft.Extensions.Logging.Abstractions.NullLogger.Instance, options);
            Assert.Equal("TestFixture.dll", Path.GetFileName(Assert.Single(workspace.Assemblies).FilePath));
        }
        finally
        {
            workspace.Dispose();
            if (Directory.Exists(output)) Directory.Delete(output, recursive: true);
            try { Directory.Delete(Path.GetDirectoryName(output)!); }
            catch (IOException) { /* another test's output is still there */ }
        }
    }

    [Fact]
    public async Task TheHandshakeName_SelectsTheClientProfile()
    {
        var options = new ServerOptions { BackgroundIndexing = false, WatchFiles = false };
        Pipe toServer = new(), toClient = new();
        using var host = ServerHost.Build(options, "test", server => server.WithStreamServerTransport(toServer.Reader.AsStream(), toClient.Writer.AsStream()));
        await host.StartAsync();
        try
        {
            await using var client = await McpClient.CreateAsync(new StreamClientTransport(toServer.Writer.AsStream(), toClient.Reader.AsStream()),
                new McpClientOptions { ClientInfo = new Implementation { Name = "gemini-cli-mcp-client", Version = "1" } });
            var status = await client.CallToolAsync("server_status", new Dictionary<string, object?>());
            var budget = System.Text.Json.Nodes.JsonNode.Parse(status.StructuredContent!.Value.GetRawText())!["sections"]!.AsArray()
                .Single(s => (string)s!["name"]! == "budget")!["fields"]!.AsArray();
            string? Field(string name, string part = "value") => (string?)budget.FirstOrDefault(f => (string)f!["name"]! == name)?[part];
            Assert.Equal(("Gemini CLI (gemini-cli)", "clientInfo"), (Field("client"), Field("client", "source")));
            Assert.Equal("9,500 tokens per result, at most 38,000 characters", Field("ceiling"));
            Assert.StartsWith("360 s per call", Field("deadline"));
        }
        finally
        {
            toServer.Writer.Complete();
            await host.StopAsync();
        }
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
