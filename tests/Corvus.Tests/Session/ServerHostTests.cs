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
    public void Preload_loads_native_images_too()
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
    public async Task A_missing_preload_path_reaches_the_first_tool_result()
    {
        var options = new ServerOptions { BackgroundIndexing = false, WatchFiles = false };
        options.Preload.Add(Path.Combine(Path.GetTempPath(), $"absent-{Guid.NewGuid():N}.dll"));
        Pipe toServer = new(), toClient = new();
        using var host = ServerHost.Build(options, "test", server => server.WithStreamServerTransport(toServer.Reader.AsStream(), toClient.Writer.AsStream()));
        await host.StartAsync();
        await host.Services.GetRequiredService<ServerHost.PreloadRun>().Completed;
        try
        {
            await using var client = await McpClient.CreateAsync(new StreamClientTransport(toServer.Writer.AsStream(), toClient.Reader.AsStream()));
            var listed = await client.CallToolAsync("list_assemblies", new Dictionary<string, object?>());
            var text = string.Concat(listed.Content.OfType<TextContentBlock>().Select(c => c.Text));
            Assert.Contains("[workspace]", text);
            Assert.Contains("Next: load_assembly path=", text);
        }
        finally
        {
            toServer.Writer.Complete();
            await host.StopAsync();
        }
    }

    [Fact]
    public void A_partial_preload_queues_one_notice_per_failed_path_in_order()
    {
        var first = Path.Combine(Path.GetTempPath(), $"absent-a-{Guid.NewGuid():N}.dll");
        var second = Path.Combine(Path.GetTempPath(), $"absent-b-{Guid.NewGuid():N}.dll");
        var options = new ServerOptions();
        options.Preload.Add(first);
        options.Preload.Add(Env.FixturePath);
        options.Preload.Add(second);
        using var workspace = new AssemblyWorkspace();
        ServerHost.Preload(workspace, Microsoft.Extensions.Logging.Abstractions.NullLogger.Instance, options);
        Assert.Single(workspace.Assemblies);
        var notices = workspace.DrainNotices();
        Assert.Equal(2, notices.Count);
        Assert.Contains(first, notices[0]);
        Assert.Contains(second, notices[1]);
    }

    [Fact]
    public void A_cancelled_preload_names_the_cancellation()
    {
        var options = new ServerOptions();
        options.Preload.Add(Env.FixturePath);
        using var workspace = new AssemblyWorkspace();
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        ServerHost.Preload(workspace, Microsoft.Extensions.Logging.Abstractions.NullLogger.Instance, options, cts.Token);
        var notice = Assert.Single(workspace.DrainNotices());
        Assert.Contains("was cancelled", notice);
        Assert.Empty(workspace.Assemblies);
    }

    // Regression: fix(session) load --load paths after the transport is up.
    [Fact]
    public async Task A_stalled_preload_does_not_delay_initialize()
    {
        using var dir = new TempDir();
        var held = dir.File("held.dll");
        File.WriteAllBytes(held, File.ReadAllBytes(Env.FixturePath));
        var options = new ServerOptions { BackgroundIndexing = false, WatchFiles = false };
        options.Preload.Add(held);
        Pipe toServer = new(), toClient = new();
        using var host = ServerHost.Build(options, "test", server => server.WithStreamServerTransport(toServer.Reader.AsStream(), toClient.Writer.AsStream()));
        var workspace = host.Services.GetRequiredService<AssemblyWorkspace>();
        // The workspace write lock is held, so the preload cannot finish until it is released.
        var gate = new ManualResetEventSlim();
        var locked = new ManualResetEventSlim();
        var holder = Task.Run(() => workspace.Write(() => { locked.Set(); gate.Wait(); return 0; }));
        locked.Wait(TimeSpan.FromSeconds(30));
        await host.StartAsync();
        try
        {
            await using var client = await McpClient.CreateAsync(new StreamClientTransport(toServer.Writer.AsStream(), toClient.Reader.AsStream()))
                .WaitAsync(TimeSpan.FromSeconds(30));
            Assert.False(host.Services.GetRequiredService<ServerHost.PreloadRun>().Completed.IsCompleted);
        }
        finally
        {
            gate.Set();
            await holder;
            await host.Services.GetRequiredService<ServerHost.PreloadRun>().Completed;
            Assert.Single(workspace.Assemblies);
            Assert.Empty(workspace.DrainNotices());
            toServer.Writer.Complete();
            await host.StopAsync();
        }
    }

    [Fact]
    public async Task A_call_during_the_preload_waits_for_it_and_sees_the_loaded_image()
    {
        using var dir = new TempDir();
        var held = dir.File("held.dll");
        File.WriteAllBytes(held, File.ReadAllBytes(Env.FixturePath));
        var options = new ServerOptions { BackgroundIndexing = false, WatchFiles = false };
        options.Preload.Add(held);
        Pipe toServer = new(), toClient = new();
        using var host = ServerHost.Build(options, "test", server => server.WithStreamServerTransport(toServer.Reader.AsStream(), toClient.Writer.AsStream()));
        var workspace = host.Services.GetRequiredService<AssemblyWorkspace>();
        // The workspace write lock is held, so the preload cannot finish until it is released.
        var gate = new ManualResetEventSlim();
        var locked = new ManualResetEventSlim();
        var holder = Task.Run(() => workspace.Write(() => { locked.Set(); gate.Wait(); return 0; }));
        locked.Wait(TimeSpan.FromSeconds(30));
        await host.StartAsync();
        try
        {
            await using var client = await McpClient.CreateAsync(new StreamClientTransport(toServer.Writer.AsStream(), toClient.Reader.AsStream()))
                .WaitAsync(TimeSpan.FromSeconds(30));
            var call = client.CallToolAsync("list_assemblies").AsTask();
            Assert.NotSame(call, await Task.WhenAny(call, Task.Delay(500)));
            gate.Set();
            var result = await call.WaitAsync(TimeSpan.FromSeconds(30));
            Assert.Contains("TestFixture", string.Concat(result.Content.OfType<TextContentBlock>().Select(c => c.Text)));
        }
        finally
        {
            gate.Set();
            await holder;
            toServer.Writer.Complete();
            await host.StopAsync();
        }
    }

    [Fact]
    public async Task The_handshake_name_selects_the_client_profile()
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
    public async Task Stream_transport_serves_the_catalog_and_tools()
    {
        var options = new ServerOptions { BackgroundIndexing = false, WatchFiles = false };
        options.Preload.Add(Env.FixturePath);
        Pipe toServer = new(), toClient = new();
        using var host = ServerHost.Build(options, "test instructions",
            server => server.WithStreamServerTransport(toServer.Reader.AsStream(), toClient.Writer.AsStream()));
        await host.StartAsync();
        await host.Services.GetRequiredService<ServerHost.PreloadRun>().Completed;
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
