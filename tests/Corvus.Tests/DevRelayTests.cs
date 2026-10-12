using System.Buffers;
using System.Collections.Concurrent;
using System.IO.Pipelines;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using ModelContextProtocol;
using ModelContextProtocol.Client;
using ModelContextProtocol.Protocol;
using Corvus.Native.Providers;
using Corvus.Relay;

namespace Corvus.Tests;

/// <summary>The relay with a client on the initialize handshake (2025-11-25).</summary>
public sealed class DevRelayInitializeTests() : DevRelayTests("2025-11-25")
{
    [Fact]
    public void ArgumentsSplitBetweenRelayAndServer()
    {
        var options = RelayCli.Parse(["--target", Dir.Path, "--load", "x.dll", "--poll-ms", "50", "--", "--target", "y"]);
        Assert.Equal(Path.GetFullPath(Dir.Path), options.Target);
        Assert.Equal(["--load", "x.dll", "--target", "y"], options.ServerArgs);
        Assert.Equal(TimeSpan.FromMilliseconds(50), options.Poll);
        Assert.Throws<ArgumentException>(() => RelayCli.Parse(["--load", "x.dll"]));
        Assert.Equal(["--load", "x.dll"], RelayCli.WithoutRelayPrefix(["relay", "--target", "d", "--state", "s", "--", "--load", "x.dll"]));
        Assert.Equal(["--load", "x.dll"], RelayCli.WithoutRelayPrefix(["--load", "x.dll"]));
    }

    [Fact]
    public void StagingSkipsTheMarkerAndRenamedAsideFiles()
    {
        File.WriteAllText(Path.Combine(Publish, "corvus.dll" + RelayBuilds.AsideInfix + "1"), "old");
        Directory.CreateDirectory(Path.Combine(Publish, "runtimes"));
        File.WriteAllText(Path.Combine(Publish, "runtimes", "n.so"), "n");
        var marker = RelayBuilds.ReadMarker(Publish);
        var staged = RelayBuilds.Stage(Publish, Path.Combine(Dir.Path, "stage"), marker);
        Assert.True(File.Exists(Path.Combine(staged, "runtimes", "n.so")));
        Assert.False(File.Exists(Path.Combine(staged, RelayBuilds.MarkerName)));
        Assert.Empty(Directory.GetFiles(staged, "*" + RelayBuilds.AsideInfix + "*"));
        Assert.Equal("A", RelayBuild.From(marker).Id);
        Assert.Throws<IOException>(() => RelayBuilds.Stage(Publish, Path.Combine(Dir.Path, "stage"), "{\"buildId\":\"other\"}"));
    }
}

/// <summary>The relay with a client on per-request metadata (2026-07-28): server/discover, no session, a listen stream.</summary>
public sealed class DevRelayDiscoverTests() : DevRelayTests("2026-07-28")
{
    [Fact]
    public async Task FailedInitializeIsNotRepeatedOnTheNewBuild()
    {
        var initialize = new JsonRpcRequest
        {
            Method = RequestMethods.Initialize,
            Params = new JsonObject { ["protocolVersion"] = Protocol, ["capabilities"] = new JsonObject(), ["clientInfo"] = new JsonObject { ["name"] = "x", ["version"] = "1" } },
        };
        await Assert.ThrowsAnyAsync<McpException>(() => Client.SendRequestAsync(initialize));
        PublishBuild("B");
        await Until(() => Notifications.Count == 3, "the swap");
        Assert.StartsWith("[relay] now serving build B", await Call("echo", new() { ["text"] = "hi" }));
    }
}

/// <summary>
/// The development reload relay against scripted fake servers (one per staged build) and the SDK's client, run once per
/// protocol family: the initialize handshake, and per-request metadata where list_changed travels on a listen stream.
/// </summary>
public abstract class DevRelayTests(string protocol) : IAsyncLifetime
{
    protected string Protocol { get; } = protocol;
    private bool PerRequest => Protocol == "2026-07-28";
    protected TempDir Dir { get; } = new();
    private readonly ConcurrentQueue<FakeMcpServer> _servers = new();
    protected ConcurrentQueue<string> Notifications { get; } = new();
    private int _tagged, _acks;
    private DevRelay _relay = null!;
    private Task<int> _run = null!;
    protected McpClient Client { get; private set; } = null!;
    private readonly CancellationTokenSource _listenEnd = new();
    private readonly Pipe _toRelay = new();
    protected string Publish => Path.Combine(Dir.Path, "publish");
    private string State => Path.Combine(Dir.Path, "state");

    public async Task InitializeAsync()
    {
        Directory.CreateDirectory(Publish);
        PublishBuild("A");
        var toRelay = _toRelay;
        var toClient = new Pipe();
        var options = new RelayOptions { Target = Publish, StateDirectory = State, Poll = TimeSpan.FromMilliseconds(20), RequestTimeout = TimeSpan.FromSeconds(60) };
        _relay = new DevRelay(options, toRelay.Reader.AsStream(), toClient.Writer.AsStream(), TextWriter.Null, dir =>
        {
            var server = new FakeMcpServer(File.ReadAllText(Path.Combine(dir, "tag.txt"))) { Directory = dir };
            _servers.Enqueue(server);
            return server;
        });
        _run = _relay.RunAsync();
        ValueTask Changed(JsonRpcNotification n, CancellationToken _)
        {
            if (n.Params?["_meta"]?["io.modelcontextprotocol/subscriptionId"] != null) Interlocked.Increment(ref _tagged);
            Notifications.Enqueue(n.Method);
            return ValueTask.CompletedTask;
        }
        var handlers = new McpClientHandlers
        {
            NotificationHandlers =
            [
                new(NotificationMethods.ToolListChangedNotification, Changed),
                new(NotificationMethods.PromptListChangedNotification, Changed),
                new(NotificationMethods.ResourceListChangedNotification, Changed),
                new("notifications/subscriptions/acknowledged", (_, _) => { Interlocked.Increment(ref _acks); return ValueTask.CompletedTask; }),
            ],
        };
        Client = await McpClient.CreateAsync(new StreamClientTransport(toRelay.Writer.AsStream(), toClient.Reader.AsStream()),
            new McpClientOptions { ClientInfo = new Implementation { Name = "relay-test", Version = "1" }, Handlers = handlers, ProtocolVersion = Protocol, DiscoverProbeTimeout = Timeout.InfiniteTimeSpan });
        Assert.Equal(Protocol, Client.NegotiatedProtocolVersion);
        if (PerRequest)
        {
            // Long-lived: answered only when the client ends it, and must not hold a swap back.
            var listen = new JsonRpcRequest
            {
                Method = "subscriptions/listen",
                Params = new JsonObject { ["notifications"] = new JsonObject { ["toolsListChanged"] = true, ["promptsListChanged"] = true, ["resourcesListChanged"] = true } },
            };
            _ = Client.SendRequestAsync(listen, _listenEnd.Token).ContinueWith(_ => { }, TaskScheduler.Default);
            await Until(() => Volatile.Read(ref _acks) == 1, "the listen acknowledgement");
        }
    }

    public async Task DisposeAsync()
    {
        await _listenEnd.CancelAsync();
        await Client.DisposeAsync();
        await _toRelay.Writer.CompleteAsync(); // the client's end of input
        Assert.Equal(0, await _run.WaitAsync(TimeSpan.FromSeconds(10)));
        Dir.Dispose();
    }

    /// <summary>Writes a build tagged <paramref name="tag"/> and then its marker, as publish.ps1 does.</summary>
    protected void PublishBuild(string tag)
    {
        File.Delete(Path.Combine(Publish, RelayBuilds.MarkerName));
        File.WriteAllText(Path.Combine(Publish, "corvus.dll"), "stand-in");
        File.WriteAllText(Path.Combine(Publish, "tag.txt"), tag);
        WriteMarker(Publish, tag);
    }

    /// <summary>Writes the marker whole, through a temporary file as publish.ps1 does: the relay would take a marker caught half written for a build of its own.</summary>
    internal static void WriteMarker(string directory, string buildId)
    {
        var marker = Path.Combine(directory, RelayBuilds.MarkerName);
        File.WriteAllText(marker + ".tmp", JsonSerializer.Serialize(new { buildId }));
        File.Move(marker + ".tmp", marker, overwrite: true);
    }

    private FakeMcpServer Server(string tag) => _servers.Last(s => s.Tag == tag);

    protected async Task<string> Call(string tool, Dictionary<string, object?>? args = null, CancellationToken token = default)
    {
        var result = await Client.CallToolAsync(tool, args ?? [], cancellationToken: token);
        return string.Join("\n", result.Content.OfType<TextContentBlock>().Select(b => b.Text));
    }

    protected static async Task Until(Func<bool> condition, string what)
    {
        for (int i = 0; i < 500 && !condition(); i++) await Task.Delay(20);
        Assert.True(condition(), "timed out waiting for " + what);
    }

    [Fact]
    public async Task ForwardsCallsAndAddsTheApplyTool()
    {
        var tools = await Client.ListToolsAsync();
        Assert.Contains(tools, t => t.Name == "echo");
        Assert.Contains(tools, t => t.Name == DevRelay.ApplyTool);
        Assert.Equal("build A: hi", await Call("echo", new() { ["text"] = "hi" }));
        Assert.True(Client.ServerCapabilities.Tools?.ListChanged);
        Assert.Contains("No newer build", await Call(DevRelay.ApplyTool));
        // The server ran from a staged copy, never from the publish folder.
        Assert.StartsWith(Path.Combine(State, "builds"), Server("A").Directory ?? Path.Combine(State, "builds"), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task NewBuildReplaysLoadsAndNotifies()
    {
        var file = Dir.File("app.dll");
        File.WriteAllText(file, "x");
        await Call("load_assembly", new() { ["path"] = file });
        await Call("load_assembly", new() { ["path"] = file, ["dryRun"] = true });
        await Call("echo", new() { ["text"] = "not replayed" });
        PublishBuild("B");
        await Until(() => Notifications.Count == 3, "list_changed notifications");
        Assert.Equal(["notifications/prompts/list_changed", "notifications/resources/list_changed", "notifications/tools/list_changed"], Notifications.Order(StringComparer.Ordinal));
        Assert.Equal(PerRequest ? 3 : 0, _tagged); // on the listen stream
        var text = await Call("echo", new() { ["text"] = "hi" });
        Assert.StartsWith("[relay] now serving build B (B, catalog t1-fake) (was A); replayed 1 workspace call(s): load_assembly " + file, text);
        Assert.EndsWith("build B: hi", text);
        var b = Server("B");
        Assert.Equal([file], b.Loaded);
        Assert.Equal("relay-test", b.ClientName);
        Assert.True(b.Ready);
        await Until(() => Server("A").Killed, "the old server to stop");
        Assert.DoesNotContain("[relay]", await Call("echo", new() { ["text"] = "again" }));
        if (!PerRequest) return;
        // The listen stream moved: the new server's own notifications reach the client, its second acknowledgement does not.
        await Until(() => b.Listens > 0, "the listen stream on the new server"); // its requests are handled concurrently: the stream may land after a later call
        Assert.Equal(1, b.Listens);
        await Call("notify");
        await Until(() => Notifications.Count == 4, "the new server's notification");
        Assert.Equal(1, Volatile.Read(ref _acks));
    }

    [Fact]
    public async Task UnsavedEditsPostponeTheSwapUntilSavedOrForced()
    {
        await Call("edit");
        PublishBuild("B");
        await Until(() => Server("A").EditChecks > 0, "the edit check");
        var text = await Call("echo", new() { ["text"] = "hi" });
        Assert.StartsWith("[relay] new build B ready; 1 unsaved edit(s) pending", text);
        Assert.EndsWith("build A: hi", text);
        Assert.Single(_servers);

        var applied = await Call(DevRelay.ApplyTool);
        Assert.Contains("now serving build B", applied);
        Assert.Contains("1 unsaved edit(s) were discarded", applied);
        Assert.EndsWith("build B: hi", await Call("echo", new() { ["text"] = "hi" }));

        // Saving lets the next build through without forcing.
        await Call("edit");
        PublishBuild("C");
        await Until(() => Server("B").EditChecks > 0, "the edit check");
        await Call("save");
        await Until(() => _servers.Any(s => s.Tag == "C"), "build C");
        Assert.EndsWith("build C: hi", await Call("echo", new() { ["text"] = "hi" }));
    }

    [Fact]
    public async Task EditsThatCannotBeCheckedPostponeTheSwapUntilForced()
    {
        await Call("edit");
        await Call("unlist");
        PublishBuild("B");
        await Until(() => Server("A").EditChecks > 0, "the edit check");
        var text = await Call("echo", new() { ["text"] = "hi" });
        Assert.StartsWith("[relay] new build B ready; its unsaved edits could not be checked (the assemblies resource is unavailable)", text);
        Assert.EndsWith("build A: hi", text);
        Assert.Single(_servers);
        Assert.Contains("now serving build B", await Call(DevRelay.ApplyTool));
        Assert.EndsWith("build B: hi", await Call("echo", new() { ["text"] = "hi" }));
    }

    [Fact]
    public async Task FailedNewServerKeepsTheOldOne()
    {
        PublishBuild("broken");
        await Until(() => _servers.Any(s => s.Tag == "broken" && s.Killed), "the broken build to be dropped");
        var text = await Call("echo", new() { ["text"] = "hi" });
        Assert.StartsWith($"[relay] new build broken was not applied: {(PerRequest ? "server/discover" : "initialize")} failed", text);
        Assert.EndsWith("build A: hi", text);
        PublishBuild("C");
        await Until(() => _servers.Any(s => s.Tag == "C" && s.Ready), "build C");
        await Until(() => Server("A").Killed, "build A to stop");
        Assert.EndsWith("build C: hi", await Call("echo", new() { ["text"] = "hi" }));
    }

    [Fact]
    public async Task FailedReplayKeepsTheOldOneUnlessForced()
    {
        var file = Dir.File("gone.dll");
        File.WriteAllText(file, "x");
        await Call("load_assembly", new() { ["path"] = file });
        File.Delete(file);
        PublishBuild("B");
        await Until(() => _servers.Any(s => s.Tag == "B" && s.Killed), "the replay to fail");
        var text = await Call("echo", new() { ["text"] = "hi" });
        Assert.Contains($"new build B was not applied: replaying load_assembly {file} failed: no such file", text);
        Assert.EndsWith("build A: hi", text);

        var applied = await Call(DevRelay.ApplyTool);
        Assert.Contains("now serving build B", applied);
        Assert.Contains($"not replayed: load_assembly {file} (no such file)", applied);
    }

    [Fact]
    public async Task SwapWaitsForCallsInFlightAndRoutesCancellation()
    {
        var slow = Call("slow");
        await Until(() => Server("A").Running == 1, "the slow call to start");
        PublishBuild("B");
        await Until(() => _relay.PendingBuild == "B", "build B to be found");
        Assert.Single(_servers); // not while a call is in flight
        var text = await Call("echo", new() { ["text"] = "hi" });
        Assert.StartsWith("[relay] new build B is ready but not applied yet: 1 call(s) in flight (tools/call slow).", text);
        Assert.DoesNotContain("[relay]", await Call("echo", new() { ["text"] = "hi" })); // said once
        // Sent by hand: this SDK version does not send notifications/cancelled for a cancelled call.
        await Client.SendNotificationAsync(NotificationMethods.CancelledNotification,
            new CancelledNotificationParams { RequestId = new RequestId(Server("A").SlowIds.Single()) });
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => slow); // the SDK drops its own pending request
        await Until(() => Server("A").Cancelled == 1, "the cancellation to reach the server");
        await Until(() => _servers.Any(s => s.Tag == "B" && s.Ready), "build B");
    }

    [Fact]
    public async Task ServerRequestsReachTheClientAcrossSwaps()
    {
        // A 2026-07-28 client refuses ping (removed there); its error reply still has to find the asking server.
        var answer = PerRequest ? "failed" : "answered";
        Assert.Equal($"build A: the client {answer} ping", await Call("ask"));
        PublishBuild("B");
        await Until(() => Notifications.Count == 3, "the swap");
        Assert.EndsWith($"build B: the client {answer} ping", await Call("ask"));
    }

    [Fact]
    public async Task ExitedServerIsRestartedWithReplay()
    {
        var file = Dir.File("app.dll");
        File.WriteAllText(file, "x");
        await Call("load_assembly", new() { ["path"] = file });
        await Assert.ThrowsAnyAsync<McpException>(() => Call("crash"));
        await Until(() => _servers.Count == 2 && _servers.Last().Ready, "the restart");
        var text = await Call("echo", new() { ["text"] = "hi" });
        Assert.Contains("exited", text);
        Assert.Contains("replayed 1 workspace call(s)", text);
        Assert.Equal([file], _servers.Last().Loaded);
        if (PerRequest) await Until(() => _servers.Last().Listens > 0, "the listen stream on the restarted server");
        Assert.Equal(PerRequest ? 1 : 0, _servers.Last().Listens); // the open stream is taken over
    }
}

/// <summary>
/// The relay with the real server: two publishes of this build, a load replayed, an edit holding the swap back; on
/// 2026-07-28 with a listen stream open throughout, which carries list_changed.
/// </summary>
public sealed class DevRelayRealServerTests
{
    [Trait("Speed", "Slow")]
    [Theory]
    [InlineData("2025-11-25")]
    [InlineData("2026-07-28")]
    public async Task RepublishSwapsTheRealServerAndKeepsTheWorkspace(string protocol)
    {
        using var dir = new TempDir();
        var publish = Path.Combine(dir.Path, "publish");
        var server = Path.GetDirectoryName(typeof(DevRelay).Assembly.Location)!;
        foreach (var file in Directory.EnumerateFiles(server, "*", SearchOption.AllDirectories))
        {
            var to = Path.Combine(publish, Path.GetRelativePath(server, file));
            Directory.CreateDirectory(Path.GetDirectoryName(to)!);
            File.Copy(file, to);
        }
        void Mark(string id) => DevRelayTests.WriteMarker(publish, id);
        Mark("one");

        var toRelay = new Pipe();
        var toClient = new Pipe();
        var options = new RelayOptions { Target = publish, StateDirectory = Path.Combine(dir.Path, "state"), Poll = TimeSpan.FromMilliseconds(100) };
        var processes = new ConcurrentQueue<ChildProcess>();
        var relay = new DevRelay(options, toRelay.Reader.AsStream(), toClient.Writer.AsStream(), TextWriter.Null, staged =>
        {
            var process = ChildProcess.Start(new ChildProcessStart(Path.Combine(staged, RelayBuilds.ProgramName), [])
            {
                Environment = new Dictionary<string, string?> { ["CORVUS_ANNOTATIONS_DIR"] = Path.Combine(dir.Path, "annotations") },
            });
            processes.Enqueue(process);
            return process;
        });
        var run = relay.RunAsync();
        int changed = 0, acks = 0;
        var handlers = new McpClientHandlers
        {
            NotificationHandlers =
            [
                new(NotificationMethods.ToolListChangedNotification, (_, _) => { Interlocked.Increment(ref changed); return ValueTask.CompletedTask; }),
                new("notifications/subscriptions/acknowledged", (_, _) => { Interlocked.Increment(ref acks); return ValueTask.CompletedTask; }),
            ],
        };
        using var listenEnd = new CancellationTokenSource();
        await using (var client = await McpClient.CreateAsync(new StreamClientTransport(toRelay.Writer.AsStream(), toClient.Reader.AsStream()),
                         new McpClientOptions { Handlers = handlers, ProtocolVersion = protocol, DiscoverProbeTimeout = Timeout.InfiniteTimeSpan }))
        {
            Assert.Equal(protocol, client.NegotiatedProtocolVersion);
            async Task<string> Call(string tool, Dictionary<string, object?> args) =>
                string.Join("\n", (await client.CallToolAsync(tool, args)).Content.OfType<TextContentBlock>().Select(b => b.Text));
            if (protocol == "2026-07-28")
            {
                var listen = new JsonRpcRequest { Method = "subscriptions/listen", Params = new JsonObject { ["notifications"] = new JsonObject { ["toolsListChanged"] = true } } };
                _ = client.SendRequestAsync(listen, listenEnd.Token).ContinueWith(_ => { }, TaskScheduler.Default);
                for (int i = 0; i < 200 && Volatile.Read(ref acks) == 0; i++) await Task.Delay(50);
                Assert.Equal(1, acks);
            }

            await Call("load_assembly", new() { ["path"] = Env.FixturePath });
            Mark("two");
            for (int i = 0; i < 300 && Volatile.Read(ref changed) == 0; i++) await Task.Delay(50);
            Assert.Equal(1, changed);
            var listed = await Call("list_assemblies", []);
            Assert.StartsWith("[relay] now serving build two (", listed);
            Assert.Contains("replayed 1 workspace call(s): load_assembly", listed);
            Assert.Contains("TestFixture", listed);
            Assert.True(processes.First().HasExited || await processes.First().Exited.WaitAsync(TimeSpan.FromSeconds(10)).ContinueWith(t => t.IsCompletedSuccessfully));

            await Call("rename_symbol", new() { ["symbol"] = "Account", ["newName"] = "Customer" });
            Mark("three");
            await Task.Delay(1000);
            Assert.Contains("unsaved edit(s) pending", await Call("list_assemblies", []));
            Assert.Contains("now serving build three", await Call(DevRelay.ApplyTool, []));
            Assert.Equal(3, processes.Count);
            Assert.Equal(protocol == "2026-07-28" ? 1 : 0, acks); // the stream moved twice without a second acknowledgement
            await listenEnd.CancelAsync();
        }
        await toRelay.Writer.CompleteAsync();
        Assert.Equal(0, await run.WaitAsync(TimeSpan.FromSeconds(30)));
    }
}

/// <summary>
/// A scripted MCP server behind in-memory pipes. Tools: echo {text}, load_assembly {path} (fails for a missing file),
/// edit / save (unsaved edits in the assemblies resource), unlist (that resource fails from then on), slow (until cancelled), ask (pings the client), crash, server_status,
/// notify (tools list_changed on each listen stream). Speaks the initialize handshake, or 2026-07-28 per-request metadata
/// (server/discover, subscriptions/listen, _meta required on every request). Tagged "broken", it exits without answering.
/// </summary>
internal sealed class FakeMcpServer : ChildProcess
{
    private readonly Pipe _in = new(), _out = new(), _err = new();
    private readonly TaskCompletionSource _exited = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly ConcurrentDictionary<string, CancellationTokenSource> _calls = new();
    private readonly ConcurrentDictionary<string, TaskCompletionSource<JsonObject>> _asks = new();
    private readonly object _write = new();
    private int _unsaved, _askIds;
    private volatile bool _unlisted;

    public string Tag { get; }
    public string? Directory { get; init; }
    public List<string> Loaded { get; } = [];
    public string? ClientName { get; private set; }
    public bool Initialized { get; private set; }
    public bool Discovered { get; private set; }
    public bool Ready => Initialized || Discovered;
    public int Listens => _listens.Count;
    private readonly ConcurrentDictionary<string, JsonNode> _listens = new();
    public bool Killed { get; private set; }
    public int Running, Cancelled, EditChecks;
    public ConcurrentQueue<long> SlowIds { get; } = new();

    public FakeMcpServer(string tag)
    {
        Tag = tag;
        _ = Task.Run(LoopAsync);
    }

    public override int Id => 0;
    public override Stream StandardInput => _in.Writer.AsStream();
    public override Stream StandardOutput => _out.Reader.AsStream();
    public override Stream StandardError => _err.Reader.AsStream();
    public override bool HasExited => _exited.Task.IsCompleted;
    public override int? ExitCode => HasExited ? 1 : null;
    public override Task Exited => _exited.Task;
    public override IReadOnlyList<int> TreeProcessIds() => [];

    public override void Kill()
    {
        Killed = true;
        Exit();
    }

    public override void Dispose() => Kill();

    private void Exit()
    {
        _out.Writer.Complete();
        _err.Writer.Complete();
        _exited.TrySetResult();
    }

    private async Task LoopAsync()
    {
        using var reader = new StreamReader(_in.Reader.AsStream(), Encoding.UTF8);
        if (Tag == "broken")
        {
            await reader.ReadLineAsync();
            Exit();
            return;
        }
        while (!HasExited && await reader.ReadLineAsync() is { } line)
        {
            var message = JsonNode.Parse(line)!.AsObject();
            _ = Task.Run(() => HandleAsync(message));
        }
    }

    private void Send(JsonObject message)
    {
        if (HasExited) return;
        var bytes = Encoding.UTF8.GetBytes(message.ToJsonString() + "\n");
        lock (_write)
        {
            _out.Writer.Write(bytes);
            _out.Writer.FlushAsync().AsTask().Wait();
        }
    }

    private void Reply(JsonNode? id, JsonNode result) => Send(new JsonObject { ["jsonrpc"] = "2.0", ["id"] = id?.DeepClone(), ["result"] = result });

    private void Fail(JsonNode? id, string message) =>
        Send(new JsonObject { ["jsonrpc"] = "2.0", ["id"] = id?.DeepClone(), ["error"] = new JsonObject { ["code"] = -32601, ["message"] = message } });

    private const string PerRequestVersion = "2026-07-28";

    private static JsonObject Capabilities() => new() { ["tools"] = new JsonObject(), ["prompts"] = new JsonObject(), ["resources"] = new JsonObject() };

    private void Notify(string method, JsonNode? stream)
    {
        var message = new JsonObject { ["jsonrpc"] = "2.0", ["method"] = method };
        if (stream != null) message["params"] = new JsonObject { ["_meta"] = new JsonObject { ["io.modelcontextprotocol/subscriptionId"] = stream.DeepClone() } };
        Send(message);
    }

    private static JsonObject Text(string text, bool isError = false) =>
        new() { ["content"] = new JsonArray(new JsonObject { ["type"] = "text", ["text"] = text }), ["isError"] = isError };

    private async Task HandleAsync(JsonObject message)
    {
        var id = message["id"];
        var p = message["params"];
        var method = message["method"]?.GetValue<string>();
        var meta = p?["_meta"];
        // As the SDK: past server/discover every request carries the client's protocol version and capabilities.
        if (id != null && method != null && Discovered && (meta?["io.modelcontextprotocol/protocolVersion"] == null || meta["io.modelcontextprotocol/clientCapabilities"] == null))
        {
            Fail(id, $"'{method}' must include _meta/io.modelcontextprotocol/protocolVersion and clientCapabilities.");
            return;
        }
        switch (method)
        {
            case null:
                if (_asks.TryRemove(id!.ToJsonString(), out var ask)) ask.TrySetResult(message);
                return;
            case "initialize":
                if (p?["protocolVersion"]?.GetValue<string>() == PerRequestVersion)
                {
                    Fail(id, $"Protocol version '{PerRequestVersion}' is not available through the initialize handshake.");
                    return;
                }
                ClientName = p?["clientInfo"]?["name"]?.GetValue<string>();
                Reply(id, new JsonObject
                {
                    ["protocolVersion"] = p?["protocolVersion"]?.DeepClone(),
                    ["capabilities"] = Capabilities(),
                    ["serverInfo"] = new JsonObject { ["name"] = "fake", ["version"] = Tag },
                });
                return;
            case "server/discover":
                if (meta?["io.modelcontextprotocol/protocolVersion"]?.GetValue<string>() != PerRequestVersion)
                {
                    Fail(id, "server/discover requires per-request metadata.");
                    return;
                }
                ClientName = meta["io.modelcontextprotocol/clientInfo"]?["name"]?.GetValue<string>();
                Discovered = true;
                Reply(id, new JsonObject
                {
                    ["supportedVersions"] = new JsonArray(PerRequestVersion),
                    ["capabilities"] = Capabilities(),
                    ["_meta"] = new JsonObject { ["io.modelcontextprotocol/serverInfo"] = new JsonObject { ["name"] = "fake", ["version"] = Tag } },
                });
                return;
            case "subscriptions/listen":
                using (var end = new CancellationTokenSource())
                {
                    _calls[id!.ToJsonString()] = end;
                    _listens[id.ToJsonString()] = id.DeepClone();
                    Send(new JsonObject
                    {
                        ["jsonrpc"] = "2.0",
                        ["method"] = "notifications/subscriptions/acknowledged",
                        ["params"] = new JsonObject { ["notifications"] = p?["notifications"]?.DeepClone(), ["_meta"] = new JsonObject { ["io.modelcontextprotocol/subscriptionId"] = id.DeepClone() } },
                    });
                    try { await Task.Delay(Timeout.Infinite, end.Token); }
                    catch (OperationCanceledException) { }
                    _listens.TryRemove(id.ToJsonString(), out _);
                    Reply(id, new JsonObject());
                }
                return;
            case "notifications/initialized":
                Initialized = true;
                return;
            case "notifications/cancelled":
                if (_calls.TryGetValue(p!["requestId"]!.ToJsonString(), out var call))
                {
                    Interlocked.Increment(ref Cancelled);
                    await call.CancelAsync();
                }
                return;
            case "tools/list":
                Reply(id, new JsonObject { ["tools"] = new JsonArray(new JsonObject { ["name"] = "echo", ["inputSchema"] = new JsonObject { ["type"] = "object" } }) });
                return;
            case "resources/read":
                Interlocked.Increment(ref EditChecks);
                if (_unlisted)
                {
                    Fail(id, "the assemblies resource is unavailable");
                    return;
                }
                var listing = _unsaved > 0 ? $"app.dll\tApp\tC:\\app.dll\t[{_unsaved} unsaved edits]" : "No assemblies loaded.";
                Reply(id, new JsonObject { ["contents"] = new JsonArray(new JsonObject { ["uri"] = "corvus://assemblies", ["text"] = listing }) });
                return;
            case "tools/call":
                await CallAsync(id!, p!["name"]!.GetValue<string>(), p["arguments"] as JsonObject);
                return;
            case not null when id != null:
                Send(new JsonObject { ["jsonrpc"] = "2.0", ["id"] = id.DeepClone(), ["error"] = new JsonObject { ["code"] = -32601, ["message"] = "method not found" } });
                return;
        }
    }

    private async Task CallAsync(JsonNode id, string tool, JsonObject? args)
    {
        switch (tool)
        {
            case "echo":
                Reply(id, Text($"build {Tag}: {args?["text"]}"));
                break;
            case "load_assembly":
                var path = args!["path"]!.GetValue<string>();
                if (!File.Exists(path)) { Reply(id, Text("no such file", isError: true)); break; }
                lock (Loaded) Loaded.Add(path);
                Reply(id, Text("loaded"));
                break;
            case "edit":
                Interlocked.Increment(ref _unsaved);
                Reply(id, Text("edited"));
                break;
            case "unlist":
                _unlisted = true;
                Reply(id, Text("unlisted"));
                break;
            case "save":
                _unsaved = 0;
                Reply(id, Text("saved"));
                break;
            case "server_status":
                var status = Text("status");
                status["structuredContent"] = new JsonObject { ["informationalVersion"] = Tag, ["catalogDigest"] = "t1-fake" };
                Reply(id, status);
                break;
            case "slow":
                using (var cancel = new CancellationTokenSource())
                {
                    _calls[id.ToJsonString()] = cancel;
                    SlowIds.Enqueue(id.GetValue<long>());
                    Interlocked.Increment(ref Running);
                    try { await Task.Delay(Timeout.Infinite, cancel.Token); }
                    catch (OperationCanceledException) { }
                    Reply(id, Text("cancelled"));
                }
                break;
            case "ask":
                var askId = $"ask-{Interlocked.Increment(ref _askIds)}";
                var reply = new TaskCompletionSource<JsonObject>(TaskCreationOptions.RunContinuationsAsynchronously);
                _asks[JsonValue.Create(askId).ToJsonString()] = reply;
                Send(new JsonObject { ["jsonrpc"] = "2.0", ["id"] = askId, ["method"] = "ping" });
                var answer = await reply.Task;
                Reply(id, Text($"build {Tag}: the client {(answer["result"] != null ? "answered" : "failed")} ping"));
                break;
            case "crash":
                Exit();
                break;
            case "notify":
                if (Discovered)
                    foreach (var stream in _listens.Values) Notify("notifications/tools/list_changed", stream);
                else
                    Notify("notifications/tools/list_changed", null);
                Reply(id, Text("notified"));
                break;
        }
    }
}

