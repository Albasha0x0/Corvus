using System.Buffers;
using System.Collections.Concurrent;
using System.IO.Pipelines;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using ModelContextProtocol;
using ModelContextProtocol.Client;
using ModelContextProtocol.Protocol;
using NetDecompilerMcp.Native.Providers;
using NetDecompilerMcp.Relay;

namespace NetDecompilerMcp.Tests;

/// <summary>The development reload relay against scripted fake servers (one per staged build) and the SDK's client.</summary>
public sealed class DevRelayTests : IAsyncLifetime
{
    private readonly TempDir _dir = new();
    private readonly ConcurrentQueue<FakeMcpServer> _servers = new();
    private readonly ConcurrentQueue<string> _notifications = new();
    private DevRelay _relay = null!;
    private Task<int> _run = null!;
    private McpClient _client = null!;
    private readonly Pipe _toRelay = new();
    private string Publish => Path.Combine(_dir.Path, "publish");
    private string State => Path.Combine(_dir.Path, "state");

    public async Task InitializeAsync()
    {
        Directory.CreateDirectory(Publish);
        PublishBuild("A");
        var toRelay = _toRelay;
        var toClient = new Pipe();
        var options = new RelayOptions { Target = Publish, StateDirectory = State, Poll = TimeSpan.FromMilliseconds(20), RequestTimeout = TimeSpan.FromSeconds(10) };
        _relay = new DevRelay(options, toRelay.Reader.AsStream(), toClient.Writer.AsStream(), TextWriter.Null, dir =>
        {
            var server = new FakeMcpServer(File.ReadAllText(Path.Combine(dir, "tag.txt"))) { Directory = dir };
            _servers.Enqueue(server);
            return server;
        });
        _run = _relay.RunAsync();
        var handlers = new McpClientHandlers
        {
            NotificationHandlers =
            [
                new(NotificationMethods.ToolListChangedNotification, (n, _) => { _notifications.Enqueue(n.Method); return ValueTask.CompletedTask; }),
                new(NotificationMethods.PromptListChangedNotification, (n, _) => { _notifications.Enqueue(n.Method); return ValueTask.CompletedTask; }),
                new(NotificationMethods.ResourceListChangedNotification, (n, _) => { _notifications.Enqueue(n.Method); return ValueTask.CompletedTask; }),
            ],
        };
        _client = await McpClient.CreateAsync(new StreamClientTransport(toRelay.Writer.AsStream(), toClient.Reader.AsStream()),
            new McpClientOptions { ClientInfo = new Implementation { Name = "relay-test", Version = "1" }, Handlers = handlers });
    }

    public async Task DisposeAsync()
    {
        await _client.DisposeAsync();
        await _toRelay.Writer.CompleteAsync(); // the client's end of input
        Assert.Equal(0, await _run.WaitAsync(TimeSpan.FromSeconds(10)));
        _dir.Dispose();
    }

    /// <summary>Writes a build tagged <paramref name="tag"/> and then its marker, as publish.ps1 does.</summary>
    private void PublishBuild(string tag)
    {
        File.Delete(Path.Combine(Publish, RelayBuilds.MarkerName));
        File.WriteAllText(Path.Combine(Publish, "NetDecompilerMcp.dll"), "stand-in");
        File.WriteAllText(Path.Combine(Publish, "tag.txt"), tag);
        File.WriteAllText(Path.Combine(Publish, RelayBuilds.MarkerName), JsonSerializer.Serialize(new { buildId = tag }));
    }

    private FakeMcpServer Server(string tag) => _servers.Last(s => s.Tag == tag);

    private async Task<string> Call(string tool, Dictionary<string, object?>? args = null, CancellationToken token = default)
    {
        var result = await _client.CallToolAsync(tool, args ?? [], cancellationToken: token);
        return string.Join("\n", result.Content.OfType<TextContentBlock>().Select(b => b.Text));
    }

    private static async Task Until(Func<bool> condition, string what)
    {
        for (int i = 0; i < 500 && !condition(); i++) await Task.Delay(20);
        Assert.True(condition(), "timed out waiting for " + what);
    }

    [Fact]
    public async Task ForwardsCallsAndAddsTheApplyTool()
    {
        var tools = await _client.ListToolsAsync();
        Assert.Contains(tools, t => t.Name == "echo");
        Assert.Contains(tools, t => t.Name == DevRelay.ApplyTool);
        Assert.Equal("build A: hi", await Call("echo", new() { ["text"] = "hi" }));
        Assert.True(_client.ServerCapabilities.Tools?.ListChanged);
        Assert.Contains("No newer build", await Call(DevRelay.ApplyTool));
        // The server ran from a staged copy, never from the publish folder.
        Assert.StartsWith(Path.Combine(State, "builds"), Server("A").Directory ?? Path.Combine(State, "builds"), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task NewBuildReplaysLoadsAndNotifies()
    {
        var file = _dir.File("app.dll");
        File.WriteAllText(file, "x");
        await Call("load_assembly", new() { ["path"] = file });
        await Call("load_assembly", new() { ["path"] = file, ["dryRun"] = true });
        await Call("echo", new() { ["text"] = "not replayed" });
        PublishBuild("B");
        await Until(() => _notifications.Count == 3, "list_changed notifications");
        Assert.Equal(["notifications/prompts/list_changed", "notifications/resources/list_changed", "notifications/tools/list_changed"], _notifications.Order(StringComparer.Ordinal));
        var text = await Call("echo", new() { ["text"] = "hi" });
        Assert.StartsWith("[relay] now serving build B (B, catalog t1-fake) (was A); replayed 1 workspace call(s): load_assembly " + file, text);
        Assert.EndsWith("build B: hi", text);
        var b = Server("B");
        Assert.Equal([file], b.Loaded);
        Assert.Equal("relay-test", b.ClientName);
        Assert.True(b.Initialized);
        await Until(() => Server("A").Killed, "the old server to stop");
        Assert.DoesNotContain("[relay]", await Call("echo", new() { ["text"] = "again" }));
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
    public async Task FailedNewServerKeepsTheOldOne()
    {
        PublishBuild("broken");
        await Until(() => _servers.Any(s => s.Tag == "broken" && s.Killed), "the broken build to be dropped");
        var text = await Call("echo", new() { ["text"] = "hi" });
        Assert.StartsWith("[relay] new build broken was not applied: initialize failed", text);
        Assert.EndsWith("build A: hi", text);
        PublishBuild("C");
        await Until(() => _servers.Any(s => s.Tag == "C" && s.Initialized), "build C");
        await Until(() => Server("A").Killed, "build A to stop");
        Assert.EndsWith("build C: hi", await Call("echo", new() { ["text"] = "hi" }));
    }

    [Fact]
    public async Task FailedReplayKeepsTheOldOneUnlessForced()
    {
        var file = _dir.File("gone.dll");
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
        await Task.Delay(300);
        Assert.Single(_servers); // not while a call is in flight
        // Sent by hand: this SDK version does not send notifications/cancelled for a cancelled call.
        await _client.SendNotificationAsync(NotificationMethods.CancelledNotification,
            new CancelledNotificationParams { RequestId = new RequestId(Server("A").SlowIds.Single()) });
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => slow); // the SDK drops its own pending request
        await Until(() => Server("A").Cancelled == 1, "the cancellation to reach the server");
        await Until(() => _servers.Any(s => s.Tag == "B" && s.Initialized), "build B");
    }

    [Fact]
    public async Task ServerRequestsReachTheClientAcrossSwaps()
    {
        Assert.Equal("build A: the client answered ping", await Call("ask"));
        PublishBuild("B");
        await Until(() => _notifications.Count == 3, "the swap");
        Assert.EndsWith("build B: the client answered ping", await Call("ask"));
    }

    [Fact]
    public async Task ExitedServerIsRestartedWithReplay()
    {
        var file = _dir.File("app.dll");
        File.WriteAllText(file, "x");
        await Call("load_assembly", new() { ["path"] = file });
        await Assert.ThrowsAnyAsync<McpException>(() => Call("crash"));
        await Until(() => _servers.Count == 2 && _servers.Last().Initialized, "the restart");
        var text = await Call("echo", new() { ["text"] = "hi" });
        Assert.Contains("exited", text);
        Assert.Contains("replayed 1 workspace call(s)", text);
        Assert.Equal([file], _servers.Last().Loaded);
    }

    [Fact]
    public void ArgumentsSplitBetweenRelayAndServer()
    {
        var options = RelayCli.Parse(["--target", _dir.Path, "--load", "x.dll", "--poll-ms", "50", "--", "--target", "y"]);
        Assert.Equal(Path.GetFullPath(_dir.Path), options.Target);
        Assert.Equal(["--load", "x.dll", "--target", "y"], options.ServerArgs);
        Assert.Equal(TimeSpan.FromMilliseconds(50), options.Poll);
        Assert.Throws<ArgumentException>(() => RelayCli.Parse(["--load", "x.dll"]));
        Assert.Equal(["--load", "x.dll"], RelayCli.WithoutRelayPrefix(["relay", "--target", "d", "--state", "s", "--", "--load", "x.dll"]));
        Assert.Equal(["--load", "x.dll"], RelayCli.WithoutRelayPrefix(["--load", "x.dll"]));
    }

    [Fact]
    public void StagingSkipsTheMarkerAndRenamedAsideFiles()
    {
        File.WriteAllText(Path.Combine(Publish, "NetDecompilerMcp.dll" + RelayBuilds.AsideInfix + "1"), "old");
        Directory.CreateDirectory(Path.Combine(Publish, "runtimes"));
        File.WriteAllText(Path.Combine(Publish, "runtimes", "n.so"), "n");
        var marker = RelayBuilds.ReadMarker(Publish);
        var staged = RelayBuilds.Stage(Publish, Path.Combine(_dir.Path, "stage"), marker);
        Assert.True(File.Exists(Path.Combine(staged, "runtimes", "n.so")));
        Assert.False(File.Exists(Path.Combine(staged, RelayBuilds.MarkerName)));
        Assert.Empty(Directory.GetFiles(staged, "*" + RelayBuilds.AsideInfix + "*"));
        Assert.Equal("A", RelayBuild.From(marker).Id);
        Assert.Throws<IOException>(() => RelayBuilds.Stage(Publish, Path.Combine(_dir.Path, "stage"), "{\"buildId\":\"other\"}"));
    }
}

/// <summary>The relay with the real server: two publishes of this build, a load replayed, an edit holding the swap back.</summary>
public sealed class DevRelayRealServerTests
{
    [Trait("Speed", "Slow")]
    [Fact]
    public async Task RepublishSwapsTheRealServerAndKeepsTheWorkspace()
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
        void Mark(string id) => File.WriteAllText(Path.Combine(publish, RelayBuilds.MarkerName), JsonSerializer.Serialize(new { buildId = id }));
        Mark("one");

        var toRelay = new Pipe();
        var toClient = new Pipe();
        var options = new RelayOptions { Target = publish, StateDirectory = Path.Combine(dir.Path, "state"), Poll = TimeSpan.FromMilliseconds(100) };
        var processes = new ConcurrentQueue<ChildProcess>();
        var relay = new DevRelay(options, toRelay.Reader.AsStream(), toClient.Writer.AsStream(), TextWriter.Null, staged =>
        {
            var process = ChildProcess.Start(new ChildProcessStart(Path.Combine(staged, RelayBuilds.ProgramName), [])
            {
                Environment = new Dictionary<string, string?> { ["NDM_ANNOTATIONS_DIR"] = Path.Combine(dir.Path, "annotations") },
            });
            processes.Enqueue(process);
            return process;
        });
        var run = relay.RunAsync();
        var changed = 0;
        var handlers = new McpClientHandlers
        {
            NotificationHandlers = [new(NotificationMethods.ToolListChangedNotification, (_, _) => { Interlocked.Increment(ref changed); return ValueTask.CompletedTask; })],
        };
        await using (var client = await McpClient.CreateAsync(new StreamClientTransport(toRelay.Writer.AsStream(), toClient.Reader.AsStream()), new McpClientOptions { Handlers = handlers }))
        {
            async Task<string> Call(string tool, Dictionary<string, object?> args) =>
                string.Join("\n", (await client.CallToolAsync(tool, args)).Content.OfType<TextContentBlock>().Select(b => b.Text));

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
        }
        await toRelay.Writer.CompleteAsync();
        Assert.Equal(0, await run.WaitAsync(TimeSpan.FromSeconds(30)));
    }
}

/// <summary>
/// A scripted MCP server behind in-memory pipes. Tools: echo {text}, load_assembly {path} (fails for a missing file),
/// edit / save (unsaved edits in the assemblies resource), slow (until cancelled), ask (pings the client), crash, server_status.
/// Tagged "broken", it exits without answering.
/// </summary>
internal sealed class FakeMcpServer : ChildProcess
{
    private readonly Pipe _in = new(), _out = new(), _err = new();
    private readonly TaskCompletionSource _exited = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private readonly ConcurrentDictionary<string, CancellationTokenSource> _calls = new();
    private readonly ConcurrentDictionary<string, TaskCompletionSource<JsonObject>> _asks = new();
    private readonly object _write = new();
    private int _unsaved, _askIds;

    public string Tag { get; }
    public string? Directory { get; init; }
    public List<string> Loaded { get; } = [];
    public string? ClientName { get; private set; }
    public bool Initialized { get; private set; }
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

    private static JsonObject Text(string text, bool isError = false) =>
        new() { ["content"] = new JsonArray(new JsonObject { ["type"] = "text", ["text"] = text }), ["isError"] = isError };

    private async Task HandleAsync(JsonObject message)
    {
        var id = message["id"];
        var p = message["params"];
        switch (message["method"]?.GetValue<string>())
        {
            case null:
                if (_asks.TryRemove(id!.ToJsonString(), out var ask)) ask.TrySetResult(message);
                return;
            case "initialize":
                ClientName = p?["clientInfo"]?["name"]?.GetValue<string>();
                Reply(id, new JsonObject
                {
                    ["protocolVersion"] = p?["protocolVersion"]?.DeepClone(),
                    ["capabilities"] = new JsonObject { ["tools"] = new JsonObject(), ["prompts"] = new JsonObject(), ["resources"] = new JsonObject() },
                    ["serverInfo"] = new JsonObject { ["name"] = "fake", ["version"] = Tag },
                });
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
                var listing = _unsaved > 0 ? $"app.dll\tApp\tC:\\app.dll\t[{_unsaved} unsaved edits]" : "No assemblies loaded.";
                Reply(id, new JsonObject { ["contents"] = new JsonArray(new JsonObject { ["uri"] = "netdecomp://assemblies", ["text"] = listing }) });
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
        }
    }
}

