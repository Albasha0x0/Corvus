using System.Collections.Concurrent;
using System.ComponentModel;
using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using System.Threading.Channels;
using NetDecompilerMcp.Native.Providers;

namespace NetDecompilerMcp.Relay;

/// <summary>Relay settings: the watched publish folder, the server's own arguments and where builds are staged.</summary>
public sealed record RelayOptions
{
    public required string Target { get; init; }
    public IReadOnlyList<string> ServerArgs { get; init; } = [];
    public required string StateDirectory { get; init; }
    public TimeSpan Poll { get; init; } = TimeSpan.FromSeconds(1);
    /// <summary>Limit for each request the relay itself sends (initialize, one replayed call, the edit check).</summary>
    public TimeSpan RequestTimeout { get; init; } = TimeSpan.FromMinutes(2);
}

/// <summary>
/// Development reload. Speaks MCP stdio to the client and forwards JSON-RPC to the real server, run as a child from a
/// staged copy of the publish folder. When a new publish marker is stable and no client request is in flight, a new
/// child is initialized with the client's initialize params, replays the workspace-establishing calls, and replaces the
/// old one; the client then gets list_changed notifications and a [relay] notice on its next tool result.
/// </summary>
public sealed partial class DevRelay : IAsyncDisposable
{
    /// <summary>Tool the relay adds to tools/list: switch to the newer build now.</summary>
    public const string ApplyTool = "relay_apply";

    private static readonly HashSet<string> ReplayedTools = ["load_assembly", "unload_assembly", "add_search_directory", "load_pdb", "unpack_container"];
    private static readonly string[] ListChanged =
        ["notifications/tools/list_changed", "notifications/prompts/list_changed", "notifications/resources/list_changed"];
    private const string NotCarried = "not carried over: in-memory edits, native engine sessions and kept results (read_result ids).";

    // Relaxed escaping keeps forwarded text as the server wrote it ('+', quotes inside strings) instead of \uXXXX.
    private static readonly System.Text.Json.JsonSerializerOptions Wire = new() { Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping };

    private readonly RelayOptions _options;
    private readonly Stream _clientIn, _clientOut;
    private readonly TextWriter _log;
    private readonly Func<string, ChildProcess> _launch;
    private readonly object _gate = new();
    private readonly object _clientWrite = new();
    private readonly Channel<JsonObject> _fromClient = Channel.CreateUnbounded<JsonObject>(new UnboundedChannelOptions { SingleReader = true, SingleWriter = true });
    private readonly CancellationTokenSource _stop = new();

    // Guarded by _gate.
    private Child? _active;
    private readonly Dictionary<string, (Child Child, JsonObject Request)> _inFlight = [];
    private readonly Dictionary<string, (Child Child, JsonNode? Id)> _serverRequests = [];
    private readonly List<(string Method, JsonObject? Params, string Label)> _replay = [];
    private readonly List<string> _notices = [];
    private readonly List<TaskCompletionSource<(bool Ok, string Text)>> _applyWaiters = [];
    private JsonObject? _initializeParams;
    private string? _protocolVersion;
    private bool _initialized, _swapping, _force, _postponed, _clientSpoke;
    private TaskCompletionSource _swapDone = Done();
    private RelayBuild? _pending;
    private string? _failedMarker, _postponeNoticeFor;
    private long _ids;
    private int _generation;

    /// <param name="launch">Starts the server in a staged folder (tests pass a fake).</param>
    public DevRelay(RelayOptions options, Stream clientIn, Stream clientOut, TextWriter log, Func<string, ChildProcess>? launch = null)
    {
        _options = options;
        _clientIn = clientIn;
        _clientOut = clientOut;
        _log = log;
        _launch = launch ?? (dir => RelayBuilds.Launch(dir, options.ServerArgs));
    }

    /// <summary>Serves until the client closes its input; 1 when the first server cannot start.</summary>
    public async Task<int> RunAsync()
    {
        RelayBuilds.RemoveStale(_options.StateDirectory);
        try { _active = Start(RelayBuild.From(RelayBuilds.ReadMarker(_options.Target))); }
        catch (Exception ex) when (IsStartFailure(ex))
        {
            _log.WriteLine($"net-decompiler relay: cannot start the server from {_options.Target}: {ex.Message}");
            return 1;
        }
        var watch = WatchAsync(_stop.Token);
        var dispatch = DispatchAsync(_stop.Token);
        try { await ReadClientAsync(_stop.Token); }
        catch (OperationCanceledException) { }
        await DisposeAsync();
        await Task.WhenAll(Quiet(watch), Quiet(dispatch));
        return 0;
    }

    public async ValueTask DisposeAsync()
    {
        await _stop.CancelAsync();
        _fromClient.Writer.TryComplete();
        List<Child> children;
        lock (_gate)
        {
            children = _active != null ? [_active] : [];
            _active = null;
        }
        // Bounded: staged folders left behind are removed by the next relay's start.
        await Task.WhenAny(Task.WhenAll(children.Select(Retire)), Task.Delay(TimeSpan.FromSeconds(5)));
    }

    private sealed class Child(ChildProcess process, RelayBuild build, string directory, int generation)
    {
        public ChildProcess Process { get; } = process;
        public RelayBuild Build { get; } = build;
        public string Directory { get; } = directory;
        public int Generation { get; } = generation;
        /// <summary>Replies to the relay's own requests, by id.</summary>
        public ConcurrentDictionary<string, TaskCompletionSource<JsonObject>> Own { get; } = new();
        public volatile bool Retired, Gone;
        private readonly object _write = new();

        public bool Send(JsonNode message)
        {
            var bytes = Encoding.UTF8.GetBytes(message.ToJsonString(Wire) + "\n");
            try
            {
                lock (_write)
                {
                    Process.StandardInput.Write(bytes);
                    Process.StandardInput.Flush();
                }
                return true;
            }
            catch (Exception ex) when (ex is IOException or ObjectDisposedException) { return false; }
        }
    }

    private Child Start(RelayBuild build)
    {
        var dir = RelayBuilds.Stage(_options.Target, _options.StateDirectory, build.Marker);
        ChildProcess process;
        try { process = _launch(dir); }
        catch
        {
            RelayBuilds.TryDelete(dir);
            throw;
        }
        var child = new Child(process, build, dir, Interlocked.Increment(ref _generation));
        _ = Task.Run(() => PumpAsync(child));
        _ = Task.Run(() => PumpErrorsAsync(child));
        return child;
    }

    private static bool IsStartFailure(Exception ex) => ex is IOException or UnauthorizedAccessException or Win32Exception or InvalidOperationException;

    private async Task ReadClientAsync(CancellationToken token)
    {
        using var reader = new StreamReader(_clientIn, new UTF8Encoding(false));
        while (await reader.ReadLineAsync(token) is { } line)
        {
            if (Parse(line) is not { } message) continue;
            if (IsResponse(message)) RouteClientResponse(message);
            else _fromClient.Writer.TryWrite(message);
        }
    }

    /// <summary>Forwards client requests and notifications in order; holds them while a swap runs.</summary>
    private async Task DispatchAsync(CancellationToken token)
    {
        await foreach (var message in _fromClient.Reader.ReadAllAsync(token))
        {
            Child? child;
            while (true)
            {
                Task wait;
                lock (_gate)
                {
                    if (!_swapping)
                    {
                        child = Admit(message);
                        break;
                    }
                    wait = _swapDone.Task;
                }
                await wait.WaitAsync(token);
            }
            if (child == null) continue;
            if (!child.Send(message) && message["id"] is { } id)
            {
                lock (_gate) _inFlight.Remove(Key(id));
                WriteClient(Error(id, "the server process is not running."));
            }
            if (Method(message) == "notifications/initialized") TryBeginSwap();
        }
    }

    /// <summary>Where a client message goes (null: answered here). Called under _gate.</summary>
    private Child? Admit(JsonObject message)
    {
        var method = Method(message);
        var id = message["id"];
        switch (method)
        {
            case "initialize":
                _initializeParams = message["params"]?.DeepClone() as JsonObject;
                break;
            case "notifications/initialized":
                _initialized = true;
                break;
            case "notifications/cancelled":
                var cancelled = message["params"]?["requestId"];
                return cancelled != null && _inFlight.TryGetValue(Key(cancelled), out var owner) ? owner.Child : _active;
            case "tools/call":
                if (id != null && ToolName(message) == ApplyTool)
                {
                    var applyId = id.DeepClone();
                    _ = Task.Run(() => ApplyAsync(applyId));
                    return null;
                }
                break;
        }
        if (id == null) return _active;
        _clientSpoke = true;
        if (_active is not { Gone: false } active)
        {
            var reason = _notices.Count > 0 ? " " + _notices[^1] : "";
            WriteClient(Error(id, "the server process is not running; publish a build or call relay_apply to restart it." + reason));
            return null;
        }
        _inFlight[Key(id)] = (active, message);
        return active;
    }

    private async Task PumpAsync(Child child)
    {
        try
        {
            using var reader = new StreamReader(child.Process.StandardOutput, new UTF8Encoding(false));
            while (await reader.ReadLineAsync() is { } line)
                if (Parse(line) is { } message) OnChildMessage(child, message);
        }
        catch (Exception ex) when (ex is IOException or ObjectDisposedException) { }
        OnChildGone(child);
    }

    private async Task PumpErrorsAsync(Child child)
    {
        try
        {
            using var reader = new StreamReader(child.Process.StandardError);
            while (await reader.ReadLineAsync() is { } line)
                lock (_log) _log.WriteLine(line);
        }
        catch (Exception ex) when (ex is IOException or ObjectDisposedException) { }
    }

    private void OnChildMessage(Child child, JsonObject message)
    {
        if (message["method"] != null)
        {
            if (message["id"] is { } requestId)
            {
                // Server-to-client request: ids of different children may collide, so the client sees the relay's own.
                var relayId = $"relay-{child.Generation}-{Interlocked.Increment(ref _ids)}";
                lock (_gate) _serverRequests[Key(JsonValue.Create(relayId))] = (child, requestId.DeepClone());
                message["id"] = relayId;
                WriteClient(message);
                return;
            }
            bool active;
            lock (_gate) active = child == _active && !child.Retired;
            if (active) WriteClient(message);
            return;
        }
        if (message["id"] is not { } id) return;
        var key = Key(id);
        if (child.Own.TryRemove(key, out var own))
        {
            own.TrySetResult(message);
            return;
        }
        bool drained;
        lock (_gate)
        {
            if (!_inFlight.TryGetValue(key, out var entry) || entry.Child != child) return;
            _inFlight.Remove(key);
            Record(entry.Request, message);
            Decorate(entry.Request, message);
            drained = _inFlight.Count == 0;
        }
        WriteClient(message);
        if (drained) TryBeginSwap();
    }

    private void OnChildGone(Child child)
    {
        child.Gone = true;
        foreach (var key in child.Own.Keys)
            if (child.Own.TryRemove(key, out var own)) own.TrySetResult(Error(null, "the server process exited."));
        var failed = new List<JsonNode>();
        lock (_gate)
        {
            foreach (var (key, entry) in _inFlight.Where(e => e.Value.Child == child).ToList())
            {
                _inFlight.Remove(key);
                if (entry.Request["id"] is { } id) failed.Add(id.DeepClone());
            }
            if (child.Retired || child != _active || _stop.IsCancellationRequested) return;
            _notices.Add($"the server process of build {child.Build.Id} exited (exit code {child.Process.ExitCode?.ToString() ?? "?"}); it is restarted with the workspace calls replayed.");
            _pending ??= RelayBuild.From(RelayBuilds.ReadMarker(_options.Target));
            _postponed = false;
        }
        foreach (var id in failed) WriteClient(Error(id, "the server process exited during the call."));
        TryBeginSwap();
    }

    private void RouteClientResponse(JsonObject message)
    {
        (Child Child, JsonNode? Id) target;
        lock (_gate)
            if (message["id"] is not { } id || !_serverRequests.Remove(Key(id), out target)) return;
        message["id"] = target.Id?.DeepClone();
        target.Child.Send(message);
    }

    /// <summary>Keeps successful workspace-establishing requests for replay. Called under _gate.</summary>
    private void Record(JsonObject request, JsonObject response)
    {
        if (response["error"] != null) return;
        var p = request["params"] as JsonObject;
        switch (Method(request))
        {
            case "tools/call":
                var name = p?["name"]?.GetValue<string>();
                if (name == null || !ReplayedTools.Contains(name) || IsTrue(response["result"]?["isError"])) return;
                var args = p!["arguments"] as JsonObject;
                if (IsTrue(args?["dryRun"]) || (name == "unpack_container" && args?["load"] is JsonValue load && load.TryGetValue<bool>(out var l) && !l)) return;
                _replay.Add(("tools/call", new JsonObject { ["name"] = name, ["arguments"] = args?.DeepClone() }, Label(name, args)));
                break;
            case "logging/setLevel":
                _replay.RemoveAll(r => r.Method == "logging/setLevel");
                _replay.Add(("logging/setLevel", p?.DeepClone() as JsonObject, "logging level"));
                break;
            case "resources/subscribe" or "resources/unsubscribe":
                _replay.Add((Method(request)!, p?.DeepClone() as JsonObject, $"{Method(request)} {p?["uri"]}"));
                break;
        }
    }

    /// <summary>Adjusts a reply on its way to the client. Called under _gate.</summary>
    private void Decorate(JsonObject request, JsonObject response)
    {
        if (response["result"] is not JsonObject result) return;
        switch (Method(request))
        {
            case "initialize":
                _protocolVersion = result["protocolVersion"]?.GetValue<string>();
                // The relay sends these after a swap whatever the server declares.
                if (result["capabilities"] is JsonObject capabilities)
                    foreach (var kind in new[] { "tools", "prompts", "resources" })
                        if (capabilities[kind] is JsonObject o) o["listChanged"] = true;
                break;
            case "tools/list" when result["nextCursor"] == null && result["tools"] is JsonArray tools:
                tools.Add(ApplyToolDefinition());
                break;
            case "tools/call":
                _postponed = false; // the call may have saved or reverted the edits that held a swap back
                if (_notices.Count > 0 && result["content"] is JsonArray content)
                {
                    content.Insert(0, new JsonObject { ["type"] = "text", ["text"] = string.Join("\n", _notices.Select(n => "[relay] " + n)) + "\n\n" });
                    _notices.Clear();
                }
                break;
        }
    }

    private static JsonObject ApplyToolDefinition() => new()
    {
        ["name"] = ApplyTool,
        ["title"] = "Apply the newer server build",
        ["description"] = "Development relay: switch to the newest published server build now, also when unsaved in-memory edits would be lost " +
                          "or a workspace call fails to replay (it is then listed). Without a newer build, restarts a server that exited.",
        ["inputSchema"] = new JsonObject { ["type"] = "object", ["properties"] = new JsonObject() },
        ["annotations"] = new JsonObject { ["readOnlyHint"] = false, ["destructiveHint"] = true, ["idempotentHint"] = false, ["openWorldHint"] = false },
    };

    private async Task ApplyAsync(JsonNode id)
    {
        var marker = RelayBuilds.ReadMarker(_options.Target);
        var waiter = new TaskCompletionSource<(bool Ok, string Text)>(TaskCreationOptions.RunContinuationsAsynchronously);
        lock (_gate)
        {
            if (_pending == null && (_active is null or { Gone: true } || (marker != null && marker != _active.Build.Marker)))
                _pending = RelayBuild.From(marker);
            if (_pending == null)
            {
                WriteClient(ToolResult(id, $"No newer build in {_options.Target}; serving build {_active?.Build.Id}.", isError: false));
                return;
            }
            _force = true;
            _postponed = false;
            _applyWaiters.Add(waiter);
        }
        TryBeginSwap();
        var (ok, text) = await waiter.Task;
        WriteClient(ToolResult(id, text, isError: !ok));
    }

    private async Task WatchAsync(CancellationToken token)
    {
        using var timer = new PeriodicTimer(_options.Poll);
        string? seen = null;
        while (await timer.WaitForNextTickAsync(token))
        {
            var marker = RelayBuilds.ReadMarker(_options.Target);
            // Debounce: the same marker on two polls in a row.
            if (marker == null || marker != seen)
            {
                seen = marker;
                continue;
            }
            lock (_gate)
            {
                if (_active == null || marker == _active.Build.Marker || marker == _failedMarker || marker == _pending?.Marker) continue;
                _pending = RelayBuild.From(marker);
                _postponed = false;
            }
            TryBeginSwap();
        }
    }

    private void TryBeginSwap()
    {
        lock (_gate)
        {
            if (_swapping || _pending == null || _postponed || _inFlight.Count > 0 || _stop.IsCancellationRequested) return;
            // Before the client's handshake there is nothing to replay into: a new child then just replaces the old one.
            if (_initializeParams != null && !_initialized) return;
            _swapping = true;
            _swapDone = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        }
        _ = Task.Run(RunSwapAsync);
    }

    private async Task RunSwapAsync()
    {
        RelayBuild build;
        bool force;
        Child? old, next = null;
        JsonObject? initialize;
        bool spoke;
        List<(string Method, JsonObject? Params, string Label)> replay;
        lock (_gate)
        {
            build = _pending!;
            force = _force;
            old = _active;
            initialize = _initializeParams;
            spoke = _clientSpoke;
            replay = [.. _replay];
        }
        (bool Ok, string Text) outcome = (false, "");
        try
        {
            int discarded = 0;
            if (old is { Gone: false })
            {
                discarded = await UnsavedEditsAsync(old);
                if (discarded > 0 && !force)
                {
                    lock (_gate)
                    {
                        _postponed = true;
                        if (_postponeNoticeFor != build.Marker)
                        {
                            _postponeNoticeFor = build.Marker;
                            _notices.Add($"new build {build.Id} ready; {discarded} unsaved edit(s) pending — save or revert them, or call {ApplyTool} to switch now and discard them.");
                        }
                    }
                    outcome = (false, $"build {build.Id} not applied: {discarded} unsaved edit(s) pending.");
                    return;
                }
            }

            next = Start(build);
            var replayed = new List<string>();
            var skipped = new List<string>();
            if (initialize != null)
            {
                var init = await RequestAsync(next, "initialize", (JsonObject)initialize.DeepClone());
                if (Failure(init) is { } why) throw new RelayException($"initialize failed: {why}");
                var version = init["result"]?["protocolVersion"]?.GetValue<string>();
                if (version != _protocolVersion) throw new RelayException($"the new server negotiated protocol {version}, the client uses {_protocolVersion}");
                if (!next.Send(new JsonObject { ["jsonrpc"] = "2.0", ["method"] = "notifications/initialized" }))
                    throw new RelayException("the new server stopped reading its input");
            }
            // A client without an initialize handshake (stateless protocol versions) still gets its workspace replayed.
            foreach (var (method, parameters, label) in replay)
            {
                var reply = await RequestAsync(next, method, (JsonObject?)parameters?.DeepClone());
                if (Failure(reply) is not { } why2) replayed.Add(label);
                else if (force) skipped.Add($"{label} ({why2})");
                else throw new RelayException($"replaying {label} failed: {why2}");
            }
            var identity = spoke ? await IdentityAsync(next) : null;

            var text = new StringBuilder($"now serving build {build.Id}{identity} (was {old?.Build.Id ?? "none"}); ");
            text.Append(replayed.Count == 0 ? "no workspace calls to replay" : $"replayed {replayed.Count} workspace call(s): {string.Join("; ", replayed)}");
            if (skipped.Count > 0) text.Append($"; not replayed: {string.Join("; ", skipped)}");
            if (discarded > 0) text.Append($"; {discarded} unsaved edit(s) were discarded");
            text.Append("; ").Append(NotCarried);
            lock (_gate)
            {
                _active = next;
                if (old != null) old.Retired = true;
                if (_pending == build) _pending = null;
                _force = false;
                _failedMarker = null;
                _notices.Add(text.ToString());
            }
            next = null;
            if (spoke)
                foreach (var method in ListChanged) WriteClient(new JsonObject { ["jsonrpc"] = "2.0", ["method"] = method });
            if (old != null) _ = Retire(old);
            outcome = (true, text.ToString());
        }
        catch (Exception ex) when (ex is RelayException or TimeoutException or OperationCanceledException || IsStartFailure(ex))
        {
            if (next != null) _ = Retire(next);
            var serving = old is { Gone: false } ? $"still serving build {old.Build.Id}" : "no server is running";
            var text = $"new build {build.Id} was not applied: {ex.Message}; {serving}. Publish again, or call {ApplyTool} to apply it anyway.";
            lock (_gate)
            {
                _failedMarker = build.Marker;
                if (_pending == build) _pending = null;
                _force = false;
                _notices.Add(text);
            }
            lock (_log) _log.WriteLine("net-decompiler relay: " + text);
            outcome = (false, text);
        }
        finally
        {
            TaskCompletionSource done;
            List<TaskCompletionSource<(bool, string)>> waiters;
            lock (_gate)
            {
                _swapping = false;
                done = _swapDone;
                waiters = [.. _applyWaiters];
                _applyWaiters.Clear();
            }
            done.TrySetResult();
            foreach (var waiter in waiters) waiter.TrySetResult(outcome);
            TryBeginSwap(); // a newer build that arrived meanwhile
        }
    }

    /// <summary>Unsaved .NET edits and native patches in the server's assemblies resource; 0 when it cannot tell.</summary>
    private async Task<int> UnsavedEditsAsync(Child child)
    {
        JsonObject reply;
        try { reply = await RequestAsync(child, "resources/read", new JsonObject { ["uri"] = "netdecomp://assemblies" }); }
        catch (Exception ex) when (ex is TimeoutException or RelayException or IOException) { return 0; }
        int count = 0;
        foreach (var content in reply["result"]?["contents"] as JsonArray ?? [])
            foreach (Match m in UnsavedPattern().Matches(content?["text"]?.GetValue<string>() ?? ""))
                count += int.Parse(m.Groups[1].ValueSpan, System.Globalization.CultureInfo.InvariantCulture);
        return count;
    }

    /// <summary>" (version, catalog digest)" from the new server's server_status, or "" when it does not say.</summary>
    private async Task<string> IdentityAsync(Child child)
    {
        try
        {
            var reply = await RequestAsync(child, "tools/call", new JsonObject { ["name"] = "server_status", ["arguments"] = new JsonObject() });
            var status = reply["result"]?["structuredContent"];
            var version = status?["informationalVersion"]?.GetValue<string>();
            var digest = status?["catalogDigest"]?.GetValue<string>();
            return version == null && digest == null ? "" : $" ({version}, catalog {digest})";
        }
        catch (Exception ex) when (ex is TimeoutException or RelayException or InvalidOperationException) { return ""; }
    }

    private async Task<JsonObject> RequestAsync(Child child, string method, JsonObject? parameters)
    {
        var id = JsonValue.Create($"relay-own-{Interlocked.Increment(ref _ids)}");
        var reply = new TaskCompletionSource<JsonObject>(TaskCreationOptions.RunContinuationsAsynchronously);
        child.Own[Key(id)] = reply;
        var request = new JsonObject { ["jsonrpc"] = "2.0", ["id"] = id.DeepClone(), ["method"] = method };
        if (parameters != null) request["params"] = parameters;
        if (child.Gone || !child.Send(request)) throw new RelayException($"the server process is not running ({method})");
        try { return await reply.Task.WaitAsync(_options.RequestTimeout, _stop.Token); }
        catch (TimeoutException) { throw new TimeoutException($"{method} got no reply within {_options.RequestTimeout.TotalSeconds:0} s"); }
        finally { child.Own.TryRemove(Key(id), out _); }
    }

    private Task Retire(Child child)
    {
        child.Retired = true;
        child.Process.Dispose();
        return Task.Run(async () =>
        {
            // Files of a killed process unlock a moment after it exits.
            for (int i = 0; i < 20 && Directory.Exists(child.Directory); i++)
            {
                RelayBuilds.TryDelete(child.Directory);
                if (Directory.Exists(child.Directory)) await Task.Delay(250);
            }
        });
    }

    private void WriteClient(JsonNode message)
    {
        var bytes = Encoding.UTF8.GetBytes(message.ToJsonString(Wire) + "\n");
        lock (_clientWrite)
        {
            try
            {
                _clientOut.Write(bytes);
                _clientOut.Flush();
            }
            catch (Exception ex) when (ex is IOException or ObjectDisposedException) { _stop.Cancel(); }
        }
    }

    private static string? Failure(JsonObject reply)
    {
        if (reply["error"] is { } error) return error["message"]?.GetValue<string>() ?? "error";
        if (!IsTrue(reply["result"]?["isError"])) return null;
        var text = (reply["result"]?["content"] as JsonArray)?.Select(c => c?["text"]?.GetValue<string>()).FirstOrDefault(t => t != null) ?? "error";
        return text.Length > 200 ? text[..200] + "..." : text;
    }

    private static string Label(string tool, JsonObject? args)
    {
        var first = args?.Select(a => a.Value).OfType<JsonValue>().Select(v => v.TryGetValue<string>(out var s) ? s : null).FirstOrDefault(s => s != null);
        return first == null ? tool : $"{tool} {first}";
    }

    private static JsonObject Error(JsonNode? id, string message) => new()
    {
        ["jsonrpc"] = "2.0",
        ["id"] = id?.DeepClone(),
        ["error"] = new JsonObject { ["code"] = -32603, ["message"] = "[relay] " + message },
    };

    private static JsonObject ToolResult(JsonNode id, string text, bool isError) => new()
    {
        ["jsonrpc"] = "2.0",
        ["id"] = id.DeepClone(),
        ["result"] = new JsonObject
        {
            ["content"] = new JsonArray(new JsonObject { ["type"] = "text", ["text"] = "[relay] " + text }),
            ["isError"] = isError,
        },
    };

    private static JsonObject? Parse(string line)
    {
        if (string.IsNullOrWhiteSpace(line)) return null;
        try { return JsonNode.Parse(line) as JsonObject; }
        catch (System.Text.Json.JsonException) { return null; }
    }

    private static bool IsResponse(JsonObject message) => message["method"] == null && message.ContainsKey("id");
    private static string? Method(JsonObject message) => message["method"] is JsonValue v && v.TryGetValue<string>(out var s) ? s : null;
    private static string Key(JsonNode id) => id.ToJsonString();
    private static string? ToolName(JsonObject message) => message["params"]?["name"] is JsonValue v && v.TryGetValue<string>(out var s) ? s : null;
    private static bool IsTrue(JsonNode? node) => node is JsonValue v && v.TryGetValue<bool>(out var b) && b;
    private static TaskCompletionSource Done()
    {
        var done = new TaskCompletionSource();
        done.SetResult();
        return done;
    }

    private static async Task Quiet(Task task)
    {
        try { await task; }
        catch (OperationCanceledException) { }
        catch (ChannelClosedException) { }
    }

    [GeneratedRegex(@"\[(\d+) unsaved (?:edits|patches)\]")]
    private static partial Regex UnsavedPattern();

    private sealed class RelayException(string message) : Exception(message);
}
