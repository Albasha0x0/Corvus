using System.Collections.Concurrent;
using System.ComponentModel;
using System.Text;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using System.Threading.Channels;
using Corvus.Native.Providers;

namespace Corvus.Relay;

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

/// <summary>Development reload: forwards MCP stdio to a server run from a staged publish copy and swaps in each new publish.</summary>
// A swap waits for a stable marker and no call in flight, joins the new child to the client's session, replays the workspace
// calls, moves open listen streams, then sends list_changed and a [relay] notice on the next tool result.
public sealed partial class DevRelay : IAsyncDisposable
{
    /// <summary>Tool the relay adds to tools/list: switch to the newer build now.</summary>
    public const string ApplyTool = "relay_apply";

    private static readonly HashSet<string> ReplayedTools = ["load_assembly", "unload_assembly", "add_search_directory", "load_pdb", "unpack_container"];
    private static readonly string[] ListChanged =
        ["notifications/tools/list_changed", "notifications/prompts/list_changed", "notifications/resources/list_changed"];
    private static readonly string[] ListenFlags = ["toolsListChanged", "promptsListChanged", "resourcesListChanged"];
    // Long-lived requests: moved to the new child on a swap instead of holding it back.
    private static readonly HashSet<string> StreamMethods = ["subscriptions/listen"];
    private const string MetaPrefix = "io.modelcontextprotocol/";
    private const string ProtocolKey = MetaPrefix + "protocolVersion";
    private const string SubscriptionKey = MetaPrefix + "subscriptionId";
    private const string NotCarried = "not carried over: in-memory edits and native engine sessions (kept results are, unless CORVUS_RESULT_CACHE=off).";

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
    private readonly Dictionary<string, (Child Child, JsonObject Request, bool Stream)> _inFlight = [];
    // The new child's acknowledgement of these is not news to the client.
    private readonly HashSet<string> _movedStreams = [];
    // A late reply to these is dropped, as the protocol asks of the receiver.
    private readonly HashSet<string> _cancelledByClient = [];
    private readonly Dictionary<string, (Child Child, JsonNode? Id)> _serverRequests = [];
    private readonly List<(string Method, JsonObject? Params, string Label)> _replay = [];
    private readonly List<string> _notices = [];
    private readonly List<TaskCompletionSource<(bool Ok, string Text)>> _applyWaiters = [];
    // Of a successful initialize.
    private JsonObject? _initializeParams;
    // The client's per-request metadata (2026-07-28 and later).
    private JsonObject? _requestMeta;
    private string? _protocolVersion;
    private bool _initialized, _swapping, _force, _postponed, _clientSpoke;
    private TaskCompletionSource _swapDone = Done();
    private RelayBuild? _pending;
    private string? _failedMarker, _postponeNoticeFor, _waitNoticeFor;
    private long _ids;
    private int _generation;

    /// <summary>The id of a newer build found but not yet swapped in, or null.</summary>
    internal string? PendingBuild
    {
        get { lock (_gate) return _pending?.Id; }
    }

    /// <param name="launch">Starts the server in a staged folder (tests pass a fake).</param>
    public DevRelay(RelayOptions options, Stream clientIn, Stream clientOut, TextWriter log, Func<string, ChildProcess>? launch = null)
    {
        _options = options;
        _clientIn = clientIn;
        _clientOut = clientOut;
        _log = log;
        _launch = launch ?? (dir => RelayBuilds.Launch(dir, options.ServerArgs, options.Target));
    }

    /// <summary>Serves until the client closes its input; 1 when the first server cannot start.</summary>
    public async Task<int> RunAsync()
    {
        RelayBuilds.RemoveStale(_options.StateDirectory);
        try { _active = Start(RelayBuild.From(RelayBuilds.ReadMarker(_options.Target))); }
        catch (Exception ex) when (IsStartFailure(ex))
        {
            _log.WriteLine($"corvus relay: cannot start the server from {_options.Target}: {ex.Message}");
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
        if (RequestMeta(message) is { } meta) _requestMeta = meta;
        switch (method)
        {
            case "notifications/initialized":
                _initialized = true;
                break;
            case "notifications/cancelled":
                var cancelled = message["params"]?["requestId"];
                if (cancelled == null || !_inFlight.TryGetValue(Key(cancelled), out var owner)) return _active;
                _cancelledByClient.Add(Key(cancelled));
                return owner.Child;
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
        _inFlight[Key(id)] = (active, message, method != null && StreamMethods.Contains(method));
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
            bool forward;
            lock (_gate)
            {
                forward = child == _active && !child.Retired;
                if (forward && Method(message) == "notifications/subscriptions/acknowledged" && message["params"]?["_meta"]?[SubscriptionKey] is { } stream)
                    forward = !_movedStreams.Remove(Key(stream));
            }
            if (forward) WriteClient(message);
            return;
        }
        if (message["id"] is not { } id) return;
        var key = Key(id);
        if (child.Own.TryRemove(key, out var own))
        {
            own.TrySetResult(message);
            return;
        }
        bool drained, cancelled;
        lock (_gate)
        {
            if (!_inFlight.TryGetValue(key, out var entry) || entry.Child != child) return;
            _inFlight.Remove(key);
            _movedStreams.Remove(key);
            cancelled = _cancelledByClient.Remove(key);
            if (!cancelled)
            {
                Record(entry.Request, message);
                Decorate(entry.Request, message);
            }
            drained = Calls() == 0;
        }
        if (!cancelled) WriteClient(message);
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
            var restart = !child.Retired && child == _active && !_stop.IsCancellationRequested;
            foreach (var (key, entry) in _inFlight.Where(e => e.Value.Child == child).ToList())
            {
                // Taken over by the restarted server.
                if (entry.Stream && restart) continue;
                _inFlight.Remove(key);
                if (!_cancelledByClient.Remove(key) && entry.Request["id"] is { } id) failed.Add(id.DeepClone());
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
                if (IsTrue(args?["dryRun"]) || (name == "unpack_container" && IsTrue(args?["extractOnly"]))) return;
                _replay.Add(("tools/call", new JsonObject { ["name"] = name, ["arguments"] = args?.DeepClone() }, Label(name, args)));
                break;
            case "logging/setLevel":
                _replay.RemoveAll(r => r.Method == "logging/setLevel");
                _replay.Add(("logging/setLevel", WithoutMeta(p), "logging level"));
                break;
            case "resources/subscribe" or "resources/unsubscribe":
                _replay.Add((Method(request)!, WithoutMeta(p), $"{Method(request)} {p?["uri"]}"));
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
                // Only a handshake that succeeded is repeated (a 2026-07-28 client's initialize fails; it uses server/discover).
                _initializeParams = request["params"]?.DeepClone() as JsonObject;
                _initialized = false;
                _protocolVersion = result["protocolVersion"]?.GetValue<string>();
                ListChangedCapabilities(result);
                break;
            case "server/discover":
                ListChangedCapabilities(result);
                break;
            case "tools/list" when result["nextCursor"] == null && result["tools"] is JsonArray tools:
                tools.Add(ApplyToolDefinition());
                break;
            case "tools/call":
                // The call may have saved or reverted the edits that held a swap back.
                _postponed = false;
                if (_pending != null && !_swapping && SwapBlocker(_force) is { } why && _waitNoticeFor != _pending.Marker + why)
                {
                    _waitNoticeFor = _pending.Marker + why;
                    _notices.Add($"new build {_pending.Id} is ready but not applied yet: {why}. It is applied once that clears, or call {ApplyTool}.");
                }
                if (_notices.Count > 0 && result["content"] is JsonArray content)
                {
                    content.Insert(0, new JsonObject { ["type"] = "text", ["text"] = string.Join("\n", _notices.Select(n => "[relay] " + n)) + "\n\n" });
                    _notices.Clear();
                }
                break;
        }
    }

    /// <summary>The relay sends list_changed after a swap whatever the server declares.</summary>
    private static void ListChangedCapabilities(JsonObject result)
    {
        if (result["capabilities"] is not JsonObject capabilities) return;
        foreach (var kind in new[] { "tools", "prompts", "resources" })
            if (capabilities[kind] is JsonObject o) o["listChanged"] = true;
    }

    private static JsonObject ApplyToolDefinition() => new()
    {
        ["name"] = ApplyTool,
        ["title"] = "Apply the newer server build",
        ["description"] = "Switch to the newest published server build now, discarding unsaved edits and listing calls that fail to replay. " +
                          "Without a newer build, restarts an exited server.",
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
            if (_swapping || _pending == null || _postponed || _stop.IsCancellationRequested || SwapBlocker(_force) != null) return;
            _swapping = true;
            _swapDone = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        }
        _ = Task.Run(RunSwapAsync);
    }

    /// <summary>Why a swap cannot start now (null: it can). Called under _gate.</summary>
    private string? SwapBlocker(bool force)
    {
        if (!force && _initializeParams != null && !_initialized) return "the client has not completed its initialize handshake";
        var calls = _inFlight.Values.Where(e => !e.Stream).Select(e => Method(e.Request) == "tools/call" ? $"tools/call {ToolName(e.Request)}" : Method(e.Request)).ToList();
        return calls.Count == 0 ? null : $"{calls.Count} call(s) in flight ({string.Join(", ", calls.Distinct())})";
    }

    /// <summary>Client requests in flight, not counting listen streams. Called under _gate.</summary>
    private int Calls() => _inFlight.Values.Count(e => !e.Stream);

    private async Task RunSwapAsync()
    {
        RelayBuild build;
        bool force;
        Child? old, next = null;
        JsonObject? initialize, meta;
        bool spoke;
        List<(string Method, JsonObject? Params, string Label)> replay;
        lock (_gate)
        {
            build = _pending!;
            force = _force;
            old = _active;
            initialize = _initializeParams;
            meta = _requestMeta?.DeepClone() as JsonObject;
            spoke = _clientSpoke;
            replay = [.. _replay];
        }
        (bool Ok, string Text) outcome = (false, "");
        try
        {
            int discarded = 0;
            if (old is { Gone: false })
            {
                (discarded, var unknown) = await UnsavedEditsAsync(old, meta);
                // An edit count the server did not give holds the swap too: switching would lose any edits it has.
                if ((discarded > 0 || unknown != null) && !force)
                {
                    var pending = unknown == null ? $"{discarded} unsaved edit(s) pending" : $"its unsaved edits could not be checked ({unknown})";
                    lock (_gate)
                    {
                        _postponed = true;
                        if (_postponeNoticeFor != build.Marker + pending)
                        {
                            _postponeNoticeFor = build.Marker + pending;
                            _notices.Add(unknown == null
                                ? $"new build {build.Id} ready; {pending} — save or revert them, or call {ApplyTool} to switch now and discard them."
                                : $"new build {build.Id} ready; {pending}: checked again after the next call, or call {ApplyTool} to switch now.");
                        }
                    }
                    outcome = (false, $"build {build.Id} not applied: {pending}.");
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
            else if (meta?[ProtocolKey] is JsonValue v && v.TryGetValue<string>(out var version))
            {
                // No session handshake on this protocol: the new server only has to accept the client's version.
                var discover = await RequestAsync(next, "server/discover", WithMeta(null, meta));
                if (Failure(discover) is { } why) throw new RelayException($"server/discover failed: {why}");
                if (discover["result"]?["supportedVersions"] is not JsonArray versions || !versions.Any(s => s is JsonValue sv && sv.TryGetValue<string>(out var t) && t == version))
                    throw new RelayException($"the new server does not support protocol {version}, which the client uses");
            }
            // A client without an initialize handshake (stateless protocol versions) still gets its workspace replayed.
            foreach (var (method, parameters, label) in replay)
            {
                var reply = await RequestAsync(next, method, WithMeta((JsonObject?)parameters?.DeepClone(), meta));
                if (Failure(reply) is not { } why2) replayed.Add(label);
                else if (force) skipped.Add($"{label} ({why2})");
                else throw new RelayException($"replaying {label} failed: {why2}");
            }
            var identity = spoke ? await IdentityAsync(next, meta) : null;

            var text = new StringBuilder($"now serving build {build.Id}{identity} (was {old?.Build.Id ?? "none"}); ");
            text.Append(replayed.Count == 0 ? "no workspace calls to replay" : $"replayed {replayed.Count} workspace call(s): {string.Join("; ", replayed)}");
            if (skipped.Count > 0) text.Append($"; not replayed: {string.Join("; ", skipped)}");
            if (discarded > 0) text.Append($"; {discarded} unsaved edit(s) were discarded");
            text.Append("; ").Append(NotCarried);
            var streams = new List<JsonObject>();
            lock (_gate)
            {
                _active = next;
                if (old != null) old.Retired = true;
                if (_pending == build) _pending = null;
                _force = false;
                _failedMarker = null;
                _notices.Add(text.ToString());
                // Open listen streams continue on the new server under the client's own ids.
                foreach (var (key, entry) in _inFlight.Where(e => e.Value.Stream).ToList())
                {
                    _inFlight[key] = entry with { Child = next };
                    _movedStreams.Add(key);
                    streams.Add(entry.Request);
                }
            }
            foreach (var request in streams) next.Send(request);
            next = null;
            if (spoke)
                foreach (var notification in ListChangedNotifications(initialize != null || meta == null, streams))
                    WriteClient(notification);
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
            lock (_log) _log.WriteLine("corvus relay: " + text);
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
            // A newer build may have arrived meanwhile.
            TryBeginSwap();
        }
    }

    /// <summary>list_changed for the client: plain on handshake protocols; on 2026-07-28 only on listen streams that asked, with their subscription id.</summary>
    private static IEnumerable<JsonObject> ListChangedNotifications(bool session, List<JsonObject> streams)
    {
        if (session)
        {
            foreach (var method in ListChanged) yield return new JsonObject { ["jsonrpc"] = "2.0", ["method"] = method };
            yield break;
        }
        foreach (var request in streams)
        {
            var wanted = request["params"]?["notifications"];
            foreach (var (method, flag) in ListChanged.Zip(ListenFlags))
                if (IsTrue(wanted?[flag]))
                    yield return new JsonObject
                    {
                        ["jsonrpc"] = "2.0",
                        ["method"] = method,
                        ["params"] = new JsonObject { ["_meta"] = new JsonObject { [SubscriptionKey] = request["id"]?.DeepClone() } },
                    };
        }
    }

    /// <summary>Unsaved .NET edits and native patches in the server's assemblies resource, or why it cannot tell.</summary>
    private async Task<(int Count, string? Unknown)> UnsavedEditsAsync(Child child, JsonObject? meta)
    {
        JsonObject reply;
        try { reply = await RequestAsync(child, "resources/read", WithMeta(new JsonObject { ["uri"] = "corvus://assemblies" }, meta)); }
        catch (Exception ex) when (ex is TimeoutException or RelayException or IOException) { return (0, ex.Message); }
        if (Failure(reply) is { } why) return (0, why);
        int count = 0;
        foreach (var content in reply["result"]?["contents"] as JsonArray ?? [])
            foreach (Match m in UnsavedPattern().Matches(content?["text"]?.GetValue<string>() ?? ""))
                count += int.Parse(m.Groups[1].ValueSpan, System.Globalization.CultureInfo.InvariantCulture);
        return (count, null);
    }

    /// <summary>" (version, catalog digest)" from the new server's server_status, or "" when it does not say.</summary>
    private async Task<string> IdentityAsync(Child child, JsonObject? meta)
    {
        try
        {
            var reply = await RequestAsync(child, "tools/call", WithMeta(new JsonObject { ["name"] = "server_status", ["arguments"] = new JsonObject() }, meta));
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

    /// <summary>The io.modelcontextprotocol/* keys of a request's _meta: protocol version, client info and capabilities.</summary>
    private static JsonObject? RequestMeta(JsonObject message)
    {
        if (message["params"]?["_meta"] is not JsonObject meta || meta[ProtocolKey] == null) return null;
        var kept = new JsonObject();
        foreach (var (name, value) in meta)
            if (name.StartsWith(MetaPrefix, StringComparison.Ordinal) && name != SubscriptionKey) kept[name] = value?.DeepClone();
        return kept;
    }

    /// <summary>Params of a relay request with the client's per-request metadata, which those protocols require on every request.</summary>
    private static JsonObject? WithMeta(JsonObject? parameters, JsonObject? meta)
    {
        if (meta == null) return parameters;
        parameters ??= new JsonObject();
        parameters["_meta"] = meta.DeepClone();
        return parameters;
    }

    private static JsonObject? WithoutMeta(JsonObject? parameters)
    {
        var copy = parameters?.DeepClone() as JsonObject;
        copy?.Remove("_meta");
        return copy;
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
