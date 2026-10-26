using System.Text.Json;
using System.Text.Json.Nodes;
using Corvus.Core;
using Corvus.Native.Providers.Worker;

namespace Corvus.Native.Providers.Live.Inspector;

/// <summary>
/// The <c>corvus inspector-worker</c> process: the session worker protocol answered over one V8 inspector connection
/// (Chrome DevTools Protocol). Ops: hello, open, scripts, source, set, clear, resume, close. Events: stop (a pause, with
/// its frames by script position), output (console calls) and exit (the connection ended). Positions are 0-based.
/// </summary>
internal static class InspectorWorker
{
    public const string Command = "inspector-worker";
    private static readonly TimeSpan CommandTimeout = TimeSpan.FromSeconds(30);
    // How long open waits for the pause at the first statement of a program started with --inspect-brk.
    private static readonly TimeSpan StartPause = TimeSpan.FromSeconds(1);

    /// <summary>Runs the worker when <paramref name="args"/> is its command; null for any other command line.</summary>
    public static int? TryRun(string[] args) => args is [Command] ? WorkerHost.Serve(new State().Ops, endOp: "close") : null;

    private sealed record Script(string Id, string Url, string? Map, int Length, string Hash);

    private sealed class State
    {
        private readonly Lock _gate = new();
        private readonly Dictionary<string, Script> _scripts = new(StringComparer.Ordinal);
        // Inspector breakpoint id to the session's stop point id, and the reverse.
        private readonly Dictionary<string, string> _points = new(StringComparer.Ordinal), _breakpoints = new(StringComparer.Ordinal);
        private readonly Dictionary<string, int> _hits = new(StringComparer.Ordinal);
        private CdpConnection? _cdp;
        private bool _paused, _closing, _heldAtStart;
        private TaskCompletionSource? _startPause;

        public IReadOnlyDictionary<string, WorkerOp> Ops
        {
            get
            {
                var ops = new Dictionary<string, WorkerOp>(StringComparer.Ordinal)
                {
                    ["hello"] = (_, _) => Task.FromResult<JsonNode?>(new JsonObject { ["inspector"] = "cdp" }),
                    // A script session has no native modules.
                    ["info"] = (_, _) => Task.FromResult<JsonNode?>(new JsonObject { ["modules"] = new JsonArray() }),
                    ["open"] = OpenAsync,
                    ["scripts"] = (_, _) => Task.FromResult<JsonNode?>(Scripts()),
                    ["source"] = SourceAsync,
                    ["set"] = SetAsync,
                    ["clear"] = ClearAsync,
                    ["resume"] = ResumeAsync,
                    ["close"] = CloseAsync,
                };
                // Ops on native code are refused by name, so every tool that sends one says why.
                foreach (var op in NativeOps) ops[op] = (_, _) => throw new ToolError(ErrorCode.Unsupported,
                    $"'{op}' works on native code; a V8 inspector session has scripts only: stop points at file:line, live_events for console output.");
                return ops;
            }
        }

        private static readonly string[] NativeOps =
        [
            "read", "export", "watch", "unwatch", "set_many", "clear_many", "defer_module", "undefer_module", "release_load", "watch_jit", "count_jit",
            "load_script", "unload_script", "art_dump", "capture_memory", "resume_child", "drop_child",
        ];

        private CdpConnection Cdp => _cdp ?? throw new ToolError(ErrorCode.InvalidArgument, "no inspector is connected (open first)");

        private async Task<JsonNode?> OpenAsync(JsonObject args, CancellationToken ct)
        {
            if (_cdp != null) throw new ToolError(ErrorCode.Conflict, "an inspector is already connected");
            var target = await InspectorEndpoint.ResolveAsync(args["inspector"]?.GetValue<string>() ?? "", ct).ConfigureAwait(false);
            _cdp = await CdpConnection.ConnectAsync(target.WebSocket, ct).ConfigureAwait(false);
            _cdp.Event += OnEvent;
            _ = _cdp.Closed.ContinueWith(t =>
            {
                if (!_closing) WorkerHost.Emit?.Invoke(new JsonObject { ["event"] = "exit", ["reason"] = "inspector connection ended: " + t.Result });
            }, TaskScheduler.Default);
            await _cdp.SendAsync("Runtime.enable", null, CommandTimeout, ct).ConfigureAwait(false);
            // Enabling the debugger reports every script already parsed.
            await _cdp.SendAsync("Debugger.enable", null, CommandTimeout, ct).ConfigureAwait(false);
            // A program started with --inspect-brk waits for this, then pauses at its first statement: held as a suspended start.
            _startPause = new(TaskCreationOptions.RunContinuationsAsynchronously);
            await _cdp.SendAsync("Runtime.runIfWaitingForDebugger", null, CommandTimeout, ct).ConfigureAwait(false);
            var suspended = await Task.WhenAny(_startPause.Task, Task.Delay(StartPause, ct)).ConfigureAwait(false) == _startPause.Task;
            _startPause = null;
            lock (_gate) _heldAtStart = suspended;
            var pid = await EvaluateAsync("typeof process === 'object' ? process.pid : 0", ct).ConfigureAwait(false);
            var runtime = await EvaluateAsync("typeof process === 'object' ? 'node ' + process.version : navigator.userAgent", ct).ConfigureAwait(false);
            int count;
            lock (_gate) count = _scripts.Count;
            return new JsonObject
            {
                ["pid"] = pid?.GetValueKind() == JsonValueKind.Number ? pid.GetValue<int>() : 0,
                ["arch"] = "js",
                ["platform"] = target.Type == "page" ? "page" : "node",
                ["suspended"] = suspended,
                ["target"] = new JsonObject { ["id"] = target.Id, ["type"] = target.Type, ["title"] = target.Title, ["url"] = target.Url },
                ["runtime"] = runtime?.GetValueKind() == JsonValueKind.String ? runtime.GetValue<string>() : null,
                ["scripts"] = count,
            };
        }

        private async Task<JsonNode?> EvaluateAsync(string expression, CancellationToken ct)
        {
            try
            {
                var r = await Cdp.SendAsync("Runtime.evaluate", new JsonObject { ["expression"] = expression, ["returnByValue"] = true, ["silent"] = true }, CommandTimeout, ct).ConfigureAwait(false);
                return r.TryGetProperty("result", out var v) && v.TryGetProperty("value", out var value) ? JsonNode.Parse(value.GetRawText()) : null;
            }
            // A paused program evaluates nothing until it runs: the value stays unknown.
            catch (ToolError) { return null; }
        }

        private JsonArray Scripts()
        {
            lock (_gate)
                return [.. _scripts.Values.Select(s => (JsonNode)new JsonObject { ["id"] = s.Id, ["url"] = s.Url, ["map"] = s.Map, ["length"] = s.Length, ["hash"] = s.Hash })];
        }

        private async Task<JsonNode?> SourceAsync(JsonObject args, CancellationToken ct)
        {
            var r = await Cdp.SendAsync("Debugger.getScriptSource", new JsonObject { ["scriptId"] = args["script"]?.GetValue<string>() }, CommandTimeout, ct).ConfigureAwait(false);
            return new JsonObject { ["text"] = r.TryGetProperty("scriptSource", out var t) ? t.GetString() : null };
        }

        // By url (a loaded or later script of that url) or urlRegex; the inspector keeps it for scripts parsed later.
        private async Task<JsonNode?> SetAsync(JsonObject args, CancellationToken ct)
        {
            var id = args["id"]!.GetValue<string>();
            var p = new JsonObject { ["lineNumber"] = args["line"]!.GetValue<int>() };
            if (args["column"] is { } column) p["columnNumber"] = column.GetValue<int>();
            if (args["url"] is { } url) p["url"] = url.GetValue<string>();
            else p["urlRegex"] = args["urlRegex"]!.GetValue<string>();
            var r = await Cdp.SendAsync("Debugger.setBreakpointByUrl", p, CommandTimeout, ct).ConfigureAwait(false);
            var breakpoint = r.GetProperty("breakpointId").GetString()!;
            lock (_gate)
            {
                _points[breakpoint] = id;
                _breakpoints[id] = breakpoint;
                _hits[id] = 0;
            }
            var locations = new JsonArray();
            foreach (var l in r.GetProperty("locations").EnumerateArray()) locations.Add(Location(l));
            return new JsonObject { ["locations"] = locations };
        }

        private async Task<JsonNode?> ClearAsync(JsonObject args, CancellationToken ct)
        {
            var id = args["id"]!.GetValue<string>();
            string? breakpoint;
            lock (_gate)
                if (_breakpoints.Remove(id, out breakpoint)) _points.Remove(breakpoint);
            if (breakpoint != null) await Cdp.SendAsync("Debugger.removeBreakpoint", new JsonObject { ["breakpointId"] = breakpoint }, CommandTimeout, ct).ConfigureAwait(false);
            return new JsonObject { ["cleared"] = breakpoint != null };
        }

        // The one thread is 1; started: the pause at the first statement was the one left.
        private async Task<JsonNode?> ResumeAsync(JsonObject args, CancellationToken ct)
        {
            bool paused, started;
            lock (_gate) (paused, started) = (_paused, _heldAtStart);
            if (paused) await Cdp.SendAsync("Debugger.resume", null, CommandTimeout, ct).ConfigureAwait(false);
            lock (_gate) _heldAtStart = false;
            return new JsonObject { ["resumed"] = paused && !started ? new JsonArray(1) : new JsonArray(), ["started"] = started };
        }

        // Breakpoints go and a paused program runs on: the program outlives its session, as after a detach.
        private async Task<JsonNode?> CloseAsync(JsonObject args, CancellationToken ct)
        {
            if (_cdp is not { } cdp) return new JsonObject { ["ended"] = false, ["kept"] = 0 };
            _closing = true;
            try
            {
                string[] breakpoints;
                lock (_gate) breakpoints = [.. _breakpoints.Values];
                foreach (var b in breakpoints) await cdp.SendAsync("Debugger.removeBreakpoint", new JsonObject { ["breakpointId"] = b }, CommandTimeout, ct).ConfigureAwait(false);
                await cdp.SendAsync("Debugger.disable", null, CommandTimeout, ct).ConfigureAwait(false);
            }
            catch (ToolError) { }
            await cdp.DisposeAsync().ConfigureAwait(false);
            _cdp = null;
            return new JsonObject { ["ended"] = false, ["kept"] = 0 };
        }

        private static JsonObject Location(JsonElement l) => new()
        {
            ["script"] = l.GetProperty("scriptId").GetString(),
            ["line"] = l.GetProperty("lineNumber").GetInt32(),
            ["column"] = l.TryGetProperty("columnNumber", out var c) ? c.GetInt32() : 0,
        };

        private void OnEvent(string method, JsonElement p)
        {
            switch (method)
            {
                case "Debugger.scriptParsed":
                {
                    var map = p.TryGetProperty("sourceMapURL", out var m) && m.GetString() is { Length: > 0 } u ? u : null;
                    var script = new Script(p.GetProperty("scriptId").GetString()!, p.TryGetProperty("url", out var url) ? url.GetString() ?? "" : "", map,
                        p.TryGetProperty("length", out var len) ? len.GetInt32() : 0, p.TryGetProperty("hash", out var h) ? h.GetString() ?? "" : "");
                    lock (_gate) _scripts[script.Id] = script;
                    break;
                }
                case "Debugger.paused":
                    Paused(p);
                    break;
                case "Debugger.resumed":
                    lock (_gate) _paused = false;
                    break;
                case "Runtime.consoleAPICalled":
                {
                    var parts = p.GetProperty("args").EnumerateArray().Select(a =>
                        a.TryGetProperty("value", out var v) ? v.ValueKind == JsonValueKind.String ? v.GetString() : v.GetRawText()
                        : a.TryGetProperty("description", out var d) ? d.GetString() : a.GetProperty("type").GetString());
                    WorkerHost.Emit?.Invoke(new JsonObject { ["event"] = "output", ["stream"] = "console." + p.GetProperty("type").GetString(), ["text"] = string.Join(' ', parts) });
                    break;
                }
                case "Runtime.executionContextsCleared":
                    lock (_gate) _scripts.Clear();
                    break;
            }
        }

        private void Paused(JsonElement p)
        {
            var reason = p.GetProperty("reason").GetString() ?? "";
            lock (_gate) _paused = true;
            if (_startPause is { } start && reason == "Break on start")
            {
                start.TrySetResult();
                return;
            }
            string point = "pause";
            int hits = 0;
            if (p.TryGetProperty("hitBreakpoints", out var hit))
                lock (_gate)
                    foreach (var b in hit.EnumerateArray())
                        if (_points.TryGetValue(b.GetString() ?? "", out var id))
                        {
                            point = id;
                            hits = _hits[id] = _hits.GetValueOrDefault(id) + 1;
                            break;
                        }
            var frames = new JsonArray();
            foreach (var f in p.GetProperty("callFrames").EnumerateArray())
            {
                var at = Location(f.GetProperty("location"));
                at["function"] = f.TryGetProperty("functionName", out var fn) ? fn.GetString() : "";
                // V8 leaves the frame's own url empty; the script's is kept from its parse.
                Script? script;
                lock (_gate) _scripts.TryGetValue(at["script"]!.GetValue<string>(), out script);
                at["url"] = script?.Url ?? (f.TryGetProperty("url", out var url) ? url.GetString() : "");
                frames.Add(at);
            }
            WorkerHost.Emit?.Invoke(new JsonObject { ["event"] = "stop", ["point"] = point, ["reason"] = reason, ["hits"] = hits, ["tid"] = 1, ["frames"] = frames });
        }
    }
}
