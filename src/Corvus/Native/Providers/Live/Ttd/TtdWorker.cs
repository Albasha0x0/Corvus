using System.Globalization;
using System.Text;
using System.Text.Json.Nodes;
using Corvus.Core;
using Corvus.Native.Providers.Worker;

namespace Corvus.Native.Providers.Live.Ttd;

// resume replays to the next stop point, recording watched calls; the recording's end is the exit.
// Ops: hello, open, info, read, export, set, set_many, clear, clear_many, watch, unwatch, resume, close.
/// <summary>The <c>corvus ttd-worker</c> process: the session worker protocol over a TTD recording, held at its first position; nothing runs, the replay engine reads the file.</summary>
internal static class TtdWorker
{
    public const string Command = "ttd-worker";
    private const int MaxFrames = 32;
    private const int StringChars = 256;

    /// <summary>Runs the worker when <paramref name="args"/> is its command; null for any other command line.</summary>
    public static int? TryRun(string[] args) => args is [Command] ? WorkerHost.Serve(new State().Ops, endOp: "close") : null;

    /// <summary>True when <paramref name="program"/> names a recording (<c>ttd:PATH</c>) rather than a process.</summary>
    public static bool Is(string? program) => program?.TrimStart().StartsWith("ttd:", StringComparison.OrdinalIgnoreCase) == true;

    /// <summary>The folder holding TTDReplay.dll: CORVUS_TTD; null when unset.</summary>
    public static string? Folder() => Environment.GetEnvironmentVariable("CORVUS_TTD") is { Length: > 0 } f ? f.Trim().Trim('"') : null;

    private sealed record Watch(string Id, string[] Kinds);

    private sealed class State
    {
        private readonly Lock _gate = new();
        private readonly Dictionary<ulong, HashSet<string>> _points = [];
        private readonly Dictionary<string, ulong> _pointAddresses = new(StringComparer.Ordinal);
        private readonly Dictionary<string, int> _hits = new(StringComparer.Ordinal);
        private readonly Dictionary<ulong, List<Watch>> _watches = [];
        private readonly Dictionary<string, ulong> _watchAddresses = new(StringComparer.Ordinal);
        private TtdReplay? _replay;
        private bool _started, _ended, _held;
        private Task? _running;

        public IReadOnlyDictionary<string, WorkerOp> Ops
        {
            get
            {
                var ops = new Dictionary<string, WorkerOp>(StringComparer.Ordinal)
                {
                    ["hello"] = (_, _) => Task.FromResult<JsonNode?>(new JsonObject { ["ttd"] = "replay" }),
                    ["open"] = (a, _) => Task.FromResult(Open(a)),
                    ["info"] = (_, _) => Task.FromResult<JsonNode?>(Info()),
                    ["read"] = (a, _) => Locked(() => Read(a)),
                    ["export"] = (a, _) => Locked(() => Export(a)),
                    ["set"] = (a, _) => Locked(() => Set(a)),
                    ["set_many"] = (a, _) => Locked(() => new JsonObject { ["results"] = new JsonArray([.. a["points"]!.AsArray().Select(p => (JsonNode)Try(() => Set(p!.AsObject())))]) }),
                    ["clear"] = (a, _) => Locked(() => new JsonObject { ["cleared"] = Clear(a["id"]!.GetValue<string>()) }),
                    ["clear_many"] = (a, _) => Locked(() => new JsonObject { ["cleared"] = new JsonArray([.. a["ids"]!.AsArray().Select(i => i!.GetValue<string>()).Where(Clear).Select(i => (JsonNode)i)]) }),
                    ["watch"] = (a, _) => Locked(() => Watching(a)),
                    ["unwatch"] = (a, _) => Locked(() => Unwatch(a["id"]!.GetValue<string>())),
                    ["resume"] = (_, _) => Task.FromResult(Resume()),
                    ["close"] = (_, _) => Task.FromResult<JsonNode?>(Close()),
                };
                foreach (var op in new[] { "defer_module", "undefer_module", "release_load", "watch_jit", "count_jit", "load_script", "unload_script", "art_dump", "capture_memory", "resume_child", "drop_child" })
                    ops[op] = (_, _) => throw new ToolError(ErrorCode.Unsupported, $"'{op}' needs a running program; a recording replays what it holds: stop points, watches and memory reads.");
                return ops;
            }
        }

        private TtdReplay Replay => _replay ?? throw new ToolError(ErrorCode.InvalidArgument, "no recording is open (open first)");

        // The replay engine is not thread-safe: requests wait for a running replay to stop.
        private Task<JsonNode?> Locked(Func<JsonNode?> op)
        {
            if (_running is { IsCompleted: false }) throw new ToolError(ErrorCode.Conflict, "the recording is replaying; wait for the next stop (live_break wait=true)");
            lock (_gate) return Task.FromResult(op());
        }

        private static JsonNode Try(Func<JsonNode?> op)
        {
            try { return new JsonObject { ["ok"] = op() ?? true }; }
            catch (ToolError e) { return new JsonObject { ["error"] = e.Message }; }
        }

        private JsonNode? Open(JsonObject args)
        {
            if (_replay != null) throw new ToolError(ErrorCode.Conflict, "a recording is already open");
            var path = (args["ttd"]?.GetValue<string>() ?? "").Trim();
            if (path.StartsWith("ttd:", StringComparison.OrdinalIgnoreCase)) path = path[4..].Trim().Trim('"');
            if (!File.Exists(path)) throw new ToolError(ErrorCode.NotFound, $"No recording at {path}.", "program=ttd:<path to a .run file recorded with TTD.exe>");
            var folder = Folder() ?? throw new ToolError(ErrorCode.ProviderUnavailable, "CORVUS_TTD is not set.", TtdReplay.Remedy);
            _replay = TtdReplay.Open(folder, Path.GetFullPath(path));
            var info = Info();
            info["pid"] = (int)_replay.ProcessId;
            info["suspended"] = true;
            return info;
        }

        // Every module the recording loaded, at the address it had.
        private JsonObject Info() => new()
        {
            ["arch"] = "x64", ["platform"] = "windows", ["pointerSize"] = 8, ["pid"] = (int)(_replay?.ProcessId ?? 0),
            ["modules"] = new JsonArray([.. (_replay?.Modules ?? []).GroupBy(m => m.Base).Select(g => g.First())
                .Select(m => (JsonNode)new JsonObject { ["name"] = m.Name, ["base"] = Hex(m.Base), ["size"] = (long)m.Size, ["path"] = m.Path })]),
        };

        private JsonNode? Read(JsonObject args)
        {
            var bytes = Replay.Read(Address(args["address"]), Math.Clamp(args["length"]!.GetValue<int>(), 0, 16 << 20));
            return new JsonObject { ["bytes"] = bytes.Length == 0 ? null : Convert.ToHexString(bytes).ToLowerInvariant() };
        }

        // An export by name, from the module's export directory as the recording holds it at the current position.
        private JsonNode? Export(JsonObject args)
        {
            var module = args["module"]!.GetValue<string>();
            var name = args["name"]!.GetValue<string>();
            var m = Replay.Modules.FirstOrDefault(x => x.Name.Equals(module, StringComparison.OrdinalIgnoreCase) || Path.GetFileNameWithoutExtension(x.Name).Equals(module, StringComparison.OrdinalIgnoreCase));
            if (m == null) return new JsonObject { ["address"] = null };
            uint U32(ulong at) => BitConverter.ToUInt32(Replay.Read(at, 4) is { Length: 4 } b ? b : new byte[4]);
            var pe = m.Base + U32(m.Base + 0x3C);
            var dir = U32(pe + 0x88);
            if (dir == 0) return new JsonObject { ["address"] = null };
            var e = m.Base + dir;
            uint count = U32(e + 0x18), functions = U32(e + 0x1C), names = U32(e + 0x20), ordinals = U32(e + 0x24);
            for (uint i = 0; i < count; i++)
            {
                var text = Encoding.ASCII.GetString(Replay.Read(m.Base + U32(m.Base + names + 4 * i), 256).TakeWhile(c => c != 0).ToArray());
                if (text != name) continue;
                var ordinal = BitConverter.ToUInt16(Replay.Read(m.Base + ordinals + 2 * i, 2) is { Length: 2 } o ? o : new byte[2]);
                return new JsonObject { ["address"] = Hex(m.Base + U32(m.Base + functions + 4u * ordinal)) };
            }
            return new JsonObject { ["address"] = null };
        }

        private JsonNode? Set(JsonObject args)
        {
            var id = args["id"]!.GetValue<string>();
            var at = Address(args["address"]);
            if (!_points.ContainsKey(at) && !_watches.ContainsKey(at) && !Replay.AddExecute(at)) throw new ToolError(ErrorCode.Failed, $"The replay engine refused a stop point at {Hex(at)}.");
            if (!_points.TryGetValue(at, out var ids)) _points[at] = ids = new(StringComparer.Ordinal);
            ids.Add(id);
            _pointAddresses[id] = at;
            _hits[id] = 0;
            return true;
        }

        private bool Clear(string id)
        {
            if (!_pointAddresses.Remove(id, out var at)) return false;
            if (_points.TryGetValue(at, out var ids) && ids.Remove(id) && ids.Count == 0)
            {
                _points.Remove(at);
                if (!_watches.ContainsKey(at)) Replay.RemoveExecute(at);
            }
            return true;
        }

        private JsonNode? Watching(JsonObject args)
        {
            var id = args["id"]!.GetValue<string>();
            var at = Address(args["address"]);
            if (!_points.ContainsKey(at) && !_watches.ContainsKey(at) && !Replay.AddExecute(at)) throw new ToolError(ErrorCode.Failed, $"The replay engine refused a watch at {Hex(at)}.");
            if (!_watches.TryGetValue(at, out var list)) _watches[at] = list = [];
            list.Add(new Watch(id, [.. args["args"]!.AsArray().Select(k => k!.GetValue<string>())]));
            _watchAddresses[id] = at;
            return true;
        }

        private JsonNode? Unwatch(string id)
        {
            if (!_watchAddresses.Remove(id, out var at)) return false;
            if (_watches.TryGetValue(at, out var list) && list.RemoveAll(w => w.Id == id) > 0 && list.Count == 0)
            {
                _watches.Remove(at);
                if (!_points.ContainsKey(at)) Replay.RemoveExecute(at);
            }
            return true;
        }

        // Replays in the background; the next stop point hit, or the recording's end, arrives as an event.
        private JsonNode? Resume()
        {
            if (_running is { IsCompleted: false }) return new JsonObject { ["resumed"] = new JsonArray(), ["started"] = false };
            var started = !_started;
            _started = true;
            if (_ended) return new JsonObject { ["resumed"] = new JsonArray(), ["started"] = started };
            var thread = _replay is { } r ? r.Thread : 0;
            _running = Task.Run(Run);
            return new JsonObject { ["resumed"] = started ? new JsonArray() : new JsonArray(thread), ["started"] = started };
        }

        private void Run()
        {
            try
            {
                lock (_gate)
                {
                    var replay = Replay;
                    // The call held at a stop point is the first one a watch at that address records.
                    if (_held && _watches.TryGetValue(replay.Registers()["pc"], out var first)) Record(replay, first);
                    _held = false;
                    // A replay from a stop point's own position first moves past it, so the same hit is not reported again.
                    var from = replay.Position;
                    while (true)
                    {
                        var stop = replay.Replay();
                        if (!stop.Watchpoint)
                        {
                            _ended = true;
                            Flush();
                            WorkerHost.Emit?.Invoke(new JsonObject { ["event"] = "exit", ["reason"] = $"{stop.Reason} (position {replay.Position})" });
                            return;
                        }
                        var at = replay.Registers()["pc"];
                        if (replay.Position.Equals(from)) { replay.Replay(steps: 1); from = default; continue; }
                        from = default;
                        if (_watches.TryGetValue(at, out var watches)) Record(replay, watches);
                        if (_points.TryGetValue(at, out var ids) && ids.Count > 0)
                        {
                            Flush();
                            Stopped(replay, ids);
                            _held = true;
                            return;
                        }
                        // A watch alone: step past the call's first instruction and go on.
                        replay.Replay(steps: 1);
                    }
                }
            }
            catch (Exception e) when (e is ToolError or InvalidOperationException)
            {
                WorkerHost.Emit?.Invoke(new JsonObject { ["event"] = "exit", ["reason"] = "replay failed: " + e.Message });
            }
        }

        private readonly Dictionary<string, JsonArray> _rows = new(StringComparer.Ordinal);

        // One call: its arguments at entry (x64 calling convention), and its return value once the thread returns past it.
        private void Record(TtdReplay replay, List<Watch> watches)
        {
            var regs = replay.Registers();
            var entry = replay.Position;
            var sp = regs["sp"];
            var ret = replay.ReadU64(sp);
            var thread = replay.Thread;
            var unique = replay.UniqueThread;
            ulong[] Args(int n) => [.. Enumerable.Range(0, n).Select(i => i switch { 0 => regs["rcx"], 1 => regs["rdx"], 2 => regs["r8"], 3 => regs["r9"], _ => replay.ReadU64(sp + 8 + 8 * (ulong)i) })];
            var values = watches.ToDictionary(w => w.Id, w => Args(w.Kinds.Length).Select((v, i) => Value(replay, w.Kinds[i], v)).ToList());
            // The return: the thread executes the return address with its stack above the entry's.
            string result = "?";
            // A return address that is itself watched keeps its own watchpoint.
            var shared = _points.ContainsKey(ret) || _watches.ContainsKey(ret);
            if (!shared) replay.AddExecute(ret, unique);
            try
            {
                while (replay.Replay() is { Watchpoint: true })
                    if (replay.UniqueThread == unique && replay.Registers() is var r && r["pc"] == ret && r["sp"] > sp)
                    {
                        result = Hex(r["rax"]);
                        break;
                    }
            }
            finally
            {
                if (!shared) replay.RemoveExecute(ret, unique);
                // Back to the entry, so nothing between it and the return is skipped.
                replay.SetPosition(entry);
            }
            foreach (var w in watches)
            {
                if (!_rows.TryGetValue(w.Id, out var rows)) _rows[w.Id] = rows = [];
                rows.Add(new JsonArray(thread, (long)entry.Sequence, Hex(ret), new JsonArray([.. values[w.Id].Select(v => (JsonNode?)v)]), result));
            }
        }

        private static string? Value(TtdReplay replay, string kind, ulong v)
        {
            if (kind == "skip") return null;
            if (kind == "proc" && v < 0x10000) return Hex(v);
            if (kind is not ("cstr" or "wstr" or "proc")) return Hex(v);
            if (v == 0) return null;
            var bytes = replay.Read(v, (StringChars + 1) * (kind == "wstr" ? 2 : 4));
            if (bytes.Length == 0) return $"<unreadable {Hex(v)}>";
            string s;
            if (kind == "wstr")
            {
                int end = 0;
                while (end + 1 < bytes.Length && (bytes[end] | bytes[end + 1]) != 0) end += 2;
                s = Encoding.Unicode.GetString(bytes, 0, end);
            }
            else s = Encoding.UTF8.GetString(bytes, 0, Array.IndexOf(bytes, (byte)0) is var z and >= 0 ? z : bytes.Length);
            return s.Length > StringChars ? s[..StringChars] + "..." : s;
        }

        private void Flush()
        {
            foreach (var (id, rows) in _rows)
                if (rows.Count > 0) WorkerHost.Emit?.Invoke(new JsonObject { ["event"] = "calls", ["watch"] = id, ["rows"] = rows, ["skipped"] = 0 });
            _rows.Clear();
        }

        private void Stopped(TtdReplay replay, HashSet<string> ids)
        {
            var regs = replay.Registers();
            var point = ids.Order(StringComparer.Ordinal).First();
            var hits = _hits[point] = _hits.GetValueOrDefault(point) + 1;
            WorkerHost.Emit?.Invoke(new JsonObject
            {
                ["event"] = "stop", ["point"] = point, ["tid"] = replay.Thread, ["hits"] = hits, ["position"] = replay.Position.ToString(),
                ["registers"] = new JsonObject([.. regs.Select(r => KeyValuePair.Create(r.Key, (JsonNode?)Hex(r.Value)))]),
                ["frames"] = new JsonArray([.. new TtdMemory(replay).Frames(regs, MaxFrames).Select(f => (JsonNode)Hex(f))]),
            });
        }

        private JsonObject Close()
        {
            if (_running is { IsCompleted: false }) _replay?.Interrupt();
            lock (_gate)
            {
                _replay?.Dispose();
                _replay = null;
            }
            return new JsonObject { ["ended"] = false, ["kept"] = 0 };
        }

        private static ulong Address(JsonNode? node) => node?.GetValue<string>() is { } s && ulong.TryParse(s.StartsWith("0x", StringComparison.OrdinalIgnoreCase) ? s[2..] : s, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var v)
            ? v : throw new ToolError(ErrorCode.InvalidArgument, $"'{node}' is not an address.");

        private static string Hex(ulong v) => "0x" + v.ToString("x", CultureInfo.InvariantCulture);
    }
}
