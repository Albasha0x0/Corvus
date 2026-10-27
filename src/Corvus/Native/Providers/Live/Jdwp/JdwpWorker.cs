using System.Globalization;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Corvus.Core;
using Corvus.Native.Providers.Live.Inspector;
using Corvus.Native.Providers.Worker;

namespace Corvus.Native.Providers.Live.Jdwp;

// Ops: hello, open, scripts, set, clear, resume, threads, close. Events: stop, exit. Lines are 0-based; -1 without line info.
/// <summary>The <c>corvus jdwp-worker</c> process: the session worker protocol over one JDWP connection.</summary>
internal static class JdwpWorker
{
    public const string Command = "jdwp-worker";
    private static readonly TimeSpan CommandTimeout = TimeSpan.FromSeconds(30);
    // How long open waits for the VM start event, which says whether the JVM waits for a debugger (suspend=y).
    private static readonly TimeSpan StartEvent = TimeSpan.FromSeconds(1);
    // Frames read per thread by threads; a stop reads them all.
    private const int ThreadFrames = 64;
    // Classes of the JDK itself are never the program's own; class prepare events skip them too.
    private static readonly string[] RuntimePackages = ["java.", "javax.", "jdk.", "sun.", "com.sun."];

    /// <summary>Runs the worker when <paramref name="args"/> is its command; null for any other command line.</summary>
    public static int? TryRun(string[] args) => args is [Command] ? WorkerHost.Serve(new State().Ops, endOp: "close") : null;

    /// <summary>The JVM a session connects to, named <c>jdwp:PORT</c> or <c>jdwp:HOST:PORT</c>; only loopback hosts are accepted.</summary>
    public static (string Host, int Port) Endpoint(string program)
    {
        var text = program.Trim()["jdwp:".Length..];
        var (host, port) = text.LastIndexOf(':') is var colon and > 0 ? (text[..colon].Trim('[', ']'), text[(colon + 1)..]) : ("127.0.0.1", text);
        if (!int.TryParse(port, NumberStyles.None, CultureInfo.InvariantCulture, out var number) || number is < 1 or > 65535)
            throw new ToolError(ErrorCode.InvalidArgument, $"{program}: '{port}' is not a port.", "program=jdwp:PORT names a JVM started with -agentlib:jdwp=transport=dt_socket,server=y,address=127.0.0.1:PORT");
        InspectorEndpoint.RequireLoopback(host, program, "a JDWP agent");
        return (host, number);
    }

    /// <summary>True when <paramref name="program"/> names a JDWP agent rather than a process.</summary>
    public static bool Is(string? program) => program?.TrimStart().StartsWith("jdwp:", StringComparison.OrdinalIgnoreCase) == true;

    private sealed record ClassInfo(long Id, byte Tag, string Name, string? SourceFile)
    {
        public string Url => Name.LastIndexOf('.') is var dot and >= 0 ? Name[..(dot + 1)].Replace('.', '/') + (SourceFile ?? Name[(dot + 1)..] + ".class") : SourceFile ?? Name + ".class";
    }

    private sealed record MethodInfo(long Id, string Name);

    private sealed class Point(string id, string? url, Regex? match, int line)
    {
        public string Id { get; } = id;
        public int Line { get; } = line;
        public List<int> Requests { get; } = [];
        public bool Matches(string u) => url != null ? u == url : match!.IsMatch(u);
    }

    private sealed class State
    {
        private readonly Lock _gate = new();
        private readonly Dictionary<long, ClassInfo> _classes = [];
        private readonly Dictionary<long, List<MethodInfo>> _methods = [];
        private readonly Dictionary<(long, long), List<(long Index, int Line)>?> _lines = [];
        private readonly Dictionary<string, Point> _points = new(StringComparer.Ordinal);
        private readonly Dictionary<int, string> _requests = [];
        private readonly Dictionary<string, int> _hits = new(StringComparer.Ordinal);
        private readonly HashSet<long> _held = [];
        private JdwpConnection? _jdwp;
        private int? _classPrepare;
        private bool _closing, _heldAtStart;
        private TaskCompletionSource<bool>? _start;

        public IReadOnlyDictionary<string, WorkerOp> Ops
        {
            get
            {
                var ops = new Dictionary<string, WorkerOp>(StringComparer.Ordinal)
                {
                    ["hello"] = (_, _) => Task.FromResult<JsonNode?>(new JsonObject { ["jdwp"] = "1" }),
                    // A JVM session has classes, not native modules.
                    ["info"] = (_, _) => Task.FromResult<JsonNode?>(new JsonObject { ["modules"] = new JsonArray() }),
                    ["open"] = OpenAsync,
                    ["scripts"] = ScriptsAsync,
                    ["source"] = (_, _) => Task.FromResult<JsonNode?>(new JsonObject { ["text"] = null }),
                    ["set"] = SetAsync,
                    ["clear"] = ClearAsync,
                    ["resume"] = ResumeAsync,
                    ["threads"] = ThreadsAsync,
                    ["close"] = CloseAsync,
                };
                foreach (var op in InspectorWorker.NativeOps) ops[op] = (_, _) => throw new ToolError(ErrorCode.Unsupported,
                    $"'{op}' works on native code; a JVM session has classes only: stop points at File.java:LINE, threads and stacks in live_session action=status.");
                return ops;
            }
        }

        private JdwpConnection Jdwp => _jdwp ?? throw new ToolError(ErrorCode.InvalidArgument, "no JVM is connected (open first)");

        private async Task<byte[]> Send(byte set, byte command, JdwpWriter? data, CancellationToken ct) =>
            await Jdwp.SendAsync(set, command, data?.ToArray() ?? [], CommandTimeout, ct).ConfigureAwait(false);

        private JdwpWriter W() => new(Jdwp);
        private JdwpReader R(byte[] data) => new(data, Jdwp);

        private async Task<JsonNode?> OpenAsync(JsonObject args, CancellationToken ct)
        {
            if (_jdwp != null) throw new ToolError(ErrorCode.Conflict, "a JVM is already connected");
            var program = args["jdwp"]?.GetValue<string>() ?? "";
            var (host, port) = Endpoint(program);
            // The agent stops listening once a debugger connects, so the port names its process only before.
            var pid = ListeningProcess.Of(port) ?? 0;
            _start = new(TaskCreationOptions.RunContinuationsAsynchronously);
            _jdwp = await JdwpConnection.ConnectAsync(host, port, CommandTimeout, OnComposite, ct).ConfigureAwait(false);
            _ = _jdwp.Closed.ContinueWith(t =>
            {
                if (!_closing) WorkerHost.Emit?.Invoke(new JsonObject { ["event"] = "exit", ["reason"] = "JDWP connection ended: " + t.Result });
            }, TaskScheduler.Default);
            var started = await Task.WhenAny(_start.Task, Task.Delay(StartEvent, ct)).ConfigureAwait(false) == _start.Task && _start.Task.Result;
            lock (_gate) _heldAtStart = started;
            var version = R(await Send(1, 1, null, ct).ConfigureAwait(false));
            var description = version.String();
            _ = (version.Int(), version.Int());
            var vmVersion = version.String();
            var vmName = version.String();
            var scripts = await RefreshClassesAsync(ct).ConfigureAwait(false);
            return new JsonObject
            {
                ["pid"] = pid,
                ["arch"] = "jvm",
                ["platform"] = "jvm",
                ["suspended"] = started,
                ["target"] = new JsonObject { ["id"] = $"{host}:{port}", ["type"] = "jvm", ["title"] = vmName, ["url"] = "" },
                ["runtime"] = $"{vmName} {vmVersion}",
                ["description"] = description,
                ["scripts"] = scripts.Count,
            };
        }

        // The program's classes (JDK classes left out), each with its source path.
        private async Task<JsonNode?> ScriptsAsync(JsonObject args, CancellationToken ct)
        {
            var own = await RefreshClassesAsync(ct).ConfigureAwait(false);
            return new JsonArray([.. own.Select(c => (JsonNode)new JsonObject { ["id"] = Hex(c.Id), ["url"] = c.Url, ["map"] = null, ["length"] = 0, ["hash"] = "", ["class"] = c.Name })]);
        }

        private async Task<List<ClassInfo>> RefreshClassesAsync(CancellationToken ct)
        {
            var r = R(await Send(1, 3, null, ct).ConfigureAwait(false));
            var found = new List<(long Id, byte Tag, string Name)>();
            for (int i = r.Int(); i > 0; i--)
            {
                var tag = r.Byte();
                var id = r.Type();
                var signature = r.String();
                _ = r.Int();
                if (tag is 1 or 2 && signature.StartsWith('L')) found.Add((id, tag, ClassName(signature)));
            }
            var own = new List<ClassInfo>();
            foreach (var (id, tag, name) in found)
            {
                // Hidden classes the JVM spins for lambdas have no source of their own.
                if (RuntimePackages.Any(p => name.StartsWith(p, StringComparison.Ordinal)) || name.Contains("$$Lambda", StringComparison.Ordinal)) continue;
                own.Add(await ClassAsync(id, tag, name, ct).ConfigureAwait(false));
            }
            return own;
        }

        private async Task<ClassInfo> ClassAsync(long id, byte tag, string? name, CancellationToken ct)
        {
            lock (_gate)
                if (_classes.TryGetValue(id, out var known)) return known;
            name ??= ClassName(R(await Send(2, 1, W().Type(id), ct).ConfigureAwait(false)).String());
            string? source = null;
            try { source = R(await Send(2, 7, W().Type(id), ct).ConfigureAwait(false)).String(); }
            // ABSENT_INFORMATION: compiled without a SourceFile attribute.
            catch (ToolError) { }
            var info = new ClassInfo(id, tag, name, source);
            lock (_gate) _classes[id] = info;
            return info;
        }

        // A hidden class keeps its /0x... suffix, as jstack prints it.
        private static string ClassName(string signature)
        {
            if (signature.Length <= 2 || signature[0] != 'L') return signature;
            var name = signature[1..^1];
            var hidden = name.IndexOf("/0x", StringComparison.Ordinal);
            return hidden < 0 ? name.Replace('/', '.') : name[..hidden].Replace('/', '.') + name[hidden..];
        }

        private async Task<List<MethodInfo>> MethodsAsync(long type, CancellationToken ct)
        {
            lock (_gate)
                if (_methods.TryGetValue(type, out var known)) return known;
            var r = R(await Send(2, 5, W().Type(type), ct).ConfigureAwait(false));
            var list = new List<MethodInfo>();
            for (int i = r.Int(); i > 0; i--)
            {
                var id = r.Method();
                var name = r.String();
                _ = (r.String(), r.Int());
                list.Add(new MethodInfo(id, name));
            }
            lock (_gate) _methods[type] = list;
            return list;
        }

        // Rows of (bytecode index, line); null for a method without line information (native, abstract, no LineNumberTable).
        private async Task<List<(long Index, int Line)>?> LinesAsync(long type, long method, CancellationToken ct)
        {
            lock (_gate)
                if (_lines.TryGetValue((type, method), out var known)) return known;
            List<(long, int)>? rows = null;
            try
            {
                var r = R(await Send(6, 1, W().Type(type).Method(method), ct).ConfigureAwait(false));
                _ = (r.Long(), r.Long());
                rows = [];
                for (int i = r.Int(); i > 0; i--) rows.Add((r.Long(), r.Int()));
            }
            catch (ToolError) { }
            lock (_gate) _lines[(type, method)] = rows;
            return rows;
        }

        // The first bytecode index of a line (1-based) in each method of a class that has code there; none when no method does.
        private async Task<List<JdwpLocation>> LocationsAsync(ClassInfo c, int line, CancellationToken ct)
        {
            var found = new List<JdwpLocation>();
            foreach (var m in await MethodsAsync(c.Id, ct).ConfigureAwait(false))
                if (await LinesAsync(c.Id, m.Id, ct).ConfigureAwait(false) is { } rows && rows.Where(x => x.Line == line).Select(x => (long?)x.Index).Min() is { } index)
                    found.Add(new JdwpLocation(c.Tag, c.Id, m.Id, index));
            return found;
        }

        // A class prepare request, held on its thread, so a class loaded later gets its points before its code runs.
        private async Task WatchClassLoadsAsync(CancellationToken ct)
        {
            lock (_gate)
                if (_classPrepare != null) return;
            var w = W().Byte(8).Byte(1).Int(RuntimePackages.Length);
            foreach (var p in RuntimePackages) w.Byte(6).String(p + "*");
            var id = R(await Send(15, 1, w, ct).ConfigureAwait(false)).Int();
            lock (_gate) _classPrepare = id;
        }

        private async Task<JsonNode?> SetAsync(JsonObject args, CancellationToken ct)
        {
            var id = args["id"]!.GetValue<string>();
            var line = args["line"]!.GetValue<int>() + 1;
            var point = new Point(id, args["url"]?.GetValue<string>(), args["url"] == null ? new Regex(args["urlRegex"]!.GetValue<string>(), RegexOptions.CultureInvariant) : null, line);
            lock (_gate)
            {
                _points[id] = point;
                _hits[id] = 0;
            }
            await WatchClassLoadsAsync(ct).ConfigureAwait(false);
            var locations = new JsonArray();
            foreach (var c in await RefreshClassesAsync(ct).ConfigureAwait(false))
                if (point.Matches(c.Url))
                    foreach (var at in await PlaceAsync(point, c, ct).ConfigureAwait(false)) locations.Add(at);
            return new JsonObject { ["locations"] = locations };
        }

        // Breakpoint requests at a point's line in one class, holding only the thread that reaches it.
        private async Task<List<JsonNode>> PlaceAsync(Point point, ClassInfo c, CancellationToken ct)
        {
            var placed = new List<JsonNode>();
            foreach (var at in await LocationsAsync(c, point.Line, ct).ConfigureAwait(false))
            {
                var request = R(await Send(15, 1, W().Byte(2).Byte(1).Int(1).Byte(7).Location(at), ct).ConfigureAwait(false)).Int();
                lock (_gate)
                {
                    point.Requests.Add(request);
                    _requests[request] = point.Id;
                }
                placed.Add(new JsonObject { ["script"] = Hex(c.Id), ["line"] = point.Line - 1, ["column"] = 0 });
            }
            return placed;
        }

        private async Task<JsonNode?> ClearAsync(JsonObject args, CancellationToken ct)
        {
            Point? point;
            lock (_gate)
                if (_points.Remove(args["id"]!.GetValue<string>(), out point))
                    foreach (var r in point.Requests) _requests.Remove(r);
            if (point != null)
                foreach (var r in point.Requests) await Send(15, 2, W().Byte(2).Int(r), ct).ConfigureAwait(false);
            return new JsonObject { ["cleared"] = point != null };
        }

        // started: the JVM waited for a debugger (suspend=y) and runs now.
        private async Task<JsonNode?> ResumeAsync(JsonObject args, CancellationToken ct)
        {
            bool start;
            long[] threads;
            lock (_gate)
            {
                start = _heldAtStart;
                _heldAtStart = false;
                long? one = args["thread"] is { } t ? t.GetValue<long>() : null;
                threads = one is { } x ? (_held.Contains(x) ? [x] : []) : [.. _held];
                foreach (var x2 in threads) _held.Remove(x2);
            }
            foreach (var t in threads) await Send(11, 3, W().Object(t), ct).ConfigureAwait(false);
            if (start) await Send(1, 9, null, ct).ConfigureAwait(false);
            return new JsonObject { ["resumed"] = new JsonArray([.. threads.Select(t => (JsonNode)t)]), ["started"] = start };
        }

        // Every thread with its state and its first frames, read with the JVM suspended for the read only.
        private async Task<JsonNode?> ThreadsAsync(JsonObject args, CancellationToken ct)
        {
            await Send(1, 8, null, ct).ConfigureAwait(false);
            var list = new JsonArray();
            try
            {
                var r = R(await Send(1, 4, null, ct).ConfigureAwait(false));
                var threads = new List<long>();
                for (int i = r.Int(); i > 0; i--) threads.Add(r.Object());
                foreach (var t in threads)
                {
                    try
                    {
                        var name = R(await Send(11, 1, W().Object(t), ct).ConfigureAwait(false)).String();
                        var status = R(await Send(11, 4, W().Object(t), ct).ConfigureAwait(false)).Int();
                        var count = R(await Send(11, 7, W().Object(t), ct).ConfigureAwait(false)).Int();
                        bool held;
                        lock (_gate) held = _held.Contains(t);
                        list.Add(new JsonObject
                        {
                            ["tid"] = t, ["name"] = name, ["status"] = StatusName(status), ["held"] = held, ["depth"] = count,
                            ["frames"] = await FramesAsync(t, Math.Min(count, ThreadFrames), ct).ConfigureAwait(false),
                        });
                    }
                    // A thread that ended during the read.
                    catch (ToolError) { }
                }
            }
            finally { await Send(1, 9, null, ct).ConfigureAwait(false); }
            return list;
        }

        // The JDWP ThreadStatus constants.
        private static string StatusName(int status) => status switch
        {
            0 => "ended",
            1 => "running",
            2 => "sleeping",
            3 => "waiting for a monitor",
            4 => "waiting",
            _ => "unknown",
        };

        private async Task<JsonArray> FramesAsync(long thread, int count, CancellationToken ct)
        {
            var frames = new JsonArray();
            if (count == 0) return frames;
            var r = R(await Send(11, 6, W().Object(thread).Int(0).Int(count), ct).ConfigureAwait(false));
            var locations = new List<JdwpLocation>();
            for (int i = r.Int(); i > 0; i--)
            {
                _ = r.Frame();
                locations.Add(r.Location());
            }
            foreach (var l in locations)
            {
                var c = await ClassAsync(l.Class, l.Tag, null, ct).ConfigureAwait(false);
                var method = (await MethodsAsync(l.Class, ct).ConfigureAwait(false)).FirstOrDefault(m => m.Id == l.Method)?.Name ?? "?";
                var rows = await LinesAsync(l.Class, l.Method, ct).ConfigureAwait(false);
                var line = rows?.Where(x => x.Index <= l.Index).OrderByDescending(x => x.Index).Select(x => (int?)x.Line).FirstOrDefault();
                frames.Add(new JsonObject { ["script"] = Hex(c.Id), ["url"] = c.Url, ["name"] = c.SourceFile ?? c.Name, ["function"] = $"{c.Name}.{method}", ["line"] = line is { } n ? n - 1 : -1 });
            }
            return frames;
        }

        // Stop points and the class prepare request go, then VirtualMachine.Dispose resumes what the session held: the program runs on.
        private async Task<JsonNode?> CloseAsync(JsonObject args, CancellationToken ct)
        {
            if (_jdwp is not { } jdwp) return new JsonObject { ["ended"] = false, ["kept"] = 0 };
            _closing = true;
            try
            {
                await Send(15, 3, null, ct).ConfigureAwait(false);
                int? prepare;
                lock (_gate) prepare = _classPrepare;
                if (prepare is { } p) await Send(15, 2, W().Byte(8).Int(p), ct).ConfigureAwait(false);
                await Send(1, 6, null, ct).ConfigureAwait(false);
            }
            catch (ToolError) { }
            await jdwp.DisposeAsync().ConfigureAwait(false);
            _jdwp = null;
            return new JsonObject { ["ended"] = false, ["kept"] = 0 };
        }

        private static string Hex(long id) => "0x" + id.ToString("x", CultureInfo.InvariantCulture);

        // Runs on the receive thread: replies to commands sent from here would never be read, so work moves off it.
        private void OnComposite(JdwpConnection connection, byte[] data)
        {
            var r = new JdwpReader(data, connection);
            var policy = r.Byte();
            for (int i = r.Int(); i > 0; i--)
            {
                var kind = r.Byte();
                var request = r.Int();
                switch (kind)
                {
                    case 90:
                        _ = r.Object();
                        // SuspendPolicy ALL: the JVM waits for a debugger (suspend=y).
                        _start?.TrySetResult(policy == 2);
                        break;
                    case 2:
                    {
                        var thread = r.Object();
                        var at = r.Location();
                        _ = Task.Run(() => StoppedAsync(request, thread, at));
                        break;
                    }
                    case 8:
                    {
                        var thread = r.Object();
                        var tag = r.Byte();
                        var type = r.Type();
                        var signature = r.String();
                        _ = r.Int();
                        _ = Task.Run(() => PreparedAsync(thread, tag, type, ClassName(signature), policy != 0));
                        break;
                    }
                    case 99:
                        if (!_closing) WorkerHost.Emit?.Invoke(new JsonObject { ["event"] = "exit", ["reason"] = "the JVM ended" });
                        break;
                    // An event this worker never requests: its layout is unknown, so the rest of the packet is skipped.
                    default:
                        return;
                }
            }
        }

        private async Task StoppedAsync(int request, long thread, JdwpLocation at)
        {
            string point;
            int hits;
            lock (_gate)
            {
                point = _requests.GetValueOrDefault(request, "pause");
                hits = _hits[point] = _hits.GetValueOrDefault(point) + 1;
                _held.Add(thread);
            }
            JsonArray frames;
            try
            {
                var count = R(await Send(11, 7, W().Object(thread), CancellationToken.None).ConfigureAwait(false)).Int();
                frames = await FramesAsync(thread, count, CancellationToken.None).ConfigureAwait(false);
            }
            catch (Exception e) when (e is ToolError or EndOfStreamException) { frames = []; }
            WorkerHost.Emit?.Invoke(new JsonObject { ["event"] = "stop", ["point"] = point, ["reason"] = "breakpoint", ["hits"] = hits, ["tid"] = thread, ["frames"] = frames });
        }

        // A class of the program was loaded: points whose file it is get their breakpoints, then its thread goes on.
        private async Task PreparedAsync(long thread, byte tag, long type, string name, bool suspended)
        {
            try
            {
                var c = await ClassAsync(type, tag, name, CancellationToken.None).ConfigureAwait(false);
                List<Point> points;
                lock (_gate) points = [.. _points.Values.Where(p => p.Matches(c.Url))];
                foreach (var p in points) await PlaceAsync(p, c, CancellationToken.None).ConfigureAwait(false);
            }
            catch (Exception e) when (e is ToolError or EndOfStreamException) { }
            finally
            {
                if (suspended)
                    try { await Send(11, 3, W().Object(thread), CancellationToken.None).ConfigureAwait(false); }
                    catch (ToolError) { }
            }
        }
    }
}
