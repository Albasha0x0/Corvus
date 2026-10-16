using System.Collections.Concurrent;
using System.Globalization;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Corvus.Core;
using Corvus.Native;
using Corvus.Native.Code;
using Corvus.Native.Providers;
using Corvus.Native.Providers.Live;

namespace Corvus.Services;

/// <summary>A module of the observed program; <see cref="Image"/> is the loaded image it matched by path.</summary>
public sealed record LiveModuleState(string Name, ulong Base, ulong Size, string Path)
{
    public LoadedNative? Image { get; set; }
    public bool Contains(ulong address) => address >= Base && address - Base < Size;
}

public sealed record LiveStopPointState(string Id, string Where, ulong Address, LiveFrameName At)
{
    public int Hits { get; set; }
}

/// <summary>A thread held at a stop point until it is resumed: its general registers and return addresses.</summary>
public sealed record LiveHeldStop(long Sequence, long Thread, string Point, IReadOnlyDictionary<string, string> Registers, IReadOnlyList<ulong> Frames);

public sealed record LiveRingEvent(long Sequence, string Kind, long? Thread, ulong? Address, string Text);

/// <summary>
/// An address joined to the static model: its module, the loaded image and RVA, the containing function's name and offset,
/// the PDB source line, and the function start a saved record names (null when the image gives no name).
/// </summary>
public sealed record LiveFrameName(ulong Address, string? Module, LoadedNative? Image, uint Rva, string? Function, uint Offset, string? Source,
    EvidenceName? Named)
{
    public string Display => Module == null ? $"0x{Address:X}"
        : Function == null ? $"{Module}+0x{Rva:X}"
        : Offset == 0 ? $"{Module}!{Function}" : $"{Module}!{Function}+0x{Offset:X}";
}

/// <summary>A function start by image, SHA-256 and RVA with the name it had, for read_result format=verify.</summary>
public sealed record EvidenceName(string Image, string Sha256, uint Rva, string Name);

/// <summary>
/// One session on a local program: the worker holding it, its modules, stop points, held threads and a bounded event ring.
/// Ends on close, on its deadline, and with the server; the server never leaves a thread held or a started program behind.
/// </summary>
public sealed class LiveSession
{
    public const int RingCapacity = 10_000;
    private readonly object _gate = new();
    private readonly Queue<LiveRingEvent> _ring = new();
    private readonly Dictionary<long, LiveHeldStop> _held = [];
    private TaskCompletionSource _changed = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private long _sequence;
    private long _waited;
    private int _nextPoint;

    internal LiveSession(string id, string backend, string program, bool spawned, WorkerConnection worker)
    {
        Id = id;
        Backend = backend;
        Program = program;
        Spawned = spawned;
        Worker = worker;
    }

    public string Id { get; }
    public string Backend { get; }
    public string Program { get; }
    public bool Spawned { get; }
    public int ProcessId { get; internal set; }
    public string Arch { get; internal set; } = "";
    internal WorkerConnection Worker { get; }
    internal Timer? Deadline { get; set; }
    internal List<Task> Indexing { get; } = [];
    public List<LiveModuleState> Modules { get; } = [];
    public Dictionary<string, LiveStopPointState> StopPoints { get; } = new(StringComparer.Ordinal);
    public bool Suspended { get; internal set; }
    public string? Ended { get; internal set; }
    public bool Closed { get; internal set; }
    /// <summary>Events the ring dropped, oldest first.</summary>
    public long Dropped { get; private set; }

    public string State
    {
        get
        {
            lock (_gate)
            {
                if (Closed) return "closed";
                if (Ended != null) return Ended.StartsWith("failed", StringComparison.Ordinal) ? "failed" : "exited";
                if (_held.Count > 0) return "stopped";
                return Suspended ? "suspended" : "running";
            }
        }
    }

    public IReadOnlyList<LiveHeldStop> Held
    {
        get { lock (_gate) return _held.Values.OrderBy(h => h.Sequence).ToList(); }
    }

    internal string NextPointId() => "s" + Interlocked.Increment(ref _nextPoint);

    internal long Add(string kind, long? thread, ulong? address, string text, Func<long, LiveHeldStop>? held = null)
    {
        lock (_gate)
        {
            var seq = ++_sequence;
            _ring.Enqueue(new LiveRingEvent(seq, kind, thread, address, text));
            if (_ring.Count > RingCapacity)
            {
                _ring.Dequeue();
                Dropped++;
            }
            if (held != null && thread is { } t) _held[t] = held(seq);
            Signal();
            return seq;
        }
    }

    internal void Release(IEnumerable<long> threads)
    {
        lock (_gate)
            foreach (var t in threads) _held.Remove(t);
    }

    internal void ReleaseAll()
    {
        lock (_gate) _held.Clear();
    }

    /// <summary>Wakes waiters (a new event, an exit, a close).</summary>
    internal void Signal()
    {
        lock (_gate)
        {
            _changed.TrySetResult();
            _changed = new(TaskCreationOptions.RunContinuationsAsynchronously);
        }
    }

    /// <summary>The oldest held stop no earlier wait returned, waiting up to <paramref name="wait"/> for one; null when none came.</summary>
    internal async Task<LiveHeldStop?> NextStopAsync(TimeSpan wait, CancellationToken ct)
    {
        var until = DateTime.UtcNow + wait;
        while (true)
        {
            Task changed;
            lock (_gate)
            {
                if (_held.Values.Where(h => h.Sequence > _waited).MinBy(h => h.Sequence) is { } next)
                {
                    _waited = next.Sequence;
                    return next;
                }
                if (Closed || Ended != null) return null;
                changed = _changed.Task;
            }
            var left = until - DateTime.UtcNow;
            if (left <= TimeSpan.Zero) return null;
            await Task.WhenAny(changed, Task.Delay(left, ct)).ConfigureAwait(false);
            ct.ThrowIfCancellationRequested();
        }
    }

    /// <summary>Events from <paramref name="from"/> (a sequence) on, filtered; the first sequence kept tells what was dropped.</summary>
    internal (IReadOnlyList<LiveRingEvent> Events, long FirstKept, long Last) Page(long from, string? kind, long? thread, int limit)
    {
        lock (_gate)
        {
            var first = _ring.Count > 0 ? _ring.Peek().Sequence : _sequence + 1;
            var rows = _ring.Where(e => e.Sequence >= from && (kind == null || e.Kind == kind) && (thread == null || e.Thread == thread))
                .Take(limit).ToList();
            return (rows, first, _sequence);
        }
    }
}

/// <summary>
/// The sessions of this server (ids live-1, live-2, ...), each held by one backend worker. Joins what a session reports to
/// the static model: modules to loaded images by path, addresses to function names, offsets and PDB source lines; stop
/// points accept names, module!export, file:line and addresses.
/// </summary>
public sealed class LiveSessionService(AssemblyWorkspace workspace, NativeCodeService code) : IDisposable
{
    public const string MaxMinutesVariable = "CORVUS_LIVE_MAX_MINUTES";
    public const int MaxSessions = 8;
    private static readonly TimeSpan StartTimeout = TimeSpan.FromSeconds(30);
    private static readonly TimeSpan RequestTimeout = TimeSpan.FromSeconds(60);
    private readonly ConcurrentDictionary<string, LiveSession> _sessions = new(StringComparer.OrdinalIgnoreCase);
    private int _next;

    /// <summary>The backend new sessions start on.</summary>
    public ILiveBackend Backend { get; set; } = new FridaBackend();

    public IReadOnlyList<LiveSession> Sessions => _sessions.Values.OrderBy(s => int.Parse(s.Id[5..], CultureInfo.InvariantCulture)).ToList();

    public LiveSession Get(string id) =>
        _sessions.TryGetValue(id?.Trim() ?? "", out var s) ? s
            : throw new ToolError(ErrorCode.NotFound, $"No session '{id}'.", "live_session action=list shows the sessions; action=attach or spawn opens one");

    /// <summary>Attaches to a process (id or name) or starts <paramref name="program"/>; returns the open session.</summary>
    public async Task<LiveSession> OpenAsync(bool spawn, string program, IReadOnlyList<string> arguments, CancellationToken ct)
    {
        if (_sessions.Values.Count(s => !s.Closed) >= MaxSessions)
            throw new ToolError(ErrorCode.LimitExceeded, $"{MaxSessions} sessions are open.", "close one with live_session action=close");
        if (Backend.Unavailable() is { } missing)
            throw new ToolError(ErrorCode.ProviderUnavailable, missing.Reason, missing.Remediation);
        string target = program.Trim();
        if (spawn) target = InputFiles.RequireRegularFile(target);
        var worker = Backend.Start();
        var session = new LiveSession("live-" + Interlocked.Increment(ref _next), Backend.Name, target, spawn, worker);
        worker.EventReceived += e => OnEvent(session, e);
        try
        {
            await worker.WaitReadyAsync(StartTimeout, ct).ConfigureAwait(false);
            await worker.RequestAsync("hello", null, StartTimeout, ct).ConfigureAwait(false);
            var args = spawn
                ? new JsonObject
                {
                    ["spawn"] = target, ["arguments"] = new JsonArray(arguments.Select(a => (JsonNode)a).ToArray()),
                    // the worker's own TEMP is private (see FridaBackend); a started program gets the user's
                    ["temp"] = Environment.GetEnvironmentVariable("TEMP"), ["tmp"] = Environment.GetEnvironmentVariable("TMP"),
                }
                : new JsonObject { ["attach"] = target };
            var info = await worker.RequestAsync("open", args, RequestTimeout, ct).ConfigureAwait(false);
            session.ProcessId = info.GetProperty("pid").GetInt32();
            session.Arch = info.GetProperty("arch").GetString() ?? "";
            session.Suspended = info.TryGetProperty("suspended", out var s) && s.GetBoolean();
            lock (session.Modules)
                foreach (var m in info.GetProperty("modules").EnumerateArray().Select(Module))
                    if (!session.Modules.Any(x => x.Base == m.Base)) session.Modules.Add(m); // a load event may have come first
        }
        catch
        {
            worker.Kill("open failed");
            worker.Dispose();
            throw;
        }
        // The program's own image joins the static model: loaded (it is the file being analyzed) and indexed in the background.
        if (session.Modules.FirstOrDefault() is { } main && File.Exists(main.Path))
        {
            try
            {
                if (workspace.LoadAny(main.Path).Native is { } native) Index(session, native);
            }
            catch (ToolError) { /* an image the loader refuses stays unnamed */ }
        }
        lock (session.Modules)
            foreach (var m in session.Modules) Match(m);
        _sessions[session.Id] = session;
        var minutes = int.TryParse(Environment.GetEnvironmentVariable(MaxMinutesVariable), out var n) && n > 0 ? n : 30;
        session.Deadline = new Timer(_ => _ = CloseAsync(session, "deadline"), null, TimeSpan.FromMinutes(minutes), Timeout.InfiniteTimeSpan);
        _ = worker.Closed.ContinueWith(_ =>
        {
            if (!session.Closed && session.Ended == null)
            {
                session.Ended = "failed: the session worker ended" + (worker.StderrText.Length > 0 ? ": " + worker.StderrText.Trim().Split('\n')[^1] : "");
                session.ReleaseAll();
                session.Add("exit", null, null, session.Ended);
            }
        }, TaskScheduler.Default);
        return session;
    }

    private static LiveModuleState Module(JsonElement m) =>
        new(m.GetProperty("name").GetString() ?? "", Hex(m.GetProperty("base").GetString()), (ulong)m.GetProperty("size").GetInt64(), m.GetProperty("path").GetString() ?? "");

    private static ulong Hex(string? s) =>
        s != null && ulong.TryParse(s.StartsWith("0x", StringComparison.OrdinalIgnoreCase) ? s[2..] : s, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var v) ? v : 0;

    private void Index(LiveSession session, LoadedNative native)
    {
        lock (session.Indexing) session.Indexing.Add(code.Index(native, null, CancellationToken.None));
    }

    /// <summary>The loaded image at the module's path (looked up again each time, so images loaded later join too).</summary>
    private LoadedNative? Match(LiveModuleState m)
    {
        if (m.Image is { } image && workspace.Natives.Contains(image)) return image;
        m.Image = workspace.Natives.FirstOrDefault(n => n.SliceName == null && InputFiles.SamePath(n.FilePath, m.Path));
        return m.Image;
    }

    private void OnEvent(LiveSession session, Native.Providers.WorkerMessage.Event e)
    {
        var body = e.Body;
        long? Thread() => body.TryGetProperty("tid", out var t) && t.ValueKind == JsonValueKind.Number ? t.GetInt64() : null;
        switch (e.Name)
        {
            case "stop":
            {
                var point = body.GetProperty("point").GetString() ?? "";
                var registers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                foreach (var r in body.GetProperty("registers").EnumerateObject())
                    if (r.Value.ValueKind == JsonValueKind.String) registers[r.Name] = r.Value.GetString()!;
                var frames = body.GetProperty("frames").EnumerateArray().Select(f => Hex(f.GetString())).ToList();
                int hits = body.TryGetProperty("hits", out var h) ? h.GetInt32() : 0;
                if (session.StopPoints.TryGetValue(point, out var sp)) sp.Hits = hits;
                var thread = Thread();
                session.Add("stop", thread, frames.FirstOrDefault(), $"stop point {point} hit {hits}",
                    seq => new LiveHeldStop(seq, thread ?? 0, point, registers, frames));
                break;
            }
            case "module":
            {
                var m = Module(body.GetProperty("module"));
                var loaded = body.GetProperty("action").GetString() == "loaded";
                lock (session.Modules)
                {
                    session.Modules.RemoveAll(x => x.Base == m.Base);
                    if (loaded) session.Modules.Add(m);
                }
                session.Add("module", null, m.Base, $"{(loaded ? "loaded" : "unloaded")} {m.Name} ({m.Path})");
                break;
            }
            case "thread":
                session.Add("thread", Thread(), null, $"thread {body.GetProperty("action").GetString()}");
                break;
            case "exception":
                session.Add("exception", Thread(), Hex(body.GetProperty("address").GetString()),
                    $"{body.GetProperty("kind").GetString()}" + (body.TryGetProperty("memory", out var mem) && mem.ValueKind == JsonValueKind.Object
                        ? $" ({mem.GetProperty("operation").GetString()} of 0x{Hex(mem.GetProperty("address").GetString()):X})" : ""));
                break;
            case "output":
                session.Add("output", null, null, $"{body.GetProperty("stream").GetString()}: {body.GetProperty("text").GetString()}");
                break;
            case "script_error":
                session.Add("error", null, null, "session script: " + body.GetProperty("message").GetString());
                break;
            case "exit":
                session.Ended = "exited: " + body.GetProperty("reason").GetString();
                session.ReleaseAll();
                session.Add("exit", null, null, session.Ended);
                break;
        }
    }

    /// <summary>Names <paramref name="address"/> through the module holding it and its loaded image (return addresses look up the call's line).</summary>
    public LiveFrameName Name(LiveSession session, ulong address, bool returnAddress = false, CancellationToken ct = default)
    {
        LiveModuleState? module;
        lock (session.Modules) module = session.Modules.FirstOrDefault(m => m.Contains(address));
        if (module == null) return new(address, null, null, 0, null, 0, null, null);
        var rva = (uint)(address - module.Base);
        var native = Match(module);
        if (native == null) return new(address, module.Name, null, rva, null, 0, null, null);
        string? function = null, source = null;
        uint offset = 0;
        EvidenceName? named = null;
        if (code.Ready(native) is { } index && index.FunctionAt(rva) is { } f)
        {
            var name = index.NameAt(f.Start);
            function = name ?? $"sub_{native.Image.ImageBase + f.Start:X}";
            offset = rva - f.Start;
            if (name != null) named = new(native.Id, native.OriginalSha256, f.Start, name);
        }
        if (PdbService.StateOf(native)?.Pdb.Source is { } lines && lines.Lookup([returnAddress && rva > 0 ? rva - 1 : rva], ct)[0] is { } at)
            source = $"{at.File ?? "?"}:{at.Line}";
        return new(address, module.Name, native, rva, function, offset, source, named);
    }

    /// <summary>Waits (bounded) for the background index of the session's images, so names are ready for a stop.</summary>
    public async Task IndexedAsync(LiveSession session, TimeSpan wait, CancellationToken ct)
    {
        Task[] pending;
        lock (session.Indexing) pending = session.Indexing.Where(t => !t.IsCompleted).ToArray();
        if (pending.Length > 0) await Task.WhenAny(Task.WhenAll(pending), Task.Delay(wait, ct)).ConfigureAwait(false);
    }

    private static readonly Regex FileLine = new(@"^(?<file>.+\.[A-Za-z0-9+]{1,8}):(?<line>\d+)$", RegexOptions.CultureInvariant);

    /// <summary>
    /// The live address of a name (in the program's image, then any matched image), module!export, file:line (PDB line
    /// tables), an image VA (translated to where the module is loaded) or a live address.
    /// </summary>
    public async Task<ulong> ResolveAsync(LiveSession session, string where, CancellationToken ct)
    {
        var t = where.Trim();
        if (t.Length == 0) throw new ToolError(ErrorCode.InvalidArgument, "The stop point location is empty.", "at=<name>, module!export, file:line or 0xADDRESS");
        await IndexedAsync(session, TimeSpan.FromSeconds(30), ct).ConfigureAwait(false);
        List<LiveModuleState> modules;
        lock (session.Modules) modules = session.Modules.ToList();

        if (FileLine.Match(t) is { Success: true } fl && !t.Contains('!'))
        {
            var line = int.Parse(fl.Groups["line"].Value, CultureInfo.InvariantCulture);
            foreach (var m in modules)
                if (Match(m) is { } native && PdbService.StateOf(native)?.Pdb.Source is Native.Pdb.PdbLines lines
                    && lines.Addresses(fl.Groups["file"].Value, line) is { Count: > 0 } found)
                    return m.Base + found[0].Rva;
            throw new ToolError(ErrorCode.NotFound, $"No loaded image's PDB has code at {t}.",
                "load the program's PDB (load_pdb) or check the file name; the line tables name files by their build path");
        }
        if (t.IndexOf('!') is > 0 and var bang)
        {
            var name = t[..bang];
            var m = modules.FirstOrDefault(x => x.Name.Equals(name, StringComparison.OrdinalIgnoreCase)
                                               || Path.GetFileNameWithoutExtension(x.Name).Equals(name, StringComparison.OrdinalIgnoreCase))
                    ?? throw new ToolError(ErrorCode.NotFound, $"The program has no module '{name}'.", "live_session action=status lists its modules");
            var native = Match(m);
            if (native == null && File.Exists(m.Path))
            {
                native = workspace.LoadAny(m.Path).Native;
                if (native != null) m.Image = native;
            }
            if (native == null) throw new ToolError(ErrorCode.Unsupported, $"{m.Path} could not be loaded as a native image.", "pass a live address instead");
            return m.Base + await RvaOf(native, t[(bang + 1)..], ct).ConfigureAwait(false);
        }
        if (t.StartsWith("0x", StringComparison.OrdinalIgnoreCase) && ulong.TryParse(t[2..], NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var value))
        {
            if (modules.Any(m => m.Contains(value))) return value;
            foreach (var m in modules)
                if (Match(m) is { } native && value >= native.Image.ImageBase && value - native.Image.ImageBase < native.Image.SizeOfImage)
                    return m.Base + (value - native.Image.ImageBase);
            throw new ToolError(ErrorCode.NotFound, $"0x{value:X} is in no module of the program, live or as an image address.", "live_session action=status lists module ranges");
        }
        ToolError? first = null;
        foreach (var m in modules)
        {
            if (Match(m) is not { } native) continue;
            try { return m.Base + await RvaOf(native, t, ct).ConfigureAwait(false); }
            catch (ToolError e) when (e.Code == ErrorCode.NotFound || e.Code == ErrorCode.InvalidArgument) { first ??= e; }
        }
        throw first ?? new ToolError(ErrorCode.NotFound, $"No loaded image of the program names '{t}'.", "use module!export, file:line or an address");
    }

    private async Task<uint> RvaOf(LoadedNative native, string name, CancellationToken ct)
    {
        var index = code.Ready(native) ?? await code.Index(native, null, ct).ConfigureAwait(false);
        return NativeAddress.Parse(native.Image, name, index.AddressesOfName);
    }

    public async Task<LiveStopPointState> SetAsync(LiveSession session, string where, CancellationToken ct)
    {
        var address = await ResolveAsync(session, where, ct).ConfigureAwait(false);
        var id = session.NextPointId();
        await session.Worker.RequestAsync("set", new JsonObject { ["id"] = id, ["address"] = $"0x{address:X}" }, RequestTimeout, ct).ConfigureAwait(false);
        var point = new LiveStopPointState(id, where.Trim(), address, Name(session, address, ct: ct));
        lock (session.StopPoints) session.StopPoints[id] = point;
        return point;
    }

    public async Task ClearAsync(LiveSession session, string id, CancellationToken ct)
    {
        lock (session.StopPoints)
            if (!session.StopPoints.ContainsKey(id))
                throw new ToolError(ErrorCode.NotFound, $"Session {session.Id} has no stop point '{id}'.", "live_break action=list shows them");
        await session.Worker.RequestAsync("clear", new JsonObject { ["id"] = id }, RequestTimeout, ct).ConfigureAwait(false);
        lock (session.StopPoints) session.StopPoints.Remove(id);
    }

    /// <summary>Resumes held threads (one, or all) and starts a program still suspended at its start.</summary>
    public async Task<(IReadOnlyList<long> Resumed, bool Started)> ResumeAsync(LiveSession session, long? thread, CancellationToken ct)
    {
        Live(session);
        var args = new JsonObject();
        if (thread != null) args["thread"] = thread;
        var r = await session.Worker.RequestAsync("resume", args, RequestTimeout, ct).ConfigureAwait(false);
        var resumed = r.GetProperty("resumed").EnumerateArray().Select(x => x.GetInt64()).ToList();
        session.Release(resumed);
        var started = r.GetProperty("started").GetBoolean();
        if (started) session.Suspended = false;
        return (resumed, started);
    }

    /// <summary>Bytes at a live address; null when the program cannot be read there.</summary>
    public async Task<byte[]?> ReadAsync(LiveSession session, ulong address, int length, CancellationToken ct)
    {
        Live(session);
        var r = await session.Worker.RequestAsync("read", new JsonObject { ["address"] = $"0x{address:X}", ["length"] = length }, RequestTimeout, ct).ConfigureAwait(false);
        return r.GetProperty("bytes").GetString() is { } hex ? Convert.FromHexString(hex) : null;
    }

    internal static void Live(LiveSession session)
    {
        if (session.Closed || session.Ended != null)
            throw new ToolError(ErrorCode.Unsupported, $"Session {session.Id} is {session.State}{(session.Ended != null ? " (" + session.Ended + ")" : "")}.",
                "its events stay readable with live_events; open a new session with live_session");
    }

    /// <summary>Releases every held thread and disconnects; a program the session started is ended.</summary>
    public async Task CloseAsync(LiveSession session, string reason)
    {
        if (session.Closed) return;
        session.Closed = true;
        session.Deadline?.Dispose();
        if (session.Worker.IsAlive)
            await session.Worker.ShutdownAsync("close", new JsonObject { ["end"] = session.Spawned }, TimeSpan.FromSeconds(5)).ConfigureAwait(false);
        session.Worker.Dispose();
        session.ReleaseAll();
        session.Add("exit", null, null, "session closed (" + reason + ")");
    }

    public void Dispose()
    {
        foreach (var s in _sessions.Values)
            try { CloseAsync(s, "server exit").Wait(TimeSpan.FromSeconds(6)); }
            catch (AggregateException) { s.Worker.Kill("server exit"); }
    }
}
