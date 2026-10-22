using System.Diagnostics;
using System.Collections.Concurrent;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Corvus.Core;
using Corvus.Native;
using Corvus.Native.Annotations;
using Corvus.Native.Calls;
using Corvus.Native.Code;
using Corvus.Native.Providers;
using Corvus.Native.Providers.Live;

namespace Corvus.Services;

/// <summary>A module of the observed program; <see cref="Image"/> is the loaded image it matched by path, <see cref="Assembly"/> the loaded assembly it is.</summary>
public sealed record LiveModuleState(string Name, ulong Base, ulong Size, string Path)
{
    public LoadedNative? Image { get; set; }
    public LoadedAssembly? Assembly { get; set; }
    public bool Contains(ulong address) => address >= Base && address - Base < Size;
}

public sealed record LiveStopPointState(string Id, string Where, ulong Address, LiveFrameName At)
{
    public int Hits { get; set; }
    /// <summary>Set when the location was a jump and the point went where it leads.</summary>
    public string? Followed { get; init; }
    /// <summary>The writable pointer the jump went through and the value it held, which the program may still rebind (delay-load, first-call stubs).</summary>
    internal (ulong Address, ulong Value)? Slot { get; init; }
}

/// <summary>
/// A stop point or watch on a module the program has not loaded yet, set when the module loads; or, with
/// <see cref="UntilCompiled"/>, on a managed method (<see cref="Module"/> names it) set when the runtime compiles it.
/// </summary>
public sealed record LiveDeferred(string Id, string Where, string Module, bool Watch, int PerSecond, int RawArguments)
{
    public bool UntilCompiled { get; init; }
    /// <summary>Why the runtime cannot be read, when only the backend's JIT hook tells when the method is compiled.</summary>
    public string? Unreadable { get; init; }
    /// <summary>Where the method's IL body is mapped, which the backend's JIT hook reports the compile of; empty when unknown.</summary>
    public IReadOnlyList<ulong> IlBodies { get; init; } = [];
}

/// <summary>A deferred stop point or watch that could not be set when its module loaded or its method compiled; <see cref="Reported"/> once a call has said so.</summary>
public sealed record LiveFailedPoint(string Id, string Where, bool Watch, string Because, string Reason, string? Next)
{
    public bool Reported { get; set; }
}

/// <summary>A stop point or watch on a managed method, by the method's IL bodies, and the code it is hooked at.</summary>
internal sealed record LiveJitBinding(string Id, bool Watch, string Name, IReadOnlyList<ulong> IlBodies)
{
    public List<ulong> Code { get; } = [];
}

/// <summary>A thread held at a stop point until it is resumed: its general registers and return addresses.</summary>
public sealed record LiveHeldStop(long Sequence, long Thread, string Point, IReadOnlyDictionary<string, string> Registers, IReadOnlyList<ulong> Frames);

/// <summary>An event; <see cref="Source"/> is the watch or user script it came from.</summary>
public sealed record LiveRingEvent(long Sequence, string Kind, long? Thread, ulong? Address, string Text, string? Source = null);

/// <summary>
/// An address joined to the static model: its module, the loaded image and RVA, the containing function's name and offset,
/// the PDB source line, and the function start a saved record names (null when the image gives no name).
/// </summary>
public sealed record LiveFrameName(ulong Address, string? Module, LoadedNative? Image, uint Rva, string? Function, long Offset, string? Source,
    EvidenceName? Named)
{
    /// <summary>The function is known but not where its code starts, so <see cref="Offset"/> is unknown, not 0.</summary>
    public bool OffsetUnknown { get; init; }

    public string Display => Module == null ? $"0x{Address:X}"
        : Function == null ? $"{Module}+0x{Rva:X}"
        : OffsetUnknown ? $"{Module}!{Function} (offset unknown)"
        : Offset == 0 ? $"{Module}!{Function}" : Offset > 0 ? $"{Module}!{Function}+0x{Offset:X}" : $"{Module}!{Function}-0x{-Offset:X}";
}

/// <summary>A function start by image, SHA-256 and RVA with the name it had, for read_result format=verify.</summary>
public sealed record EvidenceName(string Image, string Sha256, uint Rva, string Name);

/// <summary>
/// One session on a local program: the worker holding it, its modules, stop points, held threads and a bounded event ring.
/// Ends on close, on its deadline, and with the server; the server never leaves a thread held or a started program behind.
/// </summary>
public sealed class LiveSession
{
    /// <summary>Events other than calls kept; calls have a ring of their own, so a call flood never evicts an output line, a stop or the exit.</summary>
    public const int RingCapacity = 10_000;
    public const int CallRingCapacity = 10_000;
    private readonly object _gate = new();
    private bool _exitLogged;
    private readonly EventRing _calls = new(CallRingCapacity), _others = new(RingCapacity);
    private readonly Dictionary<long, LiveHeldStop> _held = [];
    private TaskCompletionSource _changed = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private long _sequence;
    private long _waited;
    private int _nextPoint;
    private int _nextWatch;
    private int _nextScript;

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
    /// <summary>windows, linux or darwin (Frida's names).</summary>
    public string Platform { get; internal set; } = "";
    /// <summary>An x64 or x86 program on an ARM64 Windows machine, which runs it under emulation.</summary>
    public bool Emulated => OperatingSystem.IsWindows() && System.Runtime.InteropServices.RuntimeInformation.OSArchitecture == System.Runtime.InteropServices.Architecture.Arm64 && Arch is "x64" or "ia32";
    internal WorkerConnection Worker { get; }
    /// <summary>Unwinds stops from the stack bytes they carry (outside Windows); null where the architecture has no register file.</summary>
    internal LiveStackWalk? Stacks { get; set; }
    internal Timer? Deadline { get; set; }
    /// <summary>Checks each second for a program whose exit is stuck in a module's shutdown.</summary>
    internal Timer? ExitCheck { get; set; }
    /// <summary>When the program's exit code was first seen set while its process had not yet ended.</summary>
    internal DateTime? ExitingSince { get; set; }
    /// <summary>The backend's exit reason while its exit report waits for the process to end; null otherwise.</summary>
    internal volatile string? PendingExit;
    internal List<Task> Indexing { get; } = [];
    /// <summary>The program's .NET runtime once read (<see cref="LiveSessionService.ClrAsync"/>).</summary>
    internal LiveClr? Clr { get; set; }
    /// <summary>The module count at the last attempt to read the runtime; it is tried again when the count changes.</summary>
    internal int ClrTriedAt { get; set; } = -1;
    internal SemaphoreSlim ClrOpen { get; } = new(1, 1);
    /// <summary>Checks the points deferred until their method is compiled.</summary>
    internal Timer? CompileCheck { get; set; }
    /// <summary>A runtime DAC found nowhere on this machine is downloaded from a symbol server (opted in at open).</summary>
    public bool DownloadDac { get; init; }
    // methods the backend saw the JIT compile, by their code: the runtime reads them only once the thread that compiled them goes on
    private readonly Dictionary<ulong, LiveFrameName> _compiled = [];

    internal void AddCompiled(LiveFrameName name)
    {
        lock (_compiled) _compiled[name.Address] = name;
    }

    internal LiveFrameName? CompiledName(ulong address)
    {
        lock (_compiled) return _compiled.GetValueOrDefault(address);
    }

    private readonly Dictionary<ulong, LiveJitBinding> _bound = [];

    internal void Bind(LiveJitBinding binding)
    {
        lock (_bound)
            foreach (var il in binding.IlBodies) _bound[il] = binding;
    }

    internal LiveJitBinding? Bound(ulong il)
    {
        lock (_bound) return _bound.GetValueOrDefault(il);
    }
    internal int CompileChecking;
    public List<LiveModuleState> Modules { get; } = [];
    public Dictionary<string, LiveStopPointState> StopPoints { get; } = new(StringComparer.Ordinal);
    /// <summary>Stop points cleared in this session; guarded by <see cref="StopPoints"/>'s lock.</summary>
    internal HashSet<string> ClearedPoints { get; } = new(StringComparer.Ordinal);
    public Dictionary<string, LiveWatchState> Watches { get; } = new(StringComparer.Ordinal);
    public List<LiveDeferred> Deferred { get; } = [];
    public List<LiveFailedPoint> Failed { get; } = [];
    /// <summary>User scripts loaded with live_script: id to where the source came from.</summary>
    public Dictionary<string, string> Scripts { get; } = new(StringComparer.Ordinal);
    /// <summary>Stop points of coverage runs: point id to its run.</summary>
    internal ConcurrentDictionary<string, LiveCoverageRun> CoveragePoints { get; } = new(StringComparer.Ordinal);
    public bool Suspended { get; internal set; }
    /// <summary>A query-and-wait handle to the program, for its exit code (the worker's exit event carries none).</summary>
    internal Native.Live.SafeKernelHandle? ProcessHandle { get; set; }
    public uint? ExitCode { get; internal set; }
    public string? Ended { get; internal set; }
    public bool Closed { get; internal set; }
    /// <summary>Why the session closed (closed by request, deadline, server exit); null while open.</summary>
    public string? CloseReason { get; internal set; }
    /// <summary>Events both rings dropped, oldest first.</summary>
    public long Dropped
    {
        get { lock (_gate) return _calls.Dropped + _others.Dropped; }
    }
    /// <summary>Call events the call ring dropped.</summary>
    public long CallsDropped
    {
        get { lock (_gate) return _calls.Dropped; }
    }
    /// <summary>Exception events recorded, dropped ones included.</summary>
    public long Exceptions { get; private set; }
    /// <summary>Image names a followed child must have to be held (empty: every child); null when children are not followed.</summary>
    public IReadOnlyList<string>? ChildNames { get; internal set; }
    /// <summary>Processes the program started while the session follows child processes.</summary>
    public List<LiveChild> Children { get; } = [];
    /// <summary>The session whose gate holds this program at its start, until this session's first continue.</summary>
    public LiveSession? HeldBy { get; internal set; }

    public string State
    {
        get
        {
            lock (_gate)
            {
                if (Closed) return "closed";
                if (Ended != null && _exitLogged) return Ended.StartsWith("failed", StringComparison.Ordinal) ? "failed" : "exited";
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
    internal string NextWatchId() => "w" + Interlocked.Increment(ref _nextWatch);
    internal string NextScriptId() => "u" + Interlocked.Increment(ref _nextScript);

    /// <summary>Whether <paramref name="id"/> is a watch or script id this session gave out (cleared and unloaded ones too).</summary>
    public bool Issued(string id) =>
        id.Length > 1 && int.TryParse(id.AsSpan(1), NumberStyles.None, CultureInfo.InvariantCulture, out var n) && n > 0
        && n <= (id[0] switch { 'w' => Volatile.Read(ref _nextWatch), 'u' => Volatile.Read(ref _nextScript), _ => 0 });

    internal long Add(string kind, long? thread, ulong? address, string text, Func<long, LiveHeldStop>? held = null, string? source = null)
    {
        lock (_gate)
        {
            var seq = ++_sequence;
            if (kind == "exception") Exceptions++;
            (kind == "call" ? _calls : _others).Add(new LiveRingEvent(seq, kind, thread, address, text, source));
            if (held != null && thread is { } t) _held[t] = held(seq);
            Signal();
            return seq;
        }
    }

    /// <summary>
    /// Records the exit event for <see cref="Ended"/>; the state reads exited or failed only from here on, so a caller that
    /// waits for the state finds the event.
    /// </summary>
    internal void AddExit()
    {
        lock (_gate)
        {
            Add("exit", null, null, Ended!);
            _exitLogged = true;
        }
    }

    /// <summary>
    /// Records the close event and marks the session closed in one step, so the state reads closed only with the event
    /// recorded; false when the session was closed already.
    /// </summary>
    internal bool AddClose(string reason)
    {
        lock (_gate)
        {
            if (Closed) return false;
            CloseReason = reason;
            Add("exit", null, null, "session closed (" + reason + ")");
            Closed = true;
            return true;
        }
    }

    /// <summary>The last event sequence: a resume sent after it releases only the stops held up to it.</summary>
    internal long Sequence
    {
        get { lock (_gate) return _sequence; }
    }

    /// <summary>Releases the threads' stops recorded up to <paramref name="upTo"/>; a thread that stopped again since keeps its new stop.</summary>
    internal void Release(IEnumerable<long> threads, long upTo)
    {
        lock (_gate)
            foreach (var t in threads)
                if (_held.TryGetValue(t, out var h) && h.Sequence <= upTo) _held.Remove(t);
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

    /// <summary>
    /// Events from <paramref name="from"/> (a sequence) on, filtered, in sequence order; Gaps names the evicted events from
    /// <paramref name="from"/> to Last, More whether events past the limit match too.
    /// </summary>
    internal (IReadOnlyList<LiveRingEvent> Events, LiveRingGaps Gaps, long Last, bool More) Page(long from, string? kind, long? thread, int limit, string? source = null)
    {
        lock (_gate)
        {
            var events = kind == "call" ? _calls.Events : kind != null ? _others.Events : Merged(_calls.Events, _others.Events);
            var rows = events.Where(e => e.Sequence >= from && (kind == null || e.Kind == kind) && (thread == null || e.Thread == thread)
                                         && (source == null || e.Source == source))
                .Take(limit + 1).ToList();
            var more = rows.Count > limit;
            if (more) rows.RemoveAt(limit);
            return (rows, new LiveRingGaps(_calls.EvictedFrom(from), _others.EvictedFrom(from)), _sequence, more);
        }
    }

    private static IEnumerable<LiveRingEvent> Merged(IEnumerable<LiveRingEvent> a, IEnumerable<LiveRingEvent> b)
    {
        using var x = a.GetEnumerator();
        using var y = b.GetEnumerator();
        bool hx = x.MoveNext(), hy = y.MoveNext();
        while (hx || hy)
        {
            if (hx && (!hy || x.Current.Sequence < y.Current.Sequence)) { yield return x.Current; hx = x.MoveNext(); }
            else { yield return y.Current; hy = y.MoveNext(); }
        }
    }

    /// <summary>A bounded queue of events; the evicted ones are kept as sequence ranges, split where the other ring has an event between.</summary>
    private sealed class EventRing(int capacity)
    {
        // Past this the two oldest ranges merge, and a count inside them becomes an estimate.
        private const int MaxRanges = 4_096;
        private readonly List<LiveRingRange> _evicted = [];
        public Queue<LiveRingEvent> Events { get; } = new();
        public long Dropped { get; private set; }

        public void Add(LiveRingEvent e)
        {
            Events.Enqueue(e);
            if (Events.Count <= capacity) return;
            var gone = Events.Dequeue().Sequence;
            Dropped++;
            if (_evicted.Count > 0 && _evicted[^1].To == gone - 1) _evicted[^1] = _evicted[^1] with { To = gone, Count = _evicted[^1].Count + 1 };
            else _evicted.Add(new(gone, gone, 1));
            if (_evicted.Count > MaxRanges)
            {
                _evicted[1] = new(_evicted[0].From, _evicted[1].To, _evicted[0].Count + _evicted[1].Count);
                _evicted.RemoveAt(0);
            }
        }

        public LiveRingRange[] EvictedFrom(long from)
        {
            int i = _evicted.FindIndex(r => r.To >= from);
            return i < 0 ? [] : [.. _evicted.Skip(i)];
        }
    }
}

/// <summary>Sequences From to To, of which Count events were evicted (all of them, unless ranges were merged).</summary>
public readonly record struct LiveRingRange(long From, long To, long Count);

/// <summary>The evicted event ranges of a page: calls (the call ring) and the other events; empty lists when nothing was evicted.</summary>
public sealed record LiveRingGaps(IReadOnlyList<LiveRingRange> Calls, IReadOnlyList<LiveRingRange> Others)
{
    /// <summary>The events of <paramref name="ranges"/> evicted from sequences <paramref name="from"/> to <paramref name="to"/>; 0 when to is before from.</summary>
    public static long Count(IReadOnlyList<LiveRingRange> ranges, long from, long to)
    {
        long n = 0;
        foreach (var r in ranges)
        {
            if (r.From > to) break;
            if (r.To < from) continue;
            n += Math.Min(r.Count, Math.Min(r.To, to) - Math.Max(r.From, from) + 1);
        }
        return n;
    }
}

/// <summary>
/// The sessions of this server (ids live-1, live-2, ...), each held by one backend worker. Joins what a session reports to
/// the static model: modules to loaded images by path, addresses to function names, offsets and source lines; stop
/// points accept names, module!export, file:line and addresses.
/// </summary>
public sealed partial class LiveSessionService(AssemblyWorkspace workspace, NativeCodeService code, ServerOptions? options = null) : IDisposable
{
    public const string MaxMinutesVariable = "CORVUS_LIVE_MAX_MINUTES";
    public const int MaxSessions = 8;
    private static readonly TimeSpan StartTimeout = TimeSpan.FromSeconds(30);
    private static readonly TimeSpan RequestTimeout = TimeSpan.FromSeconds(60);
    private const int MaxScriptText = 4096; // characters of one script message kept in its event
    private readonly ConcurrentDictionary<string, LiveSession> _sessions = new(StringComparer.OrdinalIgnoreCase);
    private int _next;

    /// <summary>The backend new sessions start on.</summary>
    public ILiveBackend Backend { get; set; } = new FridaBackend { InstallPinned = options?.LiveInstallFrida == true };

    /// <summary>Tests: the 32-bit decoder this server's sessions use, in place of the process-wide CORVUS_CLR32.</summary>
    internal string? DecoderPath { get; set; }

    public IReadOnlyList<LiveSession> Sessions => _sessions.Values.OrderBy(s => int.Parse(s.Id[5..], CultureInfo.InvariantCulture)).ToList();

    public LiveSession Get(string id) =>
        _sessions.TryGetValue(id?.Trim() ?? "", out var s) ? s
            : throw new ToolError(ErrorCode.NotFound, $"No session '{id}'.", "live_session action=list shows the sessions; action=attach or spawn opens one");

    /// <summary>Whether <paramref name="text"/> is a session id (live-1) rather than a path, process name or dump id.</summary>
    public static bool IsSessionId(string? text) => System.Text.RegularExpressions.Regex.IsMatch(text?.Trim() ?? "", @"^live-\d+$", System.Text.RegularExpressions.RegexOptions.IgnoreCase);

    /// <summary>
    /// The session <paramref name="id"/> while its program runs; after its exit the process id may name another process,
    /// so an ended program is not_found.
    /// </summary>
    public LiveSession Running(string id)
    {
        var session = Get(id);
        if (session.Ended != null && !session.Closed || session.Closed && session.Spawned)
            throw new ToolError(ErrorCode.NotFound, $"The program of session {session.Id} has ended ({session.Ended}).", "open_minidump reads a snapshot saved while it ran (live_session action=snapshot)");
        return session;
    }

    /// <summary>Attaches to a process (id or name) or starts <paramref name="program"/>; returns the open session.</summary>
    public async Task<LiveSession> OpenAsync(bool spawn, string program, IReadOnlyList<string> arguments, CancellationToken ct,
        IReadOnlyList<string>? environment = null, IReadOnlyList<string>? childNames = null, bool downloadDac = false)
    {
        if (_sessions.Values.Count(s => !s.Closed) >= MaxSessions)
            throw new ToolError(ErrorCode.LimitExceeded, $"{MaxSessions} sessions are open.", "close one with live_session action=close");
        if (Backend.Unavailable() is { } missing)
            throw new ToolError(ErrorCode.ProviderUnavailable, missing.Reason, missing.Remediation);
        if (childNames != null && OperatingSystem.IsMacOS() && Backend is FridaBackend)
            throw new ToolError(ErrorCode.Unsupported, "Following child processes is not supported on macOS: Frida's child gating misses a fork there intermittently, so a child can run unobserved.",
                "open a session on the child once it runs (action=attach program=<process id or name>)");
        string target = program.Trim();
        if (spawn)
        {
            target = InputFiles.RequireRegularFile(target, "program");
            if (!File.Exists(target)) throw new ToolError(ErrorCode.NotFound, $"No program at {target}.", "program=<path to the program's file>");
            if (Native.Live.StaticProgram.Is(target)) throw Native.Live.StaticProgram.Refusal(target);
        }
        else
        {
            LiveProgramScope.RefuseOwnChain(target);
            if (int.TryParse(target, out var id) && OperatingSystem.IsLinux() && LiveProgramScope.ImagePath(id) is { } image && Native.Live.StaticProgram.Is(image))
                throw Native.Live.StaticProgram.Refusal(image);
        }
        var worker = Backend.Start();
        var session = new LiveSession("live-" + Interlocked.Increment(ref _next), Backend.Name, target, spawn, worker) { DownloadDac = downloadDac };
        worker.EventReceived += e => OnEvent(session, e);
        try
        {
            await worker.WaitReadyAsync(StartTimeout, ct).ConfigureAwait(false);
            var hello = await worker.RequestAsync("hello", null, StartTimeout, ct).ConfigureAwait(false);
            var frida = hello.ValueKind == JsonValueKind.Object && hello.TryGetProperty("frida", out var v) ? v.GetString() : null;
            if (FridaVersions.Refusal(frida) is { } old) throw new ToolError(ErrorCode.ProviderUnavailable, old, FridaBackend.Upgrade);
            if (FridaVersions.Warning(frida) is { } untested) session.Add("error", null, null, untested);
            var args = spawn
                ? new JsonObject
                {
                    ["spawn"] = target, ["arguments"] = new JsonArray(arguments.Select(a => (JsonNode)a).ToArray()),
                    // a started program runs in its own folder, as a debugger starts it, not in the worker's
                    ["cwd"] = Path.GetDirectoryName(target),
                    // the worker's own TEMP is private (see FridaBackend); a started program gets the user's
                    ["temp"] = Environment.GetEnvironmentVariable("TEMP"), ["tmp"] = Environment.GetEnvironmentVariable("TMP"),
                    ["environment"] = ProgramEnvironment(environment ?? []),
                }
                : new JsonObject { ["attach"] = target };
            if (childNames != null)
            {
                session.ChildNames = childNames;
                args["children"] = new JsonObject { ["names"] = new JsonArray([.. childNames.Select(n => (JsonNode)n)]) };
            }
            var info = await worker.RequestAsync("open", args, RequestTimeout, ct).ConfigureAwait(false);
            session.ProcessId = info.GetProperty("pid").GetInt32();
            if (OperatingSystem.IsWindows())
            {
                // full query rights let stop frames be checked against page protection; the limited right still reads the exit code
                foreach (var access in new[] { Native.Live.LiveNative.PROCESS_QUERY_INFORMATION, Native.Live.LiveNative.PROCESS_QUERY_LIMITED_INFORMATION })
                {
                    var h = Native.Live.LiveNative.OpenProcess(Native.Live.LiveNative.SYNCHRONIZE | access, false, session.ProcessId);
                    if (h.IsInvalid) { h.Dispose(); continue; }
                    // Windows ignores a process id's low two bits, so an id that is not a multiple of 4 opens another process.
                    if (Native.Live.LiveNative.GetProcessId(h) != session.ProcessId) { h.Dispose(); break; }
                    session.ProcessHandle = h;
                    break;
                }
            }
            // two sessions in one process place their hooks independently, at the same functions
            if (_sessions.Values.FirstOrDefault(o => o.ProcessId == session.ProcessId && o.State is not ("closed" or "exited" or "failed")) is { } other)
                throw new ToolError(ErrorCode.Conflict, $"Process {session.ProcessId} is already in session {other.Id}.", $"use {other.Id}, or close it first (live_session action=close session={other.Id})");
            session.Arch = info.GetProperty("arch").GetString() ?? "";
            session.Platform = info.TryGetProperty("platform", out var platform) ? platform.GetString() ?? "" : "";
            session.Suspended = info.TryGetProperty("suspended", out var s) && s.GetBoolean();
            if (info.TryGetProperty("spawn_retried", out var retried))
                session.Add("error", null, null, $"the program's first start timed out in Frida ({retried.GetString()})");
            session.Stacks = LiveStackWalk.For(session, address => Name(session, address) is { Function: not null, Offset: 0 });
            lock (session.Modules)
            {
                foreach (var m in info.GetProperty("modules").EnumerateArray().Select(Module))
                    if (!session.Modules.Any(x => x.Base == m.Base)) session.Modules.Add(m); // a load event may have come first
                // Frida lists modules in no fixed order (and names a system DLL as the main module of a program started
                // suspended): the program's own module, by the path the OS reports, leads, as the rest of the session expects
                var mainPath = spawn ? target : LiveProgramScope.ImagePath(session.ProcessId);
                if (mainPath != null && session.Modules.FindIndex(x => SamePath(x.Path, mainPath)) is > 0 and var at)
                {
                    var own = session.Modules[at];
                    session.Modules.RemoveAt(at);
                    session.Modules.Insert(0, own);
                }
            }
        }
        catch (Exception e)
        {
            worker.Kill("open failed");
            worker.Dispose();
            // the backend sees only that tracing failed (a started program exits with status 1); the setting says why
            if (e is ToolError { Code: ErrorCode.Failed or ErrorCode.AccessDenied } t && Native.Live.PtraceScope.Refusing(started: spawn) is { } scope)
                throw Native.Live.PtraceScope.Refusal(scope, t.Message);
            // a program attached by name is checked once the injection failed
            if (!spawn && OperatingSystem.IsLinux() && e is ToolError { Code: ErrorCode.Failed } && !int.TryParse(target, out _)
                && System.Diagnostics.Process.GetProcessesByName(target).Select(p => LiveProgramScope.ImagePath(p.Id)).FirstOrDefault(i => i != null && Native.Live.StaticProgram.Is(i)) is { } named)
                throw Native.Live.StaticProgram.Refusal(named);
            // the agent refused on Windows: a sandbox token (a Chromium child) is the usual cause, read from the target
            if (!spawn && e is ToolError { Code: ErrorCode.Failed } f && f.Message.Contains("refused to load", StringComparison.Ordinal)
                && int.TryParse(target, out var pid) && Native.Providers.Live.ProcessSandbox.Describe(pid) is { } sandbox)
                throw Native.Providers.Live.ProcessSandbox.Refusal(sandbox, f.Message);
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
        if (session.ProcessHandle != null) session.ExitCheck = new Timer(_ => CheckExit(session), null, TimeSpan.FromSeconds(1), TimeSpan.FromSeconds(1));
        _ = worker.Closed.ContinueWith(_ =>
        {
            if (!session.Closed && session.Ended == null && session.PendingExit == null)
            {
                session.Ended = "failed: the session worker ended" + (worker.StderrText.Length > 0 ? ": " + worker.StderrText.Trim().Split('\n')[^1] : "");
                session.ReleaseAll();
                EndCoverage(session);
                EndTimeline(session);
                session.AddExit();
            }
            if (!session.Closed) ResumeChildrenDirectly(session);
        }, TaskScheduler.Default);
        return session;
    }

    private static LiveModuleState Module(JsonElement m)
    {
        ulong size = (ulong)m.GetProperty("size").GetInt64();
        return new(m.GetProperty("name").GetString() ?? "", Hex(m.GetProperty("base").GetString()), size, ModuleFile(m.GetProperty("path").GetString() ?? "", size));
    }

    /// <summary>
    /// The file behind a module. A 32-bit program on 64-bit Windows names its system DLLs by their System32 path, which
    /// this 64-bit server opens as the 64-bit copy; the SysWOW64 copy is used when its image size matches the module's.
    /// </summary>
    internal static string ModuleFile(string path, ulong size, string? system = null, string? wow64 = null)
    {
        system ??= Environment.GetFolderPath(Environment.SpecialFolder.System);
        wow64 ??= Environment.Is64BitOperatingSystem ? Environment.GetFolderPath(Environment.SpecialFolder.SystemX86) : "";
        system = Path.TrimEndingDirectorySeparator(system);
        if (wow64.Length == 0 || system.Length == 0 || !path.StartsWith(system + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)) return path;
        if (SizeOfImage(path) == size) return path;
        var other = Path.Combine(wow64, path[(system.Length + 1)..]);
        return SizeOfImage(other) == size ? other : path;
    }

    /// <summary>The optional header's SizeOfImage (the same offset in PE32 and PE32+), or null when the file is no PE image.</summary>
    private static ulong? SizeOfImage(string path)
    {
        try
        {
            using var f = File.OpenRead(path);
            Span<byte> head = stackalloc byte[4096];
            int n = f.ReadAtLeast(head, head.Length, throwOnEndOfStream: false);
            if (n < 0x40 || head[0] != 'M' || head[1] != 'Z') return null;
            int pe = BitConverter.ToInt32(head[0x3C..]);
            if (pe < 0 || pe + 24 + 60 > n || BitConverter.ToUInt32(head[pe..]) != 0x00004550) return null;
            return BitConverter.ToUInt32(head[(pe + 24 + 56)..]);
        }
        catch (IOException) { return null; }
        catch (UnauthorizedAccessException) { return null; }
    }

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
        if (m.Image == null && (m.Assembly == null || !workspace.Assemblies.Contains(m.Assembly))) m.Assembly = AssemblyOf(m);
        return m.Image;
    }

    /// <summary>The loaded assembly a module is: its own file, or a copy of it (same name, image size and SHA-256).</summary>
    private LoadedAssembly? AssemblyOf(LiveModuleState m)
    {
        var assemblies = workspace.Assemblies;
        if (assemblies.FirstOrDefault(a => InputFiles.SamePath(a.FilePath, m.Path)) is { } own) return own;
        var copies = assemblies.Where(a => Path.GetFileName(a.FilePath).Equals(m.Name, StringComparison.OrdinalIgnoreCase) && SizeOfImage(a.OriginalBytes) == m.Size).ToList();
        if (copies.Count == 0) return null;
        string sha;
        try { sha = Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(File.ReadAllBytes(m.Path))); }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { return null; }
        return copies.FirstOrDefault(a => a.OriginalSha256 == sha);

        static ulong SizeOfImage(byte[] pe)
        {
            if (pe.Length < 0x40) return 0;
            int optional = BitConverter.ToInt32(pe, 0x3C) + 24;
            return optional > 0 && optional + 60 <= pe.Length ? BitConverter.ToUInt32(pe, optional + 56) : 0;
        }
    }

    /// <summary>The module's loaded image, else its file loaded now; null when the file is missing or holds no native image.</summary>
    private LoadedNative? ImageOf(LiveModuleState m)
    {
        if (Match(m) is { } native) return native;
        if (!File.Exists(m.Path)) return null;
        native = workspace.LoadAny(m.Path).Native;
        if (native != null) m.Image = native;
        return native;
    }

    /// <summary>
    /// While a thread is held, a DLL the loader mapped through a delay-load import can have no load event yet (it comes
    /// with the next load, often after the resume): the backend's module list, read now, adds it. Its event, and the
    /// deferred points it sets, still come with the load event.
    /// </summary>
    public async Task RefreshModulesAsync(LiveSession session, CancellationToken ct)
    {
        if (session.Held.Count == 0 || session.Closed || session.Ended != null) return;
        JsonElement info;
        try { info = await session.Worker.RequestAsync("info", null, RequestTimeout, ct).ConfigureAwait(false); }
        catch (ToolError) { return; }
        if (info.ValueKind != JsonValueKind.Object || !info.TryGetProperty("modules", out var listed) || listed.ValueKind != JsonValueKind.Array) return;
        lock (session.Modules)
            foreach (var m in listed.EnumerateArray().Select(Module))
                if (!session.Modules.Any(x => x.Base == m.Base))
                {
                    session.Modules.Add(m);
                    Match(m);
                }
    }

    /// <summary>Reads the module list again when a frame of <paramref name="held"/> lies outside every module the session knows, so the stop names it.</summary>
    public async Task FrameModulesAsync(LiveSession session, LiveHeldStop held, CancellationToken ct)
    {
        bool unknown;
        lock (session.Modules) unknown = held.Frames.Any(f => !session.Modules.Any(m => m.Contains(f)));
        if (unknown) await RefreshModulesAsync(session, ct).ConfigureAwait(false);
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
                if (session.CoveragePoints.TryGetValue(point, out var run))
                {
                    CoverageStop(session, run, point, Thread(), body.TryGetProperty("counted", out var c) && c.ValueKind == JsonValueKind.True);
                    break;
                }
                // A thread already inside a point's hook when the point was cleared
                // stops after the clear; it is released, so a continue that came
                // before its stop does not leave it held.
                bool cleared;
                lock (session.StopPoints) cleared = !session.StopPoints.ContainsKey(point) && session.ClearedPoints.Contains(point);
                if (cleared && Thread() is { } late)
                {
                    session.Add("stop", late, null, $"stop point {point} hit after it was cleared: thread released");
                    _ = Task.Run(async () =>
                    {
                        // An error here means the session ended meanwhile.
                        try { await Resume(session, late).ConfigureAwait(false); }
                        catch (Exception x) when (x is ToolError or InvalidOperationException or ObjectDisposedException) { }
                    });
                    break;
                }
                var registers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                foreach (var r in body.GetProperty("registers").EnumerateObject())
                    if (r.Value.ValueKind == JsonValueKind.String) registers[r.Name] = r.Value.GetString()!;
                var reported = body.GetProperty("frames").EnumerateArray().Select(f => Hex(f.GetString())).ToList();
                var frames = Unwound(session, registers, body, reported) ?? [.. reported.Where((f, i) => i == 0 || CouldBeCode(session, f))];
                // a call returns past its call instruction, so the stopped address further down is the hook's saved copy (x86),
                // and the return address beside that copy repeats frame #1
                var at = frames[0];
                frames = [.. frames.Where((f, i) => i == 0 || f != at && !(i > 1 && f == frames[1] && frames[i - 1] == at))];
                int hits = body.TryGetProperty("hits", out var h) ? h.GetInt32() : 0;
                if (session.StopPoints.TryGetValue(point, out var sp)) sp.Hits = hits;
                var thread = Thread();
                session.Add("stop", thread, frames.FirstOrDefault(), $"stop point {point} hit {hits}",
                    seq => new LiveHeldStop(seq, thread ?? 0, point, registers, frames));
                break;
            }
            case "calls":
            {
                LiveWatchState? w;
                lock (session.Watches) session.Watches.TryGetValue(body.GetProperty("watch").GetString() ?? "", out w);
                if (w == null) break;
                // each row: thread, program clock (ms), return address, argument values, return value
                foreach (var row in body.GetProperty("rows").EnumerateArray())
                {
                    var values = row[3].EnumerateArray().Select(v => v.ValueKind == JsonValueKind.String ? v.GetString() : null).ToList();
                    long ms = row[1].GetInt64();
                    lock (w)
                    {
                        if (w.Calls++ == 0) w.FirstMs = ms;
                        w.LastMs = ms;
                    }
                    session.Add("call", row[0].GetInt64(), Hex(row[2].GetString()), LiveWatchPlans.Describe(w.Plan, values, row[4].GetString()), source: w.Id);
                }
                lock (w) w.Skipped += body.GetProperty("skipped").GetInt64();
                break;
            }
            case "user_script":
            {
                var id = body.GetProperty("script").GetString();
                var text = body.TryGetProperty("error", out var err) && err.ValueKind == JsonValueKind.String ? "error: " + err.GetString()
                    : body.TryGetProperty("payload", out var payload) ? payload.ValueKind == JsonValueKind.String ? payload.GetString()! : payload.GetRawText() : "";
                if (body.TryGetProperty("bytes", out var bytes) && bytes.GetInt32() > 0) text += $" (+{bytes.GetInt32()} bytes of data)";
                session.Add("script", null, null, $"{id}: {(text.Length > MaxScriptText ? text[..MaxScriptText] + "..." : text)}", source: id);
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
                if (loaded) Match(m);
                session.Add("module", null, m.Base, $"{(loaded ? "loaded" : "unloaded")} {m.Name} ({m.Path})");
                long? holder = loaded && body.TryGetProperty("held", out var held) && held.ValueKind == JsonValueKind.True ? Thread() : null;
                var afterEntry = body.TryGetProperty("afterEntry", out var started) && started.ValueKind == JsonValueKind.True;
                var unobserved = body.TryGetProperty("unobserved", out var reason) && reason.ValueKind == JsonValueKind.String ? reason.GetString() : null;
                if (loaded) _ = SetDeferredAsync(session, m, holder, afterEntry, unobserved);
                break;
            }
            case "jit_ran":
                JitRan(body.GetProperty("run").GetString() ?? "", Hex(body.GetProperty("il").GetString()));
                break;
            case "compiled":
                _ = SetCompiledAsync(session, Hex(body.GetProperty("il").GetString()), Hex(body.GetProperty("code").GetString()),
                    body.TryGetProperty("frames", out var callers) ? [.. callers.EnumerateArray().Select(f => Hex(f.GetString()))] : [], Thread());
                break;
            case "thread":
                session.Add("thread", Thread(), null, $"thread {body.GetProperty("action").GetString()}");
                break;
            case "exception":
                session.Add("exception", Thread(), Hex(body.GetProperty("address").GetString()),
                    $"{body.GetProperty("kind").GetString()}" + (body.TryGetProperty("memory", out var mem) && mem.ValueKind == JsonValueKind.Object
                        ? $" ({mem.GetProperty("operation").GetString()} of 0x{Hex(mem.GetProperty("address").GetString()):X})" : ""));
                break;
            case "exit_status":
                // Windows keeps all 32 bits; elsewhere the low 8, as waitpid reports them
                var status = body.GetProperty("code").GetInt32();
                session.ExitCode = session.Platform == "windows" ? (uint)status : (uint)(status & 0xFF);
                break;
            case "output":
                session.Add("output", null, null, $"{body.GetProperty("stream").GetString()}: {body.GetProperty("text").GetString()}");
                break;
            case "child":
                ChildStarted(session, body);
                break;
            case "script_error":
                session.Add("error", null, null, "session script: " + body.GetProperty("message").GetString());
                break;
            case "exit":
                var exitReason = body.GetProperty("reason").GetString() ?? "";
                // Frida can report process-terminated once the exit has begun while the process stays
                // in its exit: the report waits for the process to end, so the stuck exit check can still end it.
                if (exitReason == "process-terminated" && session.CloseReason == null && InExit(session))
                {
                    session.PendingExit = exitReason;
                    _ = ExitWhenEnded(session);
                }
                else Exited(session, exitReason);
                break;
        }
    }

    private const uint WaitTimeout = 0x102;

    // Whether a process Frida reports terminated is still in its exit: process object not yet signaled; false where no
    // handle is held.
    private static bool InExit(LiveSession session)
    {
        try
        {
            // The report can come before the agent's exit status and before the exit code is set, so neither is required.
            return session.ProcessHandle is { IsInvalid: false, IsClosed: false } h && Native.Live.LiveNative.WaitForSingleObject(h, 0) == WaitTimeout;
        }
        catch (ObjectDisposedException) { return false; }
    }

    /// <summary>
    /// Records the pending exit once the process ends, or after twice <see cref="StuckExit"/> (the stuck exit check
    /// ends it before then); a close meanwhile records the session's end itself.
    /// </summary>
    private async Task ExitWhenEnded(LiveSession session)
    {
        var deadline = DateTime.UtcNow + 2 * StuckExit + TimeSpan.FromSeconds(5);
        while (DateTime.UtcNow < deadline && session.Ended == null && InExit(session))
            await Task.Delay(100).ConfigureAwait(false);
        if (session.Ended == null && session.PendingExit is { } reason) Exited(session, reason);
        session.PendingExit = null;
    }

    private void Exited(LiveSession session, string reason)
    {
        // after close, the exit is the session's doing (Frida ends a started program with its own code): say so instead
        session.Ended = session.CloseReason is { } why
            ? $"{(session.Spawned ? "ended" : "detached")} when the session closed ({why})"
            : "exited: " + reason + ExitText(session);
        // the worker's exception event can be lost when the process dies at once; the exit code still names it
        if (session is { Exceptions: 0, ExitCode: >= 0xC000_0000 and not StatusControlCExit and { } code } && Native.Dump.ExceptionCodes.Name(code) is { } exception)
            session.Add("exception", null, null, $"{exception} (0x{code:X8}), from the exit code: the program ended before the exception's address was reported");
        session.ReleaseAll();
        EndCoverage(session);
        EndTimeline(session);
        session.AddExit();
    }

    /// <summary>
    /// The stop's frames unwound from the stack bytes it carries; where the walk ends before the end of the stack, the backend's
    /// frames past the last one reached follow. Null when the stop has no stack or the walk finds no caller.
    /// </summary>
    private List<ulong>? Unwound(LiveSession session, Dictionary<string, string> registers, JsonElement body, List<ulong> reported)
    {
        if (session.Stacks is not { } stacks || !body.TryGetProperty("stack", out var st) || st.GetString() is not { Length: > 0 } hex) return null;
        if (stacks.Walk(registers, Convert.FromHexString(hex)) is not { Frames.Count: > 1 } walk) return null;
        var frames = walk.Frames.Select(f => f.Ip).ToList();
        if (walk.Stop != "end_of_stack" && reported.LastIndexOf(frames[^1]) is > 0 and var at)
            frames.AddRange(reported.Skip(at + 1).Where(f => CouldBeCode(session, f)));
        return frames;
    }

    /// <summary>
    /// False for a frame a stack scan picked up that cannot be a return address: below 64 KiB, past user space, or in a
    /// loaded image outside its executable sections (code outside every module, such as JIT code, stays).
    /// </summary>
    private bool CouldBeCode(LiveSession session, ulong address)
    {
        if (address < 0x10000 || address >= (session.Arch is "ia32" or "arm" ? 0xFFFF_0000UL : 0x8000_0000_0000UL)) return false;
        LiveModuleState? m;
        lock (session.Modules) m = session.Modules.FirstOrDefault(x => x.Contains(address));
        if (m == null) return ExecutablePage(session, address) != false;
        return Match(m) is not { } native || native.Image.SectionAt((uint)(address - m.Base)) is { IsExecutable: true };
    }

    /// <summary>Whether the page at <paramref name="address"/> is committed and executable; null when it cannot be queried.</summary>
    private static bool? ExecutablePage(LiveSession session, ulong address)
    {
        const uint MemCommit = 0x1000, AnyExecute = 0x10 | 0x20 | 0x40 | 0x80;
        if (!OperatingSystem.IsWindows() || !Environment.Is64BitProcess || session.ProcessHandle is not { IsInvalid: false } h) return null;
        if (Native.Live.LiveNative.VirtualQueryEx64(h, (nint)address, out var info, Marshal.SizeOf<Native.Live.LiveNative.MEMORY_BASIC_INFORMATION64>()) == 0) return null;
        return info.State == MemCommit && (info.Protect & AnyExecute) != 0;
    }

    private readonly ConcurrentDictionary<string, (Native.Dump.ModuleNames? Pe, (uint Rva, uint Size, string Name)[] Symbols)> _exports = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// The function symbol holding <paramref name="rva"/> in a module no image is loaded for (system libraries), as dump_stack names
    /// a core's frames: a PE's exports and COFF symbols within its unwind data, an ELF's .symtab and .dynsym functions (exports
    /// where it has no sized symbols), the nearest below when a symbol has no size; null past a sized symbol's end.
    /// </summary>
    private (uint Rva, string Name)? NearestSymbol(string path, uint rva)
    {
        var (pe, table) = _exports.GetOrAdd(path, p =>
        {
            try
            {
                if (!File.Exists(p)) return (null, []);
                var image = NativeImageLoader.Open(p);
                if (image is Native.Pe.PeFile file) return (new Native.Dump.ModuleNames(file, null, null), []);
                return (null, SymbolTable(image));
            }
            catch (Exception e) when (e is ToolError or IOException or UnauthorizedAccessException or InvalidDataException) { return (null, []); }
        });
        if (pe != null) return pe.Lookup(rva) is { Name: { } name, Start: { } start } ? (start, name) : null;
        int lo = 0, hi = table.Length - 1, best = -1;
        while (lo <= hi)
        {
            int mid = (lo + hi) / 2;
            if (table[mid].Rva <= rva) { best = mid; lo = mid + 1; }
            else hi = mid - 1;
        }
        return best < 0 || table[best].Size > 0 && rva - table[best].Rva >= table[best].Size ? null : (table[best].Rva, table[best].Name);
    }

    /// <summary>An image's function symbols with their sizes, and its other exports that are not data, by RVA; an exported symbol keeps its export name.</summary>
    internal static (uint Rva, uint Size, string Name)[] SymbolTable(INativeImage image)
    {
        var map = new SortedDictionary<uint, (uint Size, string Name)>();
        var data = image.Symbols.Where(s => s.Kind != ImageSymbolKind.Function).Select(s => s.Rva).ToHashSet();
        foreach (var x in image.Exports)
            if (x.ForwardedTo == null && !string.IsNullOrEmpty(x.Name) && !data.Contains(x.Rva)) map.TryAdd(x.Rva, (0u, x.Name));
        foreach (var s in image.Symbols)
            if (s.Kind == ImageSymbolKind.Function && !string.IsNullOrEmpty(s.Name) && s.Rva != 0)
                map[s.Rva] = ((uint)Math.Min(s.Size, uint.MaxValue), map.TryGetValue(s.Rva, out var e) ? e.Name : s.Name);
        return [.. map.Select(kv => (kv.Key, kv.Value.Size, kv.Value.Name))];
    }

    private readonly ConcurrentDictionary<string, (uint Rva, string Name)[]> _exportTables = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>A module file's named exports by RVA (read once per path).</summary>
    private (uint Rva, string Name)[] ExportTable(string path) =>
        _exportTables.GetOrAdd(path, p =>
        {
            try
            {
                if (!File.Exists(p)) return [];
                return [.. NativeImageLoader.Open(p).Exports.Where(x => x.ForwardedTo == null && !string.IsNullOrEmpty(x.Name))
                    .Select(x => (x.Rva, x.Name!)).DistinctBy(x => x.Rva).OrderBy(x => x.Rva)];
            }
            catch (Exception e) when (e is ToolError or IOException or UnauthorizedAccessException or InvalidDataException) { return []; }
        });

    private static readonly TimeSpan ExitCodeWait = TimeSpan.FromSeconds(1);

    // bound here, not in Native.Live: the process inspector there binds no API that changes a process
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool TerminateProcess(Native.Live.SafeKernelHandle process, uint exitCode);

    /// <summary>How long a program may stay in its exit (exit code set, process not ended) before it is ended.</summary>
    internal static TimeSpan StuckExit { get; set; } = TimeSpan.FromSeconds(10);

    /// <summary>
    /// Ends a program that called ExitProcess but whose exit does not finish (a module's DLL shutdown waits forever: Frida's
    /// agent can, after a watch on x86), with the exit code it chose; the backend then reports the exit as usual.
    /// </summary>
    private void CheckExit(LiveSession session)
    {
        try
        {
            if (session.Closed || session.Ended != null || session.ProcessHandle is not { IsInvalid: false } h) return;
            if (Native.Live.LiveNative.WaitForSingleObject(h, 0) == 0 || !Native.Live.LiveNative.GetExitCodeProcess(h, out var code)
                || code == Native.Live.LiveNative.STILL_ACTIVE)
            {
                session.ExitingSince = null;
                return;
            }
            session.ExitingSince ??= DateTime.UtcNow;
            if (DateTime.UtcNow - session.ExitingSince < StuckExit) return;
            session.ExitCheck?.Dispose();
            session.Add("error", null, null, $"the program called ExitProcess({(code < 0x10000 ? code : $"0x{code:X8}")}) but its exit did not finish in {StuckExit.TotalSeconds:0} s " +
                "(a module's shutdown is stuck): ended with that exit code");
            const uint ProcessTerminate = 0x0001;
            using var end = Native.Live.LiveNative.OpenProcess(ProcessTerminate, false, session.ProcessId);
            if (!end.IsInvalid) TerminateProcess(end, code);
        }
        catch (ObjectDisposedException) { } // closed meanwhile
    }

    /// <summary>
    /// After a close, a program that is in its exit still gets <see cref="StuckExit"/> to finish it, then is ended with its
    /// exit code: an unload that meets the start of an exit (seen on x86) can leave the exit unable to finish. The watch
    /// lasts twice that long; a program still running then goes on unobserved, as a detached program does.
    /// </summary>
    private async Task WatchExitAfterClose(LiveSession session, Native.Live.SafeKernelHandle handle)
    {
        using (handle)
        {
            session.ExitingSince = null;
            for (var watched = TimeSpan.Zero; watched < 2 * StuckExit; watched += TimeSpan.FromSeconds(1))
            {
                if (Native.Live.LiveNative.WaitForSingleObject(handle, 0) == 0 || !Native.Live.LiveNative.GetExitCodeProcess(handle, out var code)) return;
                if (code == Native.Live.LiveNative.STILL_ACTIVE) session.ExitingSince = null;
                else if ((session.ExitingSince ??= DateTime.UtcNow) <= DateTime.UtcNow - StuckExit)
                {
                    session.Add("error", null, null, $"the program's exit (code {(code < 0x10000 ? code : $"0x{code:X8}")}) did not finish within {StuckExit.TotalSeconds:0} s " +
                        "of the session's close: ended with that exit code");
                    const uint ProcessTerminate = 0x0001;
                    using var end = Native.Live.LiveNative.OpenProcess(ProcessTerminate, false, session.ProcessId);
                    if (!end.IsInvalid) TerminateProcess(end, code);
                    return;
                }
                await Task.Delay(TimeSpan.FromSeconds(1)).ConfigureAwait(false);
            }
        }
    }

    private const uint StatusControlCExit = 0xC000_013A;

    /// <summary>
    /// ", exit code N" from the program's handle once it has ended (crash codes named), else from the worker's exit_status
    /// event; empty when neither gives one.
    /// </summary>
    private static string ExitText(LiveSession session)
    {
        // the exit event can come just before the process object is signaled
        const uint WaitObject0 = 0;
        if (session.ProcessHandle is { IsInvalid: false, IsClosed: false } h
            && Native.Live.LiveNative.WaitForSingleObject(h, (uint)ExitCodeWait.TotalMilliseconds) == WaitObject0
            && Native.Live.LiveNative.GetExitCodeProcess(h, out var status))
            session.ExitCode = status;
        if (session.ExitCode is not { } code) return "";
        return code < 0x10000 ? $", exit code {code}"
            : $", exit code 0x{code:X8}{(Native.Dump.ExceptionCodes.Name(code) is { } n ? $" ({n})" : "")}";
    }

    /// <summary>Names <paramref name="address"/> through the module holding it and its loaded image (return addresses look up the call's line).</summary>
    public LiveFrameName Name(LiveSession session, ulong address, bool returnAddress = false, CancellationToken ct = default)
    {
        LiveModuleState? module;
        lock (session.Modules) module = session.Modules.FirstOrDefault(m => m.Contains(address));
        if (module == null)
        {
            // until the runtime has recorded a just-compiled method, it names the code after the method before it
            var managed = ManagedName(session, address, null);
            return managed is not { Offset: 0 } && session.CompiledName(address) is { } compiled ? compiled : managed ?? new(address, null, null, 0, null, 0, null, null);
        }
        var rva = (uint)(address - module.Base);
        // A return address can be the first byte past a noreturn call at a
        // function's end, so the call before it names the frame.
        var call = returnAddress && rva > 0 ? rva - 1 : rva;
        var native = Match(module);
        if (native == null)
            return ManagedName(session, address, module) ?? (NearestSymbol(module.Path, call) is { } e ? new(address, module.Name, null, rva, e.Name, rva - e.Rva, null, null)
                : new(address, module.Name, null, rva, null, 0, null, null));
        string? function = null, source = null;
        long offset = 0;
        EvidenceName? named = null;
        if (code.Ready(native) is { } index && index.FunctionAt(call) is { } f)
        {
            var name = index.NameAt(f.Start);
            function = name ?? $"sub_{native.Image.ImageBase + f.Start:X}";
            offset = (long)rva - f.Start; // negative in a chunk placed before the entry
            if (name != null) named = new(native.Id, native.OriginalSha256, f.Start, name);
        }
        // code the module writes at run time (a packed DLL) has no file bytes to index: its exports name it
        else if (native.Image.Sections.FirstOrDefault(s => s.Contains(rva)) is { IsExecutable: true } s && rva - s.Rva >= s.RawSize
                 && NearestSymbol(module.Path, call) is { } e)
            (function, offset) = (e.Name, rva - e.Rva);
        if (PdbService.StateOf(native)?.Pdb.Source is { } lines && lines.Lookup([call], ct)[0] is { } at)
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

    private static readonly Regex NameOffset = new(@"^(?<name>.+?)\+0x(?<offset>[0-9A-Fa-f]{1,8})$", RegexOptions.CultureInvariant);
    private static readonly Regex FileLine = new(@"^(?<file>.+\.[A-Za-z0-9+]{1,8}):(?<line>\d+)$", RegexOptions.CultureInvariant);

    /// <summary>
    /// The live address of a name (in the program's image, then any matched image), module!export, file:line (PDB or DWARF line
    /// tables), an image VA (translated to where the module is loaded) or a live address. With <paramref name="data"/>, a
    /// module name is its base and an address outside every module (stack, heap) is taken as is.
    /// </summary>
    public async Task<ulong> ResolveAsync(LiveSession session, string where, CancellationToken ct, bool data = false)
    {
        ToolError failed;
        try { return await ResolveNativeAsync(session, where, ct, data).ConfigureAwait(false); }
        catch (ToolError e) when (!data && e.Code is ErrorCode.NotFound or ErrorCode.Unsupported or ErrorCode.InvalidArgument) { failed = e; }
        if (await ManagedTargetAsync(session, where, ct).ConfigureAwait(false) is not { } target) throw failed;
        return await ManagedCodeAsync(session, target, ct).ConfigureAwait(false) is { } code ? code.Code
            : throw new ToolError(ErrorCode.NotFound, $"{target.Display} has no code yet: the runtime compiles it at its first call.",
                $"live_break action=set at={where.Trim()} defers it until then");
    }

    /// <summary>The live address of a native name, module!export, file:line or address (see <see cref="ResolveAsync"/>).</summary>
    private async Task<ulong> ResolveNativeAsync(LiveSession session, string where, CancellationToken ct, bool data = false)
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
                if (Match(m) is { } native && PdbService.StateOf(native)?.Pdb.Source is { } lines
                    && lines.Addresses(fl.Groups["file"].Value, line, ct) is { Count: > 0 } found)
                    return m.Base + found[0].Rva;
            throw new ToolError(ErrorCode.NotFound, $"No loaded image's PDB or DWARF has code at {t}.",
                "load the program's debug information (load_pdb) or check the file name; the line tables name files by their build path");
        }
        if (NameOffset.Match(t) is { Success: true } no && !t.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
        {
            var start = await ResolveAsync(session, no.Groups["name"].Value, ct, data).ConfigureAwait(false);
            var target = start + ulong.Parse(no.Groups["offset"].Value, NumberStyles.HexNumber, CultureInfo.InvariantCulture);
            var holder = modules.FirstOrDefault(m => m.Contains(start));
            if (holder != null && !holder.Contains(target))
                throw new ToolError(ErrorCode.InvalidArgument, $"{t} is past the end of {holder.Name}.", "use a smaller offset");
            return target;
        }
        if (t.IndexOf('!') is > 0 and var bang)
        {
            var name = t[..bang];
            LiveModuleState? Named() => modules.FirstOrDefault(x => x.Name.Equals(name, StringComparison.OrdinalIgnoreCase)
                                                               || Path.GetFileNameWithoutExtension(x.Name).Equals(name, StringComparison.OrdinalIgnoreCase));
            if (Named() == null && session.Held.Count > 0)
            {
                await RefreshModulesAsync(session, ct).ConfigureAwait(false);
                lock (session.Modules) modules = session.Modules.ToList();
            }
            var m = Named()
                    ?? throw new ToolError(ErrorCode.NotFound, $"The program has no module '{name}'.", "live_session action=status lists its modules");
            var export = t[(bang + 1)..];
            var native = ImageOf(m);
            // An emulated program calls a hybrid DLL's x64 or x86 view (ARM64X,
            // CHPE), whose exports the file's own table does not hold. Other
            // files answer for themselves, since the program's lookup waits on
            // a loader lock a held load keeps.
            if (session.Emulated && native?.Image is Native.Pe.PeFile { LoadConfig.ChpeMetadataPointer: not 0 }
                && await ExportAsync(session, m.Name, export, ct).ConfigureAwait(false) is { } emulated) return emulated;
            ToolError missing;
            if (native == null) missing = new ToolError(ErrorCode.Unsupported, $"{m.Path} could not be loaded as a native image.", "pass a live address instead");
            else
                try { return m.Base + await RvaOf(native, export, ct).ConfigureAwait(false); }
                catch (ToolError e) when (e.Code == ErrorCode.NotFound) { missing = e; }
            // The loader's own view answers for a module whose file is not on
            // disk (the dyld shared cache).
            if (await ExportAsync(session, m.Name, export, ct).ConfigureAwait(false) is { } loaded) return loaded;
            throw native != null && missing.Code == ErrorCode.NotFound ? await WithLayerNameAsync(missing, m, native, export, ct).ConfigureAwait(false) : missing;
        }
        if (t.StartsWith("0x", StringComparison.OrdinalIgnoreCase) && ulong.TryParse(t[2..], NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var value))
        {
            if (modules.Any(m => m.Contains(value))) return value;
            foreach (var m in modules)
                if (Match(m) is { } native && value >= native.Image.ImageBase && value - native.Image.ImageBase < native.Image.SizeOfImage)
                    return m.Base + (value - native.Image.ImageBase);
            if (data || session.CompiledName(value) != null) return value;
            throw new ToolError(ErrorCode.NotFound, $"0x{value:X} is in no module of the program, live or as an image address.", "live_session action=status lists module ranges");
        }
        if (data && modules.FirstOrDefault(m => m.Name.Equals(t, StringComparison.OrdinalIgnoreCase)) is { } whole) return whole.Base;
        ToolError? first = null;
        foreach (var m in modules)
        {
            if (Match(m) is not { } native) continue;
            try { return m.Base + await RvaOf(native, t, ct).ConfigureAwait(false); }
            catch (ToolError e) when (e.Code == ErrorCode.NotFound || e.Code == ErrorCode.InvalidArgument)
            {
                var hinted = await WithLayerNameAsync(e, m, native, t, ct).ConfigureAwait(false);
                if (first == null || hinted != e) first = hinted;
            }
        }
        throw first ?? new ToolError(ErrorCode.NotFound, $"No loaded image of the program names '{t}'.", "use module!export, file:line or an address");
    }

    /// <summary>
    /// <paramref name="e"/> with a next step naming the Il2Cpp or NativeAOT layer's C identifier for a managed name
    /// ("Ns.Type::Method(int)" as "Ns_Type__Method"), when that layer of <paramref name="native"/> names a function so.
    /// </summary>
    private async Task<ToolError> WithLayerNameAsync(ToolError e, LiveModuleState m, LoadedNative native, string name, CancellationToken ct)
    {
        var t = name.Trim();
        if (t.IndexOf('(') is > 0 and var paren) t = t[..paren];
        if (!t.Contains("::", StringComparison.Ordinal)) return e;
        var index = code.Ready(native) ?? await code.Index(native, null, ct).ConfigureAwait(false);
        var identifier = NativeName.Identifier(t.Replace("::", "$$", StringComparison.Ordinal));
        return index.AddressesOfName(identifier).Select(c => c.Source).FirstOrDefault(l => l is "il2cpp" or "nativeaot") is { } layer
            ? new ToolError(e.Code, e.Message, $"at={m.Name}!{identifier} (the {layer} layer's name for it)")
            : e;
    }

    private async Task<uint> RvaOf(LoadedNative native, string name, CancellationToken ct)
    {
        var index = code.Ready(native) ?? await code.Index(native, null, ct).ConfigureAwait(false);
        return NativeAddress.Parse(native.Image, name, index.AddressesOfName);
    }

    /// <summary>
    /// Where code at <paramref name="address"/> really starts: the backend places a stop point on a jump (direct or through
    /// memory) at the jump's target, so the server follows it first and says so; a jump through a CFG dispatch or check
    /// pointer is refused, since its target runs for every indirect call of the program.
    /// </summary>
    internal async Task<(ulong Address, string? Followed)> FollowJumpsAsync(LiveSession session, ulong address, CancellationToken ct)
    {
        var (a, followed, _) = await FollowJumpsThroughAsync(session, address, ct).ConfigureAwait(false);
        return (a, followed);
    }

    /// <summary><see cref="FollowJumpsAsync"/>, also giving the last pointer in a writable section the path went through.</summary>
    private async Task<(ulong Address, string? Followed, (ulong Address, ulong Value)? Slot)> FollowJumpsThroughAsync(LiveSession session, ulong address, CancellationToken ct)
    {
        var start = address;
        (ulong, ulong)? writable = null;
        for (int hop = 0; hop < 8; hop++)
        {
            LiveModuleState? m;
            lock (session.Modules) m = session.Modules.FirstOrDefault(x => x.Contains(address));
            if (m == null || Match(m) is not { } native) break;
            // In an ARM64X module of an emulated x64 program, the file's code
            // is not the code the program runs.
            if (session.Emulated && native.Image.Arch == NativeArch.Arm64) break;
            var index = code.Ready(native) ?? await code.Index(native, null, ct).ConfigureAwait(false);
            var rva = (uint)(address - m.Base);
            if (index.Decode(rva) is not { } insn) break;
            ulong next;
            if (insn.Flow == FlowKind.Jump && insn.BranchTarget is { } target) next = m.Base + target;
            else if (insn.Flow == FlowKind.IndirectJump && insn.MemoryTarget is { } slot)
            {
                if (GuardPointerSlots(native).Contains(slot))
                    throw new ToolError(ErrorCode.Unsupported,
                        $"{Name(session, address, ct: ct).Display} jumps through the Control Flow Guard dispatch pointer: a stop point or watch there would run for every indirect call of the program.",
                        "set it at the function the indirect call reaches");
                int size = native.Image.Is64Bit ? 8 : 4;
                if (await ReadAsync(session, m.Base + slot, size, ct).ConfigureAwait(false) is not { } b || b.Length < size) break;
                next = size == 8 ? BitConverter.ToUInt64(b) : BitConverter.ToUInt32(b);
                if (native.Image.Sections.FirstOrDefault(x => x.Contains(slot)) is { } sec && (sec.Access & SectionAccess.Write) != 0) writable = (m.Base + slot, next);
            }
            else break;
            if (next == 0 || next == address) break;
            lock (session.Modules) if (!session.Modules.Any(x => x.Contains(next))) break; // a target outside every module is no code to set a point on
            address = next;
        }
        return address == start ? (start, null, null) : (address, $"{Name(session, start, ct: ct).Display} jumps to {Name(session, address, ct: ct).Display}, so it is set there", writable);
    }

    private static readonly TimeSpan RebindPoll = TimeSpan.FromMilliseconds(100);

    /// <summary>
    /// Moves a stop point set through a writable pointer when the program rewrites the pointer (a delay-load import is bound,
    /// a first-call stub fills its table): the code it pointed to at set time runs once or never. Calls between the rewrite
    /// and the move are not seen.
    /// </summary>
    private async Task FollowRebindAsync(LiveSession session, string id, (ulong Address, ulong Value) slot)
    {
        int size = session.Arch is "ia32" or "arm" ? 4 : 8;
        var seen = slot.Value;
        while (!session.Closed && session.Ended == null)
        {
            LiveStopPointState? point;
            lock (session.StopPoints) point = session.StopPoints.GetValueOrDefault(id);
            if (point == null || point.Slot != slot) return;
            try
            {
                var b = await ReadAsync(session, slot.Address, size, CancellationToken.None).ConfigureAwait(false);
                if (b == null || b.Length < size) return;
                var value = size == 8 ? BitConverter.ToUInt64(b) : BitConverter.ToUInt32(b);
                if (value != seen)
                {
                    bool code;
                    lock (session.Modules) code = session.Modules.Any(x => x.Contains(value));
                    // cleared or pointed outside every module (a sentinel while it binds): keep waiting for a code address
                    if (!code) { await Task.Delay(RebindPoll).ConfigureAwait(false); continue; }
                    var (address, _, again) = await FollowJumpsThroughAsync(session, value, CancellationToken.None).ConfigureAwait(false);
                    seen = value;
                    if (address == point.Address) continue;
                    await session.Worker.RequestAsync("clear", new JsonObject { ["id"] = id }, RequestTimeout, CancellationToken.None).ConfigureAwait(false);
                    await session.Worker.RequestAsync("set", new JsonObject { ["id"] = id, ["address"] = $"0x{address:X}" }, RequestTimeout, CancellationToken.None).ConfigureAwait(false);
                    var at = Name(session, address);
                    var moved = point with { Address = address, At = at, Followed = $"{point.Where} went through a pointer the program rebound; it moved to {at.Display}", Slot = again };
                    lock (session.StopPoints) session.StopPoints[id] = moved;
                    session.Add("module", null, address, $"{id} moved from {point.At.Display} to {at.Display}: the program rebound the pointer at 0x{slot.Address:X}");
                    if (again is not { } next) return;
                    (slot, seen) = (next, next.Value);
                    continue;
                }
            }
            catch (Exception e) when (e is ToolError or TimeoutException or OperationCanceledException) { return; }
            await Task.Delay(RebindPoll).ConfigureAwait(false);
        }
    }

    /// <summary>RVAs of the image's CFG check and dispatch pointers (the load configuration's guard function pointers).</summary>
    private static HashSet<uint> GuardPointerSlots(LoadedNative native)
    {
        var slots = new HashSet<uint>();
        if (native.Image is Native.Pe.PeFile { LoadConfig: { } lc })
            foreach (var va in new[] { lc.GuardCfCheckFunctionPointer, lc.GuardCfDispatchFunctionPointer, lc.GuardXfgCheckFunctionPointer,
                         lc.GuardXfgDispatchFunctionPointer, lc.GuardXfgTableDispatchFunctionPointer })
                if (va > native.Image.ImageBase && va - native.Image.ImageBase < native.Image.SizeOfImage) slots.Add((uint)(va - native.Image.ImageBase));
        return slots;
    }

    /// <summary>Bytes a hook's jump can rewrite: 5 on 32-bit x86 (a jmp rel32 reaches the whole address space), else up to 16.</summary>
    private static int HookBytes(LiveSession session) => session.Arch == "ia32" ? 5 : WatchPatchBytes;

    /// <summary>Bytes a watch rewrites at its function's start; a stop point inside them (past the first byte) silences the watch.</summary>
    internal const int WatchPatchBytes = 16;

    private void CheckOverlap(LiveSession session, ulong stop, ulong watch, string conflict, string next, CancellationToken ct)
    {
        if (stop <= watch || stop - watch >= WatchPatchBytes) return;
        throw new ToolError(ErrorCode.Conflict,
            $"{conflict} at {Name(session, stop, ct: ct).Display} is {stop - watch} bytes into {Name(session, watch, ct: ct).Display}, " +
            $"whose first {WatchPatchBytes} bytes a watch rewrites: the watch would record nothing.", next);
    }

    /// <summary>Whether the backend refused to hook an address (Frida: "unable to intercept function" or "instruction").</summary>
    internal static bool Unhookable(ToolError e) => e.Message.Contains("unable to intercept ", StringComparison.OrdinalIgnoreCase);

    /// <summary>The backend's refusal to hook, explained: a function shorter than the jump a hook writes over its start.</summary>
    private ToolError HookRefused(LiveSession session, ulong address, string what, CancellationToken ct) =>
        new(ErrorCode.Unsupported, $"A {what} cannot be placed at {Name(session, address, ct: ct).Display}: {HookReason(session, address, ct)}",
            "set it at a caller (find_xrefs lists the call sites) or inside a longer function");

    /// <summary>Why a hook cannot be written at <paramref name="address"/>, naming the instructions it would have to move.</summary>
    internal string HookReason(LiveSession session, ulong address, CancellationToken ct)
    {
        var at = Name(session, address, ct: ct);
        var index = at.Image != null ? code.Ready(at.Image) : null;
        var f = index?.FunctionAt(at.Rva) is { Size: > 0 } found && found.Start == at.Rva ? found : null;
        var lines = index?.Disassemble(at.Rva, 6, f != null ? f.Start + (uint)f.Size : uint.MaxValue) ?? [];
        var pad = LandingPad(lines);
        var listing = lines.Count > 0 ? $" ({Listing(lines)})" : "";
        return f != null && f.Size - pad < WatchPatchBytes
            ? $"the function is {f.Size} bytes long{listing}, too short for the jump a hook writes over its start{(pad > 0 ? $" after its {Listing(lines[..1])}" : "")}."
            : $"the instructions there{listing} cannot be moved aside for the hook's jump.";
    }

    /// <summary>
    /// Bytes of a leading endbr64 or endbr32: Frida keeps that landing pad in place
    /// and writes a hook's jump after it, so they do not count toward the jump.
    /// </summary>
    internal static uint LandingPad(IReadOnlyList<DisasmLine> lines) => lines.Count > 0 && lines[0].Bytes is "F30F1EFA" or "F30F1EFB" ? 4u : 0;

    /// <summary>Instructions as one line: "endbr64; xor eax, eax; ret".</summary>
    internal static string Listing(IEnumerable<DisasmLine> lines) => string.Join("; ", lines.Select(l => Regex.Replace(l.Text.Trim(), @"\s+", " ")));

    /// <summary>
    /// Defers a module!name whose module the program has not loaded (a plug-in loaded later): the point or watch is set
    /// when the module loads. Held is true when the worker holds the loading thread until then, so no call is missed.
    /// Null when the module is loaded.
    /// </summary>
    public async Task<(LiveDeferred Point, bool Held)?> DeferAsync(LiveSession session, string where, bool watch, int perSecond = 0, int rawArguments = 0,
        CancellationToken ct = default, string? id = null)
    {
        var t = where.Trim();
        if (NameOffset.Match(t) is { Success: true } no) t = no.Groups["name"].Value;
        if (t.StartsWith("0x", StringComparison.OrdinalIgnoreCase)) return null;
        if (t.IndexOf('!') is not (> 0 and var bang)) return await DeferManagedAsync(session, t, watch, perSecond, rawArguments, id, ct).ConfigureAwait(false);
        var module = t[..bang];
        bool loaded;
        lock (session.Modules) loaded = session.Modules.Any(m => ModuleNamed(m, module));
        if (loaded) return await DeferManagedAsync(session, t, watch, perSecond, rawArguments, id, ct).ConfigureAwait(false);
        // a managed name that is ambiguous or unknown fails now, not at the load
        if (await ManagedTargetAsync(session, t, ct).ConfigureAwait(false) is { } managed && IsBundled(managed.Path))
            return await DeferManagedAsync(session, t, watch, perSecond, rawArguments, id, ct).ConfigureAwait(false);
        var d = new LiveDeferred(id ?? (watch ? session.NextWatchId() : session.NextPointId()), where.Trim(), module, watch, perSecond, rawArguments);
        lock (session.Deferred) session.Deferred.Add(d);
        // a worker without the op still sets the point on the load event, after the module's first calls
        try { await session.Worker.RequestAsync("defer_module", new JsonObject { ["name"] = module }, RequestTimeout, ct).ConfigureAwait(false); }
        catch (ToolError) { return (d, false); }
        return (d, true);
    }

    private static bool ModuleNamed(LiveModuleState m, string name) =>
        ModuleNamed(m.Name, name) || (NativeImageOf(m.Name) is { } assembly && ModuleNamed(assembly, name));

    /// <summary>A module or file named <paramref name="name"/>, with or without its extension.</summary>
    private static bool ModuleNamed(string file, string name)
    {
        var (f, n) = (Path.GetFileName(file), name.Trim());
        return f.Equals(n, StringComparison.OrdinalIgnoreCase) || Path.GetFileNameWithoutExtension(f).Equals(n, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>The assembly file a .NET Framework native image (NGEN, <c>name.ni.dll</c>) was compiled from; null for any other file.</summary>
    private static string? NativeImageOf(string file) =>
        file.EndsWith(".ni.dll", StringComparison.OrdinalIgnoreCase) ? file[..^7] + ".dll"
        : file.EndsWith(".ni.exe", StringComparison.OrdinalIgnoreCase) ? file[..^7] + ".exe"
        : null;

    /// <summary>
    /// Sets the points deferred to <paramref name="module"/>, then lets its loading thread (held by the worker) go on;
    /// <paramref name="unobserved"/> names why a point in the module would not be seen, and fails them instead.
    /// </summary>
    private async Task SetDeferredAsync(LiveSession session, LiveModuleState module, long? holder, bool afterEntry, string? unobserved)
    {
        List<LiveDeferred> due;
        bool rest;
        lock (session.Deferred)
        {
            due = session.Deferred.Where(d => !d.UntilCompiled && ModuleNamed(module, d.Module)).ToList();
            session.Deferred.RemoveAll(due.Contains);
            rest = session.Deferred.Any(d => due.Any(x => x.Module.Equals(d.Module, StringComparison.OrdinalIgnoreCase)));
        }
        try
        {
            if (unobserved != null)
                foreach (var d in due)
                    FailDeferred(session, d, $"{module.Name} loaded", unobserved, "run the program on an x64 machine, where it is not emulated");
            else
                await SetDueAsync(session, afterEntry ? $"{module.Name} loaded; its entry point writes its code, so set once that returned" : $"{module.Name} loaded", due).ConfigureAwait(false);
            var placed = await PlaceCoverageAsync(session, module).ConfigureAwait(false);
            if (!rest)
                foreach (var name in due.Select(d => d.Module).Concat(placed).Distinct(StringComparer.OrdinalIgnoreCase))
                    await session.Worker.RequestAsync("undefer_module", new JsonObject { ["name"] = name }, RequestTimeout, CancellationToken.None).ConfigureAwait(false);
        }
        catch (Exception e) when (e is ToolError or TimeoutException or OperationCanceledException) { }
        finally
        {
            if (holder is { } tid)
                try { await session.Worker.RequestAsync("release_load", new JsonObject { ["thread"] = tid }, RequestTimeout, CancellationToken.None).ConfigureAwait(false); }
                catch (Exception e) when (e is ToolError or TimeoutException or OperationCanceledException) { }
        }
    }

    /// <summary>Sets deferred points now that <paramref name="because"/> (their module loaded, their method compiled).</summary>
    private async Task SetDueAsync(LiveSession session, string because, List<LiveDeferred> due)
    {
        foreach (var d in due)
        {
            try
            {
                // a managed method that is compiled at its first call waits for that
                if (await DeferManagedAsync(session, d.Where, d.Watch, d.PerSecond, d.RawArguments, d.Id, CancellationToken.None).ConfigureAwait(false) is { } later)
                {
                    session.Add("module", null, null, $"deferred {(d.Watch ? "watch" : "stop point")} {d.Id}: {later.Point.Module} has no code yet ({because}); it is set when the runtime compiles it");
                    continue;
                }
                var (at, plan) = d.Watch
                    ? await WatchAsync(session, d.Where, d.PerSecond, d.RawArguments, CancellationToken.None, d.Id).ConfigureAwait(false) is var w ? (w.At, $": {w.Plan.Prototype} ({w.Plan.Source})") : default
                    : ((await SetAsync(session, d.Where, CancellationToken.None, d.Id).ConfigureAwait(false)).At, "");
                session.Add("module", null, at.Address, $"deferred {(d.Watch ? "watch" : "stop point")} {d.Id} set at {at.Display}{plan} ({because})");
            }
            catch (Exception e) when (e is ToolError or TimeoutException or OperationCanceledException)
            {
                FailDeferred(session, d, because, e.Message, (e as ToolError)?.Remediation);
            }
        }
    }

    private static void FailDeferred(LiveSession session, LiveDeferred d, string because, string reason, string? next)
    {
        session.Add("error", null, null, $"deferred {d.Id} at {d.Where} could not be set ({because}): {reason}");
        lock (session.Failed) session.Failed.Add(new(d.Id, d.Where, d.Watch, because, reason, next));
    }

    /// <summary>Refuses an address in the first bytes of a function a recording coverage run hooks at its start.</summary>
    private void CheckCoverageOverlap(LiveSession session, ulong address, string what, CancellationToken ct)
    {
        foreach (var run in _coverage.Values.Where(r => r.Session == session.Id && r.State == "recording"))
            foreach (var rva in run.ArmedRvas)
            {
                var start = run.ModuleBase + rva;
                if (address <= start || address >= start + WatchPatchBytes) continue;
                throw new ToolError(ErrorCode.Conflict,
                    $"{what} at {Name(session, address, ct: ct).Display} is {address - start} bytes into {Name(session, start, ct: ct).Display}, whose first {WatchPatchBytes} bytes coverage run {run.Id} rewrites.",
                    $"set it at the function's start or {WatchPatchBytes}+ bytes in, or stop {run.Id} first (live_coverage action=stop)");
            }
    }

    /// <summary>Refuses an address inside an instruction of a known function: a hook written there corrupts the code and crashes the program.</summary>
    private async Task CheckInstructionStartAsync(LiveSession session, ulong address, CancellationToken ct)
    {
        LiveModuleState? m;
        lock (session.Modules) m = session.Modules.FirstOrDefault(x => x.Contains(address));
        if (m == null || Match(m) is not { } native) return;
        var index = code.Ready(native) ?? await code.Index(native, null, ct).ConfigureAwait(false);
        var rva = (uint)(address - m.Base);
        if (index.FunctionAt(rva) is not { } f || f.Start == rva) return;
        if (index.GetGraph(f, ct).Blocks.FirstOrDefault(b => b.Start <= rva && rva < b.End) is not { } block) return;
        var starts = index.Disassemble(block.Start, block.InstructionCount, block.End).Select(l => l.Rva).ToList();
        if (starts.Count == 0 || starts.Contains(rva)) return;
        string At(uint r) => Name(session, m.Base + r, ct: ct).Display;
        var before = starts.LastOrDefault(r => r < rva, block.Start);
        var after = starts.FirstOrDefault(r => r > rva);
        throw new ToolError(ErrorCode.InvalidArgument, $"{At(rva)} is inside an instruction: a hook there would corrupt the code.",
            $"use an instruction start: {At(before)}{(after > rva ? $" or {At(after)}" : "")}");
    }

    public async Task<LiveStopPointState> SetAsync(LiveSession session, string where, CancellationToken ct, string? id = null)
    {
        var (address, followed, slot) = await FollowJumpsThroughAsync(session, await ResolveAsync(session, where, ct).ConfigureAwait(false), ct).ConfigureAwait(false);
        await CheckInstructionStartAsync(session, address, ct).ConfigureAwait(false);
        CheckCoverageOverlap(session, address, "This stop point", ct);
        List<LiveWatchState> watches;
        lock (session.Watches) watches = session.Watches.Values.Where(w => !w.Cleared).ToList();
        foreach (var w in watches)
            CheckOverlap(session, address, w.Address, "This stop point", $"set it at the function's start or {WatchPatchBytes}+ bytes in, or clear watch {w.Id} first", ct);
        List<LiveStopPointState> points;
        lock (session.StopPoints) points = session.StopPoints.Values.ToList();
        var reach = HookBytes(session);
        foreach (var other in points.Select(p => (p.Id, p.Address)).Concat(watches.Select(w => (w.Id, w.Address))))
            if (other.Address != address && (address > other.Address ? address - other.Address : other.Address - address) < (ulong)reach)
                throw new ToolError(ErrorCode.Conflict,
                    $"This stop point at {Name(session, address, ct: ct).Display} is {(address > other.Address ? address - other.Address : other.Address - address)} bytes from {other.Id} at {Name(session, other.Address, ct: ct).Display}: " +
                    $"the jumps the two hooks write ({reach} bytes each) would overlap and corrupt the code.",
                    $"set it {reach}+ bytes away, or clear {other.Id} first");
        id ??= session.NextPointId();
        try { await session.Worker.RequestAsync("set", new JsonObject { ["id"] = id, ["address"] = $"0x{address:X}" }, RequestTimeout, ct).ConfigureAwait(false); }
        catch (ToolError e) when (Unhookable(e)) { throw HookRefused(session, address, "stop point", ct); }
        var point = new LiveStopPointState(id, where.Trim(), address, Name(session, address, ct: ct)) { Followed = followed, Slot = slot };
        lock (session.StopPoints) session.StopPoints[id] = point;
        if (slot is { } pointer) _ = Task.Run(() => FollowRebindAsync(session, id, pointer));
        await FollowRecompilesAsync(session, where, address, id, false, ct).ConfigureAwait(false);
        return point;
    }

    /// <summary>Records each call of the function at <paramref name="where"/>, decoded by the plan its name, PDB or DWARF gives.</summary>
    public async Task<LiveWatchState> WatchAsync(LiveSession session, string where, int perSecond, int rawArguments, CancellationToken ct, string? id = null)
    {
        var (address, followed) = await FollowJumpsAsync(session, await ResolveAsync(session, where, ct).ConfigureAwait(false), ct).ConfigureAwait(false);
        await CheckInstructionStartAsync(session, address, ct).ConfigureAwait(false);
        CheckCoverageOverlap(session, address, "This watch", ct);
        // a watch reads the return value through the return address, which only a function's start has on the stack top
        if (Name(session, address, ct: ct) is { Image: not null, Function: not null, Offset: > 0 } inside)
            throw new ToolError(ErrorCode.InvalidArgument, $"{inside.Display} is inside {inside.Function}: a watch records calls, from a function's start.",
                $"watch {inside.Function}, or set a stop point here (live_break action=set)");
        List<LiveStopPointState> points;
        lock (session.StopPoints) points = session.StopPoints.Values.ToList();
        foreach (var p in points)
            CheckOverlap(session, p.Address, address, $"Stop point {p.Id}", $"clear stop point {p.Id} first (live_break action=clear), or move it to the function's start", ct);
        var at = Name(session, address, ct: ct);
        var bare = where.Trim();
        // a known API is found by the name given (module!export) or the function's own name
        var function = at.Function != null && at.Offset == 0 ? at.Function : bare.StartsWith("0x", StringComparison.OrdinalIgnoreCase) ? at.Display : bare;
        if (ApiSignatures.Find(bare) is not null && !bare.StartsWith("0x", StringComparison.OrdinalIgnoreCase)) function = ApiSignatures.BareName(bare);
        var os = session.Platform switch { "windows" => ApiOs.Windows, "linux" => ApiOs.Linux, "darwin" => ApiOs.Darwin, _ => ApiOs.Unknown };
        var plan = LiveWatchPlans.Build(function, at.Image, at.Rva, session.Arch is "x64" or "arm64", os, rawArguments);
        id ??= session.NextWatchId();
        var w = new LiveWatchState(id, bare, address, at, plan, perSecond) { Followed = followed };
        lock (session.Watches) session.Watches[id] = w;
        try
        {
            await session.Worker.RequestAsync("watch", new JsonObject
            {
                ["id"] = id, ["address"] = $"0x{address:X}", ["args"] = new JsonArray(plan.ScriptKinds.Select(k => (JsonNode)k).ToArray()), ["perSecond"] = perSecond,
            }, RequestTimeout, ct).ConfigureAwait(false);
        }
        catch (Exception e)
        {
            lock (session.Watches) session.Watches.Remove(id);
            if (e is ToolError t && Unhookable(t)) throw HookRefused(session, address, "watch", ct);
            throw;
        }
        await FollowRecompilesAsync(session, where, address, id, true, ct).ConfigureAwait(false);
        return w;
    }

    public async Task UnwatchAsync(LiveSession session, string id, CancellationToken ct)
    {
        LiveWatchState? w;
        lock (session.Watches) session.Watches.TryGetValue(id, out w);
        if (w == null || w.Cleared) throw new ToolError(ErrorCode.NotFound, $"Session {session.Id} has no watch '{id}'.", "live_watch action=list shows them");
        // the script sends what it still holds before the watch ends, so the state stays for that last batch
        await session.Worker.RequestAsync("unwatch", new JsonObject { ["id"] = id }, RequestTimeout, ct).ConfigureAwait(false);
        w.Cleared = true;
    }

    /// <summary>
    /// Loads a user-supplied script into the session's program; its messages and errors go into the event ring. Error is
    /// what it reported failing within <see cref="ScriptErrorWait"/> (an exception in its top-level code).
    /// </summary>
    public async Task<(string Id, string? Error)> LoadScriptAsync(LiveSession session, string source, string origin, CancellationToken ct)
    {
        Live(session);
        var id = session.NextScriptId();
        var reply = await session.Worker.RequestAsync("load_script", new JsonObject { ["id"] = id, ["source"] = source }, RequestTimeout, ct).ConfigureAwait(false);
        lock (session.Scripts) session.Scripts[id] = origin;
        // The worker settles the script's top-level run before it replies, so the reply names its exception.
        if (reply.ValueKind == JsonValueKind.Object && reply.TryGetProperty("error", out var thrown))
            return (id, thrown.ValueKind == JsonValueKind.String ? "error: " + thrown.GetString() : null);
        // A worker without that field posts a top-level exception only as an event.
        var prefix = id + ": error: ";
        // checked once more after the wait ends: a delay overrunning it on a busy machine skips no event
        for (var waited = Stopwatch.StartNew(); ; await Task.Delay(25, ct).ConfigureAwait(false))
        {
            if (session.Page(0, "script", null, 10, id).Events.FirstOrDefault(e => e.Text.StartsWith(prefix, StringComparison.Ordinal)) is { } failed)
                return (id, failed.Text[(id.Length + 2)..]);
            if (waited.Elapsed >= ScriptErrorWait) return (id, null);
        }
    }

    private static readonly TimeSpan ScriptErrorWait = TimeSpan.FromMilliseconds(300);

    public async Task UnloadScriptAsync(LiveSession session, string id, CancellationToken ct)
    {
        Live(session);
        lock (session.Scripts)
            if (!session.Scripts.ContainsKey(id))
                throw new ToolError(ErrorCode.NotFound, $"Session {session.Id} has no script '{id}'.", "live_script action=list shows them");
        await session.Worker.RequestAsync("unload_script", new JsonObject { ["id"] = id }, RequestTimeout, ct).ConfigureAwait(false);
        lock (session.Scripts) session.Scripts.Remove(id);
    }

    /// <summary>Drops a deferred (or failed deferred) stop point or watch; false when <paramref name="id"/> is none.</summary>
    public static bool ClearDeferred(LiveSession session, string id)
    {
        lock (session.Failed)
            if (session.Failed.RemoveAll(d => d.Id == id) > 0) return true;
        lock (session.Deferred) return session.Deferred.RemoveAll(d => d.Id == id) > 0;
    }

    public async Task ClearAsync(LiveSession session, string id, CancellationToken ct)
    {
        lock (session.StopPoints)
            if (!session.StopPoints.ContainsKey(id))
                throw new ToolError(ErrorCode.NotFound, $"Session {session.Id} has no stop point '{id}'.", "live_break action=list shows them");
        await session.Worker.RequestAsync("clear", new JsonObject { ["id"] = id }, RequestTimeout, ct).ConfigureAwait(false);
        lock (session.StopPoints)
        {
            session.StopPoints.Remove(id);
            session.ClearedPoints.Add(id);
        }
    }

    /// <summary>Resumes held threads (one, or all) and starts a program still suspended at its start.</summary>
    public async Task<(IReadOnlyList<long> Resumed, bool Started)> ResumeAsync(LiveSession session, long? thread, CancellationToken ct)
    {
        Live(session);
        var args = new JsonObject();
        if (thread != null) args["thread"] = thread;
        // a resumed thread can stop again before the reply arrives
        var upTo = session.Sequence;
        var r = await session.Worker.RequestAsync("resume", args, RequestTimeout, ct).ConfigureAwait(false);
        var resumed = r.GetProperty("resumed").EnumerateArray().Select(x => x.GetInt64()).ToList();
        session.Release(resumed, upTo);
        var started = r.GetProperty("started").GetBoolean();
        if (!started && thread == null && session.HeldBy != null && session.Suspended) started = await StartHeldChildAsync(session, ct).ConfigureAwait(false);
        if (started) session.Suspended = false;
        return (resumed, started);
    }

    /// <summary>The live address of a module's export as the program's loader resolves it; null when the module has no such export.</summary>
    private async Task<ulong?> ExportAsync(LiveSession session, string module, string name, CancellationToken ct)
    {
        if (session.Closed || session.Ended != null) return null;
        var r = await session.Worker.RequestAsync("export", new JsonObject { ["module"] = module, ["name"] = name }, RequestTimeout, ct).ConfigureAwait(false);
        return r.GetProperty("address").GetString() is { } a ? Convert.ToUInt64(a[2..], 16) : null;
    }

    /// <summary>Bytes at a live address; null when the program cannot be read there.</summary>
    public async Task<byte[]?> ReadAsync(LiveSession session, ulong address, int length, CancellationToken ct)
    {
        Live(session);
        var r = await session.Worker.RequestAsync("read", new JsonObject { ["address"] = $"0x{address:X}", ["length"] = length }, RequestTimeout, ct).ConfigureAwait(false);
        return r.GetProperty("bytes").GetString() is { } hex ? Convert.FromHexString(hex) : null;
    }

    /// <summary>
    /// Variables a started program gets beyond the worker's minimal set: the .NET runtime location an apphost needs, then
    /// the caller's NAME=value entries. The rest of the server's environment (tokens, keys) never reaches the program.
    /// </summary>
    internal static JsonObject ProgramEnvironment(IReadOnlyList<string> entries, System.Collections.IDictionary? server = null)
    {
        var env = new JsonObject();
        foreach (System.Collections.DictionaryEntry e in server ?? Environment.GetEnvironmentVariables())
            if (e.Key is string name && name.StartsWith("DOTNET_ROOT", StringComparison.OrdinalIgnoreCase)) env[name] = e.Value as string;
        foreach (var entry in entries)
        {
            var eq = entry.IndexOf('=');
            if (eq <= 0) throw new ToolError(ErrorCode.InvalidArgument, $"environment entry '{entry}' is not NAME=value.", "environment=[\"NAME=value\"]");
            env[entry[..eq]] = entry[(eq + 1)..];
        }
        return env;
    }

    private static bool SamePath(string a, string b)
    {
        static string Full(string p)
        {
            try { return Path.GetFullPath(p.StartsWith(@"\\?\", StringComparison.Ordinal) ? p[4..] : p); }
            catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException) { return p; }
        }
        return string.Equals(Full(a), Full(b), OperatingSystem.IsWindows() ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal);
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
        if (!session.AddClose(reason)) return;
        session.Deadline?.Dispose();
        session.ExitCheck?.Dispose();
        await CloseChildrenAsync(session).ConfigureAwait(false);
        session.CompileCheck?.Dispose();
        // A gate whose session sits in a started child's program outlives that child's session: an agent that leaves
        // before one that came later stops the later agent's hooks (see live_worker.py drop_child).
        var kept = false;
        if (session.Worker.IsAlive && KeepsHanded(session))
        {
            try
            {
                var r = await session.Worker.RequestAsync("close", new JsonObject { ["end"] = session.Spawned, ["keep_handed"] = true }, TimeSpan.FromSeconds(5), CancellationToken.None).ConfigureAwait(false);
                kept = r.ValueKind == JsonValueKind.Object && r.TryGetProperty("kept", out var k) && k.GetInt32() > 0;
            }
            catch (ToolError) { }
        }
        if (!kept)
        {
            if (session.Worker.IsAlive)
                await session.Worker.ShutdownAsync("close", new JsonObject { ["end"] = session.Spawned }, TimeSpan.FromSeconds(5)).ConfigureAwait(false);
            session.Worker.Dispose();
        }
        await DropHandedAsync(session).ConfigureAwait(false);
        if (session.ProcessHandle is { IsInvalid: false } handle) _ = WatchExitAfterClose(session, handle);
        else session.ProcessHandle?.Dispose();
        session.ReleaseAll();
        EndCoverage(session);
        EndTimeline(session);
        await session.ClrOpen.WaitAsync().ConfigureAwait(false);
        try
        {
            session.Clr?.Dispose();
            session.Clr = null;
        }
        finally { session.ClrOpen.Release(); }
        session.Ended ??= $"{(session.Spawned ? "ended" : "detached")} when the session closed ({reason})";
    }

    public void Dispose()
    {
        foreach (var s in _sessions.Values)
            try { CloseAsync(s, "server exit").Wait(TimeSpan.FromSeconds(6)); }
            catch (AggregateException) { s.Worker.Kill("server exit"); }
        foreach (var s in _sessions.Values.Where(s => s.Worker.IsAlive))
            s.Worker.Kill("server exit");
        StopTimelines();
        StopConsoles();
    }
}
