using System.Diagnostics;
using System.Text.Json;
using System.Text.Json.Nodes;
using Corvus.Core;

namespace Corvus.Native.Providers;

/// <summary>A tool call's engine request limit on the current async flow; null uses the session's <see cref="NativeOpenOptions.RequestTimeout"/>.</summary>
public static class EngineRequestLimit
{
    private static readonly AsyncLocal<TimeSpan?> CurrentLimit = new();

    public static TimeSpan? Current => CurrentLimit.Value;

    /// <summary>Applies <paramref name="limit"/> (null: no change) until the result is disposed.</summary>
    public static IDisposable Use(TimeSpan? limit)
    {
        var previous = CurrentLimit.Value;
        if (limit is { } l) CurrentLimit.Value = l;
        return new Restore(previous);
    }

    private sealed class Restore(TimeSpan? previous) : IDisposable
    {
        public void Dispose() => CurrentLimit.Value = previous;
    }
}

/// <summary>The engine a tool call used, for its log line: the call begins a record, engine requests on its flow fill it.</summary>
public static class EngineUse
{
    public sealed class Record
    {
        public string? Engine { get; internal set; }
        /// <summary>Engine answers the output cache served instead of the engine.</summary>
        public int Cached => _cached;
        internal int _cached;
    }

    private static readonly AsyncLocal<Record?> Current = new();

    /// <summary>A record for the current flow (the caller's own flow is restored when its async method returns).</summary>
    public static Record Begin() => Current.Value = new Record();

    public static void Note(string engine)
    {
        if (Current.Value is { } r) r.Engine = engine;
    }

    public static void Cached()
    {
        if (Current.Value is { } r) Interlocked.Increment(ref r._cached);
    }
}

/// <summary>One image in an engine worker: writes serialized, a dead worker restarted with the journal replayed, closed past <see cref="MaxRestarts"/> failures.</summary>
/// <remarks>With <see cref="ConcurrentRequests"/> other requests run in parallel once the worker is up. A restart opens
/// the saved database and replays the changes journaled since the last save; the limit counts consecutive failures.</remarks>
internal abstract class WorkerSessionBase(NativeOpenOptions options) : IAsyncDisposable, IDisposable
{
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly object _sync = new();
    private readonly List<(string Op, JsonObject Args)> _unsaved = [];
    private WorkerConnection? _worker;
    /// <summary>The worker a close is shutting down, until the close disposes it.</summary>
    private WorkerConnection? _closing;
    private int _failures;
    private int _restarts;
    private int _calls;
    private long _generation;
    private (string Op, DateTime Since)? _starting;
    private string? _startStage;
    private volatile bool _closed;

    protected NativeOpenOptions Options { get; } = options;

    /// <summary>The import overrides the database was made with, for provenance.</summary>
    internal EngineOverrides? Overrides => Options.Overrides;
    /// <summary>The limit of a request on the current flow: the tool call's (<see cref="EngineRequestLimit"/>), else the session's.</summary>
    protected TimeSpan RequestTimeout => EngineRequestLimit.Current ?? Options.RequestTimeout;
    protected CacheEntry? Entry { get; private set; }
    /// <summary>A copy of a database another process holds: edits are neither journaled nor saved, and the copy goes with the session.</summary>
    protected bool ReadOnlySnapshot => Entry?.SnapshotOf != null;

    public abstract string ProviderId { get; }
    /// <summary>Engine name in messages ("IDA").</summary>
    protected abstract string EngineName { get; }
    protected abstract TimeSpan ShutdownGrace { get; }
    /// <summary>How long <see cref="Dispose"/> lets the close run before it ends the worker.</summary>
    protected virtual TimeSpan DisposeLimit => ShutdownGrace * 2 + TimeSpan.FromSeconds(5);
    protected abstract int MaxRestarts { get; }
    /// <summary>Whether requests that do not change the database may run while others are in flight.</summary>
    protected virtual bool ConcurrentRequests => false;
    /// <summary>Unsaved edits after which the database is saved, so a restart replays a bounded journal.</summary>
    protected virtual int JournalSaveThreshold => int.MaxValue;
    /// <summary>Whether <paramref name="op"/> leaves the database as it is; every other request advances <see cref="Generation"/>.</summary>
    protected virtual bool ReadsOnly(string op) => false;

    /// <summary>Advances around every database change and on each worker start; output cached under one value is current while it holds.</summary>
    internal long Generation => Interlocked.Read(ref _generation);

    public string ImagePath { get; private set; } = "";
    public string Sha256 => Entry?.Sha256 ?? "";
    public NativeArch Arch { get; protected set; }
    public ulong ImageBase { get; protected set; }
    public bool ReusedDatabase { get; protected set; }
    public TimeSpan OpenTime { get; private set; }
    public bool DecompilerAvailable { get; protected set; }
    public bool IsOpen => !_closed;
    /// <summary>Process id of the current worker, or null when none is running.</summary>
    internal int? WorkerProcessId => _worker is { IsAlive: true } w ? w.ProcessId : null;
    internal WorkerConnection? Worker => _worker;
    /// <summary>Requests a restart would replay (journaled since the last save).</summary>
    internal int UnsavedCount
    {
        get { lock (_sync) return _unsaved.Count; }
    }

    /// <summary>What sets the database apart (no auto-analysis, read-only snapshot), or null.</summary>
    protected virtual string? Note => null;

    /// <summary>The database (file or project directory) the session works on, once chosen.</summary>
    protected virtual string? DatabaseLocation => null;

    /// <summary>Records on disk whether the saved database holds a complete analysis, for processes that have not opened it.</summary>
    protected void RecordAnalysis(bool complete)
    {
        if (!ReadOnlySnapshot && Options.Analysis != EngineAnalysis.None && DatabaseLocation is { } db) PartialAnalysis.Record(db, complete);
    }

    /// <summary>What the session does now, from its own bookkeeping (never a worker request, so it answers while the worker is busy).</summary>
    public EngineSessionState State()
    {
        var w = _worker;
        var running = w?.Running ?? [];
        var starting = _starting;
        string state;
        string? op = null, stage = null;
        double seconds = 0;
        if (!IsOpen) state = "closed";
        else if (starting is { } s)
        {
            (state, op, stage, seconds) = ("opening", s.Op, _startStage, (DateTime.UtcNow - s.Since).TotalSeconds);
        }
        else if (running.Count > 0)
        {
            var first = running[0];
            (state, op, stage, seconds) = ("busy", first.Op, first.Stage, (DateTime.UtcNow - first.StartedUtc).TotalSeconds);
        }
        else state = "idle";
        int queued = Math.Max(0, Volatile.Read(ref _calls) - running.Count - (starting != null ? 1 : 0));
        return new EngineSessionState(ProviderId, ImagePath, WorkerProcessId, state, op, Math.Round(seconds, 1), stage, queued, UnsavedCount,
            Volatile.Read(ref _restarts), DatabaseLocation, ReusedDatabase,
            !BackgroundRunning && BackgroundResult is { } done ? (Note is { } n ? n + "; " : "") + "background " + done : Note)
        {
            Analysis = state == "opening" && OpenTime == TimeSpan.Zero ? "running" : this is INativeDecompilerSession { AnalysisComplete: false } ? "partial" : "complete",
        };
    }

    /// <summary>Notes the worker's progress stage while the session starts (open, load, analysis).</summary>
    protected void StartStage(string stage) => _startStage = stage;

    /// <summary>Locks the cache entry for the image (runs on the thread pool).</summary>
    protected abstract CacheEntry AcquireEntry(string imagePath, string? sha256);
    /// <summary>Checks the input and picks the database path once the entry is held.</summary>
    protected abstract void PrepareOpen();
    /// <summary>Whether a saved database exists for the image.</summary>
    protected abstract bool DatabaseExists { get; }
    /// <summary>Removes what a killed worker left beside the saved database.</summary>
    protected virtual void DiscardLeftovers() { }
    protected abstract void DeleteDatabase();
    /// <summary>Starts a worker, sets <see cref="Worker"/> through <see cref="SetWorker"/> and opens the database.</summary>
    protected abstract Task StartWorkerAndOpenCoreAsync(CancellationToken cancellationToken);
    /// <summary>Arguments of the close request.</summary>
    protected abstract JsonObject CloseArgs(bool save);
    /// <summary>Called once when the session closes for good.</summary>
    protected abstract void Forget();

    public async Task OpenAsync(string imagePath, string? sha256, CancellationToken cancellationToken)
    {
        var clock = Stopwatch.StartNew();
        EngineUse.Note(ProviderId);
        ImagePath = imagePath;
        Entry = await Task.Run(() => AcquireEntry(imagePath, sha256), cancellationToken).ConfigureAwait(false);
        PrepareOpen();
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            await StartAsync(firstOpen: true, cancellationToken).ConfigureAwait(false);
        }
        finally { _gate.Release(); }
        OpenTime = clock.Elapsed;
    }

    protected void SetWorker(WorkerConnection worker)
    {
        lock (_sync) _worker = worker;
    }

    /// <summary>Starts a worker and opens the database (reused when saved), falling back to a fresh analysis once when the saved database fails.</summary>
    private async Task StartAsync(bool firstOpen, CancellationToken cancellationToken)
    {
        _starting = (firstOpen ? "open" : "restart", DateTime.UtcNow);
        _startStage = null;
        Interlocked.Increment(ref _generation);
        if (!firstOpen) Interlocked.Increment(ref _restarts);
        try { await StartCoreAsync(firstOpen, cancellationToken).ConfigureAwait(false); }
        finally { _starting = null; }
    }

    private async Task StartCoreAsync(bool firstOpen, CancellationToken cancellationToken)
    {
        DiscardLeftovers();
        var reuse = DatabaseExists;
        // Read before the engine opens it, as an open may touch the database's files.
        var saved = reuse && firstOpen && !ReadOnlySnapshot && DatabaseLocation is { } db ? EngineOutputCache.ReadChains(db) : null;
        bool fresh = !reuse;
        try
        {
            await StartWorkerAndOpenAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (ToolError e) when (reuse && e.Code is ErrorCode.ProviderUnavailable or ErrorCode.Failed or ErrorCode.MalformedInput)
        {
            fresh = true;
            Rebuilt = $"the saved {EngineName} database could not be opened ({e.Message}); it was analyzed again";
            // A damaged or mismatched database is rebuilt from the input copy.
            KillWorker("reopen");
            DeleteDatabase();
            if (!firstOpen) lock (_sync) _unsaved.Clear();
            await StartWorkerAndOpenAsync(cancellationToken).ConfigureAwait(false);
        }
        if (!firstOpen)
        {
            List<(string Op, JsonObject Args)> replay;
            lock (_sync) replay = [.. _unsaved];
            foreach (var (op, args) in replay)
            {
                try { await _worker!.RequestAsync(op, (JsonObject)args.DeepClone(), Options.RequestTimeout, cancellationToken).ConfigureAwait(false); }
                // A replayed edit the engine now rejects is skipped.
                catch (ToolError e) when (e.Code is not (ErrorCode.Timeout or ErrorCode.ProviderUnavailable)) { }
            }
            // Unjournaled changes are lost, so the state is unknown.
            SetState(UnknownState(), offSetup: true);
            return;
        }
        // Snapshots and time-limited first analyses are not reproducible, so their state is unknown.
        bool complete = this is not INativeDecompilerSession { AnalysisComplete: false };
        var start = ReadOnlySnapshot ? UnknownState()
            : fresh ? (complete ? EngineOutputCache.Key("fresh", Options.OutputIdentity, Sha256) : UnknownState())
            : saved?.Global ?? UnknownState();
        SetState(start, offSetup: false);
        if (!fresh && !ReadOnlySnapshot && saved is { } chains)
            lock (_sync) _functions = chains.Functions;
        OpenState = DatabaseState;
        if (fresh) Saved();
    }

    /// <summary>Why the saved database was analyzed again on the last open (damaged, truncated, another input), until a tool reports it.</summary>
    internal string? Rebuilt { get; set; }

    private string _state = "";
    private int _offSetup;
    private int _writesInFlight;

    /// <summary>Chains of the changes confined to one function's output (function start → chain), on top of the global chain.</summary>
    private Dictionary<uint, string> _functions = [];
    private int _functionChanges;

    /// <summary>The database state: a chain over its changes combined with per-function chains; a "u" prefix means unknown.</summary>
    internal string DatabaseState
    {
        get
        {
            lock (_sync)
            {
                var global = Volatile.Read(ref _state);
                return _functions.Count == 0 || global.StartsWith('u') ? global
                    : EngineOutputCache.Key(global, string.Join(",", _functions.OrderBy(f => f.Key).Select(f => $"{f.Key:X}={f.Value}")));
            }
        }
    }

    /// <summary>The state the session opened at.</summary>
    internal string OpenState { get; private set; } = "";

    /// <summary>Whether only setup requests (names, types, PDB, marks and patches pushed by the server) changed the database since it opened.</summary>
    internal bool OnlySetupSinceOpen => Volatile.Read(ref _offSetup) == 0;

    /// <summary>Requests the server sends to bring a database up to date with its own state; they follow from the server's inputs.</summary>
    private static readonly HashSet<string> SetupOps = ["apply_names", "apply_types", "apply_user_types", "load_pdb", "set_marks", "sync_patches", "set_thumb", "pseudo_comments", "rebase"];

    /// <summary>Requests whose effect does not follow from their arguments alone.</summary>
    private static readonly HashSet<string> OpaqueOps = ["python", "script"];

    /// <summary>Requests that change no database content, though a worker may not list them as reads.</summary>
    private static readonly HashSet<string> NoContentOps = ["save", "save_as", "export_gzf", "export_types", "close", "sleep", "hello"];

    private static string UnknownState() => "u" + Guid.NewGuid().ToString("N");

    private void SetState(string state, bool offSetup)
    {
        lock (_sync)
        {
            Volatile.Write(ref _state, state);
            _functions = [];
            _functionChanges++;
        }
        Volatile.Write(ref _offSetup, offSetup ? 1 : 0);
    }

    /// <summary>Functions a local or stack rename alone affects (empty for a stamp only); null for any other change.</summary>
    internal static HashSet<uint>? FunctionScope(string op, JsonObject args, JsonElement result)
    {
        if (op != "apply_user_types" || result.ValueKind != JsonValueKind.Object || !result.TryGetProperty("items", out var items)) return null;
        if (result.TryGetProperty("signatures", out var signatures) && signatures.GetInt32() > 0) return null;
        foreach (var (key, value) in args)
        {
            bool confined = key switch
            {
                "stamp_key" or "stamp" or "save" => true,
                // A retype or a storage can change the prototype callers see.
                "locals" => value is JsonArray rows && rows.All(r => r is JsonArray { Count: 5 } row && row[4] == null),
                "stack" => value is JsonArray rows && rows.All(r => r is JsonArray { Count: 4 } row && row[3] == null),
                _ => value is JsonArray { Count: 0 },
            };
            if (!confined) return null;
        }
        return items.EnumerateArray().Select(i => i[1].GetUInt32()).ToHashSet();
    }

    /// <summary>A function's chain; empty when no change was confined to it.</summary>
    private string FunctionChain(uint start)
    {
        lock (_sync) return _functions.GetValueOrDefault(start, "");
    }

    /// <summary>The state after <paramref name="op"/> changed the database.</summary>
    private void Advance(string op, JsonObject args, JsonElement result)
    {
        if (NoContentOps.Contains(op)) return;
        // A patch sync that found the database as wanted changed nothing.
        if (op == "sync_patches" && result.ValueKind == JsonValueKind.Object && result.TryGetProperty("patched", out var p) && result.TryGetProperty("reverted", out var r)
            && p.GetInt32() + r.GetInt32() == 0) return;
        var scope = FunctionScope(op, args, result);
        lock (_sync)
        {
            var now = Volatile.Read(ref _state);
            if (scope != null && !now.StartsWith('u'))
            {
                var change = args.ToJsonString();
                foreach (var f in scope) _functions[f] = EngineOutputCache.Key(_functions.GetValueOrDefault(f, ""), op, change);
                if (scope.Count > 0) _functionChanges++;
            }
            else Volatile.Write(ref _state, OpaqueOps.Contains(op) || now.StartsWith('u') ? UnknownState() : EngineOutputCache.Key(now, op, args.ToJsonString()));
            if (!SetupOps.Contains(op)) Volatile.Write(ref _offSetup, 1);
        }
    }

    /// <summary>Records the saved database's state for later opens; unknown when a change other than <paramref name="own"/> is in flight.</summary>
    private void Saved(int own = 0)
    {
        if (ReadOnlySnapshot || Options.OutputCache == null || DatabaseLocation is not { } db) return;
        var state = DatabaseState;
        Dictionary<uint, string> functions;
        string global;
        lock (_sync) (global, functions) = (Volatile.Read(ref _state), new(_functions));
        if (!state.StartsWith('u') && Volatile.Read(ref _writesInFlight) == own) EngineOutputCache.WriteState(db, state, global, functions);
        else EngineOutputCache.ClearState(db);
    }

    /// <summary>A cached answer for this database state; false when the state is unknown, a change is in flight, or none is stored.</summary>
    internal bool TryCached<T>(string what, string key, out T value, out string state)
    {
        value = default!;
        string global;
        lock (_sync) (global, state) = (Volatile.Read(ref _state), $"{Volatile.Read(ref _state)}#{_functionChanges}");
        if (Options.OutputCache is not { } cache || global.StartsWith('u') || Volatile.Read(ref _writesInFlight) != 0) return false;
        if (cache.Get(EngineOutputCache.OutputKey(Options.OutputIdentity, ProviderId, Sha256, global, what, key)) is not { } hit) return false;
        try
        {
            // The entry holds its function's chain, so a later change to that function makes it stale.
            if (JsonNode.Parse(hit) is not JsonObject entry || entry["value"] is not { } stored) return false;
            value = stored.Deserialize<T>(EngineOutputCache.Json)!;
            if (value == null || (string?)entry["function"] != FunctionChain(StartOf(value) ?? uint.MaxValue)) return false;
        }
        catch (Exception e) when (e is JsonException or InvalidOperationException or FormatException) { return false; }
        EngineUse.Note(ProviderId);
        EngineUse.Cached();
        return value != null;
    }

    /// <summary>Stores an answer made in <paramref name="state"/> when the database is still in it and no change is in flight.</summary>
    internal void StoreCached<T>(string what, string key, string state, T value)
    {
        string global, now, chain;
        lock (_sync) (global, now) = (Volatile.Read(ref _state), $"{Volatile.Read(ref _state)}#{_functionChanges}");
        if (Options.OutputCache is not { } cache || global.StartsWith('u') || now != state || Volatile.Read(ref _writesInFlight) != 0 || StartOf(value) is not { } start) return;
        chain = FunctionChain(start);
        var entry = new JsonObject { ["function"] = chain, ["value"] = JsonSerializer.SerializeToNode(value, EngineOutputCache.Json) };
        cache.Put(EngineOutputCache.OutputKey(Options.OutputIdentity, ProviderId, Sha256, global, what, key), entry.ToJsonString());
    }

    /// <summary>The function a stored answer is of.</summary>
    private static uint? StartOf(object? value) => value switch
    {
        DecompiledFunction d => d.StartRva,
        NativeFrame f => f.StartRva,
        _ => null,
    };

    /// <summary>Several functions' pseudocode: those stored come from the output cache, the rest from one request to <paramref name="ask"/> (and are stored).</summary>
    internal async Task<IReadOnlyList<DecompileOutcome>> CachedManyAsync(IReadOnlyList<uint> rvas, Func<IReadOnlyList<uint>, Task<IReadOnlyList<DecompileOutcome>>> ask)
    {
        var results = new DecompileOutcome?[rvas.Count];
        var missing = new List<int>();
        string state = DatabaseState;
        for (int i = 0; i < rvas.Count; i++)
            if (TryCached<DecompiledFunction>(OutputCacheKinds.Decompile, OutputCacheKinds.At(rvas[i]), out var f, out state)) results[i] = new DecompileOutcome(rvas[i], DecompileStatus.Ok, f, null, null);
            else missing.Add(i);
        if (missing.Count > 0)
        {
            bool quiet = Volatile.Read(ref _writesInFlight) == 0;
            var asked = await ask([.. missing.Select(i => rvas[i])]).ConfigureAwait(false);
            for (int k = 0; k < missing.Count; k++)
            {
                int i = missing[k];
                var o = k < asked.Count ? asked[k] : new DecompileOutcome(rvas[i], DecompileStatus.Skipped, null, null, null);
                results[i] = o;
                if (quiet && o is { Status: DecompileStatus.Ok, Function: { } done }) StoreCached(OutputCacheKinds.Decompile, OutputCacheKinds.At(rvas[i]), state, done);
            }
        }
        return results.Select(r => r!).ToList();
    }

    /// <summary>Several frames: with locals, those stored come from the output cache; the rest from one "frames" request (and are stored).</summary>
    internal async Task<IReadOnlyList<NativeFrameOutcome>> FramesAsync(IReadOnlyList<uint> rvas, bool locals, CancellationToken cancellationToken)
    {
        var results = new NativeFrameOutcome?[rvas.Count];
        var missing = new List<int>();
        string state = "";
        for (int i = 0; i < rvas.Count; i++)
            if (locals && TryCached<NativeFrame>(OutputCacheKinds.Frame, OutputCacheKinds.At(rvas[i]), out var cached, out state)) results[i] = new(rvas[i], cached, null);
            else missing.Add(i);
        if (missing.Count > 0)
        {
            bool quiet = Volatile.Read(ref _writesInFlight) == 0;
            var r = await CallAsync("frames", WorkerRows.Args(("rvas", new JsonArray([.. missing.Select(i => (JsonNode)rvas[i])])), ("locals", locals)),
                cancellationToken).ConfigureAwait(false);
            var rows = r.GetProperty("frames").EnumerateArray().ToList();
            for (int k = 0; k < missing.Count; k++)
            {
                int i = missing[k];
                if (k >= rows.Count) results[i] = new(rvas[i], null, "the engine gave no answer");
                else if (rows[k].TryGetProperty("error", out var error)) results[i] = new(rvas[i], null, error.GetString());
                else
                {
                    var frame = WorkerRows.Frame(rows[k]);
                    results[i] = new(rvas[i], frame, null);
                    if (locals && quiet && state.Length > 0) StoreCached(OutputCacheKinds.Frame, OutputCacheKinds.At(rvas[i]), state, frame);
                }
            }
        }
        return [.. results.Select(r => r!)];
    }

    /// <summary>An engine answer from the output cache, else from <paramref name="ask"/> and stored.</summary>
    internal async Task<T> CachedAsync<T>(string what, string key, Func<Task<T>> ask)
    {
        if (TryCached<T>(what, key, out var hit, out var state)) return hit;
        bool quiet = Volatile.Read(ref _writesInFlight) == 0;
        var value = await ask().ConfigureAwait(false);
        if (quiet) StoreCached(what, key, state, value);
        return value;
    }

    /// <summary>Starts a worker after a transient start failure, at most this many times.</summary>
    internal const int TransientStartRetries = 2;

    /// <summary>Whether a start or open failure is a race with another engine process that a new worker passes.</summary>
    protected virtual bool TransientStartFailure(ToolError error) => false;

    private async Task StartWorkerAndOpenAsync(CancellationToken cancellationToken)
    {
        for (int attempt = 0; ; attempt++)
        {
            try
            {
                await StartWorkerAndOpenCoreAsync(cancellationToken).ConfigureAwait(false);
                return;
            }
            catch (ToolError e) when (attempt < TransientStartRetries && TransientStartFailure(e))
            {
                KillWorker("open failed");
                // Jitter, so workers that raced once do not start in step again.
                await Task.Delay(Random.Shared.Next(200, 1500), cancellationToken).ConfigureAwait(false);
            }
            catch
            {
                KillWorker("open failed");
                throw;
            }
        }
    }

    protected void KillWorker(string reason) => KillWorker(null, reason);

    /// <summary>Stops the current worker, or only <paramref name="expected"/> when given (a concurrent request may have replaced it).</summary>
    private void KillWorker(WorkerConnection? expected, string reason)
    {
        WorkerConnection? w;
        lock (_sync)
        {
            w = _worker;
            if (w == null || (expected != null && w != expected)) return;
            _worker = null;
        }
        w.Kill(reason);
        w.Dispose();
    }

    /// <summary>An engine error with what the session knows added (a partial analysis); the error itself when there is nothing to add.</summary>
    protected virtual ToolError Explain(ToolError error) => error;

    /// <summary>A job that runs with no caller waiting (reanalyze_native wait=false): its start and budget.</summary>
    internal sealed record BackgroundJob(string What, DateTime Started, TimeSpan Budget, Task Task);

    /// <summary>The running or last background job; <see cref="BackgroundResult"/> is its outcome once it ended.</summary>
    internal BackgroundJob? Background { get; private set; }

    internal string? BackgroundResult { get; private set; }

    // The background job's own requests pass; other callers get conflict until it ends.
    private static readonly AsyncLocal<bool> InBackground = new();

    internal bool BackgroundRunning => Background is { Task.IsCompleted: false };

    /// <summary>Starts <paramref name="run"/> with no caller; conflict when one is already running.</summary>
    internal BackgroundJob StartBackground(string what, TimeSpan budget, Func<Task<string>> run)
    {
        lock (_backgroundLock)
        {
            if (BackgroundRunning) throw Busy();
            BackgroundResult = null;
            var started = DateTime.UtcNow;
            var task = Task.Run(async () =>
            {
                InBackground.Value = true;
                try { BackgroundResult = $"{what} ended in {(DateTime.UtcNow - started).TotalSeconds:0} s: {await run().ConfigureAwait(false)}"; }
                catch (Exception e) { BackgroundResult = $"{what} failed after {(DateTime.UtcNow - started).TotalSeconds:0} s: {e.Message}"; }
            });
            return Background = new BackgroundJob(what, started, budget, task);
        }
    }

    private readonly object _backgroundLock = new();

    /// <summary>The error for a call made while a background job holds the engine: conflict, retry when it should have ended.</summary>
    internal ToolError Busy()
    {
        var job = Background!;
        var elapsed = DateTime.UtcNow - job.Started;
        return new ToolError(ErrorCode.Conflict, $"A {job.What} of {Path.GetFileName(ImagePath)} is running in the background ({elapsed.TotalSeconds:0} of {job.Budget.TotalSeconds:0} s).",
            "server_status shows the engine session busy; retry after it ends")
        { RetryAfter = TimeSpan.FromSeconds(Math.Clamp((job.Budget - elapsed).TotalSeconds, 2, 30)), Retryable = true };
    }

    /// <summary>Runs a batch that starts no item after <paramref name="budget"/> seconds, timed out one request limit later, so the item running at the budget gets a full request limit.</summary>
    internal Task<JsonElement> CallBatchAsync(string op, JsonObject args, double budget, CancellationToken cancellationToken) =>
        CallAsync(op, args, cancellationToken, timeout: TimeSpan.FromSeconds(budget) + RequestTimeout);

    /// <summary>Runs one request, restarting the worker first when it is gone.</summary>
    internal async Task<JsonElement> CallAsync(string op, JsonObject args, CancellationToken cancellationToken, bool journal = false, bool saves = false,
        TimeSpan? timeout = null)
    {
        if (!InBackground.Value && BackgroundRunning) throw Busy();
        EngineUse.Note(ProviderId);
        Interlocked.Increment(ref _calls);
        try { await _gate.WaitAsync(cancellationToken).ConfigureAwait(false); }
        catch
        {
            Interlocked.Decrement(ref _calls);
            throw;
        }
        var held = true;
        if (ReadOnlySnapshot) journal = false;
        bool changes = !ReadsOnly(op);
        if (changes)
        {
            Interlocked.Increment(ref _generation);
            Interlocked.Increment(ref _writesInFlight);
        }
        try
        {
            if (_closed) throw new ToolError(ErrorCode.NotLoaded, $"The {EngineName} session for {ImagePath} is closed.", "Open the image again.");
            if (_worker is not { IsAlive: true })
            {
                KillWorker("restart");
                try
                {
                    await StartAsync(firstOpen: false, cancellationToken).ConfigureAwait(false);
                }
                catch (ToolError)
                {
                    Failed();
                    throw;
                }
            }
            var worker = _worker!;
            if (ConcurrentRequests && !journal && !saves)
            {
                _gate.Release();
                held = false;
            }
            try
            {
                JsonElement result;
                try { result = await worker.RequestAsync(op, (JsonObject)args.DeepClone(), timeout ?? RequestTimeout, cancellationToken).ConfigureAwait(false); }
                catch when (changes)
                {
                    // A change that failed part way leaves an unknown state.
                    SetState(UnknownState(), offSetup: true);
                    throw;
                }
                if (changes) Advance(op, args, result);
                if (saves) Saved(changes ? 1 : 0);
                bool saveNow;
                lock (_sync)
                {
                    _failures = 0;
                    if (journal) _unsaved.Add((op, args));
                    if (saves) _unsaved.Clear();
                    saveNow = held && !saves && !ReadOnlySnapshot && _unsaved.Count >= JournalSaveThreshold;
                }
                if (saveNow)
                {
                    await worker.RequestAsync("save", new JsonObject(), Options.RequestTimeout, cancellationToken).ConfigureAwait(false);
                    lock (_sync) _unsaved.Clear();
                    Saved(changes ? 1 : 0);
                }
                return result;
            }
            catch (ToolError e) when (e.Code is ErrorCode.ProviderUnavailable || (e.Code is ErrorCode.Timeout && !worker.IsAlive))
            {
                KillWorker(worker, e.Code == ErrorCode.Timeout ? "timeout" : "failure");
                Failed();
                throw;
            }
            catch (OperationCanceledException) when (!worker.IsAlive)
            {
                KillWorker(worker, "cancelled");
                throw;
            }
            catch (ToolError e) when (Explain(e) is { } explained && explained != e)
            {
                throw explained;
            }
        }
        finally
        {
            if (changes)
            {
                Interlocked.Increment(ref _generation);
                Interlocked.Decrement(ref _writesInFlight);
            }
            Interlocked.Decrement(ref _calls);
            if (held) _gate.Release();
        }
    }

    private void Failed()
    {
        lock (_sync)
            if (++_failures <= MaxRestarts) return;
        _closed = true;
        KillWorker("restart budget exhausted");
        Entry?.Dispose();
        Forget();
    }

    public async Task CloseAsync(bool save = true, CancellationToken cancellationToken = default)
    {
        // The running request fails; its gate release is still awaited below.
        if (!await _gate.WaitAsync(ShutdownGrace, cancellationToken).ConfigureAwait(false))
            KillWorker("close while busy");
        else
        {
            try { await CloseCoreAsync(save).ConfigureAwait(false); }
            finally { _gate.Release(); }
            return;
        }
        await _gate.WaitAsync(CancellationToken.None).ConfigureAwait(false);
        try { await CloseCoreAsync(save).ConfigureAwait(false); }
        finally { _gate.Release(); }
    }

    private async Task CloseCoreAsync(bool save)
    {
        if (_closed && _worker == null) return;
        _closed = true;
        WorkerConnection? w;
        lock (_sync)
        {
            w = _worker;
            _worker = null;
            _closing = w;
        }
        if (w != null)
        {
            // Only a close that rewrote the database saved the named state; a killed worker saves nothing.
            var before = save && DatabaseLocation is { } db ? EngineOutputCache.Identity(db) : null;
            try
            {
                await w.ShutdownAsync("close", CloseArgs(save && !ReadOnlySnapshot), ShutdownGrace).ConfigureAwait(false);
                if (save && DatabaseLocation is { } saved && EngineOutputCache.Identity(saved) != before) Saved();
            }
            finally
            {
                lock (_sync) _closing = null;
                w.Dispose();
            }
        }
        Entry?.Dispose();
        Forget();
    }

    public async ValueTask DisposeAsync() => await CloseAsync(save: true).ConfigureAwait(false);

    public void Dispose()
    {
        try
        {
            var close = Task.Run(() => CloseAsync(save: true));
            if (!close.Wait(DisposeLimit))
            {
                KillWorker("dispose timeout");
                // A late close still holds its worker: end it, then wait for
                // the close to dispose it, so its files are closed on return.
                WorkerConnection? closing;
                lock (_sync) closing = _closing;
                closing?.Kill("dispose timeout");
                close.Wait(ChildProcess.TreeExitWait + TimeSpan.FromSeconds(5));
            }
        }
        catch (AggregateException) { KillWorker("dispose failed"); }
        finally
        {
            _closed = true;
            Entry?.Dispose();
            Forget();
        }
    }

    public Task SaveAsync(CancellationToken cancellationToken = default) =>
        ReadOnlySnapshot ? Task.CompletedTask : CallAsync("save", new JsonObject(), cancellationToken, saves: true);
}
