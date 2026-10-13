using System.Diagnostics;
using System.Text.Json;
using System.Text.Json.Nodes;
using Corvus.Core;

namespace Corvus.Native.Providers;

/// <summary>
/// The time limit of engine requests made on the current async flow, set by a tool call that names one (timeoutSeconds);
/// null: each session's <see cref="NativeOpenOptions.RequestTimeout"/>.
/// </summary>
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

/// <summary>
/// One image open in an engine worker process. Worker start and requests that change the database are serialized by
/// a gate; with <see cref="ConcurrentRequests"/> other requests run in parallel once the worker is up. When the worker
/// dies (crash, timeout, cancellation) the next request starts a new worker on the saved database and re-applies the
/// changes journaled since the last save; more than <see cref="MaxRestarts"/> consecutive failures close the session.
/// Derived sessions implement <see cref="INativeDecompilerSession"/>.
/// </summary>
internal abstract class WorkerSessionBase(NativeOpenOptions options) : IAsyncDisposable, IDisposable
{
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly object _sync = new();
    private readonly List<(string Op, JsonObject Args)> _unsaved = [];
    private WorkerConnection? _worker;
    private int _failures;
    private int _restarts;
    private int _calls;
    private long _generation;
    private (string Op, DateTime Since)? _starting;
    private string? _startStage;
    private volatile bool _closed;

    protected NativeOpenOptions Options { get; } = options;
    /// <summary>The limit of a request on the current flow: the tool call's (<see cref="EngineRequestLimit"/>), else the session's.</summary>
    protected TimeSpan RequestTimeout => EngineRequestLimit.Current ?? Options.RequestTimeout;
    protected CacheEntry? Entry { get; private set; }
    /// <summary>A copy of a database another process holds: edits are neither journaled nor saved, and the copy goes with the session.</summary>
    protected bool ReadOnlySnapshot => Entry?.SnapshotOf != null;

    public abstract string ProviderId { get; }
    /// <summary>Engine name in messages ("IDA").</summary>
    protected abstract string EngineName { get; }
    protected abstract TimeSpan ShutdownGrace { get; }
    protected abstract int MaxRestarts { get; }
    /// <summary>Whether requests that do not change the database may run while others are in flight.</summary>
    protected virtual bool ConcurrentRequests => false;
    /// <summary>Unsaved edits after which the database is saved, so a restart replays a bounded journal.</summary>
    protected virtual int JournalSaveThreshold => int.MaxValue;
    /// <summary>Whether <paramref name="op"/> leaves the database as it is; every other request advances <see cref="Generation"/>.</summary>
    protected virtual bool ReadsOnly(string op) => false;

    /// <summary>
    /// Advances before and after every request that may change the database and on each worker start: engine output
    /// cached under one value is current while it holds.
    /// </summary>
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
            Volatile.Read(ref _restarts), DatabaseLocation, ReusedDatabase, Note)
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
        // read before the engine opens it: an open may touch the database's files
        var saved = reuse && firstOpen && !ReadOnlySnapshot && DatabaseLocation is { } db ? EngineOutputCache.ReadState(db) : null;
        bool fresh = !reuse;
        try
        {
            await StartWorkerAndOpenAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (ToolError e) when (reuse && e.Code is ErrorCode.ProviderUnavailable or ErrorCode.Failed or ErrorCode.MalformedInput)
        {
            fresh = true;
            Rebuilt = $"the saved {EngineName} database could not be opened ({e.Message}); it was analyzed again";
            // A damaged database (killed during save, older engine format) or one stamped with other input is rebuilt from the input copy.
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
                catch (ToolError e) when (e.Code is not (ErrorCode.Timeout or ErrorCode.ProviderUnavailable)) { /* rejected now: skip */ }
            }
            // what was not journaled is gone: the state is unknown
            SetState(UnknownState(), offSetup: true);
            return;
        }
        // a snapshot is not saved and the snapshot's source may have unsaved changes; a time-limited first analysis is not reproducible
        bool complete = this is not INativeDecompilerSession { AnalysisComplete: false };
        var start = ReadOnlySnapshot ? UnknownState()
            : fresh ? (complete ? EngineOutputCache.Key("fresh", Options.OutputIdentity, Sha256) : UnknownState())
            : saved ?? UnknownState();
        SetState(start, offSetup: false);
        OpenState = start;
        if (fresh) Saved();
    }

    /// <summary>Why the saved database was analyzed again on the last open (damaged, truncated, another input), until a tool reports it.</summary>
    internal string? Rebuilt { get; set; }

    // ---- database state (engine output cache) ----

    private string _state = "";
    private int _offSetup;
    private int _writesInFlight;

    /// <summary>
    /// What the database holds: a chain over the requests that changed it since it was created (or loaded from a saved
    /// state); one starting "u" is unknown (not reproducible elsewhere: a worker restart, a snapshot, a partial analysis).
    /// </summary>
    internal string DatabaseState => Volatile.Read(ref _state);

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
        Volatile.Write(ref _state, state);
        Volatile.Write(ref _offSetup, offSetup ? 1 : 0);
    }

    /// <summary>The state after <paramref name="op"/> changed the database.</summary>
    private void Advance(string op, JsonObject args, JsonElement result)
    {
        if (NoContentOps.Contains(op)) return;
        // a patch sync that found the database as wanted changed nothing
        if (op == "sync_patches" && result.ValueKind == JsonValueKind.Object && result.TryGetProperty("patched", out var p) && result.TryGetProperty("reverted", out var r)
            && p.GetInt32() + r.GetInt32() == 0) return;
        lock (_sync)
        {
            var now = Volatile.Read(ref _state);
            Volatile.Write(ref _state, OpaqueOps.Contains(op) || now.StartsWith('u') ? UnknownState() : EngineOutputCache.Key(now, op, args.ToJsonString()));
            if (!SetupOps.Contains(op)) Volatile.Write(ref _offSetup, 1);
        }
    }

    /// <summary>
    /// Records the state with the database as saved now, for the next open in any process; <paramref name="own"/> counts
    /// the saving request among the changes in flight. With another change in flight the saved state is unknown.
    /// </summary>
    private void Saved(int own = 0)
    {
        if (ReadOnlySnapshot || Options.OutputCache == null || DatabaseLocation is not { } db) return;
        var state = DatabaseState;
        if (!state.StartsWith('u') && Volatile.Read(ref _writesInFlight) == own) EngineOutputCache.WriteState(db, state);
        else EngineOutputCache.ClearState(db);
    }

    /// <summary>
    /// The engine answer <paramref name="what"/> (decompile, frame) of <paramref name="key"/> stored in this database state, in
    /// any process; false in an unknown state, while a change is in flight, or when none is stored.
    /// </summary>
    internal bool TryCached<T>(string what, string key, out T value, out string state)
    {
        value = default!;
        state = DatabaseState;
        if (Options.OutputCache is not { } cache || state.StartsWith('u') || Volatile.Read(ref _writesInFlight) != 0) return false;
        if (cache.Get(EngineOutputCache.OutputKey(Options.OutputIdentity, ProviderId, Sha256, state, what, key)) is not { } hit) return false;
        try { value = JsonSerializer.Deserialize<T>(hit, EngineOutputCache.Json)!; }
        catch (JsonException) { return false; }
        EngineUse.Note(ProviderId);
        EngineUse.Cached();
        return value != null;
    }

    /// <summary>Stores an answer made in <paramref name="state"/> when the database is still in it and no change is in flight.</summary>
    internal void StoreCached<T>(string what, string key, string state, T value)
    {
        if (Options.OutputCache is not { } cache || state.StartsWith('u') || DatabaseState != state || Volatile.Read(ref _writesInFlight) != 0) return;
        cache.Put(EngineOutputCache.OutputKey(Options.OutputIdentity, ProviderId, Sha256, state, what, key), JsonSerializer.Serialize(value, EngineOutputCache.Json));
    }

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

    /// <summary>An engine answer from the output cache, else from <paramref name="ask"/> and stored.</summary>
    internal async Task<T> CachedAsync<T>(string what, string key, Func<Task<T>> ask)
    {
        if (TryCached<T>(what, key, out var hit, out var state)) return hit;
        bool quiet = Volatile.Read(ref _writesInFlight) == 0;
        var value = await ask().ConfigureAwait(false);
        if (quiet) StoreCached(what, key, state, value);
        return value;
    }

    private async Task StartWorkerAndOpenAsync(CancellationToken cancellationToken)
    {
        try
        {
            await StartWorkerAndOpenCoreAsync(cancellationToken).ConfigureAwait(false);
        }
        catch
        {
            KillWorker("open failed");
            throw;
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

    /// <summary>Runs one request, restarting the worker first when it is gone.</summary>
    internal async Task<JsonElement> CallAsync(string op, JsonObject args, CancellationToken cancellationToken, bool journal = false, bool saves = false,
        TimeSpan? timeout = null)
    {
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
                    // a change that failed part way leaves the database in a state nobody can name
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
        if (!await _gate.WaitAsync(ShutdownGrace, cancellationToken).ConfigureAwait(false))
            KillWorker("close while busy"); // the running request fails; its release is still awaited below
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
        }
        if (w != null)
        {
            // only a close that rewrote the database saved what the state names (a killed worker saves nothing)
            var before = save && DatabaseLocation is { } db ? EngineOutputCache.Identity(db) : null;
            try
            {
                await w.ShutdownAsync("close", CloseArgs(save && !ReadOnlySnapshot), ShutdownGrace).ConfigureAwait(false);
                if (save && DatabaseLocation is { } saved && EngineOutputCache.Identity(saved) != before) Saved();
            }
            finally { w.Dispose(); }
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
            if (!close.Wait(ShutdownGrace * 2 + TimeSpan.FromSeconds(5)))
                KillWorker("dispose timeout");
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
