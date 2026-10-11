using System.Diagnostics;
using System.Text.Json;
using System.Text.Json.Nodes;
using NetDecompilerMcp.Core;

namespace NetDecompilerMcp.Native.Providers;

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
            Volatile.Read(ref _restarts), DatabaseLocation, ReusedDatabase, Note);
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
        if (!firstOpen) Interlocked.Increment(ref _restarts);
        try { await StartCoreAsync(firstOpen, cancellationToken).ConfigureAwait(false); }
        finally { _starting = null; }
    }

    private async Task StartCoreAsync(bool firstOpen, CancellationToken cancellationToken)
    {
        DiscardLeftovers();
        var reuse = DatabaseExists;
        try
        {
            await StartWorkerAndOpenAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (ToolError e) when (reuse && e.Code is ErrorCode.ProviderUnavailable or ErrorCode.Failed or ErrorCode.MalformedInput)
        {
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
        }
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

    /// <summary>Runs one request, restarting the worker first when it is gone.</summary>
    internal async Task<JsonElement> CallAsync(string op, JsonObject args, CancellationToken cancellationToken, bool journal = false, bool saves = false,
        TimeSpan? timeout = null)
    {
        Interlocked.Increment(ref _calls);
        try { await _gate.WaitAsync(cancellationToken).ConfigureAwait(false); }
        catch
        {
            Interlocked.Decrement(ref _calls);
            throw;
        }
        var held = true;
        if (ReadOnlySnapshot) journal = false;
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
                var result = await worker.RequestAsync(op, (JsonObject)args.DeepClone(), timeout ?? RequestTimeout, cancellationToken).ConfigureAwait(false);
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
        }
        finally
        {
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
            try { await w.ShutdownAsync("close", CloseArgs(save && !ReadOnlySnapshot), ShutdownGrace).ConfigureAwait(false); }
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
