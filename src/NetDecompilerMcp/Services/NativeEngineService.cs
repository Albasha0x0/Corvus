using System.Runtime.CompilerServices;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Native.Providers;
using NetDecompilerMcp.Native.Providers.Ida;

namespace NetDecompilerMcp.Services;

/// <summary>
/// The external decompiler engines (IDA through idalib today) and one engine session per loaded native image,
/// opened on first use and closed when the image is unloaded or reloaded. The session analyzes the file as loaded;
/// in-memory patches (patch_bytes / patch_asm, undo) are applied to its database before it answers, so a patched
/// image decompiles without a new auto-analysis. When the database cannot take the patch set (bytes outside what the
/// engine loaded), a second session analyzes the patched bytes instead.
/// </summary>
public sealed class NativeEngineService : IDisposable
{
    private readonly Lazy<INativeDecompilerProvider> _ida;
    private readonly NativeCodeService? _code;
    private readonly ConditionalWeakTable<LoadedNative, SessionHolder> _holders = new();

    /// <param name="idaOptions">IDA provider settings (install, Python, cache root); null: the defaults.</param>
    /// <param name="code">Receives the library names an open session recognized (the ida name layer).</param>
    /// <param name="workspace">With <paramref name="options"/>.IdaPrewarm: native images it loads are analyzed in the background.</param>
    public NativeEngineService(IdaProviderOptions? idaOptions = null, NativeCodeService? code = null, AssemblyWorkspace? workspace = null,
        ServerOptions? options = null)
        : this(new Lazy<INativeDecompilerProvider>(() => new IdaProvider(idaOptions)), idaOptions?.CacheRoot, code, workspace, options)
    {
    }

    /// <summary>With another provider (tests); <paramref name="cacheRoot"/> is where its saved analyses are looked for.</summary>
    internal NativeEngineService(INativeDecompilerProvider provider, string? cacheRoot, NativeCodeService? code = null, AssemblyWorkspace? workspace = null,
        ServerOptions? options = null)
        : this(new Lazy<INativeDecompilerProvider>(provider), cacheRoot, code, workspace, options)
    {
    }

    private NativeEngineService(Lazy<INativeDecompilerProvider> provider, string? cacheRoot, NativeCodeService? code, AssemblyWorkspace? workspace,
        ServerOptions? options)
    {
        _ida = provider;
        _cacheRoot = cacheRoot;
        _code = code;
        DefaultMode = options?.Engine ?? EngineMode.Auto;
        _prewarmEnabled = options?.IdaPrewarm == true;
        if (_prewarmEnabled && workspace != null) workspace.NativeLoaded += native => _ = PrewarmCore(native);
    }

    // ---- engine preference of the native code tools (ServerOptions.Engine, per-call engine) ----

    private readonly string? _cacheRoot;
    private string? _savedRoot;

    /// <summary>The engine the native code tools use when a call names none.</summary>
    public EngineMode DefaultMode { get; }

    /// <summary>
    /// The image's engine session when its analysis is complete in this process and reflects the image's current patch
    /// set, else null. Never opens, waits for or asks the engine anything (the auto engine's check).
    /// </summary>
    public INativeDecompilerSession? CompletedSession(LoadedNative native)
    {
        if (native.Released.IsCancellationRequested || !_holders.TryGetValue(native, out var h)) return null;
        if (h.Opening is not { IsCompletedSuccessfully: true } opened || !opened.Result.IsOpen) return null;
        var key = PatchKey(native);
        if (h.SyncedKey != key) return null; // never synced, or patched since: syncing is a request
        if (h.PatchedState == key)
            return h.Patched is { IsCompletedSuccessfully: true } patched && patched.Result.IsOpen ? patched.Result : null;
        return opened.Result;
    }

    /// <summary>
    /// Whether the analysis cache holds a saved IDA database for the image's bytes (one file check; the provider is not
    /// asked). Opening it loads the analysis without running auto-analysis again.
    /// </summary>
    public bool HasSavedAnalysis(LoadedNative native)
    {
        // looked up again at most every few seconds per image (a database appears when an analysis finishes)
        var seen = _saved.GetOrCreateValue(native);
        long now = Environment.TickCount64;
        lock (seen)
        {
            if (seen.CheckedAt != 0 && now - seen.CheckedAt < SavedCheckInterval) return seen.Exists;
            try
            {
                var root = _savedRoot ??= _cacheRoot ?? AnalysisCache.DefaultRoot;
                seen.Exists = File.Exists(Path.Combine(root, IdaProvider.ProviderId, native.OriginalSha256, "ida-default.i64"));
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException) { seen.Exists = false; }
            seen.CheckedAt = now;
            return seen.Exists;
        }
    }

    private sealed class SavedCheck
    {
        public long CheckedAt;
        public bool Exists;
    }

    private readonly ConditionalWeakTable<LoadedNative, SavedCheck> _saved = new();

    /// <summary>Milliseconds a saved-analysis lookup is reused for an image.</summary>
    internal long SavedCheckInterval { get; set; } = 5_000;

    private static List<Native.Patching.NativePatch> OrderedPatches(LoadedNative native) => native.HasPatches ? native.Patches.Patches.OrderBy(p => p.Rva).ToList() : [];

    private static string PatchKey(LoadedNative native) => PatchKey(OrderedPatches(native));

    /// <summary>Identity of a patch set (in RVA order): what the database's patched bytes are compared by.</summary>
    private static string PatchKey(List<Native.Patching.NativePatch> patches) =>
        string.Join(";", patches.Select(p => $"{p.Rva:X}:{Convert.ToHexString(p.Replacement)}"));

    // ---- background analysis on load (ServerOptions.IdaPrewarm) ----

    private readonly bool _prewarmEnabled;
    private readonly SemaphoreSlim _prewarmGate = new(1, 1);
    private readonly object _prewarmLock = new();
    private int _prewarmQueued, _prewarmDone, _prewarmFailed, _prewarmCancelled;
    private (string Id, DateTime Since)? _prewarmRunning;
    private string? _prewarmLastError;

    /// <summary>State of the background analysis: what runs, how many wait, and how the finished ones ended.</summary>
    public sealed record PrewarmStatus(bool Enabled, int Queued, string? Running, double RunningSeconds, int Done, int Failed, int Cancelled, string? LastError);

    public PrewarmStatus Prewarming
    {
        get
        {
            lock (_prewarmLock)
                return new PrewarmStatus(_prewarmEnabled, _prewarmQueued, _prewarmRunning?.Id,
                    _prewarmRunning is { } r ? Math.Round((DateTime.UtcNow - r.Since).TotalSeconds, 1) : 0, _prewarmDone, _prewarmFailed, _prewarmCancelled, _prewarmLastError);
        }
    }

    /// <summary>
    /// Queues the image's IDA analysis: one image at a time, in load order; waiting and running work ends when the
    /// image is unloaded or reloaded. Images IDA is unavailable for are skipped.
    /// </summary>
    public Task Prewarm(LoadedNative native) => PrewarmCore(native);

    private async Task PrewarmCore(LoadedNative native)
    {
        if (!IsAvailable || native.Released.IsCancellationRequested) return;
        lock (_prewarmLock) _prewarmQueued++;
        bool entered = false;
        try
        {
            await _prewarmGate.WaitAsync(native.Released).ConfigureAwait(false);
            entered = true;
            lock (_prewarmLock)
            {
                _prewarmQueued--;
                _prewarmRunning = (native.Id, DateTime.UtcNow);
            }
            await Session(native, null, null, native.Released).ConfigureAwait(false);
            lock (_prewarmLock) _prewarmDone++;
        }
        catch (Exception ex) when (ex is OperationCanceledException || native.Released.IsCancellationRequested)
        {
            lock (_prewarmLock)
            {
                if (!entered) _prewarmQueued--;
                _prewarmCancelled++;
            }
        }
        catch (Exception ex)
        {
            lock (_prewarmLock)
            {
                _prewarmFailed++;
                _prewarmLastError = $"{native.Id}: {(ex is ToolError t ? t.Message : ex.GetType().Name + ": " + ex.Message)}";
            }
        }
        finally
        {
            if (entered)
            {
                lock (_prewarmLock) _prewarmRunning = null;
                _prewarmGate.Release();
            }
        }
    }

    /// <summary>Apply patches into the open database (default); false analyzes every patched state from scratch (for measurements).</summary>
    internal bool PatchInDatabase { get; set; } = true;

    public IReadOnlyList<INativeDecompilerProvider> Providers => [_ida.Value];

    /// <summary>Whether an engine is installed and usable (static checks, cached).</summary>
    public bool IsAvailable => _ida.Value.CheckAvailability().IsAvailable;

    /// <summary>Why no engine is usable and how to fix it, or null when one is.</summary>
    public (string Reason, string? Remediation)? Unavailability =>
        _ida.Value.CheckAvailability() is { IsAvailable: false } a ? (a.Reason ?? "IDA is not available", a.Remediation) : null;

    public INativeDecompilerProvider Provider(string? id)
    {
        var wanted = string.IsNullOrWhiteSpace(id) || id.Trim().Equals("auto", StringComparison.OrdinalIgnoreCase) ? null : id.Trim();
        if (wanted != null && !wanted.Equals("ida", StringComparison.OrdinalIgnoreCase))
            throw new ToolError(ErrorCode.InvalidArgument, $"Unknown engine '{id}'. Engines: ida.", "omit engine to use the available one");
        var ida = _ida.Value;
        var availability = ida.CheckAvailability();
        if (!availability.IsAvailable)
            throw new ToolError(ErrorCode.ProviderUnavailable, $"{ida.DisplayName} is not available: {availability.Reason}", availability.Remediation);
        return ida;
    }

    /// <summary>The image's holder, created on first use and disposed when the image is unloaded or reloaded (not when it is patched).</summary>
    private SessionHolder Holder(LoadedNative native)
    {
        if (native.Released.IsCancellationRequested) throw native.Gone();
        var holder = _holders.GetValue(native, n =>
        {
            var h = new SessionHolder();
            n.Released.Register(h.Dispose);
            return h;
        });
        if (native.Released.IsCancellationRequested)
        {
            holder.Dispose();
            throw native.Gone();
        }
        return holder;
    }

    /// <summary>
    /// The image's engine session reflecting its current bytes; the first call opens it (the first open of an image runs
    /// auto-analysis), later calls bring the database's patched bytes up to date with the image's patch set first.
    /// </summary>
    public async Task<INativeDecompilerSession> Session(LoadedNative native, string? engine, IProgress<NativeProviderProgress>? progress, CancellationToken ct)
    {
        var session = await SessionCore(native, engine, progress, ct).ConfigureAwait(false);
        // the image's PDB types, once per PDB and database (see NativePdbTypes)
        var holder = Holder(native);
        var patched = holder.Patched is { IsCompletedSuccessfully: true } p && ReferenceEquals(p.Result, session);
        await PdbTypes.EnsureAsync(native, session, patched ? holder.PatchedPdb : holder.OpenedPdb, ct).ConfigureAwait(false);
        return session;
    }

    /// <summary>Brings the PDB's types into the engine database (also used by the tools to report the type source).</summary>
    public NativePdbTypes PdbTypes { get; } = new();

    private async Task<INativeDecompilerSession> SessionCore(LoadedNative native, string? engine, IProgress<NativeProviderProgress>? progress, CancellationToken ct)
    {
        var holder = Holder(native);
        var session = await Base(native, holder, engine, progress, ct).ConfigureAwait(false);
        await holder.Sync.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            var patches = OrderedPatches(native);
            var key = PatchKey(patches);
            if (holder.SyncedKey == key) return holder.PatchedState == key && holder.Patched is { } same ? await Wait(native, same, ct).ConfigureAwait(false) : session;
            if (PatchInDatabase || patches.Count == 0)
            {
                // Relocation entry rewrites are not sent: the engine loads the image at its header base and does not read .reloc for code.
                var result = await session.SyncPatchesAsync(patches.Select(p => new NativeByteRange(p.Rva, p.Replacement)).ToList(), ct).ConfigureAwait(false);
                holder.LastSync = result;
                if (result.Complete)
                {
                    holder.SyncedKey = key;
                    return session;
                }
            }
            // The database cannot take this patch set: analyze the patched bytes as their own image.
            holder.SyncedKey = key;
            if (holder.PatchedState != key || holder.Patched == null)
            {
                holder.DisposePatched();
                holder.PatchedState = key;
                holder.PatchedPdb = PdbService.PathForEngines(native);
                holder.Patched = OpenPatched(native, engine, progress, holder.PatchedPdb);
            }
            return await Wait(native, holder.Patched, ct).ConfigureAwait(false);
        }
        catch
        {
            holder.SyncedKey = null; // unknown state: sync again next time
            throw;
        }
        finally { holder.Sync.Release(); }
    }

    /// <summary>The session on the file as loaded, opening it on first use (or after it closed).</summary>
    private Task<INativeDecompilerSession> Base(LoadedNative native, SessionHolder holder, string? engine, IProgress<NativeProviderProgress>? progress, CancellationToken ct)
    {
        lock (holder)
        {
            if (holder.Opening is { } existing && !(existing.IsCompleted && (existing.IsFaulted || existing.IsCanceled || !existing.Result.IsOpen)))
                return Wait(native, existing, ct);
            var provider = Provider(engine);
            holder.SyncedKey = null;
            holder.OpenedPdb = PdbService.PathForEngines(native);
            // The open is not tied to this call's cancellation (a later call reuses the same analysis) but ends when the image is unloaded or reloaded.
            holder.Opening = provider.OpenAsync(native.FilePath, native.OriginalSha256,
                new NativeOpenOptions { Progress = progress, PdbPath = holder.OpenedPdb }, native.Released);
            // Once open, the library functions the engine recognized become the image's ida name layer.
            holder.LibraryNames = holder.Opening.ContinueWith(async opened =>
            {
                if (!opened.IsCompletedSuccessfully) return -1;
                try { return await EngineLibraryNames.ImportAsync(native, opened.Result, _code, native.Released); }
                catch (Exception ex) when (ex is ToolError or OperationCanceledException) { return -1; }
            }, TaskScheduler.Default).Unwrap();
            return Wait(native, holder.Opening, ct);
        }
    }

    /// <summary>Opens a session on the patched bytes (written to a private file; the engine keeps its own copy per hash).</summary>
    private Task<INativeDecompilerSession> OpenPatched(LoadedNative native, string? engine, IProgress<NativeProviderProgress>? progress, string? pdbPath)
    {
        var provider = Provider(engine);
        return Task.Run(async () =>
        {
            var bytes = native.Patches.PatchedBytes();
            var sha = Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(bytes));
            var dir = Path.Combine(Path.GetTempPath(), "NetDecompilerMcp", "patched", sha[..16]);
            Directory.CreateDirectory(dir);
            var path = Path.Combine(dir, Path.GetFileName(native.FilePath));
            await File.WriteAllBytesAsync(path, bytes, native.Released).ConfigureAwait(false);
            try
            {
                return await provider.OpenAsync(path, sha, new NativeOpenOptions { Progress = progress, PdbPath = pdbPath },
                    native.Released).ConfigureAwait(false);
            }
            finally
            {
                try { Directory.Delete(dir, true); }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
            }
        }, native.Released);
    }

    private static async Task<INativeDecompilerSession> Wait(LoadedNative native, Task<INativeDecompilerSession> opening, CancellationToken ct)
    {
        try { return await opening.WaitAsync(ct).ConfigureAwait(false); }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested && native.Released.IsCancellationRequested) { throw native.Gone(); }
    }

    /// <summary>
    /// The import of the open session's library names (the number imported, -1 when it failed), or null when no
    /// session was opened for the image; does not open one.
    /// </summary>
    public Task<int>? LibraryNames(LoadedNative native) => _holders.TryGetValue(native, out var h) ? h.LibraryNames : null;

    /// <summary>The last patch application into the image's database, or null when none ran.</summary>
    public PatchSyncResult? LastPatchSync(LoadedNative native) => _holders.TryGetValue(native, out var h) ? h.LastSync : null;

    /// <summary>Whether the image's current patch set is served by a separate analysis of the patched bytes (the database could not take it).</summary>
    public bool ServesPatchedCopy(LoadedNative native) =>
        _holders.TryGetValue(native, out var h) && h.Patched != null && h.PatchedState == h.SyncedKey;

    public void Dispose()
    {
        if (_ida.IsValueCreated) _ida.Value.Dispose();
    }

    private sealed class SessionHolder : IDisposable
    {
        public Task<INativeDecompilerSession>? Opening;
        public Task<int>? LibraryNames;
        public readonly SemaphoreSlim Sync = new(1, 1);
        /// <summary>The patch set (key) the served analysis reflects; null: unknown, sync on the next call.</summary>
        public string? SyncedKey;
        public PatchSyncResult? LastSync;
        /// <summary>A session on the patched bytes, for a patch set the database could not take, and that set's key.</summary>
        public Task<INativeDecompilerSession>? Patched;
        public string? PatchedState;
        /// <summary>The PDB paths the sessions were opened with (the engine searched there first during analysis).</summary>
        public string? OpenedPdb, PatchedPdb;

        public void DisposePatched()
        {
            Close(Patched);
            Patched = null;
            PatchedState = null;
        }

        private static void Close(Task<INativeDecompilerSession>? opening)
        {
            if (opening is { IsCompletedSuccessfully: true } done) done.Result.Dispose();
            else opening?.ContinueWith(t => { if (t.IsCompletedSuccessfully) t.Result.Dispose(); }, TaskScheduler.Default);
        }

        public void Dispose()
        {
            Close(Opening);
            DisposePatched();
        }
    }
}
