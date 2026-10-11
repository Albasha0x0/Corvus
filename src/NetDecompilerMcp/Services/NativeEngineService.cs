using System.Collections.Concurrent;
using System.Runtime.CompilerServices;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Native.Providers;
using NetDecompilerMcp.Native.Providers.Ghidra;
using NetDecompilerMcp.Native.Providers.Ida;

namespace NetDecompilerMcp.Services;

/// <summary>
/// The external decompiler engines (IDA through idalib, Ghidra through a Java worker) and, per loaded native image, one
/// session per engine, opened on first use and closed when the image is unloaded or reloaded. A session analyzes the
/// file as loaded; in-memory patches (patch_bytes / patch_asm, undo) are applied to its database before it answers, so
/// a patched image decompiles without a new auto-analysis. When the database cannot take the patch set (bytes outside
/// what the engine loaded), a second session of that engine analyzes the patched bytes instead.
/// </summary>
public sealed class NativeEngineService : IDisposable
{
    /// <summary>The engines in order of preference (IDA, then Ghidra).</summary>
    private readonly IReadOnlyList<(string Id, Lazy<INativeDecompilerProvider> Provider)> _providers;
    private readonly NativeCodeService? _code;
    private readonly ConditionalWeakTable<LoadedNative, HolderSet> _holders = new();

    /// <param name="idaOptions">IDA provider settings (install, Python, cache root); null: the defaults.</param>
    /// <param name="code">Receives the library names an open IDA session recognized (the ida name layer).</param>
    /// <param name="workspace">With <paramref name="options"/>.Prewarm: native images it loads are analyzed in the background.</param>
    /// <param name="ghidraOptions">Ghidra provider settings; null: the defaults, under IDA's cache root when one is given.</param>
    public NativeEngineService(IdaProviderOptions? idaOptions = null, NativeCodeService? code = null, AssemblyWorkspace? workspace = null,
        ServerOptions? options = null, GhidraProviderOptions? ghidraOptions = null)
        : this([
                (IdaProvider.ProviderId, new Lazy<INativeDecompilerProvider>(() => new IdaProvider(idaOptions))),
                (GhidraProvider.ProviderId, new Lazy<INativeDecompilerProvider>(() =>
                    new GhidraProvider(ghidraOptions ?? new GhidraProviderOptions { CacheRoot = idaOptions?.CacheRoot }))),
            ], idaOptions?.CacheRoot ?? ghidraOptions?.CacheRoot, code, workspace, options)
    {
    }

    /// <summary>With another provider (tests); <paramref name="cacheRoot"/> is where its saved analyses are looked for.</summary>
    internal NativeEngineService(INativeDecompilerProvider provider, string? cacheRoot, NativeCodeService? code = null, AssemblyWorkspace? workspace = null,
        ServerOptions? options = null)
        : this([provider], cacheRoot, code, workspace, options)
    {
    }

    /// <summary>With other providers, in order of preference (tests).</summary>
    internal NativeEngineService(IReadOnlyList<INativeDecompilerProvider> providers, string? cacheRoot, NativeCodeService? code = null,
        AssemblyWorkspace? workspace = null, ServerOptions? options = null)
        : this(providers.Select(p => (p.Id, new Lazy<INativeDecompilerProvider>(p))).ToList(), cacheRoot, code, workspace, options)
    {
    }

    private NativeEngineService(IReadOnlyList<(string Id, Lazy<INativeDecompilerProvider> Provider)> providers, string? cacheRoot, NativeCodeService? code,
        AssemblyWorkspace? workspace, ServerOptions? options)
    {
        _providers = providers;
        _cacheRoot = cacheRoot;
        _code = code;
        DefaultMode = options?.Engine ?? EngineMode.Auto;
        _prewarm = options?.Prewarm;
        if (_prewarm != null && workspace != null) workspace.NativeLoaded += native => _ = PrewarmCore(native);
    }

    // ---- engines ----

    /// <summary>Provider ids in order of preference.</summary>
    public IReadOnlyList<string> ProviderIds => _providers.Select(p => p.Id).ToList();

    public IReadOnlyList<INativeDecompilerProvider> Providers => _providers.Select(p => p.Provider.Value).ToList();

    private INativeDecompilerProvider? Find(string id) => _providers.FirstOrDefault(p => p.Id.Equals(id, StringComparison.OrdinalIgnoreCase)).Provider?.Value;

    /// <summary>"IDA", "Ghidra", or the id of another engine.</summary>
    public static string DisplayName(string id) => id switch { IdaProvider.ProviderId => "IDA", GhidraProvider.ProviderId => "Ghidra", _ => id };

    /// <summary>Whether any engine is installed and usable (static checks, cached).</summary>
    public bool IsAvailable => _providers.Any(p => p.Provider.Value.CheckAvailability().IsAvailable);

    /// <summary>The first engine installed, in order of preference, or null.</summary>
    public string? FirstAvailable() => _providers.FirstOrDefault(p => p.Provider.Value.CheckAvailability().IsAvailable).Id;

    /// <summary>Why no engine is usable and how to fix it, or null when one is.</summary>
    public (string Reason, string? Remediation)? Unavailability
    {
        get
        {
            if (IsAvailable) return null;
            var missing = _providers.Select(p => p.Provider.Value.CheckAvailability()).ToList();
            if (missing.Count == 1) return (missing[0].Reason ?? $"{DisplayName(missing[0].ProviderId)} is not available", missing[0].Remediation);
            return (string.Join("; ", missing.Select(a => $"{DisplayName(a.ProviderId)}: {a.Reason ?? "not available"}")),
                string.Join("; or ", missing.Where(a => a.Remediation != null).Select(a => a.Remediation)) is { Length: > 0 } r ? r : null);
        }
    }

    /// <summary>Why the engine <paramref name="id"/> is not usable and how to fix it, or null when it is.</summary>
    public (string Reason, string? Remediation)? UnavailabilityOf(string id)
    {
        var provider = Find(id);
        if (provider == null) return ($"no {id} engine in this server", null);
        return provider.CheckAvailability() is { IsAvailable: false } a ? (a.Reason ?? $"{DisplayName(id)} is not available", a.Remediation) : null;
    }

    /// <summary>
    /// The engine <paramref name="id"/> names (InvalidArgument for an unknown one, ProviderUnavailable when it is not
    /// installed); null or auto: the first engine installed.
    /// </summary>
    public INativeDecompilerProvider Provider(string? id)
    {
        var wanted = Named(id);
        if (wanted == null)
        {
            var first = FirstAvailable() ?? throw Unavailable(Unavailability!.Value, "no native decompiler engine is available");
            return Find(first)!;
        }
        var provider = Find(wanted) ?? throw new ToolError(ErrorCode.InvalidArgument, $"Unknown engine '{id}'. Engines: {string.Join(", ", ProviderIds)}.",
            "omit engine to use the available one");
        var availability = provider.CheckAvailability();
        if (!availability.IsAvailable)
            throw new ToolError(ErrorCode.ProviderUnavailable, $"{provider.DisplayName} is not available: {availability.Reason}", availability.Remediation);
        return provider;
    }

    private static ToolError Unavailable((string Reason, string? Remediation) u, string what) =>
        new(ErrorCode.ProviderUnavailable, $"{char.ToUpperInvariant(what[0])}{what[1..]}: {u.Reason}", u.Remediation);

    /// <summary>The engine id a call names, or null for none and auto.</summary>
    private static string? Named(string? engine) =>
        string.IsNullOrWhiteSpace(engine) || engine.Trim().Equals("auto", StringComparison.OrdinalIgnoreCase) ? null : engine.Trim().ToLowerInvariant();

    /// <summary>
    /// The engine a call on the image uses: the one it names; else the server default when that names an engine; else
    /// the engine whose session of the image is open or opening (in order of preference); else the first one installed.
    /// </summary>
    public string Resolve(LoadedNative native, string? engine)
    {
        var wanted = Named(engine) ?? EngineModes.ProviderId(DefaultMode);
        if (wanted != null)
        {
            if (Find(wanted) == null)
                throw new ToolError(ErrorCode.InvalidArgument, $"Unknown engine '{engine?.Trim() ?? wanted}'. Engines: {string.Join(", ", ProviderIds)}.",
                    "omit engine to use the available one");
            return wanted;
        }
        foreach (var (id, _) in _providers)
            if (Existing(native, id)?.Opening is { } opening && !(opening.IsCompleted && (opening.IsFaulted || opening.IsCanceled || !opening.Result.IsOpen)))
                return id;
        return FirstAvailable() ?? Provider(null).Id;
    }

    // ---- engine preference of the native code tools (ServerOptions.Engine, per-call engine) ----

    private readonly string? _cacheRoot;

    /// <summary>The engine the native code tools use when a call names none.</summary>
    public EngineMode DefaultMode { get; }

    /// <summary>
    /// The image's session of engine <paramref name="provider"/> (null: the first engine in order of preference that has
    /// one) when its analysis is complete in this process and reflects the image's current patch set, else null. A
    /// Ghidra analysis that ran out of time is not complete. Never opens, waits for or asks an engine anything (the
    /// auto engine's check).
    /// </summary>
    public INativeDecompilerSession? CompletedSession(LoadedNative native, string? provider = null)
    {
        if (native.Released.IsCancellationRequested || !_holders.TryGetValue(native, out var set)) return null;
        foreach (var (id, _) in _providers)
            if ((provider == null || id == provider) && set.Holders.TryGetValue(id, out var h) && Completed(native, h) is { } session)
                return session;
        return null;
    }

    private static INativeDecompilerSession? Completed(LoadedNative native, SessionHolder h)
    {
        if (h.Opening is not { IsCompletedSuccessfully: true } opened || !opened.Result.IsOpen) return null;
        if (!opened.Result.AnalysisComplete) return null;
        var key = PatchKey(native);
        if (h.SyncedKey != key) return null; // never synced, or patched since: syncing is a request
        if (h.PatchedState == key)
            return h.Patched is { IsCompletedSuccessfully: true } patched && patched.Result.IsOpen ? patched.Result : null;
        return opened.Result;
    }

    /// <summary>
    /// The first engine, in order of preference, whose analysis cache holds a saved database of the image's bytes (file
    /// checks; no provider is asked), or null. Opening it loads the analysis without running auto-analysis again.
    /// </summary>
    public string? SavedAnalysis(LoadedNative native) => _providers.Select(p => p.Id).FirstOrDefault(id => HasSavedAnalysis(native, id));

    /// <summary>Whether the analysis cache holds a saved database of engine <paramref name="id"/> for the image's bytes.</summary>
    public bool HasSavedAnalysis(LoadedNative native, string id)
    {
        // looked up again at most every few seconds per image and engine (a database appears when an analysis finishes)
        var seen = _saved.GetOrCreateValue(native).GetOrAdd(id, _ => new SavedCheck());
        long now = Environment.TickCount64;
        lock (seen)
        {
            if (seen.CheckedAt != 0 && now - seen.CheckedAt < SavedCheckInterval) return seen.Exists;
            try { seen.Exists = SavedDatabaseExists(id, native.OriginalSha256); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException) { seen.Exists = false; }
            seen.CheckedAt = now;
            return seen.Exists;
        }
    }

    private bool SavedDatabaseExists(string id, string sha256)
    {
        var provider = Find(id);
        if (provider is IdaProvider ida) return ida.SavedDatabasePath(sha256) is { } path && File.Exists(path);
        if (provider is GhidraProvider ghidra) return ghidra.HasSavedProject(sha256);
        var dir = Path.Combine(_cacheRoot ?? AnalysisCache.DefaultRoot, id, sha256);
        if (!Directory.Exists(dir)) return false;
        return id == GhidraProvider.ProviderId
            ? Directory.EnumerateDirectories(dir, "p-*").Any(p => File.Exists(Path.Combine(p, GhidraSession.ProjectName + ".gpr")))
            : Directory.EnumerateFiles(dir, "ida-default*.i64").Any();
    }

    private sealed class SavedCheck
    {
        public long CheckedAt;
        public bool Exists;
    }

    private readonly ConditionalWeakTable<LoadedNative, ConcurrentDictionary<string, SavedCheck>> _saved = new();

    /// <summary>Milliseconds a saved-analysis lookup is reused for an image.</summary>
    internal long SavedCheckInterval { get; set; } = 5_000;

    private static List<Native.Patching.NativePatch> OrderedPatches(LoadedNative native) => native.HasPatches ? native.Patches.Patches.OrderBy(p => p.Rva).ToList() : [];

    private static string PatchKey(LoadedNative native) => PatchKey(OrderedPatches(native));

    /// <summary>Identity of a patch set (in RVA order): what the database's patched bytes are compared by.</summary>
    private static string PatchKey(List<Native.Patching.NativePatch> patches) =>
        string.Join(";", patches.Select(p => $"{p.Rva:X}:{Convert.ToHexString(p.Replacement)}"));

    // ---- background analysis on load (ServerOptions.Prewarm) ----

    private readonly EngineMode? _prewarm;
    private readonly SemaphoreSlim _prewarmGate = new(1, 1);
    private readonly object _prewarmLock = new();
    private int _prewarmQueued, _prewarmDone, _prewarmFailed, _prewarmCancelled;
    private (string Id, DateTime Since)? _prewarmRunning;
    private string? _prewarmLastError;

    /// <summary>State of the background analysis: the engine (ida, ghidra or auto), what runs, how many wait, and how the finished ones ended.</summary>
    public sealed record PrewarmStatus(bool Enabled, string? Engine, int Queued, string? Running, double RunningSeconds, int Done, int Failed, int Cancelled,
        string? LastError);

    public PrewarmStatus Prewarming
    {
        get
        {
            lock (_prewarmLock)
                return new PrewarmStatus(_prewarm != null, _prewarm is { } m ? EngineModes.Name(m) : null, _prewarmQueued, _prewarmRunning?.Id,
                    _prewarmRunning is { } r ? Math.Round((DateTime.UtcNow - r.Since).TotalSeconds, 1) : 0, _prewarmDone, _prewarmFailed, _prewarmCancelled, _prewarmLastError);
        }
    }

    /// <summary>
    /// Queues the image's analysis by the prewarm engine (auto: the first one installed): one image at a time, in load
    /// order; waiting and running work ends when the image is unloaded or reloaded. Images no engine is available for
    /// are skipped.
    /// </summary>
    public Task Prewarm(LoadedNative native) => PrewarmCore(native);

    private async Task PrewarmCore(LoadedNative native)
    {
        if (native.Released.IsCancellationRequested) return;
        var engine = _prewarm is { } mode ? EngineModes.ProviderId(mode) : null;
        if (engine != null ? UnavailabilityOf(engine) != null : !IsAvailable) return;
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
            await Session(native, engine ?? FirstAvailable(), null, native.Released).ConfigureAwait(false);
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

    /// <summary>The image's holder for an engine, created on first use and disposed when the image is unloaded or reloaded (not when it is patched).</summary>
    private SessionHolder Holder(LoadedNative native, string id)
    {
        if (native.Released.IsCancellationRequested) throw native.Gone();
        var set = _holders.GetValue(native, n =>
        {
            var s = new HolderSet();
            n.Released.Register(s.Dispose);
            return s;
        });
        var holder = set.Holders.GetOrAdd(id, _ => new SessionHolder());
        if (native.Released.IsCancellationRequested)
        {
            set.Dispose();
            throw native.Gone();
        }
        return holder;
    }

    private SessionHolder? Existing(LoadedNative native, string id) =>
        _holders.TryGetValue(native, out var set) && set.Holders.TryGetValue(id, out var h) ? h : null;

    /// <summary>
    /// The image's session of the engine <see cref="Resolve"/> picks for <paramref name="engine"/>, reflecting the image's
    /// current bytes; the first call opens it (the first open of an image runs auto-analysis), later calls bring the
    /// database's patched bytes up to date with the image's patch set first.
    /// </summary>
    public async Task<INativeDecompilerSession> Session(LoadedNative native, string? engine, IProgress<NativeProviderProgress>? progress, CancellationToken ct)
    {
        var id = Resolve(native, engine);
        var session = await SessionCore(native, id, progress, ct).ConfigureAwait(false);
        // the image's PDB types, once per PDB and database (see NativePdbTypes)
        var holder = Holder(native, id);
        var patched = holder.Patched is { IsCompletedSuccessfully: true } p && ReferenceEquals(p.Result, session);
        await PdbTypes.EnsureAsync(native, session, patched ? holder.PatchedPdb : holder.OpenedPdb, ct).ConfigureAwait(false);
        return session;
    }

    /// <summary>Brings the PDB's types into the engine database (also used by the tools to report the type source).</summary>
    public NativePdbTypes PdbTypes { get; } = new();

    private async Task<INativeDecompilerSession> SessionCore(LoadedNative native, string id, IProgress<NativeProviderProgress>? progress, CancellationToken ct)
    {
        var holder = Holder(native, id);
        var session = await Base(native, holder, id, progress, ct).ConfigureAwait(false);
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
                holder.Patched = OpenPatched(native, id, progress, holder.PatchedPdb);
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
    private Task<INativeDecompilerSession> Base(LoadedNative native, SessionHolder holder, string id, IProgress<NativeProviderProgress>? progress, CancellationToken ct)
    {
        lock (holder)
        {
            if (holder.Opening is { } existing && !(existing.IsCompleted && (existing.IsFaulted || existing.IsCanceled || !existing.Result.IsOpen)))
                return Wait(native, existing, ct);
            var provider = Provider(id);
            holder.SyncedKey = null;
            holder.OpenedPdb = PdbService.PathForEngines(native);
            // The open is not tied to this call's cancellation (a later call reuses the same analysis) but ends when the image is unloaded or reloaded.
            // A universal Mach-O slice goes to the engine as a thin file of its own, keyed by its own hash.
            holder.Opening = native.Image is Native.MachO.MachOFile { Slice: { } slice } thin
                ? OpenBytes(provider, native, $"{Path.GetFileName(native.FilePath)}-{slice.Name}", thin.FileBytes.ToArray(), progress, holder.OpenedPdb)
                : provider.OpenAsync(native.FilePath, native.OriginalSha256, new NativeOpenOptions { Progress = progress, PdbPath = holder.OpenedPdb }, native.Released);
            // Once open, the library functions IDA recognized become the image's ida name layer, Ghidra's own names its ghidra layer.
            if (id is IdaProvider.ProviderId or GhidraProvider.ProviderId)
                holder.LibraryNames = holder.Opening.ContinueWith(async opened =>
                {
                    if (!opened.IsCompletedSuccessfully) return -1;
                    try
                    {
                        return opened.Result is GhidraSession ghidra
                            ? await GhidraNames.ImportAsync(native, ghidra, _code, native.Released)
                            : await EngineLibraryNames.ImportAsync(native, opened.Result, _code, native.Released);
                    }
                    catch (Exception ex) when (ex is ToolError or OperationCanceledException) { return -1; }
                }, TaskScheduler.Default).Unwrap();
            return Wait(native, holder.Opening, ct);
        }
    }

    /// <summary>Opens a session on the patched bytes (written to a private file; the engine keeps its own copy per hash).</summary>
    private Task<INativeDecompilerSession> OpenPatched(LoadedNative native, string id, IProgress<NativeProviderProgress>? progress, string? pdbPath) =>
        OpenBytes(Provider(id), native, Path.GetFileName(native.FilePath), null, progress, pdbPath);

    /// <summary>Opens a session on <paramref name="content"/> (the patched bytes when null), written to a private file named <paramref name="name"/>.</summary>
    private static Task<INativeDecompilerSession> OpenBytes(INativeDecompilerProvider provider, LoadedNative native, string name, byte[]? content,
        IProgress<NativeProviderProgress>? progress, string? pdbPath)
    {
        return Task.Run(async () =>
        {
            var bytes = content ?? native.Patches.PatchedBytes();
            var sha = Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(bytes));
            var dir = Path.Combine(Path.GetTempPath(), "NetDecompilerMcp", content == null ? "patched" : "slices", sha[..16]);
            Directory.CreateDirectory(dir);
            var path = Path.Combine(dir, name);
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
    /// The import of the open IDA session's library names (the number imported, -1 when it failed), or null when no IDA
    /// session was opened for the image; does not open one.
    /// </summary>
    public Task<int>? LibraryNames(LoadedNative native) => Existing(native, IdaProvider.ProviderId)?.LibraryNames;

    /// <summary>The import of the open Ghidra session's names (the number imported, -1 when it failed), or null when no Ghidra session was opened; does not open one.</summary>
    public Task<int>? GhidraNameLayer(LoadedNative native) => Existing(native, GhidraProvider.ProviderId)?.LibraryNames;

    /// <summary>The last patch application into the image's database of engine <paramref name="id"/>, or null when none ran.</summary>
    public PatchSyncResult? LastPatchSync(LoadedNative native, string id) => Existing(native, id)?.LastSync;

    /// <summary>Whether the image's current patch set is served by a separate analysis of the patched bytes (engine <paramref name="id"/>'s database could not take it).</summary>
    public bool ServesPatchedCopy(LoadedNative native, string id) =>
        Existing(native, id) is { Patched: not null } h && h.PatchedState == h.SyncedKey;

    public void Dispose()
    {
        foreach (var (_, provider) in _providers)
            if (provider.IsValueCreated) provider.Value.Dispose();
    }

    /// <summary>An image's holders by engine id.</summary>
    private sealed class HolderSet : IDisposable
    {
        public readonly ConcurrentDictionary<string, SessionHolder> Holders = new(StringComparer.Ordinal);

        public void Dispose()
        {
            foreach (var h in Holders.Values) h.Dispose();
        }
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
