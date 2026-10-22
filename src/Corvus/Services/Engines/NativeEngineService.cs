using System.Collections.Concurrent;
using System.Runtime.CompilerServices;
using Corvus.Core;
using Corvus.Native.Providers;
using Corvus.Native.Providers.Ghidra;
using Corvus.Native.Providers.Ida;

namespace Corvus.Services;

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
        _outputCache = new(() => Environment.GetEnvironmentVariable(EngineOutputCache.MaxMegabytesVariable) == "0" ? null
            : new EngineOutputCache(cacheRoot ?? AnalysisCache.DefaultRoot));
        _code = code;
        DefaultMode = options?.Engine ?? EngineMode.Auto;
        RequestTimeout = TimeSpan.FromSeconds(options?.EngineRequestTimeoutSeconds ?? 120);
        OpenTimeout = TimeSpan.FromSeconds(options?.EngineOpenTimeoutSeconds ?? 1200);
        _analysis = options?.EngineAnalysis ?? EngineAnalysis.Full;
        _prewarm = options?.Prewarm;
        if (_prewarm != null && workspace != null) workspace.NativeLoaded += native => _ = PrewarmCore(native);
    }

    // ---- engines ----

    /// <summary>Provider ids in order of preference.</summary>
    public IReadOnlyList<string> ProviderIds => _providers.Select(p => p.Id).ToList();

    public IReadOnlyList<INativeDecompilerProvider> Providers => _providers.Select(p => p.Provider.Value).ToList();

    /// <summary>The saved engine databases: size, bounds and evictions.</summary>
    public AnalysisCacheStatus CacheStatus() => new AnalysisCache(_cacheRoot ?? AnalysisCache.DefaultRoot).Status();

    private INativeDecompilerProvider? Find(string id) => _providers.FirstOrDefault(p => p.Id.Equals(id, StringComparison.OrdinalIgnoreCase)).Provider?.Value;

    /// <summary>"IDA", "Ghidra", or the id of another engine.</summary>
    public static string DisplayName(string id) => id switch { IdaProvider.ProviderId => "IDA", GhidraProvider.ProviderId => "Ghidra", _ => id };

    /// <summary>An engine's version, build and analysis profile, from its static checks (no worker is started).</summary>
    public sealed record EngineIdentity(string Engine, string? Version, string? Build, string Profile);

    public EngineIdentity Identity(string id)
    {
        var analysis = _analysis == EngineAnalysis.None ? "none" : "full";
        return Find(id) switch
        {
            IdaProvider ida => new(id, ida.Version, ida.EngineBuild, analysis),
            GhidraProvider ghidra => new(id, ghidra.Version, ghidra.EngineBuild, _analysis == EngineAnalysis.None ? "none" : ghidra.Profile.ToString().ToLowerInvariant()),
            _ => new(id, null, null, analysis),
        };
    }

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
    /// The engine a call on the image uses: the one it names; else the server default when that names an engine; else the
    /// first that has analyzed these bytes (<see cref="AnalyzedBy"/>); else the first one installed. Never depends on
    /// which sessions earlier calls opened.
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
        return AnalyzedBy(native) ?? FirstAvailable() ?? Provider(null).Id;
    }

    /// <summary>
    /// The first installed engine, in order of preference, that has analyzed the image's bytes: a complete analysis open
    /// in this process, or a saved one in the analysis cache (shared by every process). Never opens or asks an engine.
    /// </summary>
    /// <summary>The Ghidra provider when this server has one set up, else null.</summary>
    internal GhidraProvider? Ghidra => _providers.Where(p => p.Id == GhidraProvider.ProviderId).Select(p => p.Provider.Value as GhidraProvider).FirstOrDefault();

    public string? AnalyzedBy(LoadedNative native)
    {
        // an image loaded from a Ghidra archive carries Ghidra's analysis
        if (native.EngineDatabase != null && _providers.Any(p => p.Id == GhidraProvider.ProviderId) && UnavailabilityOf(GhidraProvider.ProviderId) == null)
            return GhidraProvider.ProviderId;
        foreach (var (id, provider) in _providers)
            if ((LiveComplete(native, id) || HasSavedAnalysis(native, id) && !HeldElsewhere(native, id)) && provider.Value.CheckAvailability().IsAvailable)
                return id;
        return null;
    }

    /// <summary>A saved analysis another session or process has open: auto answers from the built-in index instead of a conflict.</summary>
    private bool HeldElsewhere(LoadedNative native, string id) =>
        (Find(id) switch { IdaProvider i => i.Cache, GhidraProvider g => g.Cache, _ => new AnalysisCache(_cacheRoot ?? AnalysisCache.DefaultRoot) })
            .Find(id, native.OriginalSha256) is { } dir && AnalysisCache.Held(dir);

    /// <summary>
    /// Whether engine <paramref name="id"/>'s analysis of the image is partial (an open's budget ran out): this process's
    /// open session says so, else the marker beside the saved database. Never opens or asks an engine.
    /// </summary>
    public bool IsPartial(LoadedNative native, string id)
    {
        if (_analysis == EngineAnalysis.None) return false;
        if (Existing(native, id)?.Opening is { IsCompletedSuccessfully: true } opened && opened.Result.IsOpen) return !opened.Result.AnalysisComplete;
        var db = Find(id) switch
        {
            IdaProvider ida => ida.SavedDatabasePath(native.OriginalSha256, native.Overrides != null ? "default-" + native.Overrides.Key : "default"),
            GhidraProvider ghidra => ghidra.ProjectFor(native.FilePath, native.OriginalSha256, _analysis),
            _ => null,
        };
        return db != null && PartialAnalysis.Marked(db);
    }

    private bool LiveComplete(LoadedNative native, string id) =>
        Existing(native, id)?.Opening is { IsCompletedSuccessfully: true } opened && opened.Result.IsOpen && opened.Result.AnalysisComplete;

    // ---- engine preference of the native code tools (ServerOptions.Engine, per-call engine) ----

    private readonly string? _cacheRoot;

    /// <summary>
    /// Every engine session open or opening, with the loaded image it serves (its id; a patched copy or slice by file
    /// name). Never asks a worker, so it answers while one is busy.
    /// </summary>
    public IReadOnlyList<(string Image, EngineSessionState State)> SessionStates()
    {
        var images = new Dictionary<string, string>(OperatingSystem.IsWindows() ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal);
        foreach (var (native, _) in _holders) images.TryAdd(Path.GetFullPath(native.FilePath), native.Id);
        var list = new List<(string, EngineSessionState)>();
        foreach (var (_, provider) in _providers)
        {
            if (!provider.IsValueCreated) continue;
            foreach (var s in provider.Value.SessionStates())
            {
                var path = string.IsNullOrEmpty(s.ImagePath) ? "" : Path.GetFullPath(s.ImagePath);
                list.Add((images.TryGetValue(path, out var id) ? id : Path.GetFileName(path) + " (copy)", s));
            }
        }
        return list;
    }

    /// <summary>The engine the native code tools use when a call names none.</summary>
    public EngineMode DefaultMode { get; }

    /// <summary>Limit of each engine request (CORVUS_ENGINE_REQUEST_TIMEOUT) and of an engine's start and analysis (CORVUS_ENGINE_OPEN_TIMEOUT).</summary>
    public TimeSpan RequestTimeout { get; }
    public TimeSpan OpenTimeout { get; }

    private readonly EngineAnalysis _analysis;

    /// <summary>Engine answers kept across processes (EL-1); null when switched off (<see cref="EngineOutputCache.MaxMegabytesVariable"/>=0).</summary>
    public EngineOutputCache? OutputCache => _outputCache.Value;

    private Lazy<EngineOutputCache?> _outputCache = null!;

    // ---- answers without opening an engine ----

    /// <summary>
    /// The state of engine <paramref name="id"/>'s saved database of the image when this process has no session of it (a
    /// session's own state wins: it may hold changes not saved yet); null when unknown. Reads files only.
    /// </summary>
    public string? SavedState(LoadedNative native, string id)
    {
        // answers stored without an open are those of the default database, not of an import override's own
        if (OutputCache == null || native.Overrides != null || Existing(native, id)?.Opening != null || native.HasPatches || UnavailabilityOf(id) != null) return null;
        var db = Find(id) switch
        {
            IdaProvider ida => ida.SavedDatabasePath(native.OriginalSha256, _analysis == EngineAnalysis.None ? "default-noauto" : "default"),
            GhidraProvider ghidra => ghidra.ProjectFor(native.FilePath, native.OriginalSha256, _analysis),
            _ => null,
        };
        return db != null ? EngineOutputCache.ReadState(db) : null;
    }

    private string NoOpenKey(LoadedNative native, string id, string state, string setup, string kind, uint rva) =>
        EngineOutputCache.Key("no-open", OutputIdentity(id), id, native.OriginalSha256.ToLowerInvariant(), state, setup, kind, OutputCacheKinds.At(rva));

    /// <summary>
    /// An answer stored for the database state saved on disk and the server's setup inputs <paramref name="setup"/> (names,
    /// types, PDB, notes and patches it would push first); the engine is not opened. Null when the image has a session of
    /// that engine here, or nothing is stored.
    /// </summary>
    public T? Answer<T>(LoadedNative native, string id, string setup, string kind, uint rva) where T : class
    {
        if (OutputCache is not { } cache || SavedState(native, id) is not { } state) return null;
        if (cache.Get(NoOpenKey(native, id, state, setup, kind, rva)) is not { } hit) return null;
        try { return System.Text.Json.JsonSerializer.Deserialize<T>(hit, EngineOutputCache.Json); }
        catch (System.Text.Json.JsonException) { return null; }
    }

    /// <summary>
    /// Stores an answer made by <paramref name="session"/> for later processes that have not opened the engine: under the state
    /// the session opened at and the state it is in now (a later open of the database saved now), when only the server's
    /// setup pushes for <paramref name="setup"/> changed the database since the open.
    /// </summary>
    public void Remember<T>(LoadedNative native, INativeDecompilerSession session, string setup, string kind, uint rva, T value)
    {
        if (OutputCache is not { } cache || session is not WorkerSessionBase w || !w.OnlySetupSinceOpen || native.HasPatches) return;
        var json = System.Text.Json.JsonSerializer.Serialize(value, EngineOutputCache.Json);
        foreach (var state in new[] { w.OpenState, w.DatabaseState }.Distinct())
            if (state.Length > 0 && !state.StartsWith('u')) cache.Put(NoOpenKey(native, session.ProviderId, state, setup, kind, rva), json);
    }

    /// <summary>What decides an engine's answers besides its database: its build and analysis settings.</summary>
    internal string OutputIdentity(string id) => Identity(id) is var i ? $"{i.Engine}|{i.Build}|{i.Profile}" : id;

    private NativeOpenOptions OpenOptions(LoadedNative native, string id, IProgress<NativeProviderProgress>? progress, string? pdbPath) =>
        new()
        {
            // a raw layout and import overrides are databases of their own: answers are not shared with the default one
            OutputCache = OutputCache,
            OutputIdentity = OutputIdentity(id) + ((native.Image as Native.RawCodeImage)?.Layout.Key is { } raw ? "|raw " + raw : "") +
                             (native.Overrides is { } ov ? "|" + ov.Key : ""),
            Progress = progress, PdbPath = pdbPath, RequestTimeout = RequestTimeout, OpenTimeout = OpenTimeout, Analysis = _analysis,
            Raw = (native.Image as Native.RawCodeImage)?.Layout,
            Overrides = native.Overrides,
            GhidraDatabase = native.EngineDatabase,
            ThumbCode = native.Image.Arch == Native.NativeArch.Arm && _code != null ? ct => ThumbCode(native, ct) : null,
            KnownStart = _code != null ? async (rva, ct) => (await _code.Index(native, null, ct).ConfigureAwait(false)).FunctionByStart(rva) != null : null,
        };

    /// <summary>The Thumb functions' byte ranges in the server's index, merged.</summary>
    private async Task<IReadOnlyList<(uint Start, uint End)>> ThumbCode(LoadedNative native, CancellationToken ct)
    {
        var index = await _code!.Index(native, null, ct).ConfigureAwait(false);
        if (index.ArmModes is not { } modes) return [];
        var ranges = new List<(uint Start, uint End)>();
        foreach (var r in index.Functions.Where(f => modes.At(f.Start)).SelectMany(index.Ranges).OrderBy(r => r.Start))
            if (ranges.Count > 0 && ranges[^1].End >= r.Start) ranges[^1] = (ranges[^1].Start, Math.Max(ranges[^1].End, r.End));
            else ranges.Add(r);
        return ranges;
    }

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
            try { seen.Exists = SavedDatabaseExists(id, native.OriginalSha256, native.Overrides?.Key); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException) { seen.Exists = false; }
            seen.CheckedAt = now;
            return seen.Exists;
        }
    }

    private bool SavedDatabaseExists(string id, string sha256, string? overrides)
    {
        var provider = Find(id);
        if (provider is IdaProvider ida) return ida.SavedDatabasePath(sha256, overrides != null ? "default-" + overrides : "default") is { } path && File.Exists(path);
        if (provider is GhidraProvider ghidra) return ghidra.HasSavedProject(sha256, overrides);
        if (new AnalysisCache(_cacheRoot ?? AnalysisCache.DefaultRoot).Find(id, sha256) is not { } dir) return false;
        return id == GhidraProvider.ProviderId
            ? Directory.EnumerateDirectories(dir, "p-*").Where(p => GhidraSession.OfOverrides(p, overrides)).Any(p => File.Exists(Path.Combine(p, GhidraSession.ProjectName + ".gpr")))
            : Directory.EnumerateFiles(dir, overrides != null ? $"ida-default-{overrides}*.i64" : "ida-default*.i64").Any(f => overrides != null || !f.Contains("-ov-"));
    }

    /// <summary>
    /// Checks import overrides against each installed engine's own names (Ghidra's .ldefs, IDA's processor modules); no
    /// engine is started. InvalidArgument names the nearest known ones.
    /// </summary>
    public void CheckOverrides(Native.EngineOverrides overrides, Native.RawLayout? raw)
    {
        foreach (var provider in Providers)
            switch (provider)
            {
                case IdaProvider ida when ida.CheckAvailability().IsAvailable && ida.InstallDirectory is { } dir:
                    EngineOverrideChecks.CheckIda(dir, overrides);
                    break;
                case GhidraProvider ghidra when ghidra.CheckAvailability().IsAvailable && ghidra.InstallDirectory is { } dir:
                    EngineOverrideChecks.CheckGhidra(dir, overrides, raw?.Isa.GhidraLanguage);
                    break;
            }
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
        // an open reports its stages as they change; an analysis stage can last minutes, so the wait reports every few seconds too
        var waiting = System.Diagnostics.Stopwatch.StartNew();
        using var heartbeat = progress == null ? null : new Timer(_ =>
        {
            var h = Existing(native, id);
            // An image never opened is about to be; one whose open call has not
            // returned yet is opening, though Opening still holds the old task.
            var opening = h is null or { Opening: null } || h.Starting || h.Opening is { IsCompleted: false };
            var since = h is { Starting: true } or { Opening.IsCompleted: false } ? DateTime.UtcNow - h.OpenStarted : waiting.Elapsed;
            progress.Report(new NativeProviderProgress($"{(opening ? h?.Stage ?? "start" : "sync")}, waiting {waiting.Elapsed.TotalSeconds:0} s", since));
        }, null, OpenHeartbeat, OpenHeartbeat);
        var session = await SessionCore(native, id, progress, ct).ConfigureAwait(false);
        // the image's PDB types, once per PDB and database (see NativePdbTypes)
        var holder = Holder(native, id);
        var patched = holder.Patched is { IsCompletedSuccessfully: true } p && ReferenceEquals(p.Result, session);
        var pdbClock = System.Diagnostics.Stopwatch.StartNew();
        await PdbTypes.EnsureAsync(native, session, patched ? holder.PatchedPdb : holder.OpenedPdb, ct).ConfigureAwait(false);
        if (!patched && Interlocked.Exchange(ref holder.PdbTimed, 1) == 0) holder.Profile.After("pdb types", pdbClock.Elapsed.TotalSeconds);
        return session;
    }

    /// <summary>Between progress reports while a call waits for an engine's open or patch sync (under the 5 s the progress contract allows).</summary>
    internal TimeSpan OpenHeartbeat { get; set; } = TimeSpan.FromSeconds(4);

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
            if (holder.SyncedKey == key) return holder.PatchedState == key && holder.Patched is { } same ? await Wait(native, holder, same, ct).ConfigureAwait(false) : session;
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
            return await Wait(native, holder, holder.Patched, ct).ConfigureAwait(false);
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
                return Wait(native, holder, existing, ct);
            var provider = Provider(id);
            holder.SyncedKey = null;
            holder.OpenedPdb = PdbService.PathForEngines(native);
            holder.OpenStarted = DateTime.UtcNow;
            holder.Stage = "start";
            holder.Profile = new EngineOpenProfile();
            holder.PdbTimed = 0;
            holder.Profile.Mark("prepare", 0); // the input copy and cache entry, before the engine starts
            var started = holder.OpenStarted;
            progress = new StageProgress(holder, holder.Profile.Recording(() => (DateTime.UtcNow - started).TotalSeconds, progress));
            // Set after OpenStarted and Stage, cleared once Opening holds the
            // new task, so the heartbeat never names a stale open.
            holder.Starting = true;
            try
            {
                // The open is not tied to this call's cancellation (a later call reuses the same analysis) but ends when the image is unloaded or reloaded.
                // A universal Mach-O slice goes to the engine as a thin file of its own, keyed by its own hash.
                holder.Opening = native.Image is Native.MachO.MachOFile { Slice: { } slice } thin
                    ? OpenBytes(provider, native, $"{Path.GetFileName(native.FilePath)}-{slice.Name}", thin.FileBytes.ToArray(), OpenOptions(native, id, progress, holder.OpenedPdb))
                    : provider.OpenAsync(native.FilePath, native.OriginalSha256, OpenOptions(native, id, progress, holder.OpenedPdb), native.Released);
            }
            finally { holder.Starting = false; }
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
            return Wait(native, holder, holder.Opening, ct);
        }
    }

    /// <summary>Opens a session on the patched bytes (written to a private file; the engine keeps its own copy per hash).</summary>
    private Task<INativeDecompilerSession> OpenPatched(LoadedNative native, string id, IProgress<NativeProviderProgress>? progress, string? pdbPath) =>
        OpenBytes(Provider(id), native, Path.GetFileName(native.FilePath), null, OpenOptions(native, id, progress, pdbPath));

    /// <summary>Opens a session on <paramref name="content"/> (the patched bytes when null), written to a private file named <paramref name="name"/>.</summary>
    private static Task<INativeDecompilerSession> OpenBytes(INativeDecompilerProvider provider, LoadedNative native, string name, byte[]? content,
        NativeOpenOptions options)
    {
        return Task.Run(async () =>
        {
            var bytes = content ?? native.Patches.PatchedBytes();
            var sha = Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(bytes));
            // one folder per open, deleted whole: a shared parent outlived it, and two opens of one hash shared the file
            var dir = Path.Combine(Path.GetTempPath(), $"corvus-{(content == null ? "patched" : "slice")}-{sha[..16]}-{Guid.NewGuid().ToString("N")[..8]}");
            Directory.CreateDirectory(dir);
            var path = Path.Combine(dir, name);
            await File.WriteAllBytesAsync(path, bytes, native.Released).ConfigureAwait(false);
            try
            {
                return await provider.OpenAsync(path, sha, options, native.Released).ConfigureAwait(false);
            }
            finally
            {
                try { Directory.Delete(dir, true); }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
            }
        }, native.Released);
    }

    private static async Task<INativeDecompilerSession> Wait(LoadedNative native, SessionHolder holder, Task<INativeDecompilerSession> opening, CancellationToken ct)
    {
        try { return await opening.WaitAsync(ct).ConfigureAwait(false); }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested && native.Released.IsCancellationRequested) { throw native.Gone(); }
        // the call's deadline came first: the open is not the call's and goes on, so the same call later picks it up (EL-5)
        catch (OperationCanceledException) when (ct.IsCancellationRequested && !opening.IsCompleted && !native.Released.IsCancellationRequested)
        {
            var stage = holder.Stage ?? "start";
            var seconds = Math.Round((DateTime.UtcNow - holder.OpenStarted).TotalSeconds);
            throw new ToolError(ErrorCode.Timeout,
                $"the engine is still opening {native.Id}: {stage}, {seconds:0} s so far (a first analysis can take minutes); the open goes on in the background.",
                "call again after details.retryAfterMs: the same open is picked up, not started again; server_status shows its stage and seconds")
                { Details = new { stillRunning = true, stage, seconds }, RetryAfter = OpenRetryAfter };
        }
    }

    /// <summary>When a call that left an engine open running should come back.</summary>
    internal static readonly TimeSpan OpenRetryAfter = TimeSpan.FromSeconds(30);

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

    /// <summary>
    /// One engine's session of an image as the engine status reports it: State opening (Stage, Seconds since the open
    /// started), open (Session), failed (Error) or closed.
    /// </summary>
    public sealed record ImageEngineStatus(string Engine, string State, string? Stage, double Seconds, INativeDecompilerSession? Session, string? Error)
    {
        /// <summary>The open's stages with their seconds (see <see cref="EngineOpenProfile"/>).</summary>
        public IReadOnlyList<EngineOpenStage> OpenStages { get; init; } = [];
    }

    /// <summary>The image's engine sessions opened in this process (none is started or waited for), in order of preference.</summary>
    public IReadOnlyList<ImageEngineStatus> ImageSessions(LoadedNative native)
    {
        var list = new List<ImageEngineStatus>();
        foreach (var (id, _) in _providers)
        {
            if (Existing(native, id) is not { Opening: { } opening } h) continue;
            double seconds = Math.Round((DateTime.UtcNow - h.OpenStarted).TotalSeconds, 1);
            var stages = h.Profile.Stages((DateTime.UtcNow - h.OpenStarted).TotalSeconds);
            if (!opening.IsCompleted) list.Add(new(id, "opening", h.Stage, seconds, null, null) { OpenStages = stages });
            else if (opening.IsCompletedSuccessfully)
            {
                // a patched copy serves the current patch set when the database could not take it
                var served = h.Patched is { IsCompletedSuccessfully: true } p && h.PatchedState == h.SyncedKey ? p.Result : opening.Result;
                list.Add(new(id, served.IsOpen ? "open" : "closed", null, seconds, served, null) { OpenStages = stages });
            }
            else list.Add(new(id, "failed", h.Stage, seconds, null,
                opening.Exception?.InnerException is { } e ? (e is ToolError t ? t.Message : e.Message) : "cancelled") { OpenStages = stages });
        }
        return list;
    }

    /// <summary>Records the open's stage as it is reported (synchronously, unlike <see cref="Progress{T}"/>) and passes it on.</summary>
    private sealed class StageProgress(SessionHolder holder, IProgress<NativeProviderProgress>? next) : IProgress<NativeProviderProgress>
    {
        public void Report(NativeProviderProgress value)
        {
            holder.Stage = value.Stage;
            next?.Report(value);
        }
    }

    /// <summary>The image's open session of engine <paramref name="id"/> (null: any, in order of preference), or null; never opens or waits.</summary>
    public INativeDecompilerSession? OpenSession(LoadedNative native, string? id = null) =>
        ImageSessions(native).FirstOrDefault(s => s.State == "open" && (id == null || s.Engine == id))?.Session;

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
        /// <summary>When the last open of <see cref="Opening"/> started and its latest progress stage.</summary>
        public DateTime OpenStarted;
        public volatile string? Stage;
        /// <summary>True while the provider's open call runs, before <see cref="Opening"/> holds its task.</summary>
        public volatile bool Starting;
        /// <summary>The last open's stage timings, and whether the PDB type load after it was timed.</summary>
        public EngineOpenProfile Profile = new();
        public int PdbTimed;

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
