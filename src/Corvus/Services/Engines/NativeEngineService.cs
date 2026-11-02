using System.Collections.Concurrent;
using System.Runtime.CompilerServices;
using Corvus.Core;
using Corvus.Native.Providers;
using Corvus.Native.Providers.Ghidra;
using Corvus.Native.Providers.Ida;

namespace Corvus.Services;

/// <summary>The IDA and Ghidra engines with one session per engine and image, opened on first use and closed on unload;
/// patches go into the open database, or into a second session on the patched bytes when it cannot take them.</summary>
public sealed class NativeEngineService : IDisposable
{
    /// <summary>The engines in order of preference (IDA, then Ghidra).</summary>
    private readonly IReadOnlyList<(string Id, Lazy<INativeDecompilerProvider> Provider)> _providers;
    private readonly NativeCodeService? _code;
    private readonly AssemblyWorkspace? _workspace;
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
        _workspace = workspace;
        DefaultMode = options?.Engine ?? EngineMode.Auto;
        RequestTimeout = TimeSpan.FromSeconds(options?.EngineRequestTimeoutSeconds ?? 120);
        OpenTimeout = options?.EngineOpenTimeoutSeconds is { } open ? TimeSpan.FromSeconds(open) : Timeout.InfiniteTimeSpan;
        AnalysisStall = TimeSpan.FromSeconds(options?.EngineAnalysisStallSeconds ?? new ServerOptions().EngineAnalysisStallSeconds);
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

    /// <summary>The engine <paramref name="id"/> names, or the first installed for null or auto; throws InvalidArgument or
    /// ProviderUnavailable.</summary>
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

    /// <summary>The engine a call uses: the named one, the server default, the one open on these bytes, the first that analyzed them, else the
    /// first installed; never depends on earlier calls.</summary>
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
        return OpenEngine(native) ?? AnalyzedBy(native) ?? FirstAvailable() ?? Provider(null).Id;
    }

    /// <summary>The Ghidra provider when this server has one set up, else null.</summary>
    internal GhidraProvider? Ghidra => _providers.Where(p => p.Id == GhidraProvider.ProviderId).Select(p => p.Provider.Value as GhidraProvider).FirstOrDefault();

    /// <summary>The first installed engine with a complete analysis of the image, open here or saved; null when none, or while another engine is still opening or partial on it.
    /// Never opens an engine.</summary>
    public string? AnalyzedBy(LoadedNative native)
    {
        // An image loaded from a Ghidra archive carries Ghidra's analysis.
        if (native.EngineDatabase != null && _providers.Any(p => p.Id == GhidraProvider.ProviderId) && UnavailabilityOf(GhidraProvider.ProviderId) == null)
            return GhidraProvider.ProviderId;
        foreach (var (id, provider) in _providers)
            if (LiveComplete(native, id) && provider.Value.CheckAvailability().IsAvailable) return id;
        // While one engine is open on the image, no other engine's saved analysis answers.
        var open = OpenEngine(native);
        foreach (var (id, provider) in _providers)
            if ((open == null || open == id) && HasSavedAnalysis(native, id) && !HeldElsewhere(native, id) && provider.Value.CheckAvailability().IsAvailable)
                return id;
        return null;
    }

    /// <summary>A saved analysis another session or process has open: auto answers from the built-in index instead of a conflict.</summary>
    private bool HeldElsewhere(LoadedNative native, string id) =>
        (Find(id) switch { IdaProvider i => i.Cache, GhidraProvider g => g.Cache, _ => new AnalysisCache(_cacheRoot ?? AnalysisCache.DefaultRoot) })
            .Find(id, native.OriginalSha256) is { } dir && AnalysisCache.Held(dir);

    /// <summary>Whether engine <paramref name="id"/>'s analysis ran out of budget, from the open session or the saved
    /// marker; never opens an engine.</summary>
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

    /// <summary>The installed engine with a session opening or open on the image in this process, complete or not; null when none. Never opens an engine.</summary>
    public string? OpenEngine(LoadedNative native) =>
        _providers.FirstOrDefault(p => Live(native, p.Id) && p.Provider.Value.CheckAvailability().IsAvailable).Id;

    private bool Live(LoadedNative native, string id) =>
        Existing(native, id)?.Opening is { } o && (!o.IsCompleted || (o.IsCompletedSuccessfully && o.Result.IsOpen));

    private bool LiveComplete(LoadedNative native, string id) =>
        Existing(native, id)?.Opening is { IsCompletedSuccessfully: true } opened && opened.Result.IsOpen && opened.Result.AnalysisComplete;

    // ---- engine preference of the native code tools (ServerOptions.Engine, per-call engine) ----

    private readonly string? _cacheRoot;

    /// <summary>Every engine session open or opening with the image it serves; never asks a worker.</summary>
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

    /// <summary>Limit of each engine request (CORVUS_ENGINE_REQUEST_TIMEOUT).</summary>
    public TimeSpan RequestTimeout { get; }

    /// <summary>Limit of an engine's start and analysis (CORVUS_ENGINE_OPEN_TIMEOUT); <see cref="Timeout.InfiniteTimeSpan"/> sets none.</summary>
    public TimeSpan OpenTimeout { get; }

    private readonly EngineAnalysis _analysis;
    /// <summary>Window of no progress and idle CPU after which an analysis is stopped (CORVUS_ENGINE_ANALYSIS_STALL); zero turns the check off.</summary>
    public TimeSpan AnalysisStall { get; }

    /// <summary>Engine answers kept across processes; null when switched off (<see cref="EngineOutputCache.MaxMegabytesVariable"/>=0).</summary>
    public EngineOutputCache? OutputCache => _outputCache.Value;

    private Lazy<EngineOutputCache?> _outputCache = null!;

    // ---- answers without opening an engine ----

    /// <summary>The state of engine <paramref name="id"/>'s saved database when no session is open here; null when unknown.
    /// Reads files only.</summary>
    public string? SavedState(LoadedNative native, string id)
    {
        // Answers stored without an open belong to the default database, not an import override's.
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

    /// <summary>A stored answer for the saved database state and <paramref name="setup"/>, without opening the engine;
    /// null when a session is open here or nothing is stored.</summary>
    public T? Answer<T>(LoadedNative native, string id, string setup, string kind, uint rva) where T : class
    {
        if (OutputCache is not { } cache || SavedState(native, id) is not { } state) return null;
        if (cache.Get(NoOpenKey(native, id, state, setup, kind, rva)) is not { } hit) return null;
        try { return System.Text.Json.JsonSerializer.Deserialize<T>(hit, EngineOutputCache.Json); }
        catch (System.Text.Json.JsonException) { return null; }
    }

    /// <summary>Stores a session's answer under its open and current database states, when only setup pushes changed the
    /// database.</summary>
    public void Remember<T>(LoadedNative native, INativeDecompilerSession session, string setup, string kind, uint rva, T value)
    {
        if (OutputCache is not { } cache || session is not WorkerSessionBase w || !w.OnlySetupSinceOpen || native.HasPatches) return;
        var json = System.Text.Json.JsonSerializer.Serialize(value, EngineOutputCache.Json);
        foreach (var state in new[] { w.OpenState, w.DatabaseState }.Distinct())
            if (state.Length > 0 && !state.StartsWith('u')) cache.Put(NoOpenKey(native, session.ProviderId, state, setup, kind, rva), json);
    }

    /// <summary>What decides an engine's answers besides its database: its build and analysis settings.</summary>
    internal string OutputIdentity(string id) => Identity(id) is var i ? $"{i.Engine}|{i.Build}|{i.Profile}" : id;

    // The history is advisory: a failure leaves the estimate out of the conflict another session reads.
    // Only earlier opens of this image by this engine, loading a saved database or analyzing, estimate an open.
    private OpenEstimate.Estimate? Expectation(LoadedNative native, string id, bool patchedCopy)
    {
        if (patchedCopy) return null;
        try
        {
            var saved = HasSavedAnalysis(native, id);
            return Estimates.ForRun(id, native.OriginalSha256, saved, saved && IsPartial(native, id));
        }
        catch (Exception ex) when (ex is not OperationCanceledException) { return null; }
    }

    private NativeOpenOptions OpenOptions(LoadedNative native, string id, IProgress<NativeProviderProgress>? progress, string? pdbPath, bool patchedCopy = false)
    {
        var expectation = Expectation(native, id, patchedCopy);
        return new NativeOpenOptions
        {
            // A raw layout and import overrides are databases of their own, with their own answers.
            OutputCache = OutputCache,
            OutputIdentity = OutputIdentity(id) + ((native.Image as Native.RawCodeImage)?.Layout.Key is { } raw ? "|raw " + raw : "") +
                             (native.Overrides is { } ov ? "|" + ov.Key : ""),
            ExpectedSeconds = expectation?.Seconds, ExpectedFromHistory = expectation != null,
            Progress = progress, PdbPath = pdbPath, RequestTimeout = RequestTimeout, OpenTimeout = OpenTimeout, AnalysisStall = AnalysisStall, Analysis = _analysis,
            Raw = (native.Image as Native.RawCodeImage)?.Layout,
            Overrides = native.Overrides,
            GhidraDatabase = native.EngineDatabase,
            ThumbCode = native.Image.Arch == Native.NativeArch.Arm && _code != null ? ct => ThumbCode(native, ct) : null,
            KnownStart = _code != null ? async (rva, ct) => (await _code.Index(native, null, ct).ConfigureAwait(false)).FunctionByStart(rva) != null : null,
        };
    }

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

    /// <summary>The image's session of <paramref name="provider"/> (null: any) with a complete analysis of the current
    /// patch set, else null; never opens, waits or asks.</summary>
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
        // Never synced, or patched since; syncing is a request.
        if (h.SyncedKey != key) return null;
        if (h.PatchedState == key)
            return h.Patched is { IsCompletedSuccessfully: true } patched && patched.Result.IsOpen ? patched.Result : null;
        return opened.Result;
    }

    /// <summary>The first engine with a saved database of the image's bytes, from file checks; null when none.</summary>
    public string? SavedAnalysis(LoadedNative native) => _providers.Select(p => p.Id).FirstOrDefault(id => HasSavedAnalysis(native, id));

    /// <summary>Whether the analysis cache holds a saved database of engine <paramref name="id"/> for the image's bytes.</summary>
    public bool HasSavedAnalysis(LoadedNative native, string id)
    {
        // Looked up at most every few seconds per image and engine; a database appears when an analysis finishes.
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

    /// <summary>Checks import overrides against each installed engine's names without starting it; InvalidArgument names
    /// the nearest.</summary>
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

    /// <summary>Queues the image's background analysis, one image at a time in load order, ended by unload; skipped when no
    /// engine is available.</summary>
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
            await OpenThrough(native, engine ?? OpenEngine(native) ?? AnalyzedBy(native) ?? FirstAvailable(), native.Released).ConfigureAwait(false);
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

    /// <summary>Opens the image's session and waits for the open to end; only a failed or cancelled open throws.</summary>
    private async Task OpenThrough(LoadedNative native, string? engine, CancellationToken ct)
    {
        var id = Resolve(native, engine);
        while (true)
        {
            try
            {
                await Session(native, id, null, ct).ConfigureAwait(false);
                return;
            }
            // The early answer ends the call's wait, not the open: wait on the
            // open itself, then ask again. An open that ended in between is
            // read by the next ask.
            catch (ToolError e) when (e.Code == ErrorCode.Timeout && e.Details is Dictionary<string, object?> d && d.ContainsKey("stillRunning"))
            {
                if (Existing(native, id)?.Running is { } open) await open.WaitAsync(ct).ConfigureAwait(false);
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

    /// <summary>The image's session of the engine <see cref="Resolve"/> picks, opened on first use and synced to the current
    /// patch set.</summary>
    public async Task<INativeDecompilerSession> Session(LoadedNative native, string? engine, IProgress<NativeProviderProgress>? progress, CancellationToken ct)
    {
        var id = Resolve(native, engine);
        // An analysis stage can last minutes, so the wait also reports every few seconds.
        var waiting = System.Diagnostics.Stopwatch.StartNew();
        using var heartbeat = progress == null ? null : new Timer(_ =>
        {
            var h = Existing(native, id);
            // An image never opened is about to be; one whose open call has not
            // returned yet is opening, though Opening still holds the old task.
            var running = h is { } && (h.Starting || h.Running != null);
            var opening = h is null or { Opening: null } || running;
            var since = running ? Now - h!.Current.Started : waiting.Elapsed;
            progress.Report(new NativeProviderProgress($"{(opening ? h?.Current.Stage ?? "start" : "sync")}, waiting {waiting.Elapsed.TotalSeconds:0} s", since));
        }, null, OpenHeartbeat, OpenHeartbeat);
        var session = await SessionCore(native, id, progress, ct).ConfigureAwait(false);
        // The image's PDB types, once per PDB and database.
        var holder = Holder(native, id);
        var patched = holder.Patched is { IsCompletedSuccessfully: true } p && ReferenceEquals(p.Result, session);
        var pdbClock = System.Diagnostics.Stopwatch.StartNew();
        await PdbTypes.EnsureAsync(native, session, patched ? holder.PatchedPdb : holder.OpenedPdb, ct).ConfigureAwait(false);
        if (!patched && Interlocked.Exchange(ref holder.PdbTimed, 1) == 0) holder.Run.Profile.After("pdb types", pdbClock.Elapsed.TotalSeconds);
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
            if (holder.SyncedKey == key) return holder.PatchedState == key && holder.Patched is { } same ? await Wait(native, id, holder.PatchedRun, same, ct).ConfigureAwait(false) : session;
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
                var run = holder.PatchedRun = NewRun(native, id, patchedCopy: true);
                holder.Patched = OpenPatched(native, id, run, progress, holder.PatchedPdb);
            }
            return await Wait(native, id, holder.PatchedRun, holder.Patched, ct).ConfigureAwait(false);
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
                return Wait(native, id, holder.Run, existing, ct);
            var provider = Provider(id);
            holder.SyncedKey = null;
            holder.OpenedPdb = PdbService.PathForEngines(native);
            holder.PdbTimed = 0;
            var run = holder.Run = NewRun(native, id);
            progress = Recorded(run, progress);
            // Set after Run, cleared once Opening holds the new task, so the
            // heartbeat never names a stale open.
            holder.Starting = true;
            holder.OpenCancel?.Dispose();
            var cancel = holder.OpenCancel = CancellationTokenSource.CreateLinkedTokenSource(native.Released);
            try
            {
                // The open is not tied to this call's cancellation (a later call reuses the same analysis) but ends when the image is unloaded or reloaded.
                // A universal Mach-O slice goes to the engine as a thin file of its own, keyed by its own hash.
                holder.Opening = native.Image is Native.MachO.MachOFile { Slice: { } slice } thin
                    ? OpenBytes(provider, native, $"{Path.GetFileName(native.FilePath)}-{slice.Name}", thin.FileBytes.ToArray(), OpenOptions(native, id, progress, holder.OpenedPdb), cancel.Token)
                    : provider.OpenAsync(native.FilePath, native.OriginalSha256, OpenOptions(native, id, progress, holder.OpenedPdb), cancel.Token);
            }
            finally { holder.Starting = false; }
            // A saved database measures a load; an analysis measures a rate only
            // when it completed, since a partial one stopped early.
            _ = holder.Opening.ContinueWith(opened =>
            {
                if (!opened.IsCompletedSuccessfully) return;
                var reused = opened.Result.ReusedDatabase;
                if (!reused && !opened.Result.AnalysisComplete) return;
                var analysis = run.Profile.Stages(0).Where(st => st.Stage == "analysis").Sum(st => st.Seconds);
                lock (_recordGate)
                {
                    if (!_disposed) Estimates.RecordRun(id, native.OriginalSha256, reused, analysis, (Now - run.Started).TotalSeconds, !opened.Result.AnalysisComplete);
                }
            }, TaskScheduler.Default);
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
            return Wait(native, id, run, holder.Opening, ct);
        }
    }

    private DateTime Now => Clock.GetUtcNow().UtcDateTime;

    private OpenEstimate Estimates => new(_cacheRoot ?? AnalysisCache.DefaultRoot);

    /// <summary>A new open's own start, stage, profile and estimate.</summary>
    private OpenRun NewRun(LoadedNative native, string id, bool patchedCopy = false)
    {
        var run = new OpenRun { Started = Now, Stage = "start" };
        // The input copy and cache entry, before the engine starts.
        run.Profile.Mark("prepare", 0);
        // The history is advisory, so a failure here never fails the open.
        try
        {
            run.CodeBytes = OpenEstimate.CodeBytes(native.Image);
            run.Expected = Expectation(native, id, patchedCopy);
        }
        catch (Exception ex) when (ex is not OperationCanceledException) { }
        return run;
    }

    private IProgress<NativeProviderProgress> Recorded(OpenRun run, IProgress<NativeProviderProgress>? next) =>
        new StageProgress(run, run.Profile.Recording(() => (Now - run.Started).TotalSeconds, next));

    /// <summary>Opens a session on the patched bytes (written to a private file; the engine keeps its own copy per hash).</summary>
    private Task<INativeDecompilerSession> OpenPatched(LoadedNative native, string id, OpenRun run, IProgress<NativeProviderProgress>? progress, string? pdbPath) =>
        OpenBytes(Provider(id), native, Path.GetFileName(native.FilePath), null, OpenOptions(native, id, Recorded(run, progress), pdbPath, patchedCopy: true), native.Released);

    /// <summary>Opens a session on <paramref name="content"/> (the patched bytes when null), written to a private file named <paramref name="name"/>.</summary>
    private static Task<INativeDecompilerSession> OpenBytes(INativeDecompilerProvider provider, LoadedNative native, string name, byte[]? content,
        NativeOpenOptions options, CancellationToken cancellationToken)
    {
        return Task.Run(async () =>
        {
            var bytes = content ?? native.Patches.PatchedBytes();
            var sha = Convert.ToHexStringLower(System.Security.Cryptography.SHA256.HashData(bytes));
            // One folder per open, deleted whole, so two opens of one hash never share a file.
            var dir = Native.Providers.PrivateFolder.Temp($"{(content == null ? "patched" : "slice")}-{sha[..16]}-{Guid.NewGuid().ToString("N")[..8]}");
            Directory.CreateDirectory(dir);
            var path = Path.Combine(dir, name);
            await File.WriteAllBytesAsync(path, bytes, cancellationToken).ConfigureAwait(false);
            try
            {
                return await provider.OpenAsync(path, sha, options, cancellationToken).ConfigureAwait(false);
            }
            finally
            {
                try { Directory.Delete(dir, true); }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
            }
        }, cancellationToken);
    }

    private async Task<INativeDecompilerSession> Wait(LoadedNative native, string id, OpenRun run, Task<INativeDecompilerSession> opening, CancellationToken ct)
    {
        try { return await opening.WaitAsync(EstimateAfter, Clock, ct).ConfigureAwait(false); }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested && native.Released.IsCancellationRequested) { throw native.Gone(); }
        // An open that ended as the wait timed out returns its result.
        catch (TimeoutException) when (opening.IsCompleted) { return await opening.ConfigureAwait(false); }
        // The estimate comes after a short wait or at the call's deadline; the open goes on and a later call picks it up.
        catch (Exception ex) when ((ex is TimeoutException || (ex is OperationCanceledException && ct.IsCancellationRequested))
            && !opening.IsCompleted && !native.Released.IsCancellationRequested)
        {
            var stage = run.Stage ?? "start";
            var seconds = Math.Round((Now - run.Started).TotalSeconds);
            var expected = run.Expected?.Seconds;
            // Past the estimate there is no time left to report; the overrun is.
            double? remaining = expected is { } e && seconds < e ? Math.Round(e - seconds) : null;
            var overdue = expected is { } x && remaining == null ? seconds - x : (double?)null;
            var retry = Native.Providers.BackgroundRunner.RetryFor(remaining ?? 0);
            // Once per task, so the end reaches a call that returned early; a later call finds it on the next reply.
            if (!ReferenceEquals(Interlocked.Exchange(ref run.Announced, opening), opening))
                _ = opening.ContinueWith(done => NotifyEnd(native, id, run, done), TaskScheduler.Default);
            var tool = OutputCall.Current?.Tool;
            var offersFallback = BuiltInEngineFor?.Invoke(tool) ?? true;
            var progress = $"opening ({OpenProgressText.Describe(stage, seconds, expected, run.Expected?.Basis)})";
            var next = $"get_engine_status image={native.Id} waitSeconds={(int)retry.TotalSeconds} waits for the end"
                + (offersFallback ? $", or use engine={FallbackEngine} for an answer now" : "");
            var message = $"{progress}; the engine is still opening {native.Id}; the open goes on in the background and {OpenLimitText}.";
            // The key is omitted, not null, when the fallback is not offered.
            var details = new Dictionary<string, object?>
            {
                ["stillRunning"] = true, ["stage"] = stage, ["seconds"] = seconds,
            };
            if (expected is { } exp)
            {
                details["expectedSeconds"] = exp;
                details["expectedBasis"] = run.Expected!.Value.Basis;
                if (remaining is { } left) details["remainingSeconds"] = left; else details["overdueSeconds"] = overdue;
                details["estimatedMinutes"] = Math.Max(1, (int)Math.Ceiling(exp / 60));
            }
            details["image"] = native.Id;
            if (offersFallback) details["fallbackEngine"] = FallbackEngine;
            throw new ToolError(ErrorCode.Timeout, message, next) { Details = details, RetryAfter = retry };
        }
    }


    /// <summary>The open limit in seconds; null when none is set.</summary>
    public double? OpenLimitSeconds => OpenTimeout == Timeout.InfiniteTimeSpan ? null : OpenTimeout.TotalSeconds;

    /// <summary>What ends a running open, in words.</summary>
    public string OpenLimitText =>
        "ends when the engine finishes, is cancelled or exits"
        + (AnalysisStall > TimeSpan.Zero && (OpenTimeout == Timeout.InfiniteTimeSpan || AnalysisStall < OpenTimeout) ? $", or after {AnalysisStall.TotalSeconds:0} s without progress" : "")
        + (OpenLimitSeconds is { } limit ? $", or at the open limit of {limit:0} s" : "");

    /// <summary>Queues the workspace notice for an open whose early answer was given.</summary>
    private void NotifyEnd(LoadedNative native, string id, OpenRun run, Task<INativeDecompilerSession> opening)
    {
        if (_workspace == null) return;
        var seconds = Math.Round((Now - run.Started).TotalSeconds);
        var name = $"{native.Id}: {id} analysis";
        _workspace.Notify(opening.IsCompletedSuccessfully
            ? $"{name} {(opening.Result.AnalysisComplete ? "complete" : "partial")} in {seconds:0} s; next: {EndNext(opening.Result.AnalysisComplete ? "complete" : "partial", native.Id, id)}"
            : $"{name} {(opening.IsCanceled ? "cancelled" : $"failed ({FailureReason(opening)})")} in {seconds:0} s; next: {EndNext(opening.IsCanceled ? "cancelled" : "failed", native.Id, id)}"
              + (opening.Exception?.InnerException is ToolError { Remediation: { Length: > 0 } fix } ? $"; {fix}" : ""));
    }

    /// <summary>The call a notice names for an analysis that ended as <paramref name="kind"/> (complete, partial, failed or cancelled).</summary>
    public static string EndNext(string kind, string imageId, string engine) => kind switch
    {
        "complete" => $"list_functions image={imageId} engine={engine}",
        "partial" => $"reanalyze_native image={imageId} engine={engine} completes it",
        _ => $"get_engine_status image={imageId} shows the state, engine={FallbackEngine} answers now",
    };

    /// <summary>
    /// Cancels the running open of engine <paramref name="id"/> on the image and waits for it to settle;
    /// false when no open is running. The next engine call opens it again.
    /// </summary>
    public async Task<bool> CancelOpenAsync(LoadedNative native, string id, CancellationToken ct)
    {
        if (Existing(native, id) is not { Running: { } running } holder) return false;
        // A concurrent re-open may dispose the source; the new open then needs no cancel.
        try { holder.OpenCancel?.Cancel(); }
        catch (ObjectDisposedException) { }
        try { await running.WaitAsync(ct).ConfigureAwait(false); }
        catch (Exception ex) when (ex is not OperationCanceledException || !ct.IsCancellationRequested) { }
        return true;
    }

    /// <summary>The first line of why an open failed: the stall, the exit code or the error.</summary>
    private static string FailureReason(Task opening) =>
        Format.Clip((opening.Exception?.InnerException?.Message ?? "no reason reported").Split('\n')[0].Trim(), 200);

    /// <summary>Tells whether a tool accepts engine=ours; null accepts every tool. Set by the tool contract.</summary>
    internal static Func<string?, bool>? BuiltInEngineFor { get; set; }

    /// <summary>The engine value that answers without waiting for an external engine.</summary>
    private const string FallbackEngine = "ours";

    /// <summary>The <see cref="EstimateAfter"/> of a new service: 20 s.</summary>
    internal static TimeSpan DefaultEstimateAfter { get; set; } = TimeSpan.FromSeconds(20);

    /// <summary>How long a call waits on a running open before it reports the estimate.</summary>
    internal TimeSpan EstimateAfter { get; set; } = DefaultEstimateAfter;

    /// <summary>The clock of the early-answer wait and of every open's start and seconds.</summary>
    internal TimeProvider Clock { get; set; } = TimeProvider.System;

    /// <summary>When a call that left an engine open running should come back.</summary>
    internal static readonly TimeSpan OpenRetryAfter = TimeSpan.FromSeconds(30);

    /// <summary>The IDA library name import (count, -1 on failure), or null when no IDA session was opened.</summary>
    public Task<int>? LibraryNames(LoadedNative native) => Existing(native, IdaProvider.ProviderId)?.LibraryNames;

    /// <summary>The import of the open Ghidra session's names (the number imported, -1 when it failed), or null when no Ghidra session was opened; does not open one.</summary>
    public Task<int>? GhidraNameLayer(LoadedNative native) => Existing(native, GhidraProvider.ProviderId)?.LibraryNames;

    /// <summary>The last patch application into the image's database of engine <paramref name="id"/>, or null when none ran.</summary>
    public PatchSyncResult? LastPatchSync(LoadedNative native, string id) => Existing(native, id)?.LastSync;

    /// <summary>Whether the image's current patch set is served by a separate analysis of the patched bytes (engine <paramref name="id"/>'s database could not take it).</summary>
    public bool ServesPatchedCopy(LoadedNative native, string id) =>
        Existing(native, id) is { Patched: not null } h && h.PatchedState == h.SyncedKey;

    /// <summary>One engine session's status: opening (Stage, Seconds), open (Session), failed (Error) or closed.</summary>
    public sealed record ImageEngineStatus(string Engine, string State, string? Stage, double Seconds, INativeDecompilerSession? Session, string? Error)
    {
        /// <summary>Seconds the open is expected to take; null without earlier opens of this image.</summary>
        public double? ExpectedSeconds { get; init; }
        /// <summary>What the estimate rests on: earlier opens of this image.</summary>
        public string? ExpectedBasis { get; init; }
        /// <summary>When the open started.</summary>
        public DateTime OpenStarted { get; init; }
        /// <summary>True when a failed open was cancelled rather than failed.</summary>
        public bool Cancelled { get; init; }
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
            // A patched copy still opening is the run a call waits on, not the base open behind it.
            var run = h.Current;
            double seconds = Math.Round((Now - run.Started).TotalSeconds, 1);
            var stages = run.Profile.Stages((Now - run.Started).TotalSeconds);
            if (h.Running != null)
                list.Add(new(id, "opening", run.Stage, seconds, null, null)
                    { OpenStages = stages, ExpectedSeconds = run.Expected?.Seconds, ExpectedBasis = run.Expected?.Basis, OpenStarted = run.Started });
            else if (h.Patched is { IsCompleted: true, IsCompletedSuccessfully: false } bad && h.PatchedState == h.SyncedKey)
                list.Add(new(id, "failed", h.PatchedRun.Stage, seconds, null,
                    bad.Exception?.InnerException is { } pe ? (pe is ToolError pt ? pt.Message : pe.Message) : "cancelled")
                    { OpenStages = stages, OpenStarted = run.Started, Cancelled = bad.IsCanceled || bad.Exception?.InnerException is OperationCanceledException });
            else if (opening.IsCompletedSuccessfully)
            {
                // A patched copy serves the current patch set when the database could not take it.
                var served = h.Patched is { IsCompletedSuccessfully: true } p && h.PatchedState == h.SyncedKey ? p.Result : opening.Result;
                list.Add(new(id, served.IsOpen ? "open" : "closed", null, seconds, served, null) { OpenStages = stages });
            }
            else list.Add(new(id, "failed", run.Stage, seconds, null,
                opening.Exception?.InnerException is { } e ? (e is ToolError t ? t.Message : e.Message) : "cancelled")
                { OpenStages = stages, OpenStarted = run.Started, Cancelled = opening.IsCanceled || opening.Exception?.InnerException is OperationCanceledException });
        }
        return list;
    }

    /// <summary>Records the open's stage as it is reported (synchronously, unlike <see cref="Progress{T}"/>) and passes it on.</summary>
    private sealed class StageProgress(OpenRun run, IProgress<NativeProviderProgress>? next) : IProgress<NativeProviderProgress>
    {
        public void Report(NativeProviderProgress value)
        {
            run.Stage = value.Stage;
            next?.Report(value);
        }
    }

    /// <summary>The image's open session of engine <paramref name="id"/> (null: any, in order of preference), or null; never opens or waits.</summary>
    public INativeDecompilerSession? OpenSession(LoadedNative native, string? id = null) =>
        ImageSessions(native).FirstOrDefault(s => s.State == "open" && (id == null || s.Engine == id))?.Session;

    // A disposed service writes nothing: an open ending later keeps no rate.
    private readonly object _recordGate = new();
    private bool _disposed;

    public void Dispose()
    {
        lock (_recordGate) _disposed = true;
        // Cancel running opens before closing providers, so each worker ends with the server.
        foreach (var (_, set) in _holders) set.Dispose();
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

    /// <summary>One open's start, latest stage, stage timings and estimate.</summary>
    private sealed class OpenRun
    {
        public DateTime Started;
        public volatile string? Stage;
        public long CodeBytes;
        public OpenEstimate.Estimate? Expected;
        public readonly EngineOpenProfile Profile = new();
        /// <summary>The open task whose end is announced to the next reply.</summary>
        public Task? Announced;
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
        /// <summary>The runs of <see cref="Opening"/> and <see cref="Patched"/>, each with its own start, stage and estimate.</summary>
        public OpenRun Run = new(), PatchedRun = new();
        /// <summary>True while the provider's open call runs, before <see cref="Opening"/> holds its task.</summary>
        public volatile bool Starting;
        /// <summary>Ends the base open: cancelled by the image's release or by a cancel call.</summary>
        public CancellationTokenSource? OpenCancel;
        /// <summary>Whether the PDB type load after the last open was timed.</summary>
        public int PdbTimed;

        /// <summary>The open a call waits on: the patched copy while it opens, else the base.</summary>
        public OpenRun Current => PatchedOpen is not null ? PatchedRun : Run;

        private Task? PatchedOpen => Patched is { IsCompleted: false } p ? p : null;

        /// <summary>The open task still running, or null.</summary>
        public Task? Running => PatchedOpen ?? (Opening is { IsCompleted: false } o ? o : null);

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
            try { OpenCancel?.Cancel(); }
            catch (ObjectDisposedException) { }
            var cancel = OpenCancel;
            var running = Running;
            Close(Opening);
            DisposePatched();
            // The running open may still read its token; dispose the source once it settles.
            if (running == null) cancel?.Dispose();
            else running.ContinueWith(_ => cancel?.Dispose(), TaskScheduler.Default);
        }
    }
}
