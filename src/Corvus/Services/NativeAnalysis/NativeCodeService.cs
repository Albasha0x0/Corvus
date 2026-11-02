using Microsoft.Extensions.Logging;
using Corvus.Core;
using Corvus.Native.Annotations;
using Corvus.Native.Code;

namespace Corvus.Services;

/// <summary>A native image's code index state: pending, building, ready or failed.</summary>
public readonly record struct IndexState(string State, string? Phase = null, long Done = 0, long Total = 0, string? Error = null)
{
    /// <summary>One line for list_assemblies and server_status.</summary>
    public string Text => State switch
    {
        "building" => $"building: {Phase}" + (Total > 0 ? $" {Done:N0}/{Total:N0}" : Done > 0 ? $" ({Done:N0} instructions)" : ""),
        "failed" => $"failed: {Error}",
        _ => State,
    };
}

/// <summary>Builds each native image's code index once; unload or reload cancels a build.</summary>
public sealed class NativeCodeService
{
    private readonly ILogger<NativeCodeService>? _logger;
    private readonly AnnotationStore _store;
    private readonly AssemblyWorkspace _workspace;
    private readonly bool _background;

    public NativeCodeService(AssemblyWorkspace workspace, ServerOptions options, ILogger<NativeCodeService>? logger = null, AnnotationStore? annotations = null)
    {
        _logger = logger;
        _workspace = workspace;
        _background = options.BackgroundIndexing;
        _store = annotations ?? new AnnotationStore();
        IndexCache = options.CodeIndexCache is { } cache ? new CodeIndexCache(cache) : null;
        if (options.BackgroundIndexing)
            workspace.NativeLoaded += native =>
            {
                // Unloaded again before the event ran: nothing to build.
                try { Holder(native).Start(_logger, this); }
                catch (ToolError) when (native.Released.IsCancellationRequested) { }
            };
    }

    /// <summary>Saved indexes keyed by image bytes and build options; null when the cache is off.</summary>
    public CodeIndexCache? IndexCache { get; }

    /// <summary>The saved index of <paramref name="image"/>, else a fresh build that is saved; <paramref name="complete"/> runs before the save.</summary>
    private NativeCodeIndex LoadOrBuild(Native.INativeImage image, CodeIndexOptions? options, Action<CodeIndexProgress>? progress, CancellationToken ct,
        Action<NativeCodeIndex>? complete = null)
    {
        // A WebAssembly index is rebuilt: it takes seconds and has no walker state to save.
        if (IndexCache is { } cache && image is not Native.WasmImage)
        {
            progress?.Invoke(new CodeIndexProgress("loading saved index", 0, 0));
            if (cache.TryLoad(image, options, ct) is { } loaded)
            {
                complete?.Invoke(loaded);
                progress?.Invoke(new CodeIndexProgress("done", 1, 1));
                return loaded;
            }
        }
        var index = NativeCodeIndex.Build(image, options, progress, ct);
        complete?.Invoke(index);
        if (IndexCache is { } c && !ct.IsCancellationRequested && image is not Native.WasmImage) c.Save(index, options);
        return index;
    }

    private void AddMetadataVirtualCalls(LoadedNative native, NativeCodeIndex index, CancellationToken ct)
    {
        index.SlotTargets = SlotTargets(native, index);
        try { NativeAotCode.AddVirtualCalls(native, index, ct); }
        catch (Exception ex) when (ex is not OperationCanceledException) { _logger?.LogWarning(ex, "Resolving the NativeAOT virtual calls of {Id} failed", native.Id); }
    }

    // Slot calls are read after the metadata is applied, so an earlier read is not kept.
    private static Func<NativeFunction, CancellationToken, IReadOnlyDictionary<uint, string>> SlotTargets(LoadedNative native, NativeCodeIndex index)
    {
        var known = new System.Collections.Concurrent.ConcurrentDictionary<uint, IReadOnlyDictionary<uint, string>>();
        return (fn, ct) =>
        {
            if (AotNativeNames.Of(native) == null) return new Dictionary<uint, string>();
            if (known.TryGetValue(fn.Start, out var hit)) return hit;
            IReadOnlyDictionary<uint, string> found = AotSlotNotes.Calls(native, index, fn, ct).Where(c => c.Target != null).ToDictionary(c => c.Rva, c => c.Target!);
            if (known.Count > 4096) known.Clear();
            return known[fn.Start] = found;
        };
    }

    /// <summary>The image's names and comments, loaded from the sidecar once and refreshed with what other processes saved since.</summary>
    public NativeAnnotations Annotations(LoadedNative native)
    {
        var ann = native.Annotations(n =>
        {
            var created = new NativeAnnotations(_store, n.FilePath, n.OriginalSha256, n.Image.ImageBase, _workspace.Notify);
            created.MergedFromDisk += (names, comments) =>
            {
                // A later build reads them in ApplyAnnotations.
                if (Ready(n) is not { } index) return;
                foreach (var (rva, name) in names) index.SetUserName(rva, name);
                foreach (var (rva, comment) in comments) index.SetUserComment(rva, comment);
            };
            return created;
        });
        ann.Refresh();
        return ann;
    }

    private static readonly System.Runtime.CompilerServices.ConditionalWeakTable<LoadedNative, object> RestoreDone = new();
    private static readonly NativeNameSource[] SavedSources = [NativeNameSource.Pdb, NativeNameSource.Metadata, NativeNameSource.NativeAot];
    private int _layersRestored, _namesRestored, _layersSaved;
    private string? _lastSaveProblem;

    /// <summary>Where annotations and saved imported layers live.</summary>
    public string AnnotationRoot => _store.Root;

    /// <summary>Layers restored, names in them, and layers saved this session; the last save problem.</summary>
    public (int LayersRestored, int NamesRestored, int LayersSaved, string? LastProblem) ImportStats =>
        (Volatile.Read(ref _layersRestored), Volatile.Read(ref _namesRestored), Volatile.Read(ref _layersSaved), Volatile.Read(ref _lastSaveProblem));

    // Runs before the first index build so restored PDB function starts take part in discovery.
    /// <summary>Once per image, restores saved imported name layers not already imported this session; no-op after the first call.</summary>
    public void RestoreImported(LoadedNative native, CancellationToken ct = default)
    {
        if (!RestoreDone.TryAdd(native, new object())) return;
        var layers = NativeNameLayers.Of(native);
        foreach (var source in SavedSources)
        {
            if (layers.Get(source) != null) continue;
            if (_store.LoadLayer(native.OriginalSha256, source, ct) is not { } saved) continue;
            layers.Set(saved, Ready(native));
            Interlocked.Increment(ref _layersRestored);
            Interlocked.Add(ref _namesRestored, saved.Names.Count);
            _logger?.LogInformation("Restored {Count} saved {Source} names of {Id} ({Origin})", saved.Names.Count, source.Id(), native.Id, saved.Origin);
        }
    }

    /// <summary>Saves the image's current layer of <paramref name="source"/> when it carries <see cref="ImportInfo"/>; returns the problem, or null.</summary>
    public string? SaveImported(LoadedNative native, NativeNameSource source)
    {
        // Imported now: an older saved copy is not restored over it.
        RestoreDone.TryAdd(native, new object());
        if (NativeNameLayers.OfOrNull(native)?.Get(source) is not { Info: not null } layer) return null;
        var problem = _store.SaveLayer(native.OriginalSha256, native.FilePath, layer);
        if (problem == null) Interlocked.Increment(ref _layersSaved);
        else
        {
            Volatile.Write(ref _lastSaveProblem, problem);
            _logger?.LogWarning("Saving the {Source} names of {Id} failed: {Problem}", source.Id(), native.Id, problem);
        }
        return problem;
    }

    /// <summary>Deletes the saved layer of <paramref name="source"/>; true when there was one.</summary>
    public bool ForgetImported(LoadedNative native, NativeNameSource source)
    {
        RestoreDone.TryAdd(native, new object());
        return _store.DeleteLayer(native.OriginalSha256, source);
    }

    /// <summary>Mirrors every saved name and comment onto a freshly built index so they show up in queries.</summary>
    public void ApplyAnnotations(LoadedNative native, NativeCodeIndex index)
    {
        RestoreImported(native);
        NativeNameLayers.OfOrNull(native)?.ReplayInto(index);
        if (native.AnnotationsOrNull is not { } ann && (ann = Annotations(native)) is null) return;
        foreach (var (rva, name) in ann.Names()) index.SetUserName(rva, name);
        foreach (var (rva, comment) in ann.Comments()) index.SetUserComment(rva, comment);
    }

    /// <summary>How often a caller waiting for an index hears its phase again when the build reports nothing new.</summary>
    internal static readonly TimeSpan ProgressHeartbeat = TimeSpan.FromSeconds(5);

    /// <summary>Repeats the latest progress every <paramref name="every"/>, so a slow phase still shows the server is working.</summary>
    internal static IDisposable Heartbeat(Func<CodeIndexProgress?> latest, IProgress<CodeIndexProgress> progress, TimeSpan every) =>
        new ProgressBeat(latest, progress, every);

    /// <summary>Once disposed it reports nothing more, so no progress follows the call's result.</summary>
    private sealed class ProgressBeat : IDisposable
    {
        private readonly Timer _timer;
        private readonly object _gate = new();
        private bool _stopped;

        public ProgressBeat(Func<CodeIndexProgress?> latest, IProgress<CodeIndexProgress> progress, TimeSpan every) =>
            _timer = new Timer(_ =>
            {
                lock (_gate)
                    if (!_stopped) progress.Report(latest() ?? new CodeIndexProgress("starting", 0, 0));
            }, null, every, every);

        public void Dispose()
        {
            lock (_gate) _stopped = true;
            _timer.Dispose();
        }
    }

    /// <summary>The image's index, building it if needed; progress reports the build phase while the caller waits.</summary>
    public Task<NativeCodeIndex> Index(LoadedNative native, IProgress<CodeIndexProgress>? progress, CancellationToken ct) =>
        Index(native, progress, ct, null, null);

    /// <summary>
    /// Resolves <paramref name="image"/> (loading a path) and returns its index.
    /// Waits <paramref name="waitSeconds"/> at most, else until the build makes no
    /// progress for <paramref name="stall"/> (default <see cref="Deadlines.Soft"/>); then a retryable timeout names the phase.
    /// </summary>
    public async Task<(LoadedNative Native, NativeCodeIndex Index)> Open(string image, IProgress<CodeIndexProgress>? progress, CancellationToken ct,
        int? waitSeconds = null, TimeSpan? stall = null)
    {
        var native = await Task.Run(() => Targets.Native(_workspace, image), ct);
        return (native, await Index(native, progress, ct, waitSeconds is { } s ? TimeSpan.FromSeconds(s) : null, stall ?? Deadlines.Soft));
    }

    /// <summary>The index state of <paramref name="native"/>; pending when no build started.</summary>
    public IndexState StateOf(LoadedNative native) =>
        native.Analysis.TryGetValue(typeof(IndexHolder), out var h) ? ((IndexHolder)h).State : new IndexState("pending");

    /// <summary>Callers waiting on the build of <paramref name="native"/> now.</summary>
    internal int Waiting(LoadedNative native) =>
        native.Analysis.TryGetValue(typeof(IndexHolder), out var h) ? Volatile.Read(ref ((IndexHolder)h).Waiters) : 0;

    /// <summary>
    /// Waits up to <paramref name="wait"/> for the builds under way of <paramref name="natives"/>.
    /// Builds still running after it will announce their end.
    /// </summary>
    public async Task WaitBuilding(IEnumerable<LoadedNative> natives, TimeSpan wait, CancellationToken ct)
    {
        var running = natives.Where(n => StateOf(n).State == "building").Select(n => Holder(n)).ToList();
        if (running.Count == 0) return;
        if (wait > TimeSpan.Zero)
        {
            var all = Task.WhenAll(running.Select(h => h.Task!.ContinueWith(_ => { }, TaskScheduler.Default)));
            using var stop = CancellationTokenSource.CreateLinkedTokenSource(ct);
            await Task.WhenAny(all, Task.Delay(wait, stop.Token));
            stop.Cancel();
            ct.ThrowIfCancellationRequested();
        }
        foreach (var h in running)
            if (!h.Task!.IsCompleted) h.Announce = true;
    }

    /// <summary>
    /// Waits until <paramref name="build"/> ends; false when <paramref name="cap"/> passes
    /// or <paramref name="stall"/> passes without progress. Cancellation throws.
    /// </summary>
    private static async Task<bool> Ended(Task build, IndexHolder holder, TimeSpan? cap, TimeSpan? stall, CancellationToken ct)
    {
        long started = Environment.TickCount64;
        while (!build.IsCompleted)
        {
            long now = Environment.TickCount64;
            var left = TimeSpan.FromDays(1);
            if (cap is { } c) left = c - TimeSpan.FromMilliseconds(now - started);
            if (stall is { } s) left = TimeSpan.FromTicks(Math.Min(left.Ticks, (s - TimeSpan.FromMilliseconds(now - Volatile.Read(ref holder.Touched))).Ticks));
            if (left <= TimeSpan.Zero) return false;
            using var stop = CancellationTokenSource.CreateLinkedTokenSource(ct);
            bool done = await Task.WhenAny(build, Task.Delay(left, stop.Token)) == build;
            stop.Cancel();
            ct.ThrowIfCancellationRequested();
            if (done) return true;
        }
        return true;
    }

    private async Task<NativeCodeIndex> Index(LoadedNative native, IProgress<CodeIndexProgress>? progress, CancellationToken ct, TimeSpan? cap, TimeSpan? stall)
    {
        var holder = Holder(native);
        // Boxed: written by the build thread.
        object? last = null;
        Action<CodeIndexProgress> listener = p => { Volatile.Write(ref last, p); progress?.Report(p); };
        holder.Progress += listener;
        var build = holder.Start(_logger, this);
        Interlocked.Increment(ref holder.Waiters);
        bool counted = true;
        void Leave()
        {
            if (counted) Interlocked.Decrement(ref holder.Waiters);
            counted = false;
        }
        using var heartbeat = progress == null || build.IsCompleted ? null
            : Heartbeat(() => Volatile.Read(ref last) as CodeIndexProgress?, progress, ProgressHeartbeat);
        ToolError? running = null;
        try
        {
            if ((cap != null || stall != null) && !build.IsCompleted && !await Ended(build, holder, cap, stall, ct))
            {
                // Announce and leave first, then check the end again, so no end is lost.
                holder.Announce = true;
                Leave();
                if (!build.IsCompleted) throw running = Building(native, holder.State, cap, stall);
            }
            return await build.WaitAsync(ct);
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            // The build was cancelled because the image was unloaded, reloaded or patched by another call.
            var gone = native.Gone();
            if (Volatile.Read(ref last) is CodeIndexProgress reached) gone.Partial = new { image = native.Id, indexPhase = reached.Phase, done = reached.Done, total = reached.Total };
            throw gone;
        }
        catch (Exception ex) when (build.IsFaulted && ex != running && ex is not OperationCanceledException and not ToolError { Retryable: true })
        {
            throw new ToolError(ErrorCode.Failed, $"Indexing {native.Id} failed: {ex.Message}", $"reload_assembly assembly={native.Id} builds the index again");
        }
        finally
        {
            Leave();
            holder.Progress -= listener;
        }
    }

    private static ToolError Building(LoadedNative native, IndexState state, TimeSpan? cap, TimeSpan? stall) =>
        new(ErrorCode.Timeout, $"{native.Id} is still indexing {(cap is { } c ? $"after {c.TotalSeconds:0} s" : $"with no progress for {stall!.Value.TotalSeconds:0} s")} ({state.Text}); the build goes on in the background and a [workspace] notice reports its end.",
            $"list_assemblies filter={native.Id} waitSeconds=60 waits for the end; repeat this call once it is ready")
        {
            Details = new { image = native.Id, indexState = state.State, phase = state.Phase, done = state.Done, total = state.Total },
            RetryAfter = TimeSpan.FromSeconds(30),
        };

    /// <summary>A one-off index over the image's pre-patch bytes, for patch migration; not cached in memory.</summary>
    public NativeCodeIndex IndexOfOriginal(LoadedNative native, CancellationToken ct)
    {
        var original = native.Patches.OriginalImage(native.Image, native.FilePath);
        return LoadOrBuild(original, BuildOptions(native, ct), null, ct);
    }

    /// <summary>The index when built, else null; never starts a build.</summary>
    public NativeCodeIndex? Ready(LoadedNative native) =>
        native.Analysis.TryGetValue(typeof(IndexHolder), out var h) && ((IndexHolder)h).Task is { IsCompletedSuccessfully: true } t ? t.Result : null;

    private static IndexHolder Holder(LoadedNative native) => native.GetAnalysis(n => new IndexHolder(n));

    /// <summary>The analysis of the image before its last patch (kept by <see cref="Patched"/>), and that analysis over the current bytes.</summary>
    private sealed record PriorIndex(NativeCodeIndex Index);
    private sealed record RebasedIndex(NativeCodeIndex Index);

    /// <summary>After a patch, keeps <paramref name="previous"/> for previews and starts the rebuild when indexing runs in the background.</summary>
    public void Patched(LoadedNative native, NativeCodeIndex? previous)
    {
        if (previous != null) native.Analysis[typeof(PriorIndex)] = new PriorIndex(previous);
        if (!_background) return;
        try { Holder(native).Start(_logger, this, retryFailed: true); }
        catch (ToolError) when (native.Released.IsCancellationRequested) { }
    }

    /// <summary>The built index; else, after a patch, the prior analysis over the current bytes; else null.</summary>
    public NativeCodeIndex? Provisional(LoadedNative native)
    {
        if (Ready(native) is { } ready) return ready;
        if (!native.Analysis.TryGetValue(typeof(PriorIndex), out var prior)) return null;
        var image = native.Image;
        return native.GetAnalysis(n =>
        {
            var rebased = ((PriorIndex)prior).Index.Rebase(image);
            ApplyAnnotations(n, rebased);
            return new RebasedIndex(rebased);
        }).Index;
    }

    /// <summary>Function starts from debug symbols for a build of <paramref name="native"/>, asked on the build thread; null when none.</summary>
    public Func<LoadedNative, CancellationToken, IReadOnlyCollection<uint>?>? SymbolStarts { get; set; }

    internal CodeIndexOptions? BuildOptions(LoadedNative native, CancellationToken ct)
    {
        IReadOnlyCollection<uint>? starts;
        try { RestoreImported(native, ct); }
        catch (Exception ex) when (ex is not OperationCanceledException) { _logger?.LogWarning(ex, "Restoring the saved names of {Id} failed", native.Id); }
        try { starts = SymbolStarts?.Invoke(native, ct); }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger?.LogWarning(ex, "Reading debug symbols of {Id} failed", native.Id);
            starts = null;
        }
        // A saved PDB layer whose PDB is gone still contributes its function starts.
        if (starts == null && NativeNameLayers.OfOrNull(native)?.Get(NativeNameSource.Pdb)?.Info?.FunctionStarts is { Count: > 0 } saved) starts = saved;
        try
        {
            if (NativeAotNames.AutoApply(native, this, ct) is { Count: > 0 } aot) starts = [.. starts ?? [], .. aot];
        }
        catch (Exception ex) when (ex is not OperationCanceledException) { _logger?.LogWarning(ex, "Naming the NativeAOT image {Id} failed", native.Id); }
        try
        {
            if (AppleNames.AutoApply(native, this, ct) is { Count: > 0 } apple) starts = [.. starts ?? [], .. apple];
        }
        catch (Exception ex) when (ex is not OperationCanceledException) { _logger?.LogWarning(ex, "Naming the Mach-O image {Id} from its ObjC / Swift metadata failed", native.Id); }
        try
        {
            if (DartNames.AutoApply(native, this, ct) is { Count: > 0 } dart) starts = [.. starts ?? [], .. dart];
        }
        catch (Exception ex) when (ex is not OperationCanceledException) { _logger?.LogWarning(ex, "Naming the Dart AOT image {Id} from its snapshot failed", native.Id); }
        // The native bodies of a mixed-mode assembly's methods are function starts.
        if (native.ManagedView is { } asm)
            starts = [.. starts ?? [], .. Native.Linking.MixedModeMap.Build(asm.Module, ct).Bodies.Values.Distinct()];
        return starts is { Count: > 0 } ? new CodeIndexOptions { SymbolStarts = starts } : null;
    }

    /// <summary>Rebuilds the index in the background, replacing the current one when ready; dropped if the image changed meanwhile.</summary>
    public Task Rebuild(LoadedNative native)
    {
        var image = native.Image;
        var next = new IndexHolder(native);
        return next.Start(_logger, this).ContinueWith(done =>
        {
            if (done.IsCompletedSuccessfully && ReferenceEquals(done.Result.Image, native.Image) && ReferenceEquals(image, native.Image)
                && native.Analysis.TryGetValue(typeof(IndexHolder), out var old) && native.Analysis.TryUpdate(typeof(IndexHolder), next, old))
                return;
            next.Dispose();
        }, TaskScheduler.Default);
    }

    private sealed class IndexHolder(LoadedNative native) : IDisposable
    {
        private readonly CancellationTokenSource _cts = new();
        public Task<NativeCodeIndex>? Task { get; private set; }

        /// <summary>Callers waiting on the build now.</summary>
        public int Waiters;

        public volatile bool Announce;

        /// <summary>Environment.TickCount64 of the latest build progress.</summary>
        public long Touched = Environment.TickCount64;
        private object? _last;
        private string? _failure;
        private bool _transient;

        public IndexState State => Task switch
        {
            null => new("pending"),
            { IsCompletedSuccessfully: true } => new("ready"),
            { IsFaulted: true } => new("failed", Error: _failure),
            { IsCanceled: true } => new("pending"),
            _ => _last is CodeIndexProgress p ? new("building", p.Phase, p.Done, p.Total) : new("building", "starting"),
        };

        /// <summary>Progress of the build, for every caller waiting on it.</summary>
        public event Action<CodeIndexProgress>? Progress;

        public Task<NativeCodeIndex> Start(ILogger? logger, NativeCodeService owner, bool retryFailed = false)
        {
            lock (this)
            {
                // A failure repeats until reload or patch unless transient.
                // A cancelled build restarts only while the image is loaded.
                if (Task is { } t && !(t.IsFaulted && (retryFailed || _transient) || t.IsCanceled && !_cts.IsCancellationRequested)) return t;
                var ct = _cts.Token;
                Volatile.Write(ref Touched, Environment.TickCount64);
                return Task = System.Threading.Tasks.Task.Run(() => owner.LoadOrBuild(native.Image, owner.BuildOptions(native, ct), p => { Volatile.Write(ref _last, p); Volatile.Write(ref Touched, Environment.TickCount64); Progress?.Invoke(p); }, ct,
                        index => owner.AddMetadataVirtualCalls(native, index, ct)), ct)
                    .ContinueWith(done =>
                    {
                        if (done.IsCompletedSuccessfully)
                        {
                            // Preview stand-ins are dropped once the real index is there.
                            native.Analysis.TryRemove(typeof(PriorIndex), out _);
                            native.Analysis.TryRemove(typeof(RebasedIndex), out _);
                            try { owner.ApplyAnnotations(native, done.Result); }
                            catch (Exception ex) { logger?.LogWarning(ex, "Applying annotations to {Id} failed", native.Id); }
                            try { NodeApiNames.AutoApply(native, done.Result, ct); }
                            catch (Exception ex) when (ex is not OperationCanceledException) { logger?.LogWarning(ex, "Naming the Node-API callbacks of {Id} failed", native.Id); }
                            try { NativeAotNames.NameStaticFields(native, owner, done.Result, ct); }
                            catch (Exception ex) when (ex is not OperationCanceledException) { logger?.LogWarning(ex, "Naming the NativeAOT static fields of {Id} failed", native.Id); }
                            if (done.Result.LoadedFromCache)
                                logger?.LogInformation("Loaded the saved index of {Id}: {Functions} functions, {Xrefs} references in {Seconds:0.0} s", native.Id,
                                    done.Result.Stats.Functions, done.Result.Stats.Xrefs, done.Result.CacheLoadTime.TotalSeconds);
                            else
                                logger?.LogInformation("Indexed {Id}: {Functions} functions, {Xrefs} references in {Seconds:0.0} s", native.Id,
                                    done.Result.Stats.Functions, done.Result.Stats.Xrefs, done.Result.Stats.Elapsed.TotalSeconds);
                        }
                        else if (done.Exception is { } ex)
                        {
                            var cause = ex.GetBaseException();
                            _failure = cause.Message;
                            // Reading the image or the saved index can fail once and
                            // succeed on a repeat.
                            _transient = cause is IOException or OutOfMemoryException or ToolError { Retryable: true };
                            logger?.LogWarning(cause, "Indexing {Id} failed", native.Id);
                        }
                        Announced(owner, native, done);
                        return done;
                    }, TaskScheduler.Default).Unwrap();
            }
        }

        /// <summary>Announces the end of a build a caller left; none when a caller waits or the build was superseded.</summary>
        private void Announced(NativeCodeService owner, LoadedNative image, Task<NativeCodeIndex> done)
        {
            if (!Announce || Volatile.Read(ref Waiters) > 0 || done.IsCanceled) return;
            owner._workspace.Notify(done.IsCompletedSuccessfully
                ? $"{image.Id} is indexed. Next: list_functions image={image.Id}"
                : $"Indexing {image.Id} failed: {_failure}. Next: reload_assembly assembly={image.Id} builds the index again.");
        }

        public void Dispose()
        {
            try { _cts.Cancel(); }
            catch (ObjectDisposedException) { }
        }
    }
}
