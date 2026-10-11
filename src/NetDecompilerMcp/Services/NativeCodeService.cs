using Microsoft.Extensions.Logging;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Native.Annotations;
using NetDecompilerMcp.Native.Code;

namespace NetDecompilerMcp.Services;

/// <summary>
/// Builds each native image's code index (functions, cross-references, strings) once, on a background thread
/// right after loading when background indexing is on, else on first use. Tools wait for it with progress;
/// unloading or reloading the image cancels a build in progress.
/// </summary>
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

    /// <summary>Saved indexes (null when the cache is off): an image whose bytes and build options were indexed before loads instead of building.</summary>
    public CodeIndexCache? IndexCache { get; }

    /// <summary>The saved index of <paramref name="image"/> when the cache has one, else a fresh build (then saved).</summary>
    private NativeCodeIndex LoadOrBuild(Native.INativeImage image, CodeIndexOptions? options, Action<CodeIndexProgress>? progress, CancellationToken ct)
    {
        if (IndexCache is { } cache)
        {
            progress?.Invoke(new CodeIndexProgress("loading saved index", 0, 0));
            if (cache.TryLoad(image, options, ct) is { } loaded)
            {
                progress?.Invoke(new CodeIndexProgress("done", 1, 1));
                return loaded;
            }
        }
        var index = NativeCodeIndex.Build(image, options, progress, ct);
        if (IndexCache is { } c && !ct.IsCancellationRequested) c.Save(index, options);
        return index;
    }

    /// <summary>
    /// The image's annotations (names and comments), loaded from the sidecar on first use and refreshed with what other
    /// processes saved since (a file stat when nothing changed).
    /// </summary>
    public NativeAnnotations Annotations(LoadedNative native)
    {
        var ann = native.Annotations(n =>
        {
            var created = new NativeAnnotations(_store, n.FilePath, n.OriginalSha256, n.Image.ImageBase, _workspace.Notify);
            created.MergedFromDisk += (names, comments) =>
            {
                if (Ready(n) is not { } index) return; // a later build reads them in ApplyAnnotations
                foreach (var (rva, name) in names) index.SetUserName(rva, name);
                foreach (var (rva, comment) in comments) index.SetUserComment(rva, comment);
            };
            return created;
        });
        ann.Refresh();
        return ann;
    }

    private static readonly System.Runtime.CompilerServices.ConditionalWeakTable<LoadedNative, object> RestoreDone = new();
    private static readonly NativeNameSource[] SavedSources = [NativeNameSource.Pdb, NativeNameSource.Il2Cpp, NativeNameSource.NativeAot];
    private int _layersRestored, _namesRestored, _layersSaved;
    private string? _lastSaveProblem;

    /// <summary>Where annotations and saved imported layers live.</summary>
    public string AnnotationRoot => _store.Root;

    /// <summary>Layers restored, names in them, and layers saved this session; the last save problem.</summary>
    public (int LayersRestored, int NamesRestored, int LayersSaved, string? LastProblem) ImportStats =>
        (Volatile.Read(ref _layersRestored), Volatile.Read(ref _namesRestored), Volatile.Read(ref _layersSaved), Volatile.Read(ref _lastSaveProblem));

    /// <summary>
    /// Once per loaded image: reads the saved imported layers (PDB, Il2Cpp, NativeAOT names) back into <see cref="NativeNameLayers"/>,
    /// except a source already imported in this session. Runs before the first index build so restored PDB function starts
    /// take part in discovery; tools that report layers call it too. Cheap after the first call.
    /// </summary>
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
        RestoreDone.TryAdd(native, new object()); // imported now: an older saved copy is not restored over it
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

    /// <summary>The image's index, building it if needed; progress reports the build phase while the caller waits.</summary>
    public async Task<NativeCodeIndex> Index(LoadedNative native, IProgress<CodeIndexProgress>? progress, CancellationToken ct)
    {
        var holder = Holder(native);
        object? last = null; // boxed: written by the build thread
        Action<CodeIndexProgress> listener = p => { Volatile.Write(ref last, p); progress?.Report(p); };
        holder.Progress += listener;
        try { return await holder.Start(_logger, this).WaitAsync(ct); }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            // The build was cancelled because the image was unloaded, reloaded or patched by another call.
            var gone = native.Gone();
            if (Volatile.Read(ref last) is CodeIndexProgress reached) gone.Partial = new { image = native.Id, indexPhase = reached.Phase, done = reached.Done, total = reached.Total };
            throw gone;
        }
        finally { holder.Progress -= listener; }
    }

    /// <summary>
    /// A one-off index over the image's original (pre-patch) bytes, with the same symbol starts the live index uses.
    /// Patch migration matches the clean old build so in-memory patches do not hide a function's identity. Not cached.
    /// </summary>
    public NativeCodeIndex IndexOfOriginal(LoadedNative native, CancellationToken ct)
    {
        var original = Native.Pe.PeFile.FromBytes(native.Patches.OriginalBytes(), native.FilePath);
        return LoadOrBuild(original, BuildOptions(native, ct), null, ct);
    }

    /// <summary>The index when it is already built, else null (does not start a build).</summary>
    public NativeCodeIndex? Ready(LoadedNative native) =>
        native.Analysis.TryGetValue(typeof(IndexHolder), out var h) && ((IndexHolder)h).Task is { IsCompletedSuccessfully: true } t ? t.Result : null;

    private static IndexHolder Holder(LoadedNative native) => native.GetAnalysis(n => new IndexHolder(n));

    /// <summary>The analysis of the image before its last patch (kept by <see cref="Patched"/>), and that analysis over the current bytes.</summary>
    private sealed record PriorIndex(NativeCodeIndex Index);
    private sealed record RebasedIndex(NativeCodeIndex Index);

    /// <summary>
    /// After a patch replaced the image: keeps <paramref name="previous"/> (<see cref="Provisional"/> before the patch) so
    /// previews need not wait for the rebuild, which starts now when indexing runs in the background.
    /// </summary>
    public void Patched(LoadedNative native, NativeCodeIndex? previous)
    {
        if (previous != null) native.Analysis[typeof(PriorIndex)] = new PriorIndex(previous);
        if (!_background) return;
        try { Holder(native).Start(_logger, this); }
        catch (ToolError) when (native.Released.IsCancellationRequested) { }
    }

    /// <summary>
    /// The index when it is built; else, after a patch, the analysis from before it over the current bytes (functions as
    /// they were, instructions as they are now) without waiting for the rebuild; else null.
    /// </summary>
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

    // ---- debug symbols (PdbService) ----

    /// <summary>Function starts from debug symbols for a build of <paramref name="native"/>, asked on the build thread; null when none.</summary>
    public Func<LoadedNative, CancellationToken, IReadOnlyCollection<uint>?>? SymbolStarts { get; set; }

    private CodeIndexOptions? BuildOptions(LoadedNative native, CancellationToken ct)
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
        // The native bodies of a mixed-mode assembly's methods are function starts.
        if (native.ManagedView is { } asm)
            starts = [.. starts ?? [], .. Native.Linking.MixedModeMap.Build(asm.Module, ct).Bodies.Values.Distinct()];
        return starts is { Count: > 0 } ? new CodeIndexOptions { SymbolStarts = starts } : null;
    }

    /// <summary>
    /// Builds the index again in the background (new symbol starts); the current index keeps answering until the new
    /// one is ready and replaces it. Dropped when the image changed meanwhile.
    /// </summary>
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

        /// <summary>Progress of the build, for every caller waiting on it.</summary>
        public event Action<CodeIndexProgress>? Progress;

        public Task<NativeCodeIndex> Start(ILogger? logger, NativeCodeService owner)
        {
            lock (this)
            {
                // A failed build is retried on the next request; a cancelled one only while the image is still loaded.
                if (Task is { } t && !(t.IsFaulted || t.IsCanceled && !_cts.IsCancellationRequested)) return t;
                var ct = _cts.Token;
                return Task = System.Threading.Tasks.Task.Run(() => owner.LoadOrBuild(native.Image, owner.BuildOptions(native, ct), p => Progress?.Invoke(p), ct), ct)
                    .ContinueWith(done =>
                    {
                        if (done.IsCompletedSuccessfully)
                        {
                            // the stand-ins for previews are not needed once the real index is there
                            native.Analysis.TryRemove(typeof(PriorIndex), out _);
                            native.Analysis.TryRemove(typeof(RebasedIndex), out _);
                            try { owner.ApplyAnnotations(native, done.Result); }
                            catch (Exception ex) { logger?.LogWarning(ex, "Applying annotations to {Id} failed", native.Id); }
                            if (done.Result.LoadedFromCache)
                                logger?.LogInformation("Loaded the saved index of {Id}: {Functions} functions, {Xrefs} references in {Seconds:0.0} s", native.Id,
                                    done.Result.Stats.Functions, done.Result.Stats.Xrefs, done.Result.CacheLoadTime.TotalSeconds);
                            else
                                logger?.LogInformation("Indexed {Id}: {Functions} functions, {Xrefs} references in {Seconds:0.0} s", native.Id,
                                    done.Result.Stats.Functions, done.Result.Stats.Xrefs, done.Result.Stats.Elapsed.TotalSeconds);
                        }
                        else if (done.Exception is { } ex)
                            logger?.LogWarning(ex.GetBaseException(), "Indexing {Id} failed", native.Id);
                        return done;
                    }, TaskScheduler.Default).Unwrap();
            }
        }

        public void Dispose()
        {
            try { _cts.Cancel(); }
            catch (ObjectDisposedException) { }
        }
    }
}
