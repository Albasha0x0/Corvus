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

    public NativeCodeService(AssemblyWorkspace workspace, ServerOptions options, ILogger<NativeCodeService>? logger = null, AnnotationStore? annotations = null)
    {
        _logger = logger;
        _store = annotations ?? new AnnotationStore();
        if (options.BackgroundIndexing)
            workspace.NativeLoaded += native =>
            {
                // Unloaded again before the event ran: nothing to build.
                try { Holder(native).Start(_logger, this); }
                catch (ToolError) when (native.Released.IsCancellationRequested) { }
            };
    }

    /// <summary>The image's annotations (names and comments), loaded from the sidecar on first use.</summary>
    public NativeAnnotations Annotations(LoadedNative native) =>
        native.Annotations(n => new NativeAnnotations(_store, n.FilePath, n.OriginalSha256, n.Image.ImageBase));

    /// <summary>Mirrors every saved name and comment onto a freshly built index so they show up in queries.</summary>
    public void ApplyAnnotations(LoadedNative native, NativeCodeIndex index)
    {
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
        return NativeCodeIndex.Build(original, BuildOptions(native, ct), null, ct);
    }

    /// <summary>The index when it is already built, else null (does not start a build).</summary>
    public NativeCodeIndex? Ready(LoadedNative native) =>
        native.Analysis.TryGetValue(typeof(IndexHolder), out var h) && ((IndexHolder)h).Task is { IsCompletedSuccessfully: true } t ? t.Result : null;

    private static IndexHolder Holder(LoadedNative native) => native.GetAnalysis(n => new IndexHolder(n));

    // ---- debug symbols (PdbService) ----

    /// <summary>Function starts from debug symbols for a build of <paramref name="native"/>, asked on the build thread; null when none.</summary>
    public Func<LoadedNative, CancellationToken, IReadOnlyCollection<uint>?>? SymbolStarts { get; set; }

    private CodeIndexOptions? BuildOptions(LoadedNative native, CancellationToken ct)
    {
        IReadOnlyCollection<uint>? starts;
        try { starts = SymbolStarts?.Invoke(native, ct); }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger?.LogWarning(ex, "Reading debug symbols of {Id} failed", native.Id);
            starts = null;
        }
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
                return Task = System.Threading.Tasks.Task.Run(() => NativeCodeIndex.Build(native.Image, owner.BuildOptions(native, ct), p => Progress?.Invoke(p), ct), ct)
                    .ContinueWith(done =>
                    {
                        if (done.IsCompletedSuccessfully)
                        {
                            try { owner.ApplyAnnotations(native, done.Result); }
                            catch (Exception ex) { logger?.LogWarning(ex, "Applying annotations to {Id} failed", native.Id); }
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
