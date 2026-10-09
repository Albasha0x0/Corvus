using Microsoft.Extensions.Logging;
using NetDecompilerMcp.Core;
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

    public NativeCodeService(AssemblyWorkspace workspace, ServerOptions options, ILogger<NativeCodeService>? logger = null)
    {
        _logger = logger;
        if (options.BackgroundIndexing)
            workspace.NativeLoaded += native =>
            {
                // Unloaded again before the event ran: nothing to build.
                try { Holder(native).Start(_logger); }
                catch (ToolError) when (native.Released.IsCancellationRequested) { }
            };
    }

    /// <summary>The image's index, building it if needed; progress reports the build phase while the caller waits.</summary>
    public async Task<NativeCodeIndex> Index(LoadedNative native, IProgress<CodeIndexProgress>? progress, CancellationToken ct)
    {
        var holder = Holder(native);
        Action<CodeIndexProgress>? listener = progress != null ? progress.Report : null;
        holder.Progress += listener;
        try { return await holder.Start(_logger).WaitAsync(ct); }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested && native.Released.IsCancellationRequested)
        {
            // The build was cancelled by an unload or reload, not by this caller.
            throw native.Gone();
        }
        finally { holder.Progress -= listener; }
    }

    /// <summary>The index when it is already built, else null (does not start a build).</summary>
    public NativeCodeIndex? Ready(LoadedNative native) =>
        native.Analysis.TryGetValue(typeof(IndexHolder), out var h) && ((IndexHolder)h).Task is { IsCompletedSuccessfully: true } t ? t.Result : null;

    private static IndexHolder Holder(LoadedNative native) => native.GetAnalysis(n => new IndexHolder(n));

    private sealed class IndexHolder(LoadedNative native) : IDisposable
    {
        private readonly CancellationTokenSource _cts = new();
        public Task<NativeCodeIndex>? Task { get; private set; }

        /// <summary>Progress of the build, for every caller waiting on it.</summary>
        public event Action<CodeIndexProgress>? Progress;

        public Task<NativeCodeIndex> Start(ILogger? logger)
        {
            lock (this)
            {
                // A failed build is retried on the next request; a cancelled one only while the image is still loaded.
                if (Task is { } t && !(t.IsFaulted || t.IsCanceled && !_cts.IsCancellationRequested)) return t;
                return Task = NativeCodeIndex.BuildAsync(native.Image, null, p => Progress?.Invoke(p), _cts.Token)
                    .ContinueWith(done =>
                    {
                        if (done.IsCompletedSuccessfully)
                            logger?.LogInformation("Indexed {Id}: {Functions} functions, {Xrefs} references in {Seconds:0.0} s", native.Id,
                                done.Result.Stats.Functions, done.Result.Stats.Xrefs, done.Result.Stats.Elapsed.TotalSeconds);
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
