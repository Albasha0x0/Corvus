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
            workspace.NativeLoaded += native => Holder(native).Start(_logger);
    }

    /// <summary>The image's index, building it if needed; progress reports the build phase while the caller waits.</summary>
    public async Task<NativeCodeIndex> Index(LoadedNative native, IProgress<CodeIndexProgress>? progress, CancellationToken ct)
    {
        var holder = Holder(native);
        holder.Listen(progress);
        try { return await holder.Start(_logger).WaitAsync(ct); }
        finally { holder.Listen(null); }
    }

    /// <summary>The index when it is already built, else null (does not start a build).</summary>
    public NativeCodeIndex? Ready(LoadedNative native) =>
        Holder(native).Task is { IsCompletedSuccessfully: true } t ? t.Result : null;

    private static IndexHolder Holder(LoadedNative native) => native.GetAnalysis(n => new IndexHolder(n));

    private sealed class IndexHolder(LoadedNative native) : IDisposable
    {
        private readonly CancellationTokenSource _cts = new();
        private IProgress<CodeIndexProgress>? _listener;
        public Task<NativeCodeIndex>? Task { get; private set; }

        public void Listen(IProgress<CodeIndexProgress>? progress) => _listener = progress;

        public Task<NativeCodeIndex> Start(ILogger? logger)
        {
            lock (this)
            {
                // A failed or cancelled build is retried on the next request.
                if (Task is { } t && !(t.IsFaulted || t.IsCanceled)) return t;
                return Task = NativeCodeIndex.BuildAsync(native.Image, null, p => _listener?.Report(p), _cts.Token)
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
