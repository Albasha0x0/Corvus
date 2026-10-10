using NetDecompilerMcp.Core;
using NetDecompilerMcp.Native.Providers;
using NetDecompilerMcp.Native.Providers.Ida;

namespace NetDecompilerMcp.Services;

/// <summary>
/// The external decompiler engines (IDA through idalib today) and one engine session per loaded native image,
/// opened on first use and closed when the image is unloaded or reloaded.
/// </summary>
public sealed class NativeEngineService : IDisposable
{
    private readonly Lazy<INativeDecompilerProvider> _ida;

    /// <param name="idaOptions">IDA provider settings (install, Python, cache root); null: the defaults.</param>
    public NativeEngineService(IdaProviderOptions? idaOptions = null)
    {
        _ida = new(() => new IdaProvider(idaOptions));
    }

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

    /// <summary>The image's open engine session; the first call opens it (the first open of an image runs auto-analysis).</summary>
    public Task<INativeDecompilerSession> Session(LoadedNative native, string? engine, IProgress<NativeProviderProgress>? progress, CancellationToken ct)
    {
        var holder = native.GetAnalysis(_ => new SessionHolder());
        lock (holder)
        {
            if (holder.Opening is { } existing && !(existing.IsCompleted && (existing.IsFaulted || existing.IsCanceled || !existing.Result.IsOpen)))
                return Wait(existing);
            var provider = Provider(engine);
            // The open is not tied to this call's cancellation (a later call reuses the same analysis) but ends when the image is unloaded or reloaded.
            holder.Opening = provider.OpenAsync(native.FilePath, native.Image.Sha256,
                new NativeOpenOptions { Progress = progress, PdbPath = PdbService.PathForEngines(native) }, native.Released);
            return Wait(holder.Opening);
        }

        async Task<INativeDecompilerSession> Wait(Task<INativeDecompilerSession> opening)
        {
            try { return await opening.WaitAsync(ct); }
            catch (OperationCanceledException) when (!ct.IsCancellationRequested && native.Released.IsCancellationRequested) { throw native.Gone(); }
        }
    }

    public void Dispose()
    {
        if (_ida.IsValueCreated) _ida.Value.Dispose();
    }

    private sealed class SessionHolder : IDisposable
    {
        public Task<INativeDecompilerSession>? Opening;

        public void Dispose()
        {
            if (Opening is { IsCompletedSuccessfully: true } done) done.Result.Dispose();
            else Opening?.ContinueWith(t => { if (t.IsCompletedSuccessfully) t.Result.Dispose(); }, TaskScheduler.Default);
        }
    }
}
