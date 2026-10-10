using NetDecompilerMcp.Native.Annotations;
using NetDecompilerMcp.Native.Patching;
using NetDecompilerMcp.Native.Pe;

namespace NetDecompilerMcp.Core;

/// <summary>A native PE image in the workspace (no .NET metadata, or loaded for its native code).</summary>
public sealed class LoadedNative
{
    private readonly object _gate = new();
    private readonly CancellationTokenSource _released = new();

    internal LoadedNative(string id, string filePath, PeFile image)
    {
        Id = id;
        FilePath = filePath;
        Image = image;
        OriginalSha256 = image.Sha256;
    }

    /// <summary>Unique handle used in tool calls (shared with assembly ids); the file name, suffixed #n on collision.</summary>
    public string Id { get; }
    public string FilePath { get; }

    /// <summary>
    /// For the native view of a mixed-mode (C++/CLI) assembly: the assembly, loaded from the same file, whose lifetime
    /// this view follows (unloaded and reloaded with it). Null for plain native images.
    /// </summary>
    public LoadedAssembly? ManagedView { get; internal init; }

    /// <summary>The current image: the file as loaded, or, once bytes have been patched in memory, the patched image.</summary>
    public PeFile Image { get; private set; }

    /// <summary>SHA-256 of the file as first loaded; the key for annotations, stable across in-memory patches.</summary>
    public string OriginalSha256 { get; }

    /// <summary>Cancelled when the image is unloaded or reloaded.</summary>
    public CancellationToken Released => _released.Token;

    /// <summary>Per-image analysis state (code index, engine sessions); created on first use and cleared on a patch.</summary>
    public System.Collections.Concurrent.ConcurrentDictionary<Type, object> Analysis { get; } = new();

    /// <summary>
    /// The analysis of type <typeparamref name="T"/>, created on first use. Disposable state (background builds, engine
    /// sessions) is not kept for an image that was unloaded or reloaded meanwhile: it is disposed and the call fails.
    /// </summary>
    public T GetAnalysis<T>(Func<LoadedNative, T> create) where T : class
    {
        var value = (T)Analysis.GetOrAdd(typeof(T), _ => create(this));
        if (value is IDisposable && _released.IsCancellationRequested)
        {
            if (Analysis.TryRemove(typeof(T), out var removed)) ((IDisposable)removed).Dispose();
            throw Gone();
        }
        return value;
    }

    /// <summary>The error for a call whose analysis was discarded while it ran (image unloaded, reloaded or patched).</summary>
    public ToolError Gone() =>
        new(ErrorCode.Conflict, $"{Id} was unloaded, reloaded or patched while the call was running.", "repeat the call; the image is analyzed afresh");

    /// <summary>Marks the image unloaded and disposes its analysis state (cancels a code index build, ends engine sessions).</summary>
    internal void Release()
    {
        _released.Cancel();
        DisposeAnalysis();
    }

    /// <summary>Removes and disposes every analysis object (each exactly once, also under concurrent calls).</summary>
    private void DisposeAnalysis()
    {
        foreach (var key in Analysis.Keys)
            if (Analysis.TryRemove(key, out var analysis) && analysis is IDisposable d) d.Dispose();
    }

    /// <summary>In-memory byte patches of this image; survives analysis invalidation. Created on first use.</summary>
    public NativePatchSet Patches
    {
        get
        {
            lock (_gate) return _patches ??= new NativePatchSet(Image.FileBytes.Span);
        }
    }
    private NativePatchSet? _patches;

    /// <summary>Whether unsaved byte patches exist (does not create the patch set).</summary>
    public bool HasPatches { get { lock (_gate) return _patches?.IsDirty == true; } }

    /// <summary>The user's names and comments for this image; survives analysis invalidation. Created via the service.</summary>
    public NativeAnnotations Annotations(Func<LoadedNative, NativeAnnotations> create)
    {
        lock (_gate) return _annotations ??= create(this);
    }
    private NativeAnnotations? _annotations;

    /// <summary>The loaded annotations, or null when none has been created yet.</summary>
    public NativeAnnotations? AnnotationsOrNull { get { lock (_gate) return _annotations; } }

    /// <summary>
    /// Replaces the current image with <paramref name="image"/> (built from patched bytes) and discards cached analysis
    /// so the code index and engine sessions rebuild against the patched bytes. Patches and annotations are kept.
    /// </summary>
    internal void ReplaceImage(PeFile image)
    {
        lock (_gate)
        {
            Image = image;
            DisposeAnalysis();
        }
    }
}
