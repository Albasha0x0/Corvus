using NetDecompilerMcp.Native.Annotations;
using NetDecompilerMcp.Native.Patching;
using NetDecompilerMcp.Native.Pe;

namespace NetDecompilerMcp.Core;

/// <summary>A native PE image in the workspace (no .NET metadata, or loaded for its native code).</summary>
public sealed class LoadedNative
{
    private readonly object _gate = new();

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

    /// <summary>Per-image analysis state (code index, engine sessions); created on first use and cleared on a patch.</summary>
    public System.Collections.Concurrent.ConcurrentDictionary<Type, object> Analysis { get; } = new();

    public T GetAnalysis<T>(Func<LoadedNative, T> create) where T : class =>
        (T)Analysis.GetOrAdd(typeof(T), _ => create(this));

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
            foreach (var analysis in Analysis.Values.OfType<IDisposable>()) analysis.Dispose();
            Analysis.Clear();
        }
    }
}
