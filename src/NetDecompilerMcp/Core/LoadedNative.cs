using NetDecompilerMcp.Native.Pe;

namespace NetDecompilerMcp.Core;

/// <summary>A native PE image in the workspace (no .NET metadata, or loaded for its native code).</summary>
public sealed class LoadedNative
{
    internal LoadedNative(string id, string filePath, PeFile image)
    {
        Id = id;
        FilePath = filePath;
        Image = image;
    }

    /// <summary>Unique handle used in tool calls (shared with assembly ids); the file name, suffixed #n on collision.</summary>
    public string Id { get; }
    public string FilePath { get; }
    public PeFile Image { get; }

    /// <summary>Per-image analysis state (code index, names); created on first use by the services that need it.</summary>
    public System.Collections.Concurrent.ConcurrentDictionary<Type, object> Analysis { get; } = new();

    public T GetAnalysis<T>(Func<LoadedNative, T> create) where T : class =>
        (T)Analysis.GetOrAdd(typeof(T), _ => create(this));
}
