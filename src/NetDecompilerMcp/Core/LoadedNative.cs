using NetDecompilerMcp.Native.Pe;

namespace NetDecompilerMcp.Core;

/// <summary>A native PE image in the workspace (no .NET metadata, or loaded for its native code).</summary>
public sealed class LoadedNative
{
    private readonly CancellationTokenSource _released = new();

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

    /// <summary>Cancelled when the image is unloaded or reloaded.</summary>
    public CancellationToken Released => _released.Token;

    /// <summary>Per-image analysis state (code index, names); created on first use by the services that need it.</summary>
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

    /// <summary>The error for a call whose image was unloaded or reloaded while it ran.</summary>
    public ToolError Gone() =>
        new(ErrorCode.Conflict, $"{Id} was unloaded or reloaded while the call was running.", "call again; a reloaded image is analyzed afresh");

    /// <summary>Marks the image unloaded and disposes its analysis state (cancels a code index build, closes engine sessions).</summary>
    internal void Release()
    {
        _released.Cancel();
        foreach (var key in Analysis.Keys)
            if (Analysis.TryRemove(key, out var analysis) && analysis is IDisposable d) d.Dispose();
    }
}
