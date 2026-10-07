using System.Collections.Concurrent;
using Microsoft.Extensions.Logging;
using NetDecompilerMcp.Core;

namespace NetDecompilerMcp.Services;

/// <summary>
/// Watches the files of loaded assemblies. When one changes on disk (a game update, a rebuild), it is reloaded
/// automatically — unless it has unsaved edits, in which case the client is told and nothing is discarded. Every event
/// becomes a workspace notice (shown with the next tool result) and <see cref="Changed"/> is raised for MCP notifications.
/// </summary>
public sealed class FileWatchService : IDisposable
{
    private static readonly TimeSpan Debounce = TimeSpan.FromMilliseconds(750);

    private readonly AssemblyWorkspace _workspace;
    private readonly ILogger<FileWatchService>? _logger;
    private readonly ConcurrentDictionary<string, FileSystemWatcher> _watchers = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, Timer> _pending = new(StringComparer.OrdinalIgnoreCase);
    private readonly bool _enabled;

    /// <summary>Raised after a reload or a notice-worthy change (message text).</summary>
    public event Action<string>? Changed;

    public FileWatchService(AssemblyWorkspace workspace, ServerOptions options, ILogger<FileWatchService>? logger = null)
    {
        _workspace = workspace;
        _logger = logger;
        _enabled = options.WatchFiles;
        if (!_enabled) return;
        workspace.AssembliesLoaded += loaded =>
        {
            foreach (var asm in loaded) Watch(Path.GetDirectoryName(asm.FilePath)!);
        };
        foreach (var asm in workspace.Read(() => workspace.Assemblies))
            Watch(Path.GetDirectoryName(asm.FilePath)!);
    }

    private void Watch(string directory)
    {
        _watchers.GetOrAdd(directory, dir =>
        {
            var w = new FileSystemWatcher(dir)
            {
                NotifyFilter = NotifyFilters.LastWrite | NotifyFilters.FileName | NotifyFilters.Size | NotifyFilters.CreationTime,
                IncludeSubdirectories = false,
            };
            w.Changed += (_, e) => Schedule(e.FullPath);
            w.Created += (_, e) => Schedule(e.FullPath);
            w.Deleted += (_, e) => Schedule(e.FullPath);
            w.Renamed += (_, e) => { Schedule(e.FullPath); Schedule(e.OldFullPath); };
            w.EnableRaisingEvents = true;
            return w;
        });
    }

    /// <summary>Coalesces the burst of events a single file write produces.</summary>
    private void Schedule(string path)
    {
        if (_workspace.Read(() => _workspace.FindByPath(Path.GetFullPath(path))) == null) return;
        var timer = _pending.AddOrUpdate(path,
            p => new Timer(_ => Process(p), null, Debounce, Timeout.InfiniteTimeSpan),
            (_, existing) => { existing.Change(Debounce, Timeout.InfiniteTimeSpan); return existing; });
    }

    private void Process(string path)
    {
        if (_pending.TryRemove(path, out var timer)) timer.Dispose();
        try
        {
            var asm = _workspace.Read(() => _workspace.FindByPath(Path.GetFullPath(path)));
            if (asm == null) return;
            if (!File.Exists(path))
            {
                Report($"{asm.Id}: {path} was deleted or moved on disk; the loaded copy stays in memory.");
                return;
            }
            byte[]? bytes = ReadWithRetry(path);
            if (bytes == null)
            {
                Report($"{asm.Id}: {path} changed on disk but could not be read (still being written?); the previous version stays loaded.");
                return;
            }
            if (bytes.AsSpan().SequenceEqual(asm.OriginalBytes))
                return; // touched, or rewritten with identical content
            if (asm.IsDirty && bytes.AsSpan().SequenceEqual(_workspace.Read(() => asm.GetImageBytes())))
                return; // our own save_assembly over the original file
            if (asm.IsDirty)
            {
                Report($"{asm.Id}: {path} changed on disk, but the loaded copy has {asm.Edits.Count} unsaved edit(s), so it was NOT reloaded. " +
                       "export_edits to keep them, then reload_assembly (and apply_edits) to move to the new version.");
                return;
            }
            var fresh = _workspace.Reload(asm);
            Report($"{fresh.Id} was reloaded: {path} changed on disk.");
        }
        catch (Exception ex)
        {
            Report($"{path} changed on disk but reloading failed ({ex.Message}); the previous version stays loaded.");
        }
    }

    private static byte[]? ReadWithRetry(string path)
    {
        for (int attempt = 0; attempt < 10; attempt++)
        {
            try { return File.ReadAllBytes(path); }
            catch (IOException) { Thread.Sleep(200); }
            catch (UnauthorizedAccessException) { Thread.Sleep(200); }
        }
        return null;
    }

    private void Report(string message)
    {
        _logger?.LogInformation("{Message}", message);
        _workspace.Notify(message);
        Changed?.Invoke(message);
    }

    public void Dispose()
    {
        foreach (var w in _watchers.Values) w.Dispose();
        foreach (var t in _pending.Values) t.Dispose();
        _watchers.Clear();
    }
}
