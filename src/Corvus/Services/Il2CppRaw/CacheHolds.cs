using Corvus.Core;

namespace Corvus.Services;

/// <summary>
/// Marks Il2Cpp cache folders in use across workspaces and processes: while a workspace has files loaded from a folder,
/// this process holds a lock file in it, and a trim keeps every folder whose lock file it cannot take.
/// </summary>
internal static class CacheHolds
{
    private const string LockPrefix = "in-use-";

    private sealed class Entry
    {
        public FileStream? Lock;
        public readonly List<(WeakReference<AssemblyWorkspace> Workspace, string[] Paths)> Users = [];
    }

    private static readonly Dictionary<string, Entry> Held = new(StringComparer.OrdinalIgnoreCase);
    private static readonly System.Runtime.CompilerServices.ConditionalWeakTable<AssemblyWorkspace, object> Watched = [];

    /// <summary>
    /// Holds <paramref name="dir"/> while <paramref name="workspace"/> has an assembly or native image loaded from under one
    /// of <paramref name="paths"/>. When the lock file cannot be written, other processes see only the folder's time.
    /// </summary>
    public static void Hold(string dir, AssemblyWorkspace workspace, params string[] paths)
    {
        dir = Path.GetFullPath(dir);
        lock (Held)
        {
            if (!Held.TryGetValue(dir, out var entry)) Held[dir] = entry = new Entry();
            entry.Users.Add((new WeakReference<AssemblyWorkspace>(workspace), paths.Select(Path.GetFullPath).ToArray()));
            if (Watched.TryAdd(workspace, new object())) workspace.Disposing += () => Release(workspace);
            if (entry.Lock != null) return;
            try { entry.Lock = new FileStream(LockFile(dir), FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
        }
    }

    /// <summary>
    /// Whether a reader may still use <paramref name="dir"/>: a workspace of this process with files loaded from it, or a
    /// lock file another process holds. True when that cannot be told; false for a folder that is gone.
    /// </summary>
    public static bool InUse(string dir)
    {
        dir = Path.GetFullPath(dir);
        List<(WeakReference<AssemblyWorkspace> Workspace, string[] Paths)> users;
        lock (Held) users = Held.TryGetValue(dir, out var entry) ? [.. entry.Users] : [];
        // Workspaces are read outside the lock on Held: one holding its write lock may be waiting to take a hold.
        var gone = users.Where(u => !Uses(u.Workspace, u.Paths)).ToList();
        lock (Held)
        {
            if (Held.TryGetValue(dir, out var entry))
            {
                entry.Users.RemoveAll(u => gone.Any(g => ReferenceEquals(g.Workspace, u.Workspace)));
                if (entry.Users.Count > 0) return true;
                Close(dir, entry);
            }
        }
        try
        {
            foreach (var file in Directory.EnumerateFiles(dir, LockPrefix + "*.lock"))
            {
                // A lock file nobody holds is stale: taking it removes it.
                try { using var probe = new FileStream(file, FileMode.Open, FileAccess.ReadWrite, FileShare.None, 1, FileOptions.DeleteOnClose); }
                catch (FileNotFoundException) { }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return true; }
            }
            return false;
        }
        catch (DirectoryNotFoundException) { return false; }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return true; }
    }

    /// <summary>Ends every hold of <paramref name="workspace"/>, closing the lock files no other workspace needs.</summary>
    private static void Release(AssemblyWorkspace workspace)
    {
        lock (Held)
            foreach (var (dir, entry) in Held.ToList())
            {
                entry.Users.RemoveAll(u => !u.Workspace.TryGetTarget(out var ws) || ReferenceEquals(ws, workspace));
                if (entry.Users.Count > 0) continue;
                Close(dir, entry);
            }
    }

    private static void Close(string dir, Entry entry)
    {
        entry.Lock?.Dispose();
        Held.Remove(dir);
        try { File.Delete(LockFile(dir)); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
    }

    private static string LockFile(string dir) => Path.Combine(dir, $"{LockPrefix}{Environment.ProcessId}.lock");

    private static bool Uses(WeakReference<AssemblyWorkspace> weak, string[] paths)
    {
        if (!weak.TryGetTarget(out var ws)) return false;
        bool Under(string file) => paths.Any(p => file.StartsWith(p + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase));
        try { return ws.Read(() => ws.Assemblies.Any(a => Under(a.FilePath)) || ws.Natives.Any(n => Under(n.FilePath))); }
        catch (ObjectDisposedException) { return false; }
        // A read that was cancelled cannot tell: keep the folder.
        catch (OperationCanceledException) { return true; }
    }
}
