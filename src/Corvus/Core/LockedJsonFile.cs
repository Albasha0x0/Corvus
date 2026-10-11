using System.Collections.Concurrent;
using System.Diagnostics;
using System.Text.Json;

namespace Corvus.Core;

/// <summary>
/// A JSON record file shared by several server processes. An update takes &lt;file&gt;.lock exclusively, re-reads the file
/// fresh, lets the caller merge its own changes onto what is there, and writes the result atomically through
/// <see cref="SafeFile"/>, so concurrent writers never drop each other's records.
/// </summary>
public static class LockedJsonFile
{
    public static readonly TimeSpan DefaultTimeout = TimeSpan.FromSeconds(2);

    /// <summary>What an update does with the file: write new bytes, delete it, or leave it untouched with a problem.</summary>
    public readonly record struct Change(byte[]? Bytes, bool Delete, string? Problem)
    {
        public static Change Write(byte[] bytes) => new(bytes, false, null);
        public static Change Remove() => new(null, true, null);
        public static Change Keep(string problem) => new(null, false, problem);
    }

    public static string LockPathFor(string file) => file + ".lock";

    // Threads of one process queue here instead of spinning on the lock file.
    private static readonly ConcurrentDictionary<string, object> Gates =
        new(OperatingSystem.IsWindows() ? StringComparer.OrdinalIgnoreCase : StringComparer.Ordinal);

    /// <summary>
    /// Holds the cross-process lock of <paramref name="file"/> until disposed; null with <paramref name="problem"/> when it
    /// is not acquired within <paramref name="timeout"/>. The OS releases it when the holder dies, so it cannot go stale.
    /// </summary>
    public static IDisposable? TryLock(string file, TimeSpan timeout, out string? problem)
    {
        var full = Path.GetFullPath(file);
        var gate = Gates.GetOrAdd(full, _ => new object());
        var clock = Stopwatch.StartNew();
        if (!Monitor.TryEnter(gate, timeout))
        {
            problem = $"timed out after {timeout.TotalSeconds:0.#} s waiting for another writer of {full} in this process";
            return null;
        }
        var stream = OpenLockFile(LockPathFor(full), timeout - clock.Elapsed, out problem);
        if (stream != null) return new Held(gate, stream);
        Monitor.Exit(gate);
        return null;
    }

    private static FileStream? OpenLockFile(string lockPath, TimeSpan timeout, out string? problem)
    {
        var clock = Stopwatch.StartNew();
        // Windows refuses to open a delete-pending file, so deleting on close is safe there; on Unix a waiter could lock
        // an unlinked inode while a third process creates a new one, so the lock file stays.
        var options = OperatingSystem.IsWindows() ? FileOptions.DeleteOnClose : FileOptions.None;
        for (int delay = 1; ; delay = Math.Min(delay * 2, 50))
        {
            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(lockPath)!);
                problem = null;
                return new FileStream(lockPath, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None, 1, options);
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                if (clock.Elapsed >= timeout)
                {
                    problem = $"timed out after {timeout.TotalSeconds:0.#} s waiting for the lock {lockPath} held by another process ({ex.Message})";
                    return null;
                }
                Thread.Sleep(delay + Random.Shared.Next(delay + 1));
            }
        }
    }

    private sealed class Held(object gate, FileStream stream) : IDisposable
    {
        private int _disposed;

        public void Dispose()
        {
            if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
            stream.Dispose();
            Monitor.Exit(gate);
        }
    }

    /// <summary>
    /// Under the lock, runs <paramref name="change"/> (which reads the file fresh itself) and applies its result.
    /// <paramref name="written"/> runs after a successful write, still under the lock.
    /// Returns null on success, else the problem; the file is never left torn.
    /// </summary>
    public static string? Update(string file, Func<Change> change, TimeSpan? timeout = null, Action? written = null)
    {
        using var held = TryLock(file, timeout ?? DefaultTimeout, out var problem);
        if (held == null) return problem;
        var result = change();
        if (result.Problem != null) return result.Problem;
        for (int attempt = 0; ; attempt++)
        {
            try
            {
                if (result.Delete) File.Delete(file);
                else if (result.Bytes != null) SafeFile.WriteAllBytes(file, result.Bytes, overwrite: true);
                written?.Invoke();
                return null;
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ToolError)
            {
                // A reader without delete sharing can hold the target briefly (Windows); a ToolError (a link) is final.
                if (attempt >= 7 || ex is ToolError) return ex.Message;
                Thread.Sleep(10 * (attempt + 1) + Random.Shared.Next(10));
            }
        }
    }

    /// <summary>
    /// Reads <paramref name="file"/> without blocking writers. Null value and no problem when it does not exist; a
    /// problem when it cannot be read or parsed.
    /// </summary>
    public static (T? Value, string? Problem) Read<T>(string file, JsonSerializerOptions? options = null) where T : class
    {
        try
        {
            // Shared for delete so a writer's rename over the file is not blocked by this read.
            using var fs = new FileStream(file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            return JsonSerializer.Deserialize<T>(fs, options) is { } value ? (value, null) : (null, "the document is null");
        }
        catch (Exception ex) when (ex is FileNotFoundException or DirectoryNotFoundException) { return (null, null); }
        catch (JsonException ex) { return (null, "malformed: " + ex.Message); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return (null, ex.Message); }
    }

    /// <summary>
    /// Re-reads the record under the lock and writes <paramref name="merge"/>'s result (null deletes the file). A file
    /// that cannot be read or parsed is left untouched. Returns what was written, or the problem.
    /// </summary>
    public static (T? Written, string? Problem) Update<T>(string file, Func<T?, T?> merge, JsonSerializerOptions? options = null, TimeSpan? timeout = null)
        where T : class
    {
        T? written = null;
        var problem = Update(file, () =>
        {
            var (current, readProblem) = Read<T>(file, options);
            if (readProblem != null) return Change.Keep($"{file} could not be read ({readProblem}); it is left untouched");
            written = merge(current);
            return written == null ? Change.Remove() : Change.Write(JsonSerializer.SerializeToUtf8Bytes(written, options));
        }, timeout);
        return problem == null ? (written, null) : (null, problem);
    }
}
