using System.Security.Cryptography;
using Corvus.Core;

namespace Corvus.Native.Providers;

/// <summary>
/// Per-user directory where providers keep a private copy of each input and their analysis databases, keyed by the
/// input's SHA-256: <c>root/provider/key/input/name</c> plus the provider's database files beside it. Engines
/// never write next to the user's file, and a later open of the same bytes finds the saved database. Entries unused past
/// <see cref="MaxAge"/>, then the least recently used beyond <see cref="MaxBytes"/>, are deleted after an acquire; an
/// entry whose lock is held (open in a session of any process) is never touched.
/// </summary>
public sealed class AnalysisCache(string root, long? maxBytes = null, TimeSpan? maxAge = null)
{
    public const string RootVariable = "CORVUS_ANALYSIS_CACHE";
    public const string MaxMegabytesVariable = "CORVUS_ANALYSIS_CACHE_MB";
    public const string MaxDaysVariable = "CORVUS_ANALYSIS_CACHE_DAYS";
    public const long DefaultMaxMegabytes = 32768;
    public const int DefaultMaxDays = 60;

    /// <summary>Holds the full SHA-256 of a short-keyed entry, so a prefix collision moves to a longer key.</summary>
    internal const string KeyFile = ".sha256";

    /// <summary>Longest input copy name of a short-keyed entry (the extension is kept).</summary>
    internal const int ShortNameLength = 40;

    public string Root { get; } = Path.GetFullPath(root);

    public long MaxBytes { get; } = maxBytes
        ?? (long.TryParse(Environment.GetEnvironmentVariable(MaxMegabytesVariable), out var mb) && mb > 0 ? mb : DefaultMaxMegabytes) << 20;

    public TimeSpan MaxAge { get; } = maxAge
        ?? TimeSpan.FromDays(int.TryParse(Environment.GetEnvironmentVariable(MaxDaysVariable), out var days) && days > 0 ? days : DefaultMaxDays);

    /// <summary>
    /// Entries are keyed by the first 16 hex digits of the hash (longer on a collision) and the input copy's name is capped
    /// at <see cref="ShortNameLength"/>, for engines that cannot open long paths. A full-hash entry of an earlier layout
    /// is moved to the short key when it is not in use, else used where it is.
    /// </summary>
    public bool ShortKeys { get; init; }

    /// <summary>The existing entry directory of <paramref name="sha256"/> in either layout, or null.</summary>
    public string? Find(string providerId, string sha256)
    {
        var sha = sha256.ToLowerInvariant();
        foreach (var length in new[] { 16, 32 })
        {
            var dir = Path.Combine(Root, providerId, sha[..length]);
            if (!Directory.Exists(dir)) return Legacy();
            if (KeyOf(dir) == sha) return dir;
        }
        return Legacy();

        string? Legacy() => Directory.Exists(Path.Combine(Root, providerId, sha)) ? Path.Combine(Root, providerId, sha) : null;
    }

    /// <summary>The directory of a new or existing entry: short-keyed (claimed with its key file), else the full hash.</summary>
    private string EntryDirectory(string providerId, string sha)
    {
        var legacy = Path.Combine(Root, providerId, sha);
        if (!ShortKeys) return legacy;
        foreach (var length in new[] { 16, 32 })
        {
            var dir = Path.Combine(Root, providerId, sha[..length]);
            if (Directory.Exists(dir))
            {
                var key = KeyOf(dir);
                if (key == sha) return dir;
                if (key != null) continue; // another input's entry: a longer key
                File.WriteAllText(Path.Combine(dir, KeyFile), sha); // made but not claimed (interrupted): the input stamp in its database guards reuse
                return dir;
            }
            if (Directory.Exists(legacy))
            {
                try { Directory.Move(legacy, dir); }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return legacy; } // in use by another process
            }
            else Directory.CreateDirectory(dir);
            File.WriteAllText(Path.Combine(dir, KeyFile), sha);
            return dir;
        }
        return legacy;
    }

    private static string? KeyOf(string dir)
    {
        try { return File.ReadAllText(Path.Combine(dir, KeyFile)).Trim().ToLowerInvariant(); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return null; }
    }

    public static string DefaultRoot =>
        Environment.GetEnvironmentVariable(RootVariable) is { Length: > 0 } custom
            ? custom
            : DataFolder.Combine("analysis");

    /// <summary>
    /// Locks the entry for <paramref name="imagePath"/>'s bytes and makes sure its private copy exists and hashes to
    /// <paramref name="expectedSha256"/> (the source's hash when null). Throws NotFound, IoError, InvalidArgument or
    /// Conflict (bytes differ from the expected hash, or the entry is open in another session or process).
    /// </summary>
    public CacheEntry Acquire(string providerId, string imagePath, string? expectedSha256) => Acquire(providerId, imagePath, expectedSha256, null);

    /// <param name="whenLocked">Called instead of throwing Conflict when the entry is locked: may return another entry (a snapshot).</param>
    public CacheEntry Acquire(string providerId, string imagePath, string? expectedSha256, Func<LockedEntry, string, CacheEntry>? whenLocked)
    {
        var source = Path.GetFullPath(imagePath);
        if (!File.Exists(source))
            throw new ToolError(ErrorCode.NotFound, $"{imagePath} does not exist.");
        string sha;
        if (expectedSha256 != null)
        {
            sha = expectedSha256.Trim().ToLowerInvariant();
            if (sha.Length != 64 || !sha.All(Uri.IsHexDigit))
                throw new ToolError(ErrorCode.InvalidArgument, $"'{expectedSha256}' is not a SHA-256 (64 hex digits).");
        }
        else sha = Io(source, () => HashFile(source));

        var dir = Io(Path.Combine(Root, providerId), () => EntryDirectory(providerId, sha));
        Io(dir, () => Directory.CreateDirectory(Path.Combine(dir, "input")));
        FileStream lockFile;
        try { lockFile = OpenLock(dir); }
        catch (LockedError locked) when (whenLocked != null) { return whenLocked(locked.Entry, sha); }
        catch (LockedError locked) { throw locked.Entry.Conflict; }
        try
        {
            var copy = Io(dir, () => EnsureCopy(source, Path.Combine(dir, "input"), sha, ShortKeys ? ShortNameLength : 100));
            try { File.WriteAllText(Path.Combine(dir, OwnerFile), Environment.ProcessId.ToString(System.Globalization.CultureInfo.InvariantCulture)); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { /* only names the owner in another process's conflict */ }
            EvictSoon();
            return new CacheEntry(dir, copy, sha, source, lockFile);
        }
        catch
        {
            lockFile.Dispose();
            throw;
        }
    }

    private sealed class Counters
    {
        public long LastRun;
        public int Evicted;
        public string? LastError;
    }

    /// <summary>Per root: the IDA and Ghidra providers share one.</summary>
    private static readonly System.Collections.Concurrent.ConcurrentDictionary<string, Counters> Stats = new(StringComparer.Ordinal);

    private Counters Stat => Stats.GetOrAdd(Root, _ => new Counters());

    /// <summary>Most often an eviction pass starts in one process.</summary>
    internal static TimeSpan EvictInterval { get; set; } = TimeSpan.FromMinutes(10);

    /// <summary>Whether an acquire starts an eviction pass (tests turn it off to run one themselves).</summary>
    internal bool AutoEvict { get; init; } = true;

    private void EvictSoon()
    {
        if (!AutoEvict) return;
        var stat = Stat;
        var now = Environment.TickCount64;
        var last = Interlocked.Read(ref stat.LastRun);
        if (last != 0 && now - last < EvictInterval.TotalMilliseconds) return;
        if (Interlocked.CompareExchange(ref stat.LastRun, now, last) != last) return;
        _ = Task.Run(() => Evict());
    }

    /// <summary>Snapshots left by a process that ended without disposing them are deleted once this old.</summary>
    private static readonly TimeSpan SnapshotAge = TimeSpan.FromHours(1);

    /// <summary>
    /// An entry of either layout: a short key claimed by its <see cref="KeyFile"/>, or a hex name (a full hash, or a short
    /// key made but not yet claimed).
    /// </summary>
    private static bool IsEntry(DirectoryInfo dir) =>
        File.Exists(Path.Combine(dir.FullName, KeyFile)) || (dir.Name.Length is 16 or 32 or 64 && dir.Name.All(Uri.IsHexDigit));

    /// <summary>
    /// Deletes entries (<c>root/provider/key</c>) unused past <see cref="MaxAge"/>, then the least recently used beyond
    /// <see cref="MaxBytes"/>, and abandoned snapshots; returns how many entries went. Locked entries are skipped.
    /// </summary>
    public int Evict()
    {
        FolderTally.Forget(Root);
        var stat = Stat;
        int evicted = 0;
        try
        {
            if (!Directory.Exists(Root)) return 0;
            var now = DateTime.UtcNow;
            var entries = new List<(DirectoryInfo Dir, DateTime Used, long Bytes)>();
            foreach (var provider in new DirectoryInfo(Root).EnumerateDirectories())
            {
                foreach (var dir in provider.EnumerateDirectories())
                {
                    if (dir.Name == "snapshots")
                    {
                        foreach (var snapshot in dir.EnumerateDirectories())
                            if (now - LastUse(snapshot) > SnapshotAge) TryDeleteEntry(snapshot);
                    }
                    else if (IsEntry(dir)) entries.Add((dir, LastUse(dir), Size(dir)));
                }
            }
            long total = entries.Sum(e => e.Bytes);
            foreach (var (dir, used, bytes) in entries.OrderBy(e => e.Used))
            {
                if (now - used <= MaxAge && total <= MaxBytes) break;
                if (!TryDeleteEntry(dir)) continue;
                total -= bytes;
                evicted++;
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            stat.LastError = $"evicting: {ex.Message}";
        }
        Interlocked.Add(ref stat.Evicted, evicted);
        return evicted;
    }

    /// <summary>The last acquire rewrote <see cref="OwnerFile"/>; the directory's own time otherwise.</summary>
    private static DateTime LastUse(DirectoryInfo dir)
    {
        var owner = new FileInfo(Path.Combine(dir.FullName, OwnerFile));
        return owner.Exists && owner.LastWriteTimeUtc > dir.LastWriteTimeUtc ? owner.LastWriteTimeUtc : dir.LastWriteTimeUtc;
    }

    private static long Size(DirectoryInfo dir)
    {
        try { return dir.EnumerateFiles("*", SearchOption.AllDirectories).Sum(f => f.Length); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return 0; }
    }

    /// <summary>Deletes an entry while holding its lock, so a session that has it open (in any process) keeps it.</summary>
    private bool TryDeleteEntry(DirectoryInfo dir)
    {
        FileStream lockFile;
        try { lockFile = OpenLock(dir.FullName); }
        catch (Exception ex) when (ex is LockedError or IOException or UnauthorizedAccessException) { return false; }
        bool whole = true;
        using (lockFile)
        {
            foreach (var item in dir.EnumerateFileSystemInfos())
            {
                if (item.Name == ".lock") continue;
                try
                {
                    if (item is DirectoryInfo d) d.Delete(true);
                    else item.Delete();
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                {
                    whole = false;
                    Stat.LastError = $"evicting {dir.FullName}: {ex.Message}";
                }
            }
        }
        try { dir.Delete(false); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { /* reopened meanwhile */ }
        return whole;
    }

    /// <summary>What the cache holds and how it is bounded, with this process's evictions.</summary>
    public AnalysisCacheStatus Status()
    {
        var (entries, bytes) = FolderTally.Of(Root, () =>
        {
            int entries = 0;
            long bytes = 0;
            try
            {
                if (Directory.Exists(Root))
                    foreach (var provider in new DirectoryInfo(Root).EnumerateDirectories())
                        foreach (var dir in provider.EnumerateDirectories())
                            if (dir.Name != "snapshots" && IsEntry(dir)) { entries++; bytes += Size(dir); }
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
            return (entries, bytes);
        });
        var stat = Stat;
        return new AnalysisCacheStatus(Root, entries, bytes, MaxBytes, MaxAge, Volatile.Read(ref stat.Evicted), stat.LastError);
    }

    public static string HashFile(string path)
    {
        using var s = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 1 << 16, FileOptions.SequentialScan);
        return Convert.ToHexStringLower(SHA256.HashData(s));
    }

    /// <summary>The process holding an entry's lock writes its id here, so a conflict can name it.</summary>
    internal const string OwnerFile = ".owner";

    private static FileStream OpenLock(string dir)
    {
        var path = Path.Combine(dir, ".lock");
        try
        {
            return new FileStream(path, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None, 1, FileOptions.DeleteOnClose);
        }
        catch (IOException ex) when (ex is not FileNotFoundException and not DirectoryNotFoundException
            && (!OperatingSystem.IsWindows() || (ex.HResult & 0xFFFF) is 32 or 33)) // sharing / lock violation
        {
            var owner = Owner(dir);
            var who = owner == null ? "another session or process" : owner == Environment.ProcessId ? "another session of this process" : $"process {owner}";
            throw new LockedError(new LockedEntry(dir, owner, new ToolError(ErrorCode.Conflict, $"The analysis database in {dir} is open in {who}.",
                "Close the other session (or the other server process) first, or work in that session, or retry after details.retryAfterMs.")
            {
                RetryAfter = LockRetryAfter,
            }));
        }
    }

    /// <summary>The retry hint of a database held by another session: an engine call there usually ends within this.</summary>
    public static readonly TimeSpan LockRetryAfter = TimeSpan.FromSeconds(30);

    private sealed class LockedError(LockedEntry entry) : Exception(entry.Conflict.Message)
    {
        public LockedEntry Entry { get; } = entry;
    }

    private static int? Owner(string dir)
    {
        try { return int.TryParse(File.ReadAllText(Path.Combine(dir, OwnerFile)).Trim(), out var pid) ? pid : null; }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return null; }
    }

    /// <summary>
    /// A private copy of a locked entry's input and of <paramref name="files"/> (its saved database), for a read-only
    /// session beside the process that holds the entry; the copy is deleted when the entry is disposed. Throws IoError
    /// when a file cannot be read (the owner may hold it open).
    /// </summary>
    public CacheEntry Snapshot(string providerId, LockedEntry locked, string sha256, string source, IReadOnlyList<string> files)
    {
        var dir = Path.Combine(Root, providerId, "snapshots", $"{sha256[..8]}-{Environment.ProcessId}-{Guid.NewGuid():N}"[..24]);
        try
        {
            Directory.CreateDirectory(Path.Combine(dir, "input"));
            var lockFile = new FileStream(Path.Combine(dir, ".lock"), FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None, 1, FileOptions.DeleteOnClose);
            var input = Directory.GetFiles(Path.Combine(locked.Directory, "input")).FirstOrDefault(f => !f.EndsWith(".tmp", StringComparison.OrdinalIgnoreCase))
                ?? throw locked.Conflict;
            var copy = Path.Combine(dir, "input", Path.GetFileName(input));
            CopyShared(input, copy);
            foreach (var f in files) CopyShared(f, Path.Combine(dir, Path.GetFileName(f)));
            if (HashFile(copy) != sha256) throw locked.Conflict;
            return new CacheEntry(dir, copy, sha256, source, lockFile) { SnapshotOf = locked.OwnerPid };
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ToolError)
        {
            try { Directory.Delete(dir, true); }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException) { }
            if (ex is ToolError t) throw t;
            throw new ToolError(ErrorCode.Conflict, $"{locked.Conflict.Message} Its saved database could not be copied for a read-only snapshot: {ex.Message}",
                locked.Conflict.Remediation);
        }
    }

    private static void CopyShared(string from, string to)
    {
        using var input = new FileStream(from, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 1 << 16, FileOptions.SequentialScan);
        using var output = new FileStream(to, FileMode.CreateNew, FileAccess.Write, FileShare.None, 1 << 16);
        input.CopyTo(output);
    }

    private static string EnsureCopy(string source, string inputDir, string sha, int maxName)
    {
        var existing = Directory.GetFiles(inputDir).Where(f => !f.EndsWith(".tmp", StringComparison.OrdinalIgnoreCase)).ToList();
        foreach (var f in existing)
        {
            if (HashFile(f) == sha) return f;
            File.Delete(f); // damaged or replaced copy
        }
        foreach (var stale in Directory.GetFiles(inputDir, "*.tmp")) File.Delete(stale);

        var name = SafeName(Path.GetFileName(source), maxName);
        var target = Path.Combine(inputDir, name);
        var temp = target + "." + Guid.NewGuid().ToString("N")[..8] + ".tmp";
        string copied;
        using (var input = new FileStream(source, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 1 << 16, FileOptions.SequentialScan))
        using (var output = new FileStream(temp, FileMode.CreateNew, FileAccess.Write, FileShare.None, 1 << 16))
        using (var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256))
        {
            var buffer = new byte[1 << 16];
            int n;
            while ((n = input.Read(buffer, 0, buffer.Length)) > 0)
            {
                hash.AppendData(buffer, 0, n);
                output.Write(buffer, 0, n);
            }
            output.Flush(flushToDisk: true);
            copied = Convert.ToHexStringLower(hash.GetHashAndReset());
        }
        if (copied != sha)
        {
            File.Delete(temp);
            throw new ToolError(ErrorCode.Conflict, $"{source} has SHA-256 {copied}, not the expected {sha}: the file changed since it was loaded.",
                "Reload the file and open it again.");
        }
        File.Move(temp, target, overwrite: true);
        // Read back what landed on disk.
        if (HashFile(target) != sha)
        {
            File.Delete(target);
            throw new ToolError(ErrorCode.IoError, $"The private copy of {source} in {inputDir} does not match the source after writing.", "Check the disk and retry.");
        }
        return target;
    }

    internal static string SafeName(string name, int maxLength)
    {
        var invalid = Path.GetInvalidFileNameChars();
        var clean = new string(name.Select(c => invalid.Contains(c) || c < ' ' ? '_' : c).ToArray()).Trim(' ', '.');
        if (clean.Length == 0) return "input.bin";
        if (clean.Length <= maxLength) return clean;
        var ext = Path.GetExtension(clean);
        if (ext.Length > 8) ext = "";
        return clean[..(maxLength - ext.Length)].TrimEnd(' ', '.') + ext;
    }

    private static T Io<T>(string path, Func<T> action)
    {
        try { return action(); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            throw new ToolError(ErrorCode.IoError, $"I/O error on {path}: {ex.Message}", "Check that the path is readable and the cache directory is writable (CORVUS_ANALYSIS_CACHE selects another).");
        }
    }
}

/// <summary>Entries and bytes on disk, the bounds, and the entries this process evicted.</summary>
public sealed record AnalysisCacheStatus(string Root, int Entries, long Bytes, long MaxBytes, TimeSpan MaxAge, int Evicted, string? LastError);

/// <summary>An entry locked by another session or process (<see cref="OwnerPid"/> when it recorded itself), and the conflict to report.</summary>
public sealed record LockedEntry(string Directory, int? OwnerPid, ToolError Conflict);

/// <summary>A locked cache entry; disposing releases the lock (and deletes a snapshot).</summary>
public sealed class CacheEntry(string directory, string inputCopy, string sha256, string source, FileStream lockFile) : IDisposable
{
    /// <summary>For a read-only snapshot of an entry another process holds: that process's id (0 when unknown); null otherwise.</summary>
    public int? SnapshotOf { get; init; }

    public string Directory { get; } = directory;
    /// <summary>The verified private copy of the input.</summary>
    public string InputCopy { get; } = inputCopy;
    public string Sha256 { get; } = sha256;
    public string SourcePath { get; } = source;

    public void Dispose()
    {
        lockFile.Dispose();
        if (SnapshotOf == null) return;
        try { System.IO.Directory.Delete(Directory, true); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { /* a worker still exiting; the next snapshot uses another directory */ }
    }
}
