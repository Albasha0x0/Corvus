using System.Security.Cryptography;
using Corvus.Core;

namespace Corvus.Native.Providers;

/// <summary>Per-user store of input copies and engine databases keyed by SHA-256 (<c>root/provider/key</c>); engines never write beside the user's file; evicts by age then size, never an entry locked by a session of any process.</summary>
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

    /// <summary>Keys entries by 16 hex digits (longer on collision) and caps copy names, for engines without long-path support; an earlier full-hash entry moves to the short key unless in use.</summary>
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
                // Another input's entry: try a longer key.
                if (key != null) continue;
                // Made but not claimed: the input stamp in its database guards reuse.
                File.WriteAllText(Path.Combine(dir, KeyFile), sha);
                return dir;
            }
            if (Directory.Exists(legacy))
            {
                // In use by another process: keep the full-hash entry where it is.
                try { Directory.Move(legacy, dir); }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return legacy; }
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
            ? PrivateFolder.Ensure(custom)
            : DataFolder.Combine("analysis");

    /// <summary>Locks the entry and verifies its copy against <paramref name="expectedSha256"/> (source hash when null); throws NotFound, IoError, InvalidArgument or Conflict.</summary>
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
            var fresh = !Directory.EnumerateFiles(Path.Combine(dir, "input")).Any();
            var copy = Io(dir, () => EnsureCopy(source, Path.Combine(dir, "input"), sha, ShortKeys ? ShortNameLength : 100));
            try { File.WriteAllText(Path.Combine(dir, OwnerFile), Environment.ProcessId.ToString(System.Globalization.CultureInfo.InvariantCulture)); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { /* only names the owner in another process's conflict */ }
            EvictSoon(fresh);
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
        public IReadOnlyList<string> InUse = [];
    }

    /// <summary>Per root: the IDA and Ghidra providers share one.</summary>
    private static readonly System.Collections.Concurrent.ConcurrentDictionary<string, Counters> Stats = new(StringComparer.Ordinal);

    private Counters Stat => Stats.GetOrAdd(Root, _ => new Counters());

    /// <summary>Most often an eviction pass starts in one process.</summary>
    internal static TimeSpan EvictInterval { get; set; } = TimeSpan.FromMinutes(10);

    /// <summary>Whether an acquire starts an eviction pass (tests turn it off to run one themselves).</summary>
    internal bool AutoEvict { get; init; } = true;

    private void EvictSoon(bool written)
    {
        if (!AutoEvict) return;
        var stat = Stat;
        var now = Environment.TickCount64;
        var last = Interlocked.Read(ref stat.LastRun);
        // A new copy grows the cache, so it always checks the cap; reuse is throttled.
        if (!written && (last != 0 && now - last < EvictInterval.TotalMilliseconds || Interlocked.CompareExchange(ref stat.LastRun, now, last) != last)) return;
        Interlocked.Exchange(ref stat.LastRun, now);
        _ = Task.Run(() => Evict());
    }

    /// <summary>Snapshots left by a process that ended without disposing them are deleted once this old.</summary>
    private static readonly TimeSpan SnapshotAge = TimeSpan.FromHours(1);

    /// <summary>Whether the folder is an entry: claimed by a <see cref="KeyFile"/>, or named by a hex key.</summary>
    private static bool IsEntry(DirectoryInfo dir) =>
        File.Exists(Path.Combine(dir.FullName, KeyFile)) || (dir.Name.Length is 16 or 32 or 64 && dir.Name.All(Uri.IsHexDigit));

    /// <summary>Deletes unlocked entries past <see cref="MaxAge"/>, then LRU beyond <see cref="MaxBytes"/>, and abandoned snapshots; returns the count. Files outside entries (helper and snapshot folders) count toward the cap but are never evicted; entries in use are skipped and named in <see cref="AnalysisCacheStatus.InUse"/>.</summary>
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
            long total = Math.Max(Size(new DirectoryInfo(Root)), entries.Sum(e => e.Bytes));
            var inUse = new List<string>();
            foreach (var (dir, used, bytes) in entries.OrderBy(e => e.Used))
            {
                if (now - used <= MaxAge && total <= MaxBytes) break;
                if (!TryDeleteEntry(dir)) { inUse.Add(dir.FullName); continue; }
                total -= bytes;
                evicted++;
            }
            stat.InUse = inUse;
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

    /// <summary>Entry count, and bytes of everything on disk under the root (helper and snapshot folders included), with the cap and this process's evictions.</summary>
    public AnalysisCacheStatus Status()
    {
        var (entries, bytes) = FolderTally.Of(Root, () =>
        {
            int entries = 0;
            long bytes = 0;
            try
            {
                if (Directory.Exists(Root))
                {
                    bytes = Size(new DirectoryInfo(Root));
                    foreach (var provider in new DirectoryInfo(Root).EnumerateDirectories())
                        foreach (var dir in provider.EnumerateDirectories())
                            if (dir.Name != "snapshots" && IsEntry(dir)) entries++;
                }
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
            return (entries, bytes);
        });
        var stat = Stat;
        return new AnalysisCacheStatus(Root, entries, bytes, MaxBytes, MaxAge, Volatile.Read(ref stat.Evicted), stat.LastError) { InUse = stat.InUse };
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
        // HRESULT 32/33: sharing or lock violation.
        catch (IOException ex) when (ex is not FileNotFoundException and not DirectoryNotFoundException
            && (!OperatingSystem.IsWindows() || (ex.HResult & 0xFFFF) is 32 or 33))
        {
            var owner = Owner(dir);
            var who = owner == null ? "another session or process" : owner == Environment.ProcessId ? "another session of this process" : $"process {owner}";
            var progress = ReadProgress(dir, owner);
            var message = $"The analysis database in {dir} is open in {who}.";
            var next = "Close the other session, work in it, or retry after details.retryAfterMs.";
            var retry = LockRetryAfter;
            if (progress != null)
            {
                var elapsed = Math.Max(0, Math.Round((DateTime.UtcNow - progress.Started).TotalSeconds));
                message += $" It is in {OpenProgressText.Describe(progress.Stage, elapsed, progress.ExpectedSeconds, "earlier opens")}.";
                if (progress.ExpectedSeconds is { } expected)
                {
                    var left = Math.Max(0, Math.Round(expected - elapsed));
                    retry = TimeSpan.FromSeconds(Math.Clamp(left, 5, 300));
                    next = left > 0
                        ? $"Retry in about {left} s (details.retryAfterMs), or work in the other session."
                        : $"The open is past the expected {Math.Round(expected)} s; retry in {retry.TotalSeconds} s (details.retryAfterMs), or work in the other session.";
                }
            }
            throw new LockedError(new LockedEntry(dir, owner, new ToolError(ErrorCode.Conflict, message, next)
            {
                RetryAfter = retry,
                Retryable = true,
            }));
        }
    }

    /// <summary>Whether a session (of this or another process) holds the entry open now.</summary>
    internal static bool Held(string dir)
    {
        if (!File.Exists(Path.Combine(dir, ".lock"))) return false;
        try
        {
            using (OpenLock(dir)) return false;
        }
        catch (LockedError) { return true; }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return false; }
    }

    /// <summary>The retry hint of a database held by another session: an engine call there usually ends within this.</summary>
    public static readonly TimeSpan LockRetryAfter = TimeSpan.FromSeconds(30);

    private sealed class LockedError(LockedEntry entry) : Exception(entry.Conflict.Message)
    {
        public LockedEntry Entry { get; } = entry;
    }

    /// <summary>The open stage of the process holding an entry, read for its conflict.</summary>
    private sealed record OpenProgress(int Pid, string Stage, DateTime Started, double? ExpectedSeconds, bool FromHistory);

    private const string ProgressFile = ".progress";

    /// <summary>Records the holder's open stage, start and expected seconds beside <see cref="OwnerFile"/>; a failed write is skipped.</summary>
    internal static void WriteProgress(string dir, string stage, DateTime startedUtc, double? expectedSeconds, bool fromHistory = false)
    {
        try
        {
            File.WriteAllText(Path.Combine(dir, ProgressFile),
                System.Text.Json.JsonSerializer.Serialize(new OpenProgress(Environment.ProcessId, stage, startedUtc, expectedSeconds, fromHistory)));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) 
        {
            // Only quoted in another session's conflict, so a failed write is skipped.
        }
    }

    /// <summary>Removes the open stage once the open ends.</summary>
    internal static void ClearProgress(string dir)
    {
        try { File.Delete(Path.Combine(dir, ProgressFile)); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) 
        {
            // A stale file names a stage of an ended open and is ignored.
        }
    }

    // A file from another owner is stale and ignored.
    private static OpenProgress? ReadProgress(string dir, int? owner)
    {
        try
        {
            var p = System.Text.Json.JsonSerializer.Deserialize<OpenProgress>(File.ReadAllText(Path.Combine(dir, ProgressFile)));
            return p != null && p.Pid == owner && p.Stage != null ? p : null;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Text.Json.JsonException) { return null; }
    }

    private static int? Owner(string dir)
    {
        try { return int.TryParse(File.ReadAllText(Path.Combine(dir, OwnerFile)).Trim(), out var pid) ? pid : null; }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return null; }
    }

    /// <summary>A read-only copy of a locked entry's input and database <paramref name="files"/>, deleted on dispose; throws Conflict when a file cannot be copied.</summary>
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
            foreach (var f in files)
                if (Directory.Exists(f)) CopyFolder(f, Path.Combine(dir, Path.GetFileName(f)));
                else CopyShared(f, Path.Combine(dir, Path.GetFileName(f)));
            if (HashFile(copy) != sha256) throw locked.Conflict;
            return new CacheEntry(dir, copy, sha256, source, lockFile) { SnapshotOf = locked.OwnerPid };
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ToolError)
        {
            try { Directory.Delete(dir, true); }
            catch (Exception e) when (e is IOException or UnauthorizedAccessException) { }
            if (ex is ToolError t) throw t;
            throw new ToolError(ErrorCode.Conflict, $"{locked.Conflict.Message} Its database could not be copied for a read-only snapshot: {ex.Message}",
                locked.Conflict.Remediation);
        }
    }

    // A Ghidra project's lock file names its owner; the copy is opened by another process.
    private static void CopyFolder(string from, string to)
    {
        Directory.CreateDirectory(to);
        foreach (var sub in Directory.GetDirectories(from)) CopyFolder(sub, Path.Combine(to, Path.GetFileName(sub)));
        foreach (var file in Directory.GetFiles(from))
            if (!Path.GetFileName(file).Contains(".lock", StringComparison.OrdinalIgnoreCase)) CopyShared(file, Path.Combine(to, Path.GetFileName(file)));
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
            File.Delete(f);
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
            throw new ToolError(ErrorCode.Conflict, $"{source} changed since it was loaded: SHA-256 {copied}, expected {sha}.",
                "Reload the file and open it again.");
        }
        File.Move(temp, target, overwrite: true);
        // Read back what landed on disk.
        if (HashFile(target) != sha)
        {
            File.Delete(target);
            throw new ToolError(ErrorCode.IoError, $"The copy of {source} in {inputDir} does not match after writing.", "Check the disk and retry.");
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
            throw new ToolError(ErrorCode.IoError, $"I/O error on {path}: {ex.Message}", "Check the path is readable and the cache is writable; CORVUS_ANALYSIS_CACHE selects another.");
        }
    }
}

/// <summary>Entries and bytes on disk, the bounds, and the entries this process evicted.</summary>
public sealed record AnalysisCacheStatus(string Root, int Entries, long Bytes, long MaxBytes, TimeSpan MaxAge, int Evicted, string? LastError)
{
    /// <summary>Entries the last pass kept because a session holds them; empty when none.</summary>
    public IReadOnlyList<string> InUse { get; init; } = [];
}

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

/// <summary>Marker beside a database whose analysis a budget cut short, read without opening the database; an open or reanalysis that completes removes it.</summary>
public static class PartialAnalysis
{
    public static string MarkerOf(string database) => Path.TrimEndingDirectorySeparator(database) + ".partial";

    public static bool Marked(string database) => File.Exists(MarkerOf(database));

    public static void Record(string database, bool complete)
    {
        try
        {
            if (complete) File.Delete(MarkerOf(database));
            else File.WriteAllText(MarkerOf(database), "");
        }
        // The engine choice then reads the database as complete.
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
    }
}
