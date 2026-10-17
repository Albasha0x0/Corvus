using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Corvus.Core;

/// <summary>A loaded input of the call that produced a kept result.</summary>
public sealed record KeptInput(string Id, string Sha256);

/// <summary>
/// The call that produced a kept result (S3.6). <paramref name="Arguments"/> is the canonical arguments object with secrets
/// already masked; <paramref name="ArgumentsSha256"/> hashes the unmasked canonical form.
/// </summary>
public sealed record KeptOrigin(string Tool, string? Arguments = null, string? ArgumentsSha256 = null, IReadOnlyList<KeptInput>? Inputs = null);

/// <summary>The side record of a kept result: its origin, creation time, size and whether a structured record is kept.</summary>
public sealed record KeptInfo(string Tool, string? Arguments, string? ArgumentsSha256, IReadOnlyList<KeptInput> Inputs, DateTimeOffset Created,
    long Chars, string Sha256, bool HasRecord);

/// <summary>A kept result: its text, the structured record when the call had one (JSON), and the side record.</summary>
public sealed record KeptResult(string Id, string Text, string? Record, KeptInfo Info);

/// <summary>Where kept results persist: <paramref name="Root"/> null keeps them in memory only.</summary>
public sealed record ResultCacheOptions(string? Root, long MaxBytes, TimeSpan MaxAge)
{
    public const string RootVariable = "CORVUS_RESULT_CACHE";
    public const string MaxMegabytesVariable = "CORVUS_RESULT_CACHE_MB";
    public const string MaxDaysVariable = "CORVUS_RESULT_CACHE_DAYS";
    public const long DefaultMaxMegabytes = 512;
    public const int DefaultMaxDays = 7;

    public static ResultCacheOptions MemoryOnly { get; } = new(null, DefaultMaxMegabytes << 20, TimeSpan.FromDays(DefaultMaxDays));

    /// <summary>The variables' settings; by default &lt;data root&gt;/results, and "off" keeps results in memory only.</summary>
    public static ResultCacheOptions FromEnvironment(Func<string, string?>? variable = null)
    {
        variable ??= Environment.GetEnvironmentVariable;
        var root = variable(RootVariable)?.Trim();
        long mb = long.TryParse(variable(MaxMegabytesVariable), out var m) && m > 0 ? m : DefaultMaxMegabytes;
        int days = int.TryParse(variable(MaxDaysVariable), out var d) && d > 0 ? d : DefaultMaxDays;
        string? folder = root?.ToLowerInvariant() is "off" or "none" or "0" ? null
            : string.IsNullOrEmpty(root) ? Native.Providers.DataFolder.Combine("results") : Path.GetFullPath(root);
        return new(folder, mb << 20, TimeSpan.FromDays(days));
    }
}

public sealed record ResultStoreStatus(string Mode, string? Root, int Entries, long Bytes, long MaxBytes, TimeSpan MaxAge,
    int MemoryEntries, long MemoryChars, long MaxMemoryChars, int MaxResultChars, int Kept, int Reads, int Evicted, string? LastError);

/// <summary>
/// Results too large to send, kept for read_result (S3, D5). Ids are content-addressed ("r-" + 12 hex of the text's
/// SHA-256), so an id never names other content, across restarts and servers. A memory LRU is the hot tier; the disk tier
/// (one folder, shared by every server of the user) is bounded by size and age. Entries are verified by hash on read, so
/// a truncated or foreign file is a miss. An evicted entry keeps its side record, so a read can name the original call.
/// </summary>
public sealed partial class ResultStore
{
    /// <summary>Largest result written to disk; larger ones stay in memory only.</summary>
    public const int MaxResultChars = 64 * 1024 * 1024;

    /// <summary>Characters the memory tier holds (text plus record).</summary>
    public const long MaxMemoryChars = 64L * 1024 * 1024;

    /// <summary>Side records of evicted results kept (per tier) to explain a later read.</summary>
    private const int MaxTombstones = 10_000;

    /// <summary>Characters of the original arguments quoted in an evicted read's Next; details.arguments has them all.</summary>
    private const int MaxNextArguments = 300;

    private static readonly JsonSerializerOptions SideJson = new(JsonSerializerDefaults.Web);

    private readonly LinkedList<KeptResult> _memory = new();
    private readonly Dictionary<string, KeptInfo> _forgotten = new(StringComparer.Ordinal);
    private long _memoryChars;
    private int _kept, _reads, _evicted;
    private string? _lastError;
    // Bytes on disk as of the last walk plus what this store wrote since (-1: not walked yet), and when the walk ran:
    // a write walks the folder again only past the size limit or an hour later, not on every write.
    private long _diskBytes = -1;
    private DateTime _walked;

    /// <summary>Walks of the folder by <see cref="Evict"/> (tests check that writes do not each walk it).</summary>
    internal int Walks;

    public ResultCacheOptions Options { get; }

    /// <summary>Characters the memory tier holds; lowered by tests.</summary>
    internal long MemoryLimit { get; init; } = MaxMemoryChars;

    public ResultStore() : this(ResultCacheOptions.FromEnvironment()) { }

    public ResultStore(ResultCacheOptions options) => Options = options;

    /// <summary>Whether <paramref name="id"/> has the form of a kept result id (r-&lt;12 hex&gt;).</summary>
    public static bool IsId(string id) => IdPattern().IsMatch(id.Trim().ToLowerInvariant());

    /// <summary>The content id of <paramref name="text"/>.</summary>
    public static string IdOf(string text) => "r-" + Sha256Hex(text)[..12];

    /// <summary>Keeps <paramref name="text"/> (and its structured <paramref name="record"/>) and returns its id; keeping the same text again returns the same id.</summary>
    public string Keep(string text, KeptOrigin origin, string? record = null)
    {
        var sha = Sha256Hex(text);
        var id = "r-" + sha[..12];
        var info = new KeptInfo(origin.Tool, origin.Arguments, origin.ArgumentsSha256, origin.Inputs ?? [], DateTimeOffset.UtcNow, text.Length, sha, record != null);
        var kept = new KeptResult(id, text, record, info);
        lock (_memory)
        {
            _kept++;
            if (Find(id) is { } node)
            {
                _memory.Remove(node);
                _memory.AddFirst(node);
            }
            else Remember(kept);
        }
        if (Options.Root != null && text.Length <= MaxResultChars) WriteToDisk(kept);
        return id;
    }

    /// <summary>The kept result <paramref name="id"/>; not_found with details.reason "evicted" (and the original call) or "unknown".</summary>
    public KeptResult Read(string id)
    {
        var key = id?.Trim().ToLowerInvariant() ?? "";
        lock (_memory)
        {
            if (Find(key) is { } node)
            {
                _memory.Remove(node);
                _memory.AddFirst(node);
                _reads++;
                return node.Value;
            }
        }
        KeptInfo? side = null;
        if (Options.Root != null && IdPattern().IsMatch(key))
        {
            side = ReadSide(key);
            if (side != null && ReadFromDisk(key, side) is { } kept)
            {
                lock (_memory)
                {
                    _reads++;
                    if (Find(key) == null) Remember(kept);
                }
                return kept;
            }
        }
        lock (_memory)
            if (side == null) _forgotten.TryGetValue(key, out side);
        throw side != null ? Evicted(id ?? "", side) : Unknown(id ?? "");
    }

    public ResultStoreStatus Status()
    {
        var (entries, bytes) = Options.Root is { } folder ? FolderTally.Of(folder, () =>
        {
            int entries = 0;
            long bytes = 0;
            if (Directory.Exists(folder))
                foreach (var (_, size, _) in DiskEntries())
                {
                    entries++;
                    bytes += size;
                }
            return (entries, bytes);
        }) : (0, 0L);
        lock (_memory)
            return new(Options.Root != null ? "disk" : "memory", Options.Root, entries, bytes, Options.MaxBytes, Options.MaxAge,
                _memory.Count, _memoryChars, MemoryLimit, MaxResultChars, _kept, _reads, _evicted, _lastError);
    }

    /// <summary>Deletes disk entries unused for longer than the age limit, then the least recently used beyond the size limit.</summary>
    public void Evict()
    {
        if (Options.Root is not { } root || !Directory.Exists(root)) return;
        Interlocked.Increment(ref Walks);
        FolderTally.Forget(root);
        var now = DateTime.UtcNow;
        var live = new List<(string Id, long Size, DateTime Used)>();
        foreach (var entry in DiskEntries())
        {
            if (now - entry.Used > Options.MaxAge) EvictFromDisk(entry.Id);
            else live.Add(entry);
        }
        long total = live.Sum(e => e.Size);
        foreach (var entry in live.OrderBy(e => e.Used))
        {
            if (total <= Options.MaxBytes) break;
            EvictFromDisk(entry.Id);
            total -= entry.Size;
        }
        lock (_memory) (_diskBytes, _walked) = (total, now);
        PruneTombstones(root, now);
    }

    private LinkedListNode<KeptResult>? Find(string id)
    {
        for (var node = _memory.First; node != null; node = node.Next)
            if (node.Value.Id == id) return node;
        return null;
    }

    /// <summary>Adds to the memory tier (under its lock), dropping the least recently used beyond its limit.</summary>
    private void Remember(KeptResult kept)
    {
        _memory.AddFirst(kept);
        _memoryChars += Chars(kept);
        _forgotten.Remove(kept.Id);
        while (_memoryChars > MemoryLimit && _memory.Count > 1)
        {
            var last = _memory.Last!.Value;
            _memory.RemoveLast();
            _memoryChars -= Chars(last);
            if (Options.Root == null || last.Text.Length > MaxResultChars) Forget(last);
        }
    }

    private static long Chars(KeptResult r) => r.Text.Length + (r.Record?.Length ?? 0);

    private void Forget(KeptResult r)
    {
        _evicted++;
        if (_forgotten.Count >= MaxTombstones) _forgotten.Remove(_forgotten.Keys.First());
        _forgotten[r.Id] = r.Info;
    }

    private string TextPath(string id) => Path.Combine(Options.Root!, id + ".txt");
    private string RecordPath(string id) => Path.Combine(Options.Root!, id + ".record.json");
    private string SidePath(string id) => Path.Combine(Options.Root!, id + ".meta.json");

    private void WriteToDisk(KeptResult kept)
    {
        var root = Options.Root!;
        try
        {
            var text = TextPath(kept.Id);
            if (File.Exists(text) && new FileInfo(text).Length == Encoding.UTF8.GetByteCount(kept.Text) && ReadSide(kept.Id)?.Sha256 == kept.Info.Sha256)
            {
                Touch(text);
                return;
            }
            // Text last: a reader finds the side record and record before the text that makes the entry visible.
            if (kept.Record != null) SafeFile.WriteUnderRoot(root, Path.GetFileName(RecordPath(kept.Id)), Encoding.UTF8.GetBytes(kept.Record), overwrite: true);
            SafeFile.WriteUnderRoot(root, Path.GetFileName(SidePath(kept.Id)), JsonSerializer.SerializeToUtf8Bytes(kept.Info, SideJson), overwrite: true);
            var bytes = Encoding.UTF8.GetBytes(kept.Text);
            SafeFile.WriteUnderRoot(root, Path.GetFileName(text), bytes, overwrite: true);
            bool due;
            lock (_memory)
            {
                if (_diskBytes >= 0) _diskBytes += bytes.Length + (kept.Record?.Length ?? 0);
                due = _diskBytes < 0 || _diskBytes > Options.MaxBytes || DateTime.UtcNow - _walked > TimeSpan.FromHours(1);
            }
            if (due) Evict();
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ToolError)
        {
            lock (_memory) _lastError = ex.Message;
        }
    }

    private KeptResult? ReadFromDisk(string id, KeptInfo side)
    {
        try
        {
            var path = TextPath(id);
            if (!File.Exists(path)) return null;
            var text = File.ReadAllText(path, Encoding.UTF8);
            if (Sha256Hex(text) != side.Sha256)
            {
                // Truncated or replaced: a miss, and removed so it is written again.
                TryDelete(path);
                return null;
            }
            string? record = null;
            if (side.HasRecord)
            {
                try { record = File.ReadAllText(RecordPath(id), Encoding.UTF8); }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
            }
            Touch(path);
            return new KeptResult(id, text, record, side);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    private KeptInfo? ReadSide(string id)
    {
        try { return JsonSerializer.Deserialize<KeptInfo>(File.ReadAllBytes(SidePath(id)), SideJson); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException) { return null; }
    }

    private IEnumerable<(string Id, long Size, DateTime Used)> DiskEntries()
    {
        // one pass over the folder: the sizes and times come with the listing (no call per file)
        List<FileInfo> files;
        try { files = new DirectoryInfo(Options.Root!).EnumerateFiles("r-*").ToList(); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { yield break; }
        var records = files.Where(f => f.Name.EndsWith(".record.json", StringComparison.Ordinal))
            .ToDictionary(f => f.Name[..^".record.json".Length], f => f.Length, StringComparer.Ordinal);
        foreach (var f in files.Where(f => f.Name.EndsWith(".txt", StringComparison.Ordinal)))
        {
            var id = f.Name[..^".txt".Length];
            var used = f.LastAccessTimeUtc > f.LastWriteTimeUtc ? f.LastAccessTimeUtc : f.LastWriteTimeUtc;
            yield return (id, f.Length + records.GetValueOrDefault(id), used);
        }
    }

    /// <summary>The content goes; the side record stays to explain a later read.</summary>
    private void EvictFromDisk(string id)
    {
        TryDelete(TextPath(id));
        TryDelete(RecordPath(id));
        lock (_memory) _evicted++;
    }

    /// <summary>Side records without content beyond twice the age limit, or beyond <see cref="MaxTombstones"/>, oldest first.</summary>
    private void PruneTombstones(string root, DateTime now)
    {
        List<FileInfo> orphans;
        try
        {
            orphans = [.. new DirectoryInfo(root).EnumerateFiles("r-*.meta.json")
                .Where(f => !File.Exists(TextPath(f.Name[..^".meta.json".Length])))
                .OrderByDescending(f => f.LastWriteTimeUtc)];
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return; }
        for (int i = 0; i < orphans.Count; i++)
            if (i >= MaxTombstones || now - orphans[i].LastWriteTimeUtc > 2 * Options.MaxAge)
                TryDelete(orphans[i].FullName);
        // Temp files of writers that died mid-write.
        try
        {
            foreach (var tmp in new DirectoryInfo(root).EnumerateFiles(".save-*.tmp"))
                if (now - tmp.LastWriteTimeUtc > TimeSpan.FromHours(6)) TryDelete(tmp.FullName);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
    }

    private static void Touch(string path)
    {
        try { File.SetLastAccessTimeUtc(path, DateTime.UtcNow); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
    }

    private static void TryDelete(string path)
    {
        try { File.Delete(path); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
    }

    private static string Sha256Hex(string text) => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(text)));

    private static ToolError Evicted(string id, KeptInfo side) =>
        new(ErrorCode.NotFound, $"kept result '{id}' ({side.Tool}, {side.Created:yyyy-MM-dd HH:mm} UTC) was evicted from the result store.",
            $"call {side.Tool} again{(side.Arguments is { Length: > 2 } a ? " with " + (a.Length <= MaxNextArguments ? a : a[..MaxNextArguments] + "...") : "")} (details.arguments)")
        {
            Details = new { reason = "evicted", tool = side.Tool, arguments = side.Arguments, created = side.Created },
        };

    private static ToolError Unknown(string id) =>
        new(ErrorCode.NotFound, $"no kept result '{id}'; ids look like r-0123456789ab and come from a resultId.",
            "repeat the original call; its resultId names the kept result")
        {
            Details = new { reason = "unknown" },
        };

    [GeneratedRegex("^r-[0-9a-f]{12}$")]
    private static partial Regex IdPattern();
}
