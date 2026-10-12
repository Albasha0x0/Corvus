using System.Buffers;
using System.IO.Compression;
using System.IO.Hashing;
using System.Security.Cryptography;

namespace Corvus.Core;

/// <summary>A file, link or archive entry of a walk; Path is relative with '/' separators.</summary>
public sealed class InventoryEntry
{
    public required string Path { get; init; }
    public long Size { get; set; }
    public long Ticks { get; init; }
    public string? Sha256 { get; set; }
    public uint? Crc32 { get; set; }
    /// <summary>Set for a symbolic link, junction or other reparse point: never followed.</summary>
    public string? LinkTarget { get; init; }
    /// <summary>Why the content could not be read (locked, denied); never compared as equal.</summary>
    public string? Error { get; set; }
    public bool HasContentKey => Sha256 != null || Crc32 != null;
}

/// <summary>One side of a comparison: a folder walk, a zip-family archive's central directory, or one file.</summary>
public sealed class Inventory
{
    public const string Folder = "folder", Zip = "zip", File = "file";

    public required string Root { get; init; }
    public required string Kind { get; init; }
    public required List<InventoryEntry> Entries { get; init; }
    /// <summary>False when the walk stopped early or a folder could not be listed: absence proves nothing.</summary>
    public bool Complete { get; set; } = true;
    public List<string> Problems { get; } = [];
    /// <summary>Identity of an archive or single file (size, write time) for reuse without a re-read.</summary>
    public (long Size, long Ticks) FileStamp { get; init; }
    public int Hashed { get; set; }
    public int Reused { get; set; }
    /// <summary>Entry streams opened inside an archive (0 when the central directory sufficed).</summary>
    public int EntryReads { get => _entryReads; set => _entryReads = value; }
    private int _entryReads;
    internal void CountEntryRead() => Interlocked.Increment(ref _entryReads);
}

/// <summary>Exclusion globs on relative paths: a pattern with '/' matches the path, one without matches the file name.</summary>
public sealed class PathFilter(string? patterns)
{
    private readonly string[] _paths = Split(patterns).Where(p => p.Contains('/')).ToArray();
    private readonly string[] _names = Split(patterns).Where(p => !p.Contains('/')).ToArray();

    private static IEnumerable<string> Split(string? text) =>
        (text ?? "").Replace('\\', '/').Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

    public bool ExcludesFile(string path)
    {
        int slash = path.LastIndexOf('/');
        var name = slash < 0 ? path : path[(slash + 1)..];
        return _names.Any(p => Wildcard.Matches(name, p)) || _paths.Any(p => Wildcard.Matches(path, p));
    }

    /// <summary>A folder whose every path is excluded ("Logs/**" or "Logs/*" matches "Logs/").</summary>
    public bool ExcludesDirectory(string path) => _paths.Any(p => Wildcard.Matches(path + "/", p));
}

/// <summary>Streaming inventories: enumerate first (no reads), then hash only what has no reusable hash, within a byte budget.</summary>
public static class StreamingInventory
{
    private const int BufferBytes = 1 << 20;

    public static bool IsArchive(string path)
    {
        Span<byte> magic = stackalloc byte[4];
        try
        {
            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 1);
            return fs.ReadAtLeast(magic, 4, throwOnEndOfStream: false) == 4 && Blob.Identify(magic) == "zip";
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return false; }
    }

    /// <summary>Lists <paramref name="root"/> without reading file contents; stops after <paramref name="maxEntries"/>.</summary>
    public static Inventory Enumerate(string root, PathFilter filter, int maxEntries, CancellationToken ct)
    {
        if (Directory.Exists(root)) return EnumerateFolder(root, filter, maxEntries, ct);
        var info = new FileInfo(root);
        var stamp = (info.Length, info.LastWriteTimeUtc.Ticks);
        if (IsArchive(root))
        {
            try { return EnumerateZip(root, stamp, filter, maxEntries, ct); }
            catch (InvalidDataException ex)
            {
                var single = Single(root, info, stamp);
                single.Problems.Add($"not a readable archive ({ex.Message}): compared as one file");
                return single;
            }
        }
        return Single(root, info, stamp);
    }

    private static Inventory Single(string root, FileInfo info, (long, long) stamp) => new()
    {
        Root = root, Kind = Inventory.File, FileStamp = stamp,
        Entries = [new InventoryEntry { Path = info.Name, Size = info.Length, Ticks = info.LastWriteTimeUtc.Ticks }],
    };

    private static Inventory EnumerateFolder(string root, PathFilter filter, int maxEntries, CancellationToken ct)
    {
        var inv = new Inventory { Root = root, Kind = Inventory.Folder, Entries = [] };
        var options = new EnumerationOptions { RecurseSubdirectories = false, IgnoreInaccessible = false, AttributesToSkip = 0, ReturnSpecialDirectories = false };
        var pending = new Stack<(DirectoryInfo Dir, string Rel)>();
        pending.Push((new DirectoryInfo(root), ""));
        while (pending.Count > 0)
        {
            ct.ThrowIfCancellationRequested();
            var (dir, rel) = pending.Pop();
            try
            {
                foreach (var item in dir.EnumerateFileSystemInfos("*", options))
                {
                    var path = rel.Length == 0 ? item.Name : rel + "/" + item.Name;
                    bool isDir = (item.Attributes & FileAttributes.Directory) != 0;
                    if ((item.Attributes & FileAttributes.ReparsePoint) != 0)
                    {
                        if (filter.ExcludesFile(path)) continue;
                        if (!Add(inv, new InventoryEntry { Path = path, Ticks = item.LastWriteTimeUtc.Ticks, LinkTarget = LinkTarget(item) }, maxEntries)) return inv;
                    }
                    else if (isDir)
                    {
                        if (!filter.ExcludesDirectory(path)) pending.Push(((DirectoryInfo)item, path));
                    }
                    else if (!filter.ExcludesFile(path))
                    {
                        var file = (FileInfo)item;
                        if (!Add(inv, new InventoryEntry { Path = path, Size = file.Length, Ticks = file.LastWriteTimeUtc.Ticks }, maxEntries)) return inv;
                    }
                }
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or System.Security.SecurityException)
            {
                inv.Complete = false;
                inv.Problems.Add($"folder '{(rel.Length == 0 ? "." : rel)}' not fully listed: {ex.Message}");
            }
        }
        inv.Entries.Sort((a, b) => string.CompareOrdinal(a.Path, b.Path));
        return inv;
    }

    private static string LinkTarget(FileSystemInfo item)
    {
        try { return item.LinkTarget ?? "(reparse point)"; }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return "(reparse point)"; }
    }

    private static bool Add(Inventory inv, InventoryEntry entry, int maxEntries)
    {
        if (inv.Entries.Count >= maxEntries)
        {
            inv.Complete = false;
            inv.Problems.Add($"stopped at maxEntries={maxEntries}");
            inv.Entries.Sort((a, b) => string.CompareOrdinal(a.Path, b.Path));
            return false;
        }
        inv.Entries.Add(entry);
        return true;
    }

    private static Inventory EnumerateZip(string root, (long, long) stamp, PathFilter filter, int maxEntries, CancellationToken ct)
    {
        var inv = new Inventory { Root = root, Kind = Inventory.Zip, Entries = [], FileStamp = stamp };
        using var fs = new FileStream(root, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 4096, FileOptions.RandomAccess);
        using var zip = new ZipArchive(fs, ZipArchiveMode.Read);
        var seen = new HashSet<string>(StringComparer.Ordinal);
        int duplicates = 0;
        foreach (var e in zip.Entries)
        {
            ct.ThrowIfCancellationRequested();
            var path = e.FullName.Replace('\\', '/');
            if (path.EndsWith('/') || filter.ExcludesFile(path)) continue;
            if (!seen.Add(path)) { duplicates++; continue; }
            if (!Add(inv, new InventoryEntry { Path = path, Size = e.Length, Ticks = e.LastWriteTime.UtcTicks, Crc32 = e.Crc32 }, maxEntries)) return inv;
        }
        if (duplicates > 0) inv.Problems.Add($"{duplicates} duplicate entry name(s): the first of each was compared");
        inv.Entries.Sort((a, b) => string.CompareOrdinal(a.Path, b.Path));
        return inv;
    }

    /// <summary>
    /// SHA-256 and CRC-32 of every folder or single-file entry without a hash, reusing <paramref name="previous"/> hashes of the same
    /// path, size and write time. Entries past <paramref name="budget"/> bytes stay unhashed; a file that cannot be read gets an Error.
    /// </summary>
    public static void Hash(Inventory inv, IReadOnlyDictionary<string, InventoryEntry>? previous, ref long budget, Action<int>? progress, CancellationToken ct)
    {
        if (inv.Kind == Inventory.Zip) return;
        var work = new List<InventoryEntry>();
        foreach (var e in inv.Entries)
        {
            if (e.LinkTarget != null || e.HasContentKey) continue;
            if (previous != null && previous.TryGetValue(e.Path, out var p) && p.Sha256 != null && p.Size == e.Size && p.Ticks == e.Ticks)
            {
                (e.Sha256, e.Crc32) = (p.Sha256, p.Crc32);
                inv.Reused++;
                continue;
            }
            if (budget < e.Size) continue;
            budget -= e.Size;
            work.Add(e);
        }
        int done = 0;
        Parallel.ForEach(work, new ParallelOptions { MaxDegreeOfParallelism = Math.Clamp(Environment.ProcessorCount, 2, 16), CancellationToken = ct },
            () => ArrayPool<byte>.Shared.Rent(BufferBytes),
            (e, state, buffer) =>
            {
                var full = inv.Kind == Inventory.File ? inv.Root : System.IO.Path.Combine(inv.Root, e.Path);
                try { HashFile(full, e, buffer, ct); }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { e.Error = ex.Message; }
                progress?.Invoke(Interlocked.Increment(ref done));
                return buffer;
            },
            buffer => ArrayPool<byte>.Shared.Return(buffer));
        inv.Hashed = work.Count;
    }

    private static void HashFile(string path, InventoryEntry e, byte[] buffer, CancellationToken ct)
    {
        using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 1, FileOptions.SequentialScan);
        using var sha = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var crc = new Crc32();
        long total = 0;
        int n;
        while ((n = fs.Read(buffer, 0, buffer.Length)) > 0)
        {
            sha.AppendData(buffer, 0, n);
            crc.Append(buffer.AsSpan(0, n));
            total += n;
            if (total >= 64L << 20) ct.ThrowIfCancellationRequested();
        }
        e.Size = total; // the file may have changed since it was listed
        e.Crc32 = crc.GetCurrentHashAsUInt32();
        e.Sha256 = Convert.ToHexStringLower(sha.GetHashAndReset());
    }

    /// <summary>Reads entry contents on demand (an archive is opened once); counts archive entry reads.</summary>
    public sealed class ContentReader(Inventory inv) : IDisposable
    {
        private ZipArchive? _zip;
        private Dictionary<string, ZipArchiveEntry>? _byPath;

        /// <summary>The first <paramref name="maxBytes"/> bytes (all when <paramref name="whole"/> and the entry fits), or null when unreadable or too large.</summary>
        public byte[]? Read(InventoryEntry e, long maxBytes, bool whole)
        {
            if (e.LinkTarget != null || e.Error != null || (whole && e.Size > maxBytes)) return null;
            try
            {
                using var s = Open(e);
                if (s == null) return null;
                var bytes = new byte[(int)Math.Min(e.Size, maxBytes)];
                int read = s.ReadAtLeast(bytes, bytes.Length, throwOnEndOfStream: false);
                return read == bytes.Length ? bytes : bytes[..read];
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidDataException) { return null; }
        }

        private Stream? Open(InventoryEntry e)
        {
            switch (inv.Kind)
            {
                case Inventory.File:
                    return new FileStream(inv.Root, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                case Inventory.Folder:
                    return new FileStream(System.IO.Path.Combine(inv.Root, e.Path), FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
                default:
                    if (_zip == null)
                    {
                        _zip = new ZipArchive(new FileStream(inv.Root, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete), ZipArchiveMode.Read);
                        _byPath = _zip.Entries.GroupBy(x => x.FullName.Replace('\\', '/'), StringComparer.Ordinal).ToDictionary(g => g.Key, g => g.First(), StringComparer.Ordinal);
                    }
                    if (!_byPath!.TryGetValue(e.Path, out var entry)) return null;
                    inv.CountEntryRead();
                    return entry.Open();
            }
        }

        public void Dispose() => _zip?.Dispose();
    }
}
