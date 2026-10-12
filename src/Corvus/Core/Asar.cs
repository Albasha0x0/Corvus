using System.Buffers.Binary;
using System.Globalization;
using System.Security.Cryptography;
using System.Text.Json;

namespace Corvus.Core;

public enum AsarEntryKind { File, Directory, Link }

/// <summary>Declared integrity of a file: whole-file hash and per-block hashes (hex), as @electron/asar writes them.</summary>
public sealed record AsarIntegrity(string Algorithm, string Hash, long BlockSize, IReadOnlyList<string> Blocks);

/// <summary>
/// One archive entry. Offset is relative to the data start (-1 when missing or not a number). UnsafeName marks a name with
/// a separator, "..", ":", a control character or nothing in it: listed, never extracted.
/// </summary>
public sealed record AsarEntry(string Path, AsarEntryKind Kind, long Offset, long Size, bool Unpacked, bool Executable, string? Link,
    AsarIntegrity? Integrity, bool UnsafeName);

/// <summary>
/// An Electron ASAR archive: a Chromium pickle holding the JSON header, then the packed file data. Reads only the header
/// eagerly; file data is read and verified on request through the stream. Malformed input gives issues, not exceptions,
/// except a header that cannot be located at all.
/// </summary>
public sealed class AsarArchive
{
    /// <summary>Largest header accepted; a 50,000-file app has a header of a few MB.</summary>
    public const int MaxHeaderBytes = 64 * 1024 * 1024;
    public const int MaxDepth = 256;
    public const int MaxEntries = 1_000_000;
    private const int MaxLinkHops = 32;

    public long Length { get; }
    /// <summary>Length of the header JSON; the integrity hash covers exactly these bytes.</summary>
    public int HeaderLength { get; }
    public long DataStart { get; }
    public string HeaderSha256 { get; }
    /// <summary>Directories, files and links in document order (directories before their children).</summary>
    public IReadOnlyList<AsarEntry> Entries { get; }
    public IReadOnlyList<string> Issues { get; }

    private readonly Dictionary<string, AsarEntry> _byPath;

    private AsarArchive(long length, int headerLength, long dataStart, string sha, List<AsarEntry> entries, List<string> issues)
    {
        Length = length;
        HeaderLength = headerLength;
        DataStart = dataStart;
        HeaderSha256 = sha;
        Entries = entries;
        Issues = issues;
        _byPath = new Dictionary<string, AsarEntry>(entries.Count, StringComparer.Ordinal);
        foreach (var e in entries) _byPath[e.Path] = e;
    }

    /// <summary>The first 16 bytes look like an ASAR pickle header whose JSON starts with '{'.</summary>
    public static bool Looks(ReadOnlySpan<byte> b)
    {
        if (b.Length < 17 || BinaryPrimitives.ReadUInt32LittleEndian(b) != 4) return false;
        uint pickle = BinaryPrimitives.ReadUInt32LittleEndian(b[4..]), payload = BinaryPrimitives.ReadUInt32LittleEndian(b[8..]),
            json = BinaryPrimitives.ReadUInt32LittleEndian(b[12..]);
        return payload + 4 == pickle && json + 4 <= payload && json > 1 && b[16] == '{';
    }

    public AsarEntry? Find(string path) => _byPath.GetValueOrDefault(path.Trim('/'));

    /// <summary>Reads the header; throws <see cref="ToolError"/> when the pickle header is unusable.</summary>
    public static AsarArchive Read(Stream stream, CancellationToken ct = default)
    {
        long length = stream.Length;
        Span<byte> head = stackalloc byte[16];
        stream.Position = 0;
        if (stream.ReadAtLeast(head, 16, throwOnEndOfStream: false) < 16 || BinaryPrimitives.ReadUInt32LittleEndian(head) != 4)
            throw new ToolError(ErrorCode.MalformedInput, "Not an ASAR archive: the pickle header is missing.");
        uint pickle = BinaryPrimitives.ReadUInt32LittleEndian(head[4..]), payload = BinaryPrimitives.ReadUInt32LittleEndian(head[8..]),
            json = BinaryPrimitives.ReadUInt32LittleEndian(head[12..]);
        if (payload + 4L != pickle || json + 4L > payload)
            throw new ToolError(ErrorCode.MalformedInput, $"Corrupt ASAR header: pickle size {pickle}, payload {payload}, JSON {json} bytes do not agree.");
        if (json > MaxHeaderBytes) throw new ToolError(ErrorCode.LimitExceeded, $"ASAR header of {json:N0} bytes is over the {MaxHeaderBytes:N0}-byte limit.");
        if (16 + (long)json > length || 8 + (long)pickle > length)
            throw new ToolError(ErrorCode.MalformedInput, $"Corrupt ASAR header: {json:N0} bytes of JSON past the end of the {length:N0}-byte file.");
        var bytes = new byte[json];
        stream.ReadExactly(bytes);
        var issues = new List<string>();
        var entries = new List<AsarEntry>();
        var parser = new HeaderParser(entries, issues, ct);
        try { parser.Parse(bytes); }
        catch (Exception ex) when (ex is JsonException or InvalidOperationException) // InvalidOperationException: invalid UTF-8 in a string
        {
            issues.Add($"malformed_header: the JSON stops being valid ({ex.Message}); entries before that point are kept.");
        }
        var archive = new AsarArchive(length, (int)json, 8 + (long)pickle, Convert.ToHexStringLower(SHA256.HashData(bytes)),
            parser.Duplicates ? KeepLast(entries) : entries, issues);
        archive.Validate(issues);
        return archive;
    }

    /// <summary>With duplicate keys the last occurrence wins, as in JSON.parse, and with it the subtree written after it.</summary>
    private static List<AsarEntry> KeepLast(List<AsarEntry> entries)
    {
        var last = new Dictionary<string, int>(StringComparer.Ordinal);
        for (int i = 0; i < entries.Count; i++) last[entries[i].Path] = i;
        var kept = new List<AsarEntry>(last.Count);
        for (int i = 0; i < entries.Count; i++)
        {
            var path = entries[i].Path;
            if (last[path] != i) continue;
            bool live = true;
            for (int slash = path.LastIndexOf('/'); slash > 0 && live; slash = path.LastIndexOf('/', slash - 1))
                live = !last.TryGetValue(path[..slash], out var at) || at < i;
            if (live) kept.Add(entries[i]);
        }
        return kept;
    }

    private void Validate(List<string> issues)
    {
        long dataLength = Length - DataStart;
        int outside = 0, unsafeNames = 0;
        var packed = new List<AsarEntry>();
        foreach (var e in Entries)
        {
            if (e.UnsafeName) unsafeNames++;
            if (e.Kind != AsarEntryKind.File || e.Unpacked) continue;
            if (e.Offset < 0 || e.Size < 0 || e.Offset > dataLength - e.Size)
            {
                if (outside++ < 3) issues.Add($"out_of_range: {e.Path} (offset {e.Offset}, size {e.Size}) lies outside the {dataLength:N0} bytes of data.");
                continue;
            }
            if (e.Size > 0) packed.Add(e);
        }
        if (outside > 3) issues.Add($"out_of_range: {outside - 3} more entries outside the data.");
        if (unsafeNames > 0) issues.Add($"unsafe_name: {unsafeNames} entr(ies) with a separator, '..', ':' or control character in the name; listed, never extracted.");
        packed.Sort((a, b) => a.Offset.CompareTo(b.Offset));
        int overlaps = 0;
        for (int i = 1; i < packed.Count; i++)
            if (packed[i].Offset < packed[i - 1].Offset + packed[i - 1].Size && overlaps++ < 3)
                issues.Add($"overlap: {packed[i].Path} starts inside {packed[i - 1].Path}.");
        if (overlaps > 3) issues.Add($"overlap: {overlaps - 3} more overlapping ranges.");
    }

    /// <summary>The file a link resolves to inside the archive, or null with the reason (escapes, missing, cycle, directory).</summary>
    public AsarEntry? ResolveLink(AsarEntry entry, out string? problem)
    {
        problem = null;
        var current = entry;
        for (int hop = 0; current.Kind == AsarEntryKind.Link; hop++)
        {
            if (hop >= MaxLinkHops) { problem = "link_cycle"; return null; }
            if (Normalize(current.Link!) is not { } target) { problem = "link_escapes"; return null; }
            if (!_byPath.TryGetValue(target, out var next)) { problem = "link_missing"; return null; }
            current = next;
        }
        if (current.Kind == AsarEntryKind.Directory) { problem = "link_to_directory"; return null; }
        return current;
    }

    /// <summary>"a/./b/../c" -> "a/c"; null when the path climbs above the archive root or is absolute.</summary>
    internal static string? Normalize(string link)
    {
        if (link.Length == 0 || link[0] is '/' or '\\' || link.Contains(':')) return null;
        var parts = new List<string>();
        foreach (var p in link.Split('/', '\\'))
        {
            if (p is "" or ".") continue;
            if (p == "..")
            {
                if (parts.Count == 0) return null;
                parts.RemoveAt(parts.Count - 1);
            }
            else parts.Add(p);
        }
        return parts.Count == 0 ? null : string.Join('/', parts);
    }

    /// <summary>The bytes of a packed file, or null when it lies outside the data or is over <paramref name="maxBytes"/>.</summary>
    public byte[]? ReadPacked(Stream stream, AsarEntry e, long maxBytes)
    {
        if (e.Kind != AsarEntryKind.File || e.Unpacked || e.Offset < 0 || e.Size < 0 || e.Size > maxBytes || e.Size > Array.MaxLength
            || e.Offset > Length - DataStart - e.Size) return null;
        var bytes = new byte[e.Size];
        stream.Position = DataStart + e.Offset;
        stream.ReadExactly(bytes);
        return bytes;
    }

    /// <summary>
    /// Where an unpacked entry lives (<c>&lt;archive&gt;.unpacked/&lt;path&gt;</c>); null with the reason when the name is unsafe,
    /// it would leave that folder, a component is a link or junction, or the file is missing.
    /// </summary>
    public static string? UnpackedPath(string archivePath, AsarEntry e, out string? problem)
    {
        problem = null;
        if (e.UnsafeName) { problem = "unsafe_name"; return null; }
        var root = Path.GetFullPath(archivePath + ".unpacked");
        var current = root;
        try
        {
            if (!Directory.Exists(root)) { problem = "unpacked_missing"; return null; }
            if ((File.GetAttributes(root) & FileAttributes.ReparsePoint) != 0) { problem = "unpacked_is_link"; return null; }
            foreach (var part in e.Path.Split('/'))
            {
                current = Path.Combine(current, part);
                if (!current.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.Ordinal)) { problem = "unsafe_name"; return null; }
                if (!File.Exists(current) && !Directory.Exists(current)) { problem = "unpacked_missing"; return null; }
                if ((File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0) { problem = "unpacked_is_link"; return null; }
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            problem = "unpacked_unreadable";
            return null;
        }
        if (!File.Exists(current)) { problem = "unpacked_missing"; return null; }
        return current;
    }

    /// <summary>
    /// Integrity verdict of one file: ok, ok_signed_after_packing (an unpacked PE matches once the Authenticode signature added
    /// later is taken off), hash_mismatch, block_mismatch, size_mismatch, no_integrity, unsupported_algorithm or a read problem.
    /// </summary>
    public sealed record Verdict(string Status, int? FirstBadBlock = null, string? Computed = null);

    /// <summary>
    /// Hashes the file (packed, or unpacked beside <paramref name="archivePath"/>) in one streamed pass and compares the
    /// whole-file and block hashes. <paramref name="buffer"/> is reused across calls; it grows to the block size.
    /// </summary>
    public Verdict Verify(Stream stream, string? archivePath, AsarEntry e, ref byte[] buffer, CancellationToken ct = default)
    {
        if (e.Kind != AsarEntryKind.File) return new("not_a_file");
        if (e.Integrity is not { } integrity) return new("no_integrity");
        if (!integrity.Algorithm.Equals("SHA256", StringComparison.OrdinalIgnoreCase)) return new("unsupported_algorithm");
        Stream source;
        bool own = false;
        (int Offset, int Length)[]? signedLater = null;
        long start;
        if (e.Unpacked)
        {
            if (archivePath == null) return new("unpacked_not_checked");
            if (UnpackedPath(archivePath, e, out var problem) is not { } file) return new(problem!);
            try { source = File.OpenRead(file); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return new("unpacked_unreadable"); }
            own = true;
            start = 0;
            if (source.Length != e.Size && (source.Length < e.Size || (signedLater = SignatureFields(source, e.Size)) == null))
            {
                source.Dispose();
                return new("size_mismatch");
            }
        }
        else
        {
            if (e.Size < 0 || e.Offset < 0 || e.Offset > Length - DataStart - e.Size) return new("out_of_range");
            source = stream;
            start = DataStart + e.Offset;
        }
        try
        {
            long blockSize = integrity.BlockSize is > 0 and <= 64 * 1024 * 1024 ? integrity.BlockSize : 4 * 1024 * 1024;
            if (buffer.Length < blockSize) buffer = new byte[blockSize];
            using var whole = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
            source.Position = start;
            int? badBlock = null;
            int count = 0;
            long done = 0;
            do // an empty file has one (empty) block
            {
                ct.ThrowIfCancellationRequested();
                int n = (int)Math.Min(blockSize, e.Size - done);
                source.ReadExactly(buffer, 0, n);
                foreach (var (at, length) in signedLater ?? [])
                    for (long i = Math.Max(at, done); i < Math.Min(at + length, done + n); i++) buffer[i - done] = 0;
                whole.AppendData(buffer, 0, n);
                if (badBlock == null && (count >= integrity.Blocks.Count || !BlockMatches(buffer.AsSpan(0, n), integrity.Blocks[count]))) badBlock = count;
                count++;
                done += n;
            } while (done < e.Size);
            // the writer adds an empty block after a file that fills its last block exactly
            bool extraEmpty = integrity.Blocks.Count == count + 1 && e.Size % blockSize == 0 && BlockMatches([], integrity.Blocks[count]);
            if (badBlock == null && integrity.Blocks.Count != count && !extraEmpty) badBlock = Math.Min(count, integrity.Blocks.Count);
            var computed = Convert.ToHexStringLower(whole.GetHashAndReset());
            if (!computed.Equals(integrity.Hash, StringComparison.OrdinalIgnoreCase)) return new("hash_mismatch", badBlock, computed);
            return badBlock != null ? new("block_mismatch", badBlock, computed) : new(signedLater != null ? "ok_signed_after_packing" : "ok", null, computed);
        }
        catch (EndOfStreamException) { return new("truncated"); }
        catch (IOException) { return new("unreadable"); }
        finally { if (own) source.Dispose(); }
    }

    /// <summary>
    /// For a PE whose Authenticode table starts at <paramref name=declared/> (8-byte aligned) and runs to the end: the header
    /// fields signing changed (checksum, security directory), which were zero when the file was packed. Null otherwise.
    /// </summary>
    private static (int Offset, int Length)[]? SignatureFields(Stream s, long declared)
    {
        Span<byte> head = stackalloc byte[1024];
        s.Position = 0;
        if (s.ReadAtLeast(head, head.Length, throwOnEndOfStream: false) < head.Length || head[0] != 'M' || head[1] != 'Z') return null;
        int pe = BinaryPrimitives.ReadInt32LittleEndian(head[0x3C..]);
        if (pe < 0 || pe > head.Length - 24 - 8 * 16 - 112 || BinaryPrimitives.ReadUInt32LittleEndian(head[pe..]) != 0x4550) return null;
        int opt = pe + 24, dirs = opt + (BinaryPrimitives.ReadUInt16LittleEndian(head[opt..]) == 0x20B ? 112 : 96);
        uint table = BinaryPrimitives.ReadUInt32LittleEndian(head[(dirs + 32)..]), size = BinaryPrimitives.ReadUInt32LittleEndian(head[(dirs + 36)..]);
        bool appended = table >= declared && table - declared < 8 && table + (long)size == s.Length && declared > dirs + 40;
        return appended ? [(opt + 64, 4), (dirs + 32, 8)] : null;
    }

    private static bool BlockMatches(ReadOnlySpan<byte> block, string declared) =>
        Convert.ToHexStringLower(SHA256.HashData(block)).Equals(declared, StringComparison.OrdinalIgnoreCase);

    /// <summary>A file name that cannot be written safely: empty, "." or "..", a separator, ':' or a control character.</summary>
    internal static bool IsUnsafeName(string name)
    {
        if (name.Length == 0 || name is "." or "..") return true;
        foreach (var c in name)
            if (c is '/' or '\\' or ':' || c < 0x20 || c == 0x7F) return true;
        return false;
    }

    /// <summary>Recursive descent over the header JSON into a flat entry list.</summary>
    private sealed class HeaderParser(List<AsarEntry> entries, List<string> issues, CancellationToken ct)
    {
        public bool Duplicates { get; private set; }
        private int _reported;

        public void Parse(byte[] json)
        {
            var reader = new Utf8JsonReader(json, new JsonReaderOptions { MaxDepth = MaxDepth * 2 + 8, AllowTrailingCommas = false });
            if (!reader.Read() || reader.TokenType != JsonTokenType.StartObject) throw new JsonException("the header is not a JSON object");
            Node(ref reader, "", 0, false, false, isRoot: true);
        }

        private void Issue(string text)
        {
            if (_reported++ < 20) issues.Add(text);
            else if (_reported == 21) issues.Add("more issues not listed.");
        }

        /// <summary>Reads one node object (reader on its StartObject) and adds it and its children.</summary>
        private void Node(ref Utf8JsonReader reader, string path, int depth, bool parentUnpacked, bool unsafeName, bool isRoot = false)
        {
            ct.ThrowIfCancellationRequested();
            long offset = -1, size = -1;
            bool unpacked = parentUnpacked, executable = false, hasFiles = false, badOffset = false;
            string? link = null;
            AsarIntegrity? integrity = null;
            int self = -1;
            while (reader.Read() && reader.TokenType == JsonTokenType.PropertyName)
            {
                var key = reader.GetString();
                reader.Read();
                switch (key)
                {
                    case "files" when reader.TokenType == JsonTokenType.StartObject:
                        hasFiles = true;
                        if (!isRoot)
                        {
                            self = entries.Count;
                            entries.Add(new AsarEntry(path, AsarEntryKind.Directory, -1, 0, unpacked, false, null, null, unsafeName));
                        }
                        Children(ref reader, path, depth, unpacked, unsafeName);
                        break;
                    case "offset":
                        if (reader.TokenType == JsonTokenType.String && long.TryParse(reader.GetString(), NumberStyles.None, CultureInfo.InvariantCulture, out var o)) offset = o;
                        else if (reader.TokenType == JsonTokenType.Number && reader.TryGetInt64(out var on) && on >= 0) offset = on;
                        else { badOffset = true; reader.Skip(); }
                        break;
                    case "size":
                        if (reader.TokenType == JsonTokenType.Number && reader.TryGetInt64(out var s) && s >= 0) size = s;
                        else reader.Skip();
                        break;
                    case "unpacked" when reader.TokenType is JsonTokenType.True or JsonTokenType.False:
                        unpacked = reader.TokenType == JsonTokenType.True;
                        if (self >= 0) entries[self] = entries[self] with { Unpacked = unpacked };
                        break;
                    case "executable" when reader.TokenType is JsonTokenType.True or JsonTokenType.False:
                        executable = reader.TokenType == JsonTokenType.True;
                        break;
                    case "link" when reader.TokenType == JsonTokenType.String:
                        link = reader.GetString();
                        break;
                    case "integrity" when reader.TokenType == JsonTokenType.StartObject:
                        integrity = Integrity(ref reader);
                        break;
                    default:
                        reader.Skip();
                        break;
                }
            }
            if (isRoot || hasFiles) return;
            if (entries.Count >= MaxEntries) throw new JsonException($"more than {MaxEntries:N0} entries");
            if (link != null)
            {
                entries.Add(new AsarEntry(path, AsarEntryKind.Link, -1, 0, false, false, link, null, unsafeName));
                return;
            }
            if (badOffset || (offset < 0 && !unpacked)) Issue($"bad_offset: {path} has no usable offset.");
            if (size < 0) Issue($"bad_size: {path} has no usable size.");
            entries.Add(new AsarEntry(path, AsarEntryKind.File, offset, size, unpacked, executable, null, integrity, unsafeName));
        }

        private void Children(ref Utf8JsonReader reader, string path, int depth, bool unpacked, bool unsafeParent)
        {
            if (depth + 1 > MaxDepth) throw new JsonException($"nesting deeper than {MaxDepth} directories");
            HashSet<string>? names = null;
            while (reader.Read() && reader.TokenType == JsonTokenType.PropertyName)
            {
                var name = reader.GetString()!;
                reader.Read();
                if (reader.TokenType != JsonTokenType.StartObject)
                {
                    Issue($"bad_entry: {Join(path, name)} is not an object.");
                    reader.Skip();
                    continue;
                }
                names ??= new HashSet<string>(StringComparer.Ordinal);
                if (!names.Add(name))
                {
                    Duplicates = true;
                    Issue($"duplicate_key: {Join(path, name)} appears more than once; the last one is used.");
                }
                Node(ref reader, Join(path, name), depth + 1, unpacked, unsafeParent || IsUnsafeName(name));
            }
        }

        private static string Join(string path, string name) => path.Length == 0 ? name : path + "/" + name;

        private static AsarIntegrity? Integrity(ref Utf8JsonReader reader)
        {
            string? algorithm = null, hash = null;
            long blockSize = 0;
            var blocks = new List<string>();
            while (reader.Read() && reader.TokenType == JsonTokenType.PropertyName)
            {
                var key = reader.GetString();
                reader.Read();
                switch (key)
                {
                    case "algorithm" when reader.TokenType == JsonTokenType.String: algorithm = reader.GetString(); break;
                    case "hash" when reader.TokenType == JsonTokenType.String: hash = reader.GetString(); break;
                    case "blockSize" when reader.TokenType == JsonTokenType.Number: reader.TryGetInt64(out blockSize); break;
                    case "blocks" when reader.TokenType == JsonTokenType.StartArray:
                        while (reader.Read() && reader.TokenType != JsonTokenType.EndArray)
                            if (reader.TokenType == JsonTokenType.String) blocks.Add(reader.GetString()!);
                            else reader.Skip();
                        break;
                    default: reader.Skip(); break;
                }
            }
            return algorithm != null && hash != null ? new AsarIntegrity(algorithm, hash, blockSize, blocks) : null;
        }
    }
}

/// <summary>An ASAR archive as a container: every entry listed with its integrity verdict, files extracted on request.</summary>
public static class AsarContainer
{
    public const string Kind = "Electron ASAR archive";

    /// <summary>Integrity of an archive: the header hash against the app's declared one (good, bad, absent), and file verdicts by status.</summary>
    public sealed record IntegrityFacts(string HeaderSha256, string HeaderStatus, Electron.DeclaredHash? Declared,
        IReadOnlyDictionary<string, int> Files, IReadOnlyList<string> FirstProblems);

    /// <summary>What a survey of an archive found; Items holds the extracted files.</summary>
    public sealed record Survey(AsarArchive Archive, IntegrityFacts Integrity, List<ContainerEntry> Entries, List<ExtractedItem> Items, List<string> Notes,
        int Files, int Directories, int Links, int Unpacked);

    public static ContainerContents Open(byte[] data, string? location, bool allFiles, AnalysisLimits limits, CancellationToken ct)
    {
        using var stream = new MemoryStream(data, writable: false);
        var s = Read(stream, location, e => allFiles || Containers.IsInteresting(e.Path) || e.Path.EndsWith(".asar", StringComparison.OrdinalIgnoreCase), limits, ct);
        return new ContainerContents(Kind, s.Items, s.Notes) { Entries = s.Entries };
    }

    /// <summary>Lists, verifies and extracts (<paramref name="extract"/>) the archive in <paramref name="stream"/>.</summary>
    public static Survey Read(Stream stream, string? location, Func<AsarEntry, bool> extract, AnalysisLimits limits, CancellationToken ct)
    {
        var archive = AsarArchive.Read(stream, ct);
        var entries = new List<ContainerEntry>(archive.Entries.Count);
        var items = new List<ExtractedItem>();
        var notes = new List<string>();
        var statuses = new SortedDictionary<string, int>(StringComparer.Ordinal);
        var problems = new List<string>();
        byte[] buffer = [];
        int files = 0, dirs = 0, links = 0, unpacked = 0, refused = 0, skipped = 0;
        long total = 0;
        foreach (var e in archive.Entries)
        {
            ct.ThrowIfCancellationRequested();
            var flags = new List<string>();
            if (e.UnsafeName) flags.Add("unsafe name");
            AsarEntry? source;
            switch (e.Kind)
            {
                case AsarEntryKind.Directory:
                    dirs++;
                    entries.Add(new ContainerEntry(e.Path + "/", 0, e.Unpacked ? "directory, unpacked" : "directory"));
                    continue;
                case AsarEntryKind.Link:
                    links++;
                    source = archive.ResolveLink(e, out var linkProblem);
                    flags.Insert(0, source != null ? $"link to {source.Path}" : $"link to {e.Link} ({linkProblem})");
                    break;
                default:
                    files++;
                    if (e.Unpacked) { unpacked++; flags.Add("unpacked"); }
                    if (e.Executable) flags.Add("executable");
                    var verdict = archive.Verify(stream, location, e, ref buffer, ct);
                    statuses[verdict.Status] = statuses.GetValueOrDefault(verdict.Status) + 1;
                    if (!verdict.Status.StartsWith("ok", StringComparison.Ordinal) && verdict.Status != "no_integrity" && problems.Count < 5)
                        problems.Add($"{e.Path}: {verdict.Status}{(verdict.FirstBadBlock is { } b ? $" (first bad block {b})" : "")}");
                    flags.Add("integrity " + verdict.Status + (verdict.FirstBadBlock is { } bad ? $" (block {bad})" : ""));
                    source = e;
                    break;
            }
            entries.Add(new ContainerEntry(e.Path, source?.Size ?? 0, string.Join(", ", flags)));
            if (source == null || !extract(e)) continue;
            if (e.UnsafeName) { refused++; continue; }
            if (items.Count >= limits.MaxItems || source.Size > limits.MaxItemBytes || (total += Math.Max(0, source.Size)) > limits.MaxTotalBytes) { skipped++; continue; }
            var bytes = Bytes(stream, archive, location, source, limits, out var why);
            if (bytes == null) { if (notes.Count < 20) notes.Add($"Skipped {e.Path}: {why}."); continue; }
            var origin = e.Kind == AsarEntryKind.Link ? $"ASAR link to {source.Path}" : source.Unpacked ? "ASAR unpacked entry" : "ASAR entry";
            items.Add(new ExtractedItem(e.Path, bytes, origin));
        }

        Electron.DeclaredHash? declared = null;
        try { declared = location != null ? Electron.DeclaredFor(location) : null; }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException) { }
        string headerStatus = declared == null ? "absent" : declared.Hash.Equals(archive.HeaderSha256, StringComparison.OrdinalIgnoreCase) ? "good" : "bad";

        var head = new List<string>
        {
            $"ASAR archive: {files} file(s) ({unpacked} unpacked), {dirs} director(ies), {links} link(s); header {archive.HeaderLength:N0} bytes, SHA-256 {archive.HeaderSha256}.",
            headerStatus switch
            {
                "good" => $"Header integrity good: matches the hash declared in {declared!.Source}.",
                "bad" => $"Header integrity BAD: {declared!.Source} declares {declared.Hash}; the archive changed after packaging (Electron refuses it when the EnableEmbeddedAsarIntegrityValidation fuse is on).",
                _ => location == null ? "Header integrity not checked: the archive is not on disk beside its app."
                    : "Header integrity absent: the app declares no hash for this archive (no INTEGRITY/ELECTRONASAR resource or Info.plist ElectronAsarIntegrity).",
            },
        };
        if (statuses.Count > 0)
            head.Add("File integrity: " + string.Join(", ", statuses.Select(s => $"{s.Value} {s.Key}")) + (problems.Count > 0 ? $"; first: {string.Join("; ", problems)}" : "") + ".");
        notes.InsertRange(0, head);
        notes.AddRange(archive.Issues);
        if (refused > 0) notes.Add($"{refused} entr(ies) with unsafe names not extracted.");
        if (skipped > 0) notes.Add($"{skipped} entr(ies) not extracted: the extraction limit was reached.");
        return new Survey(archive, new IntegrityFacts(archive.HeaderSha256, headerStatus, declared, statuses, problems), entries, items, notes,
            files, dirs, links, unpacked);
    }

    private static byte[]? Bytes(Stream stream, AsarArchive archive, string? location, AsarEntry e, AnalysisLimits limits, out string? why)
    {
        why = null;
        if (!e.Unpacked)
        {
            var packed = archive.ReadPacked(stream, e, limits.MaxItemBytes);
            if (packed == null) why = "its data lies outside the archive";
            return packed;
        }
        if (location == null) { why = "unpacked, and the archive is not on disk"; return null; }
        if (AsarArchive.UnpackedPath(location, e, out var problem) is not { } file) { why = problem; return null; }
        try
        {
            using var f = File.OpenRead(file);
            var bytes = Blob.ReadBounded(f, limits.MaxItemBytes);
            if (bytes == null) why = "larger than the extraction limit";
            return bytes;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { why = ex.Message.TrimEnd('.'); return null; }
    }
}
