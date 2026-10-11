using System.Buffers.Binary;
using System.Diagnostics;
using System.IO.Hashing;
using K4os.Compression.LZ4;
using Corvus.Native.Providers;

namespace Corvus.Native.Code;

/// <summary>Where the code index cache lives and how it is bounded.</summary>
/// <param name="Root">Directory of the cache files.</param>
/// <param name="MaxBytes">Total size kept; the least recently used entries go first beyond it.</param>
/// <param name="MaxAge">Entries not used for this long are deleted.</param>
/// <param name="MinBuildTime">Indexes that built faster than this are not saved (small images rebuild quicker than they load).</param>
public sealed record CodeIndexCacheOptions(string Root, long MaxBytes, TimeSpan MaxAge, TimeSpan MinBuildTime)
{
    public const string RootVariable = "CORVUS_CODE_INDEX_CACHE";
    public const string MaxMegabytesVariable = "CORVUS_CODE_INDEX_CACHE_MB";
    public const string MaxDaysVariable = "CORVUS_CODE_INDEX_CACHE_DAYS";
    public const long DefaultMaxMegabytes = 8192;
    public const int DefaultMaxDays = 30;

    /// <summary>
    /// <c>&lt;LocalAppData&gt;/Corvus/code-index</c> (a sibling of the analysis cache and the annotations), or
    /// CORVUS_CODE_INDEX_CACHE; null when that variable is "off". Size and age limits from CORVUS_CODE_INDEX_CACHE_MB and
    /// CORVUS_CODE_INDEX_CACHE_DAYS.
    /// </summary>
    public static CodeIndexCacheOptions? FromEnvironment()
    {
        var root = Environment.GetEnvironmentVariable(RootVariable)?.Trim();
        if (root is "off" or "0" or "false" or "none") return null;
        long mb = long.TryParse(Environment.GetEnvironmentVariable(MaxMegabytesVariable), out var m) && m > 0 ? m : DefaultMaxMegabytes;
        int days = int.TryParse(Environment.GetEnvironmentVariable(MaxDaysVariable), out var d) && d > 0 ? d : DefaultMaxDays;
        return Default with { Root = string.IsNullOrEmpty(root) ? Default.Root : root, MaxBytes = mb << 20, MaxAge = TimeSpan.FromDays(days) };
    }

    /// <summary>The defaults, ignoring the environment.</summary>
    public static CodeIndexCacheOptions Default =>
        new(Path.Combine(Path.GetDirectoryName(AnalysisCache.DefaultRoot)!, "code-index"), DefaultMaxMegabytes << 20, TimeSpan.FromDays(DefaultMaxDays), TimeSpan.FromSeconds(1));
}

/// <summary>Counts of one cache since the server started, and what is on disk.</summary>
public sealed record CodeIndexCacheStatus(string Root, int Entries, long Bytes, long MaxBytes, TimeSpan MaxAge,
    int Hits, int Misses, int Rejected, int Writes, int Evicted, string? LastError);

/// <summary>
/// Saved code indexes, one file per image content (SHA-256) and build options digest:
/// <c>root/&lt;sha256&gt;-&lt;digest16&gt;.cidx</c>. A file holds a header (magic, <see cref="NativeCodeIndex.PersistFormatVersion"/>,
/// the image hash, the options digest, payload length and XxHash3 of the payload) and the payload in LZ4 blocks. Anything that does
/// not match or does not decode is ignored (and rebuilt and overwritten by the caller); writes go to a temporary file
/// renamed into place, so readers in this or another server process see a whole file or none. After each write the
/// least recently used entries beyond the size limit, and entries unused past the age limit, are deleted.
/// </summary>
public sealed class CodeIndexCache(CodeIndexCacheOptions options)
{
    private const ulong Magic = 0x3158444943_4D444EUL; // "NDMCIDX1"
    private const int HeaderSize = 8 + 4 + 4 + 32 + 32 + 8 + 8;
    private const string Extension = ".cidx";

    private int _hits, _misses, _rejected, _writes, _evicted;
    private string? _lastError;

    public CodeIndexCacheOptions Options { get; } = options with { Root = Path.GetFullPath(options.Root) };

    public string PathFor(string sha256, string optionsDigest) =>
        Path.Combine(Options.Root, $"{sha256.ToLowerInvariant()}-{optionsDigest[..16]}{Extension}");

    /// <summary>The saved index of <paramref name="image"/> built with <paramref name="buildOptions"/>, or null (none, or unusable).</summary>
    public NativeCodeIndex? TryLoad(INativeImage image, CodeIndexOptions? buildOptions, CancellationToken ct = default)
    {
        var (support, _) = InstructionSets.For(image.Arch);
        if (support != CodeSupport.Full || !BitConverter.IsLittleEndian) return null;
        var sw = Stopwatch.StartNew();
        var digest = NativeCodeIndex.OptionsDigest(image, buildOptions);
        var path = PathFor(image.Sha256, digest);
        byte[] payload;
        try
        {
            if (!File.Exists(path)) { Interlocked.Increment(ref _misses); return null; }
            using var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 1, FileOptions.SequentialScan);
            Span<byte> header = stackalloc byte[HeaderSize];
            if (file.ReadAtLeast(header, HeaderSize, throwOnEndOfStream: false) < HeaderSize) return Reject("header truncated");
            if (BinaryPrimitives.ReadUInt64LittleEndian(header) != Magic) return Reject("not a code index file");
            if (BinaryPrimitives.ReadInt32LittleEndian(header[8..]) != NativeCodeIndex.PersistFormatVersion) return Reject("other format version");
            if (!header.Slice(16, 32).SequenceEqual(Convert.FromHexString(image.Sha256)) || !header.Slice(48, 32).SequenceEqual(Convert.FromHexString(digest)))
                return Reject("other image or options");
            long length = BinaryPrimitives.ReadInt64LittleEndian(header[80..]);
            ulong checksum = BinaryPrimitives.ReadUInt64LittleEndian(header[88..]);
            long stored = file.Length - HeaderSize;
            if (length < 0 || length > Array.MaxLength || stored > Array.MaxLength) return Reject("length out of range");
            var blocks = GC.AllocateUninitializedArray<byte>((int)stored);
            file.ReadExactly(blocks);
            payload = GC.AllocateUninitializedArray<byte>((int)length);
            if (!Decompress(blocks, payload)) return Reject("compressed blocks do not decode");
            if (XxHash3.HashToUInt64(payload) != checksum) return Reject("checksum differs");
        }
        catch (FileNotFoundException) { Interlocked.Increment(ref _misses); return null; } // evicted meanwhile
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or OutOfMemoryException)
        {
            return Reject(ex.Message);
        }
        NativeCodeIndex index;
        try { index = NativeCodeIndex.ReadPayload(payload, image, buildOptions, ct); }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return Reject($"payload does not decode ({ex.GetType().Name}: {ex.Message})");
        }
        index.MarkLoaded(sw.Elapsed);
        try { File.SetLastAccessTimeUtc(path, DateTime.UtcNow); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
        Interlocked.Increment(ref _hits);
        return index;

        NativeCodeIndex? Reject(string why)
        {
            Interlocked.Increment(ref _rejected);
            _lastError = $"{Path.GetFileName(path)}: {why}";
            return null;
        }
    }

    /// <summary>Saves a freshly built full index (skipped when it built faster than <see cref="CodeIndexCacheOptions.MinBuildTime"/>); best effort.</summary>
    public bool Save(NativeCodeIndex index, CodeIndexOptions? buildOptions)
    {
        if (index.Support != CodeSupport.Full || index.LoadedFromCache || !BitConverter.IsLittleEndian) return false;
        if (index.Stats.Elapsed < Options.MinBuildTime) return false;
        var path = PathFor(index.Image.Sha256, NativeCodeIndex.OptionsDigest(index.Image, buildOptions));
        var temp = $"{path}.{Environment.ProcessId}.{Guid.NewGuid():N}.tmp";
        try
        {
            Directory.CreateDirectory(Options.Root);
            using (var file = new FileStream(temp, FileMode.CreateNew, FileAccess.Write, FileShare.None, 1))
            {
                file.Write(new byte[HeaderSize]);
                var hash = new XxHash3();
                long length = 0;
                var packed = new byte[8 + LZ4Codec.MaximumOutputSize(PayloadWriter.BufferSize)];
                using (var w = new PayloadWriter(chunk =>
                {
                    hash.Append(chunk);
                    length += chunk.Length;
                    int n = LZ4Codec.Encode(chunk, packed.AsSpan(8), LZ4Level.L00_FAST);
                    bool raw = n <= 0 || n >= chunk.Length;
                    BinaryPrimitives.WriteInt32LittleEndian(packed, chunk.Length);
                    BinaryPrimitives.WriteInt32LittleEndian(packed.AsSpan(4), raw ? -1 : n);
                    file.Write(packed, 0, 8);
                    if (raw) file.Write(chunk); else file.Write(packed, 8, n);
                }))
                    index.WritePayload(w);
                var header = new byte[HeaderSize];
                BinaryPrimitives.WriteUInt64LittleEndian(header, Magic);
                BinaryPrimitives.WriteInt32LittleEndian(header.AsSpan(8), NativeCodeIndex.PersistFormatVersion);
                BinaryPrimitives.WriteInt32LittleEndian(header.AsSpan(12), HeaderSize);
                Convert.FromHexString(index.Image.Sha256).CopyTo(header, 16);
                Convert.FromHexString(NativeCodeIndex.OptionsDigest(index.Image, buildOptions)).CopyTo(header, 48);
                BinaryPrimitives.WriteInt64LittleEndian(header.AsSpan(80), length);
                BinaryPrimitives.WriteUInt64LittleEndian(header.AsSpan(88), hash.GetCurrentHashAsUInt64());
                file.Position = 0;
                file.Write(header);
            }
            try { File.Move(temp, path, overwrite: true); }
            catch (IOException) when (File.Exists(path))
            {
                // another process wrote (or is reading) the same entry: its content is the same index
                File.Delete(temp);
                return false;
            }
            Interlocked.Increment(ref _writes);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidOperationException)
        {
            _lastError = $"writing {Path.GetFileName(path)}: {ex.Message}";
            try { File.Delete(temp); } catch (Exception e) when (e is IOException or UnauthorizedAccessException) { }
            return false;
        }
        Evict();
        return true;
    }

    /// <summary>Blocks of [raw length][stored length, -1 = not compressed][bytes] that must fill <paramref name="payload"/> exactly.</summary>
    private static bool Decompress(ReadOnlySpan<byte> blocks, Span<byte> payload)
    {
        int at = 0, written = 0;
        while (at < blocks.Length)
        {
            if (blocks.Length - at < 8) return false;
            int raw = BinaryPrimitives.ReadInt32LittleEndian(blocks[at..]);
            int stored = BinaryPrimitives.ReadInt32LittleEndian(blocks[(at + 4)..]);
            at += 8;
            if (raw <= 0 || raw > PayloadWriter.BufferSize || raw > payload.Length - written) return false;
            int size = stored == -1 ? raw : stored;
            if (size <= 0 || size > blocks.Length - at) return false;
            var source = blocks.Slice(at, size);
            var target = payload.Slice(written, raw);
            if (stored == -1) source.CopyTo(target);
            else if (LZ4Codec.Decode(source, target) != raw) return false;
            at += size;
            written += raw;
        }
        return written == payload.Length;
    }

    /// <summary>Deletes entries unused past the age limit, then the least recently used beyond the size limit, and stale temporary files.</summary>
    public void Evict()
    {
        try
        {
            if (!Directory.Exists(Options.Root)) return;
            var now = DateTime.UtcNow;
            var dir = new DirectoryInfo(Options.Root);
            foreach (var tmp in dir.EnumerateFiles("*.tmp"))
                if (now - tmp.LastWriteTimeUtc > TimeSpan.FromHours(6)) TryDelete(tmp);
            var entries = new List<(FileInfo File, DateTime Used)>();
            foreach (var f in dir.EnumerateFiles("*" + Extension))
            {
                var used = f.LastAccessTimeUtc > f.LastWriteTimeUtc ? f.LastAccessTimeUtc : f.LastWriteTimeUtc;
                if (now - used > Options.MaxAge) { TryDelete(f); continue; }
                entries.Add((f, used));
            }
            long total = entries.Sum(e => e.File.Length);
            foreach (var (f, _) in entries.OrderBy(e => e.Used))
            {
                if (total <= Options.MaxBytes) break;
                long size = f.Length;
                if (TryDelete(f)) total -= size;
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            _lastError = $"evicting: {ex.Message}";
        }
    }

    private bool TryDelete(FileInfo f)
    {
        try
        {
            f.Delete();
            if (f.Extension == Extension) Interlocked.Increment(ref _evicted);
            return true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return false; }
    }

    public CodeIndexCacheStatus Status()
    {
        int entries = 0;
        long bytes = 0;
        try
        {
            if (Directory.Exists(Options.Root))
                foreach (var f in new DirectoryInfo(Options.Root).EnumerateFiles("*" + Extension)) { entries++; bytes += f.Length; }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
        return new CodeIndexCacheStatus(Options.Root, entries, bytes, Options.MaxBytes, Options.MaxAge,
            Volatile.Read(ref _hits), Volatile.Read(ref _misses), Volatile.Read(ref _rejected), Volatile.Read(ref _writes), Volatile.Read(ref _evicted), _lastError);
    }
}
