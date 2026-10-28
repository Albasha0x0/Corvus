using System.Buffers.Binary;
using System.IO.Compression;
using System.Text;

namespace Corvus.Core;

/// <summary>An Unreal Engine pak file (versions 1-11): footer, index with mount point, and each file's entry.</summary>
/// <remarks>From version 10 entries are encoded and named by a full directory index.</remarks>
public static class UnrealPak
{
    public const string Kind = "Unreal pak";
    private const uint Magic = 0x5A6F12E1;
    private const int MaxFiles = 1_000_000, MaxString = 4096;

    // Version names as the engine's FPakInfo declares them; 8 has two footer layouts (4 and 5 compression names).
    private static readonly string[] VersionNames =
    [
        "", "Initial", "NoTimestamps", "CompressionEncryption", "IndexEncryption", "RelativeChunkOffsets", "DeleteRecords",
        "EncryptionKeyGuid", "FNameBasedCompressionMethod", "FrozenIndex", "PathHashIndex", "Fnv64BugFix",
    ];

    /// <summary>A pak footer layout: version, footer size and compression name slots (8 is 8A with 4 slots, 8B with 5).</summary>
    private readonly record struct Layout(int Version, int Size, int Names);

    private static readonly Layout[] Layouts =
    [
        new(11, 221, 5), new(10, 221, 5), new(9, 222, 5), new(8, 221, 5), new(8, 189, 4), new(7, 61, 0), new(6, 45, 0),
        new(5, 45, 0), new(4, 45, 0), new(3, 44, 0), new(2, 44, 0), new(1, 44, 0),
    ];

    /// <summary>The parsed footer; null when <paramref name="b"/> does not end with a pak footer.</summary>
    private sealed record Footer(Layout Layout, bool EncryptedIndex, Guid KeyGuid, long IndexOffset, long IndexSize, bool Frozen, string?[] Compression);

    public static bool Looks(ReadOnlySpan<byte> b) => ReadFooter(b) != null;

    private static Footer? ReadFooter(ReadOnlySpan<byte> b)
    {
        foreach (var l in Layouts)
        {
            if (b.Length < l.Size) continue;
            var f = b[^l.Size..];
            int p = 0;
            var guid = Guid.Empty;
            if (l.Version >= 7) { guid = new Guid(f[..16]); p = 16; }
            bool encrypted = false;
            if (l.Version >= 4) encrypted = f[p++] != 0;
            if (BinaryPrimitives.ReadUInt32LittleEndian(f[p..]) != Magic || BinaryPrimitives.ReadUInt32LittleEndian(f[(p + 4)..]) != l.Version) continue;
            long offset = BinaryPrimitives.ReadInt64LittleEndian(f[(p + 8)..]), size = BinaryPrimitives.ReadInt64LittleEndian(f[(p + 16)..]);
            p += 44;
            bool frozen = l.Version == 9 && f[p++] != 0;
            var names = new List<string?>();
            for (int i = 0; i < l.Names; i++, p += 32)
            {
                var raw = f.Slice(p, 32);
                int end = raw.IndexOf((byte)0);
                names.Add(end == 0 ? null : Encoding.ASCII.GetString(end < 0 ? raw : raw[..end]));
            }
            // Before named methods the slot was a flag value: 1 zlib, 2 gzip, 4 Oodle.
            if (l.Version < 8) names.AddRange(["Zlib", "Gzip", "Oodle"]);
            return new Footer(l, encrypted, guid, offset, size, frozen, [.. names]);
        }
        return null;
    }

    /// <summary>One file of the index: path, data offset, sizes, compression slot (-1 none), block ranges, flags and block size.</summary>
    private sealed record Entry(long Offset, long Compressed, long Uncompressed, int Slot, (long Start, long End)[]? Blocks, byte Flags, uint BlockSize)
    {
        public bool Encrypted => (Flags & 1) != 0;
        public bool Deleted => (Flags & 2) != 0;
    }

    public static ContainerContents Open(byte[] data, string name, bool allFiles, AnalysisLimits limits, CancellationToken ct)
    {
        var footer = ReadFooter(data) ?? throw new ToolError(ErrorCode.MalformedInput, $"{name}: no Unreal pak footer.");
        var l = footer.Layout;
        string version = $"pak version {l.Version}{(l.Version == 8 ? (l.Names == 4 ? "A" : "B") : "")} ({VersionNames[l.Version]})";
        var notes = new List<string>();
        var entries = new List<ContainerEntry>();
        var items = new List<ExtractedItem>();
        if (footer.IndexOffset < 0 || footer.IndexSize < 0 || footer.IndexOffset + footer.IndexSize > data.Length - l.Size)
            throw new ToolError(ErrorCode.MalformedInput, $"{name}: the index (0x{footer.IndexOffset:X}, {footer.IndexSize:N0} bytes) lies outside the file.");
        string key = footer.KeyGuid == Guid.Empty ? "the default key" : $"key {footer.KeyGuid:N}";
        if (footer.EncryptedIndex)
        {
            notes.Add($"Unreal {version}: the index is encrypted with {key}; no files listed.");
            return new ContainerContents(Kind, items, notes) { Entries = entries };
        }
        var files = new List<(string Path, Entry Entry)>();
        string mount;
        try { mount = ReadIndex(data, footer, files, notes, ct); }
        catch (Exception ex) when (ex is InvalidDataException or ArgumentOutOfRangeException or IndexOutOfRangeException)
        {
            throw new ToolError(ErrorCode.MalformedInput, $"{name}: the {version} index is unreadable: {ex.Message}");
        }
        int encrypted = 0, deleted = 0, refused = 0, undecoded = 0, bad = 0;
        long total = 0;
        var methods = new SortedSet<string>(StringComparer.Ordinal);
        foreach (var (path, e) in files)
        {
            ct.ThrowIfCancellationRequested();
            string? method = e.Slot < 0 ? null : e.Slot < footer.Compression.Length ? footer.Compression[e.Slot] ?? $"slot {e.Slot + 1}" : $"slot {e.Slot + 1}";
            if (method != null) methods.Add(method);
            string role = e.Deleted ? "deleted record" : e.Encrypted ? "encrypted" : method != null ? $"{method} compressed" : "stored";
            if (e.Deleted) { deleted++; entries.Add(new ContainerEntry(path, 0, role)); continue; }
            if (e.Encrypted) encrypted++;
            bool unsafeName = path.Split('/').Any(AsarArchive.IsUnsafeName);
            entries.Add(new ContainerEntry(path, e.Uncompressed, unsafeName ? role + ", unsafe name" : role));
            if (e.Encrypted || !(allFiles || Containers.IsInteresting(path))) continue;
            if (unsafeName) { refused++; continue; }
            if (items.Count >= limits.MaxItems || (total += e.Uncompressed) > limits.MaxTotalBytes) { notes.Add("Stopped: the extraction limit was reached."); break; }
            if (e.Uncompressed > limits.MaxItemBytes) { notes.Add($"{path}: {e.Uncompressed:N0} bytes, over the per-item limit; not extracted."); continue; }
            byte[]? content;
            try { content = Read(data, footer, e, method); }
            catch (Exception ex) when (ex is InvalidDataException or ArgumentOutOfRangeException or IndexOutOfRangeException)
            {
                if (bad++ < 3) notes.Add($"{path}: data unreadable ({ex.Message}).");
                continue;
            }
            if (content == null) { undecoded++; continue; }
            items.Add(new ExtractedItem(path, content, $"Unreal pak entry ({role})"));
        }
        if (bad > 3) notes.Add($"{bad - 3} more entries have unreadable data.");
        if (encrypted > 0) notes.Add($"{encrypted:N0} file(s) are encrypted with {key}; not extracted.");
        if (deleted > 0) notes.Add($"{deleted:N0} record(s) mark files a patch pak deletes.");
        if (undecoded > 0) notes.Add($"{undecoded:N0} file(s) use a compression method Corvus does not decode; listed, not extracted.");
        if (refused > 0) notes.Add($"{refused:N0} entr(ies) with unsafe names not extracted.");
        notes.Insert(0, $"Unreal {version}: {files.Count:N0} file(s), mount point {mount}" +
                        (methods.Count > 0 ? $", compression {string.Join(", ", methods)}" : "") + (footer.Frozen ? ", frozen index" : "") + ".");
        return new ContainerContents(Kind, items, notes) { Entries = entries };
    }

    /// <summary>Reads the index into <paramref name="files"/> and returns the mount point.</summary>
    private static string ReadIndex(byte[] data, Footer footer, List<(string, Entry)> files, List<string> notes, CancellationToken ct)
    {
        int version = footer.Layout.Version;
        var index = new Reader(data, (int)footer.IndexOffset, (int)(footer.IndexOffset + footer.IndexSize));
        string mount = index.String();
        uint count = index.U32();
        if (count > MaxFiles) throw new InvalidDataException($"{count:N0} files declared");
        if (version < 10)
        {
            for (uint i = 0; i < count; i++)
            {
                ct.ThrowIfCancellationRequested();
                string path = index.String();
                files.Add((path, ReadEntry(ref index, footer)));
            }
            return mount;
        }
        index.U64(); // path hash seed
        if (index.U32() != 0) index.Skip(8 + 8 + 20); // path hash index: offset, size, hash
        (long Offset, long Size)? directory = null;
        if (index.U32() != 0)
        {
            directory = (index.I64(), index.I64());
            index.Skip(20);
        }
        int encodedSize = (int)index.U32();
        int encodedStart = index.Position;
        index.Skip(encodedSize);
        uint plain = index.U32();
        if (plain > MaxFiles) throw new InvalidDataException($"{plain:N0} unencoded entries declared");
        var listed = new List<Entry>();
        for (uint i = 0; i < plain; i++) listed.Add(ReadEntry(ref index, footer));
        if (directory is not { } d)
        {
            notes.Add($"The index has no full directory index; {count:N0} file(s) are known only by path hash.");
            return mount;
        }
        if (d.Offset < 0 || d.Size < 0 || d.Offset + d.Size > data.Length) throw new InvalidDataException("the full directory index lies outside the file");
        var dirs = new Reader(data, (int)d.Offset, (int)(d.Offset + d.Size));
        uint dirCount = dirs.U32();
        for (uint i = 0; i < dirCount && files.Count < MaxFiles; i++)
        {
            string dir = dirs.String();
            uint fileCount = dirs.U32();
            for (uint k = 0; k < fileCount; k++)
            {
                ct.ThrowIfCancellationRequested();
                string file = dirs.String();
                int at = dirs.I32();
                // int.MinValue marks a pruned entry.
                if (at == int.MinValue) continue;
                Entry e;
                if (at >= 0)
                {
                    if (at >= encodedSize) throw new InvalidDataException($"encoded entry 0x{at:X} past the {encodedSize:N0} encoded bytes");
                    var encoded = new Reader(data, encodedStart + at, encodedStart + encodedSize);
                    e = ReadEncoded(ref encoded, footer);
                }
                else
                {
                    int n = -at - 1;
                    if (n >= listed.Count) throw new InvalidDataException($"unencoded entry {n} past the {listed.Count} listed");
                    e = listed[n];
                }
                files.Add(((dir.StartsWith('/') ? dir[1..] : dir) + file, e));
            }
        }
        return mount;
    }

    private static Entry ReadEntry(ref Reader r, Footer footer)
    {
        int version = footer.Layout.Version;
        long offset = r.I64(), compressed = r.I64(), uncompressed = r.I64();
        int slot = (version == 8 && footer.Layout.Names == 4 ? r.U8() : (int)r.U32()) - 1;
        if (version == 1) r.Skip(8); // timestamp
        r.Skip(20); // SHA-1 of the data
        (long, long)[]? blocks = null;
        byte flags = 0;
        uint blockSize = 0;
        if (version >= 3)
        {
            if (slot >= 0)
            {
                uint n = r.U32();
                if (n > 1 << 20) throw new InvalidDataException($"{n:N0} blocks declared");
                blocks = new (long, long)[n];
                for (int i = 0; i < n; i++) blocks[i] = (r.I64(), r.I64());
            }
            flags = r.U8();
            blockSize = r.U32();
        }
        return new Entry(offset, compressed, uncompressed, slot, blocks, flags, blockSize);
    }

    // Bits: 0-5 block size >> 11 (0x3F: a u32 follows), 6-21 block count, 22 encrypted, 23-28 compression slot + 1,
    // 29-31 compressed size, uncompressed size and offset fit 32 bits.
    private static Entry ReadEncoded(ref Reader r, Footer footer)
    {
        uint bits = r.U32();
        int slot = (int)((bits >> 23) & 0x3F) - 1;
        bool encrypted = (bits & (1u << 22)) != 0;
        int count = (int)((bits >> 6) & 0xFFFF);
        uint blockSize = bits & 0x3F;
        blockSize = blockSize == 0x3F ? r.U32() : blockSize << 11;
        long offset = (bits & (1u << 31)) != 0 ? r.U32() : r.I64();
        long uncompressed = (bits & (1u << 30)) != 0 ? r.U32() : r.I64();
        long compressed = slot < 0 ? uncompressed : (bits & (1u << 29)) != 0 ? r.U32() : r.I64();
        // Block ranges are relative to the entry's offset and start after the copy of the entry before the data.
        long start = HeaderSize(footer, slot, count);
        (long, long)[]? blocks = null;
        if (count == 1 && !encrypted) blocks = [(start, start + compressed)];
        else if (count > 0)
        {
            blocks = new (long, long)[count];
            for (int i = 0; i < count; i++)
            {
                long size = r.U32();
                blocks[i] = (start, start + size);
                start += encrypted ? (size + 15) & ~15L : size;
            }
        }
        return new Entry(offset, compressed, uncompressed, slot, blocks, (byte)(encrypted ? 1 : 0), blockSize);
    }

    private static long HeaderSize(Footer footer, int slot, int blocks)
    {
        int version = footer.Layout.Version;
        long size = 8 + 8 + 8 + (version == 8 && footer.Layout.Names == 4 ? 1 : 4) + (version == 1 ? 8 : 0) + 20;
        if (version >= 3) size += (slot >= 0 ? 4 + 16L * blocks : 0) + 1 + 4;
        return size;
    }

    /// <summary>A file's bytes, decompressed; null for a compression method not decoded here.</summary>
    private static byte[]? Read(byte[] data, Footer footer, Entry e, string? method)
    {
        if (e.Offset < 0 || e.Offset >= data.Length) throw new InvalidDataException($"offset 0x{e.Offset:X} lies outside the file");
        // The data follows a copy of the entry; its own length gives where.
        var header = new Reader(data, (int)e.Offset, data.Length);
        ReadEntry(ref header, footer);
        long dataStart = header.Position;
        if (method == null)
        {
            if (e.Compressed > data.Length - dataStart) throw new InvalidDataException("data runs past the file");
            return data.AsSpan((int)dataStart, (int)e.Compressed).ToArray();
        }
        if (method is not ("Zlib" or "Gzip" or "Zstd" or "LZ4")) return null;
        var blocks = e.Blocks ?? [(dataStart - (footer.Layout.Version >= 5 ? e.Offset : 0), dataStart - (footer.Layout.Version >= 5 ? e.Offset : 0) + e.Compressed)];
        // From version 5 block offsets are relative to the entry; before, absolute in the file.
        long bias = footer.Layout.Version >= 5 ? e.Offset : 0;
        long packed = 0;
        foreach (var (s, t) in blocks)
        {
            long from = bias + s, to = bias + t;
            if (from < dataStart || to < from || to > data.Length) throw new InvalidDataException($"block 0x{from:X}-0x{to:X} lies outside the data");
            packed += to - from;
        }
        // The most a method expands one byte: Deflate 1032, an LZ4 block 255,
        // a Zstandard RLE block 32768 (128 KiB from 4 bytes).
        long most = (packed + 16) * (method switch { "LZ4" => 255, "Zstd" => 32768, _ => 1032 });
        if (e.Uncompressed > most) throw new InvalidDataException($"{e.Uncompressed:N0} bytes declared from {packed:N0} compressed bytes, more than {method} can produce");
        var output = new byte[e.Uncompressed];
        int written = 0;
        foreach (var (s, t) in blocks)
        {
            long from = bias + s, to = bias + t;
            var block = data.AsSpan((int)from, (int)(to - from));
            int want = (int)Math.Min(e.BlockSize > 0 && blocks.Length > 1 ? e.BlockSize : e.Uncompressed, e.Uncompressed - written);
            written += Decode(method, block, output.AsSpan(written, want));
        }
        if (written != e.Uncompressed) throw new InvalidDataException($"{written:N0} of {e.Uncompressed:N0} bytes decoded");
        return output;
    }

    /// <summary>Decodes one Zlib, Gzip, Zstd or LZ4 block into <paramref name="output"/>; returns the bytes written, throws InvalidDataException on corrupt data.</summary>
    internal static int Decode(string method, ReadOnlySpan<byte> block, Span<byte> output)
    {
        if (method == "LZ4")
        {
            int n = K4os.Compression.LZ4.LZ4Codec.Decode(block, output);
            return n >= 0 ? n : throw new InvalidDataException("corrupt LZ4 block");
        }
        if (method == "Zstd")
        {
            try
            {
                using var zstd = new ZstdSharp.Decompressor();
                return zstd.Unwrap(block, output);
            }
            catch (ZstdSharp.ZstdException ex) { throw new InvalidDataException("corrupt Zstandard block: " + ex.Message); }
        }
        using var input = new MemoryStream(block.ToArray(), writable: false);
        using Stream stream = method == "Gzip" ? new GZipStream(input, CompressionMode.Decompress) : new ZLibStream(input, CompressionMode.Decompress);
        int total = 0;
        try
        {
            while (total < output.Length)
            {
                int n = stream.Read(output[total..]);
                if (n == 0) break;
                total += n;
            }
        }
        catch (InvalidDataException ex) { throw new InvalidDataException($"corrupt {method} block: {ex.Message}"); }
        return total;
    }

    /// <summary>A bounded little-endian reader over [start, end) of the file; reading past the end throws InvalidDataException.</summary>
    private ref struct Reader(byte[] data, int start, int end)
    {
        private readonly byte[] _data = data;
        private readonly int _end = Math.Min(end, data.Length);

        public int Position { get; private set; } = start;

        private ReadOnlySpan<byte> Take(int n)
        {
            if (n < 0 || Position > _end - n) throw new InvalidDataException($"read of {n} bytes at 0x{Position:X} runs past 0x{_end:X}");
            var s = _data.AsSpan(Position, n);
            Position += n;
            return s;
        }

        public void Skip(int n) => Take(n);
        public byte U8() => Take(1)[0];
        public uint U32() => BinaryPrimitives.ReadUInt32LittleEndian(Take(4));
        public int I32() => BinaryPrimitives.ReadInt32LittleEndian(Take(4));
        public ulong U64() => BinaryPrimitives.ReadUInt64LittleEndian(Take(8));
        public long I64() => BinaryPrimitives.ReadInt64LittleEndian(Take(8));

        // FString: a signed length counting the terminator; negative lengths are UTF-16 code units.
        public string String()
        {
            int n = I32();
            if (n == 0) return "";
            if (n < -MaxString || n > MaxString) throw new InvalidDataException($"string length {n} at 0x{Position - 4:X}");
            var s = n < 0 ? Encoding.Unicode.GetString(Take(-2 * n)) : Encoding.UTF8.GetString(Take(n));
            int nul = s.IndexOf('\0');
            return nul >= 0 ? s[..nul] : s;
        }
    }
}
