using System.Buffers.Binary;
using System.Text;

namespace Corvus.Core;

/// <summary>
/// An Unreal Engine IoStore container: the table of contents (.utoc) names each chunk's id, offset and length in an
/// uncompressed stream cut into compression blocks, the blocks' places in the data file (.ucas, or partitions
/// name_s1.ucas and on), and a directory index that maps file paths to chunks. Chunk data is read from the .ucas files
/// beside the .utoc; without them the chunks are listed only.
/// </summary>
public static class UnrealIoStore
{
    public const string Kind = "Unreal IoStore container";
    private const int HeaderSize = 0x90, MaxChunks = 2_000_000, MaxBlocks = 8_000_000, MaxString = 4096;
    private const byte Encrypted = 2, Signed = 4, Indexed = 8;

    // Version names as the engine's EIoStoreTocVersion declares them.
    private static readonly string[] VersionNames =
    [
        "Invalid", "Initial", "DirectoryIndex", "PartitionSize", "PerfectHash", "PerfectHashWithOverflow", "OnDemandMetaData",
        "RemovedOnDemandMetaData", "ReplaceIoChunkHashWithIoHash",
    ];

    // EIoChunkType values from TOC version 5 on, and before it.
    private static readonly string[] ChunkTypes =
    [
        "Invalid", "ExportBundleData", "BulkData", "OptionalBulkData", "MemoryMappedBulkData", "ScriptObjects", "ContainerHeader",
        "ExternalFile", "ShaderCodeLibrary", "ShaderCode", "PackageStoreEntry", "DerivedData", "EditorDerivedData", "PackageResource",
    ];
    private static readonly string[] OldChunkTypes =
    [
        "Invalid", "InstallManifest", "ExportBundleData", "BulkData", "OptionalBulkData", "MemoryMappedBulkData", "LoaderGlobalMeta",
        "LoaderInitialLoadMeta", "LoaderGlobalNames", "LoaderGlobalNameHashes", "ContainerHeader", "ShaderCodeLibrary", "ShaderCode",
    ];

    public static bool Looks(ReadOnlySpan<byte> b) => b.Length >= HeaderSize && b.StartsWith("-==--==--==--==-"u8);

    private readonly record struct Block(long Offset, int Compressed, int Uncompressed, int Method);

    public static ContainerContents Open(byte[] toc, string name, string? location, bool allFiles, AnalysisLimits limits, CancellationToken ct)
    {
        if (!Looks(toc)) throw new ToolError(ErrorCode.MalformedInput, $"{name}: no IoStore TOC header.");
        try { return Read(toc, name, location, allFiles, limits, ct); }
        catch (InvalidDataException ex) { throw new ToolError(ErrorCode.MalformedInput, $"{name}: the IoStore TOC is unreadable: {ex.Message}"); }
    }

    private static ContainerContents Read(byte[] toc, string name, string? location, bool allFiles, AnalysisLimits limits, CancellationToken ct)
    {
        var h = toc.AsSpan(0, HeaderSize);
        int version = h[16];
        uint headerSize = U32(h, 20), entries = U32(h, 24), blockCount = U32(h, 28), blockEntrySize = U32(h, 32);
        uint methodCount = U32(h, 36), methodLength = U32(h, 40), blockSize = U32(h, 44), directorySize = U32(h, 48), partitions = U32(h, 52);
        ulong containerId = BinaryPrimitives.ReadUInt64LittleEndian(h[56..]);
        var keyGuid = new Guid(h.Slice(64, 16));
        byte flags = h[80];
        uint seeds = U32(h, 84);
        ulong partitionSize = BinaryPrimitives.ReadUInt64LittleEndian(h[88..]);
        uint overflow = U32(h, 96);
        if (headerSize != HeaderSize) throw new InvalidDataException($"header size {headerSize}, not {HeaderSize}");
        if (entries > MaxChunks || blockCount > MaxBlocks || blockEntrySize != 12 || methodCount > 255 || methodLength is 0 or > 256 || blockSize == 0)
            throw new InvalidDataException($"{entries:N0} chunks, {blockCount:N0} blocks of {blockEntrySize}-byte entries, {methodCount} methods, block size {blockSize}");
        string versionText = $"TOC version {version} ({(version < VersionNames.Length ? VersionNames[version] : "unknown")})";
        int p = HeaderSize;
        var chunkIds = Take(toc, ref p, 12L * entries);
        var ranges = Take(toc, ref p, 10L * entries);
        if (version >= 4) Take(toc, ref p, 4L * seeds);
        if (version >= 5) Take(toc, ref p, 4L * overflow);
        var blockBytes = Take(toc, ref p, 12L * blockCount);
        var methods = new string[methodCount];
        for (int i = 0; i < methodCount; i++)
        {
            var raw = Take(toc, ref p, methodLength);
            int end = raw.IndexOf((byte)0);
            methods[i] = Encoding.ASCII.GetString(end < 0 ? raw : raw[..end]);
        }
        if ((flags & Signed) != 0)
        {
            uint size = U32(Take(toc, ref p, 4), 0);
            Take(toc, ref p, 2L * size + 20L * blockCount);
        }
        var directory = (flags & Indexed) != 0 ? Take(toc, ref p, directorySize) : default;

        var blocks = new Block[blockCount];
        for (int i = 0; i < blockCount; i++)
        {
            var b = blockBytes.Slice(12 * i, 12);
            blocks[i] = new Block((long)(BinaryPrimitives.ReadUInt64LittleEndian(b) & 0xFF_FFFF_FFFF), (int)(BinaryPrimitives.ReadUInt32LittleEndian(b[4..]) >> 8),
                (int)(BinaryPrimitives.ReadUInt32LittleEndian(b[8..]) & 0xFF_FFFF), b[11]);
        }
        var notes = new List<string>();
        string key = keyGuid == Guid.Empty ? "the default key" : $"key {keyGuid:N}";
        var paths = new Dictionary<int, string>();
        string mount = "";
        if ((flags & Encrypted) != 0) notes.Add($"The container is encrypted with {key}; chunk data is not read" + (directory.Length > 0 ? " and the directory index is not listed." : "."));
        else if (directory.Length > 0) mount = ReadDirectory(directory, paths, entries);
        else notes.Add("The container has no directory index; chunks are listed by id.");

        var data = location != null ? new DataFiles(location, partitions, partitionSize) : null;
        if (data != null && !data.Present) notes.Add($"{Path.GetFileName(data.First)} is not beside the TOC; chunks are listed, not read.");
        var listed = new List<ContainerEntry>();
        var items = new List<ExtractedItem>();
        var types = new Dictionary<string, int>(StringComparer.Ordinal);
        var used = new SortedSet<string>(StringComparer.Ordinal);
        long total = 0;
        int undecoded = 0, bad = 0;
        for (int i = 0; i < entries; i++)
        {
            ct.ThrowIfCancellationRequested();
            var id = chunkIds.Slice(12 * i, 12);
            int raw = id[11] & 0x3F;
            var names = version >= 5 ? ChunkTypes : OldChunkTypes;
            string type = raw < names.Length ? names[raw] : $"type {raw}";
            types[type] = types.GetValueOrDefault(type) + 1;
            var range = ranges.Slice(10 * i, 10);
            long offset = BigEndian40(range), length = BigEndian40(range[5..]);
            string path = paths.TryGetValue(i, out var named) ? named : $"chunks/{Convert.ToHexStringLower(id)}.{type}";
            int first = (int)(offset / blockSize), last = length == 0 ? first - 1 : (int)((offset + length - 1) / blockSize);
            string? method = null;
            for (int b = first; b <= last && b < blocks.Length; b++)
                if (blocks[b].Method > 0) method = blocks[b].Method <= methods.Length ? methods[blocks[b].Method - 1] : $"method {blocks[b].Method}";
            if (method != null) used.Add(method);
            bool unsafeName = path.Split('/').Any(AsarArchive.IsUnsafeName);
            string detail = type + (method != null ? $", {method} compressed" : "") + (unsafeName ? ", unsafe name" : "");
            listed.Add(new ContainerEntry(path, length, detail));
            if (data is not { Present: true } || (flags & Encrypted) != 0 || unsafeName || !(allFiles || Containers.IsInteresting(path))) continue;
            if (last >= blocks.Length) { if (bad++ < 3) notes.Add($"{path}: blocks {first}-{last} past the {blocks.Length:N0} listed."); continue; }
            if (items.Count >= limits.MaxItems || (total += length) > limits.MaxTotalBytes) { notes.Add("Stopped: the extraction limit was reached."); break; }
            if (length > limits.MaxItemBytes) { notes.Add($"{path}: {length:N0} bytes, over the per-item limit; not extracted."); continue; }
            try
            {
                var bytes = ReadChunk(data, blocks, methods, first, last, offset - (long)first * blockSize, length);
                if (bytes == null) { undecoded++; continue; }
                items.Add(new ExtractedItem(path, bytes, $"IoStore chunk ({type})"));
            }
            catch (InvalidDataException ex) { if (bad++ < 3) notes.Add($"{path}: data unreadable ({ex.Message})."); }
        }
        if (bad > 3) notes.Add($"{bad - 3} more chunks have unreadable data.");
        if (undecoded > 0) notes.Add($"{undecoded:N0} chunk(s) use a compression method Corvus does not decode; listed, not extracted.");
        notes.Insert(0, $"Unreal IoStore {versionText}, container 0x{containerId:X16}: {entries:N0} chunk(s) (" +
                        string.Join(", ", types.OrderByDescending(t => t.Value).ThenBy(t => t.Key, StringComparer.Ordinal).Take(6).Select(t => $"{t.Value} {t.Key}")) + ")" +
                        (mount.Length > 0 ? $", mount point {mount}" : "") + (used.Count > 0 ? $", compression {string.Join(", ", used)}" : "") +
                        (partitions > 1 ? $", {partitions} partitions" : "") + ".");
        return new ContainerContents(Kind, items, notes) { Entries = listed };
    }

    /// <summary>Fills <paramref name="paths"/> (TOC entry index to path under the mount point) and returns the mount point.</summary>
    private static string ReadDirectory(ReadOnlySpan<byte> d, Dictionary<int, string> paths, uint entries)
    {
        int p = 0;
        string mount = String(d, ref p);
        int dirCount = Count(d, ref p, 16);
        var dirs = new (uint Name, uint Child, uint Sibling, uint File)[dirCount];
        for (int i = 0; i < dirCount; i++, p += 16) dirs[i] = (U32(d, p), U32(d, p + 4), U32(d, p + 8), U32(d, p + 12));
        int fileCount = Count(d, ref p, 12);
        var files = new (uint Name, uint Next, uint Entry)[fileCount];
        for (int i = 0; i < fileCount; i++, p += 12) files[i] = (U32(d, p), U32(d, p + 4), U32(d, p + 8));
        int stringCount = Count(d, ref p, 4);
        var strings = new string[stringCount];
        for (int i = 0; i < stringCount; i++) strings[i] = String(d, ref p);
        string Name(uint i) => i < strings.Length ? strings[i] : throw new InvalidDataException($"string {i} past the {strings.Length} listed");
        if (dirCount == 0) return mount;
        // Walk the tree from the root without recursion; each directory and file is visited once.
        var stack = new Stack<(uint Dir, string Prefix)>();
        stack.Push((0, ""));
        var seen = new HashSet<uint>();
        while (stack.Count > 0)
        {
            var (dir, prefix) = stack.Pop();
            if (dir >= dirs.Length || !seen.Add(dir)) continue;
            var e = dirs[dir];
            string here = e.Name == uint.MaxValue ? prefix : prefix + Name(e.Name) + "/";
            int guard = 0;
            for (uint f = e.File; f != uint.MaxValue && guard++ <= files.Length; f = files[f].Next)
            {
                if (f >= files.Length) throw new InvalidDataException($"file entry {f} past the {files.Length} listed");
                if (files[f].Entry < entries) paths[(int)files[f].Entry] = here + Name(files[f].Name);
            }
            guard = 0;
            for (uint c = e.Child; c != uint.MaxValue && c < dirs.Length && guard++ <= dirs.Length; c = dirs[c].Sibling) stack.Push((c, here));
        }
        return mount;
    }

    /// <summary>A chunk's bytes from its blocks; null when a block uses a method not decoded here.</summary>
    private static byte[]? ReadChunk(DataFiles data, Block[] blocks, string[] methods, int first, int last, long skip, long length)
    {
        var output = new byte[length];
        long written = 0, position = 0;
        for (int b = first; b <= last && written < length; b++)
        {
            var block = blocks[b];
            var raw = data.Read(block.Offset, block.Compressed);
            byte[] plain;
            if (block.Method == 0) plain = raw;
            else
            {
                string method = block.Method <= methods.Length ? methods[block.Method - 1] : "";
                if (method is not ("Zlib" or "Gzip" or "Zstd" or "LZ4")) return null;
                plain = new byte[block.Uncompressed];
                if (UnrealPak.Decode(method, raw, plain) != block.Uncompressed) throw new InvalidDataException($"block {b} decodes short");
            }
            long from = Math.Max(0, skip - position), take = Math.Min(plain.Length - from, length - written);
            if (take > 0) { plain.AsSpan((int)from, (int)take).CopyTo(output.AsSpan((int)written)); written += take; }
            position += block.Uncompressed;
        }
        return written == length ? output : throw new InvalidDataException($"{written:N0} of {length:N0} bytes in the blocks");
    }

    /// <summary>The .ucas data files of a TOC: partition 0 is name.ucas, partition n name_sn.ucas; each read once.</summary>
    private sealed class DataFiles(string toc, uint partitions, ulong partitionSize)
    {
        private readonly Dictionary<int, byte[]?> _files = [];
        public string First { get; } = Path.ChangeExtension(toc, ".ucas");
        public bool Present => File.Exists(First);

        public byte[] Read(long offset, int size)
        {
            int partition = partitions > 1 && partitionSize > 0 ? (int)((ulong)offset / partitionSize) : 0;
            long at = partitions > 1 && partitionSize > 0 ? (long)((ulong)offset % partitionSize) : offset;
            if (!_files.TryGetValue(partition, out var file))
            {
                string path = partition == 0 ? First : Path.Combine(Path.GetDirectoryName(First)!, $"{Path.GetFileNameWithoutExtension(First)}_s{partition}.ucas");
                _files[partition] = file = File.Exists(path) ? File.ReadAllBytes(path) : null;
            }
            if (file == null) throw new InvalidDataException($"partition {partition} is not beside the TOC");
            if (at < 0 || size < 0 || at > file.Length - size) throw new InvalidDataException($"block at 0x{at:X} ({size:N0} bytes) lies outside partition {partition}");
            return file.AsSpan((int)at, size).ToArray();
        }
    }

    private static ReadOnlySpan<byte> Take(byte[] b, ref int p, long n)
    {
        if (n < 0 || p > b.Length - n) throw new InvalidDataException($"a section of {n:N0} bytes at 0x{p:X} runs past the TOC");
        var s = b.AsSpan(p, (int)n);
        p += (int)n;
        return s;
    }

    private static int Count(ReadOnlySpan<byte> d, ref int p, int entry)
    {
        if (p > d.Length - 4) throw new InvalidDataException("the directory index ends early");
        int n = BinaryPrimitives.ReadInt32LittleEndian(d[p..]);
        p += 4;
        if (n < 0 || (long)n * entry > d.Length - p) throw new InvalidDataException($"{n} entries of {entry} bytes run past the directory index");
        return n;
    }

    // FString: a signed length counting the terminator; negative lengths are UTF-16 code units.
    private static string String(ReadOnlySpan<byte> d, ref int p)
    {
        if (p > d.Length - 4) throw new InvalidDataException("the directory index ends early");
        int n = BinaryPrimitives.ReadInt32LittleEndian(d[p..]);
        p += 4;
        if (n == 0) return "";
        long bytes = n < 0 ? -2L * n : n;
        if (n < -MaxString || n > MaxString || bytes > d.Length - p) throw new InvalidDataException($"string length {n} at 0x{p - 4:X}");
        var s = n < 0 ? Encoding.Unicode.GetString(d.Slice(p, (int)bytes)) : Encoding.UTF8.GetString(d.Slice(p, (int)bytes));
        p += (int)bytes;
        int nul = s.IndexOf('\0');
        return nul >= 0 ? s[..nul] : s;
    }

    private static long BigEndian40(ReadOnlySpan<byte> b) => ((long)b[0] << 32) | ((long)b[1] << 24) | ((long)b[2] << 16) | ((long)b[3] << 8) | b[4];

    private static uint U32(ReadOnlySpan<byte> b, int at) => BinaryPrimitives.ReadUInt32LittleEndian(b[at..]);
}
