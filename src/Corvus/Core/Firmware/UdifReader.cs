using System.Buffers.Binary;
using Corvus.Core.Mobile;

namespace Corvus.Core.Firmware;

/// <summary>Apple disk images (UDIF, .dmg); HFS+ and APFS partitions are read in place, others extracted as images.</summary>
internal sealed class UdifReader : IContainerReader
{
    public string Kind => "dmg";

    private const int TrailerSize = 512, SectorSize = 512;
    private const int MaxPartitions = 256, MaxChunks = 1 << 22;
    // One chunk decodes to at most this many bytes (hdiutil writes 1 MiB chunks).
    private const long MaxChunkBytes = 64L << 20;

    /// <summary>A koly trailer, version 4, in the last 512 bytes.</summary>
    public static bool Looks(ReadOnlySpan<byte> b) =>
        b.Length >= TrailerSize && b[^TrailerSize..].StartsWith("koly"u8)
        && BinaryPrimitives.ReadUInt32BigEndian(b[(b.Length - TrailerSize + 4)..]) == 4
        && BinaryPrimitives.ReadUInt32BigEndian(b[(b.Length - TrailerSize + 8)..]) == TrailerSize;

    public bool Accepts(ReadOnlySpan<byte> data, string name) => Looks(data);

    public ContainerContents Open(byte[] data, string name, bool allFiles, AnalysisLimits limits, CancellationToken ct) =>
        Read(new MemoryStream(data, writable: false), name, allFiles, limits, ct);

    public ContainerContents? Open(Stream stream, string name, bool allFiles, AnalysisLimits limits, CancellationToken ct) =>
        Read(stream, name, allFiles, limits, ct);

    internal readonly record struct Chunk(uint Type, long Sector, long Sectors, long Offset, long Length);

    internal sealed record Partition(int Index, string Name, long Sectors, Chunk[] Chunks);

    private static ContainerContents Read(Stream stream, string name, bool allFiles, AnalysisLimits limits, CancellationToken ct)
    {
        var src = new FsSource(stream, 0, stream.Length, name);
        try
        {
            var notes = new List<string>();
            var partitions = Partitions(src, notes);
            var items = new List<ExtractedItem>();
            var entries = new List<ContainerEntry>();
            var methods = partitions.SelectMany(p => p.Chunks).Select(c => MethodName(c.Type)).Where(m => m != null).Distinct().Order(StringComparer.Ordinal);
            notes.Insert(0, $"UDIF disk image, {partitions.Count} partitions, {partitions.Sum(p => p.Sectors) * SectorSize:N0} bytes decoded; chunks: {string.Join(", ", methods)}");
            var filesystems = new List<(Partition Partition, ContainerContents Contents)>();
            long total = 0;
            foreach (var p in partitions)
            {
                ct.ThrowIfCancellationRequested();
                var label = $"partition {p.Index} ({p.Name}, {p.Sectors * SectorSize:N0} bytes)";
                using var image = new UdifStream(src, p);
                var head = new byte[(int)Math.Min(image.Length, 4096)];
                try { image.ReadExactly(head); }
                catch (InvalidDataException ex) { notes.Add($"{label}: unreadable ({ex.Message})"); continue; }
                IContainerReader? filesystem = HfsPlusReader.Looks(head) ? new HfsPlusReader() : ApfsReader.Looks(head) ? new ApfsReader() : null;
                if (filesystem != null)
                {
                    try { filesystems.Add((p, filesystem.Open(image, $"{name} {p.Index}", allFiles, limits, ct)!)); }
                    catch (ToolError ex) when (ex.Code == ErrorCode.MalformedInput) { notes.Add($"{label}: {ex.Message}"); }
                    continue;
                }
                if (p.Chunks.All(c => c.Type is 0 or 2 || c.Sectors == 0) || p.Sectors * SectorSize <= 64 * 1024) { notes.Add(label); continue; }
                const string detail = "no filesystem read here";
                long bytes = image.Length;
                entries.Add(new ContainerEntry($"partition-{p.Index}.img", bytes, $"{p.Name}: {detail}"));
                if (bytes > limits.MaxItemBytes || total + bytes > limits.MaxTotalBytes || items.Count >= limits.MaxItems)
                {
                    notes.Add($"{label}: {detail}; over the item limit, listed, not extracted");
                    continue;
                }
                var all = new byte[bytes];
                try { image.ReadExactly(all); }
                catch (InvalidDataException ex) { notes.Add($"{label}: unreadable ({ex.Message})"); continue; }
                total += bytes;
                notes.Add($"{label}: {detail}; extracted as partition-{p.Index}.img");
                items.Add(new ExtractedItem($"partition-{p.Index}.img", all, $"dmg partition {p.Name}"));
            }
            // One filesystem lists at the top; several keep their partition number as the first path component.
            foreach (var (p, contents) in filesystems)
            {
                string Prefix(string path) => filesystems.Count == 1 ? path : $"{p.Index}/{path}";
                notes.AddRange(contents.Notes.Select(n => filesystems.Count == 1 ? n : $"partition {p.Index}: {n}"));
                items.AddRange(contents.Items.Select(i => i with { Name = Prefix(i.Name) }));
                entries.AddRange((contents.Entries ?? []).Select(e => e with { Path = Prefix(e.Path) }));
            }
            var kind = filesystems.Count > 0 ? $"dmg ({string.Join(", ", filesystems.Select(f => f.Contents.Kind).Distinct())})" : "dmg";
            return new ContainerContents(kind, items, notes) { Entries = entries };
        }
        catch (Exception ex) when (ex is InvalidDataException or EndOfStreamException) { throw src.Malformed(ex.Message); }
    }

    private static string? MethodName(uint type) => type switch
    {
        1 => "raw", 0 or 2 => "zero", 0x80000004 => "ADC", 0x80000005 => "zlib", 0x80000006 => "bzip2", 0x80000007 => "LZFSE", 0x80000008 => "xz",
        0x7FFFFFFE or 0xFFFFFFFF => null, _ => $"type 0x{type:X8}",
    };

    /// <summary>The partitions the trailer's XML property list describes, in table order.</summary>
    internal static List<Partition> Partitions(FsSource src, List<string> notes)
    {
        var koly = src.Read(src.Length - TrailerSize, TrailerSize);
        long dataFork = (long)BinaryPrimitives.ReadUInt64BigEndian(koly.AsSpan(24));
        long xmlAt = (long)BinaryPrimitives.ReadUInt64BigEndian(koly.AsSpan(216)), xmlLength = (long)BinaryPrimitives.ReadUInt64BigEndian(koly.AsSpan(224));
        if (xmlLength == 0) throw new InvalidDataException("the disk image keeps its partition table in a resource fork, not an XML property list; it is not read");
        if (xmlAt < 0 || xmlLength > 64L << 20 || xmlAt > src.Length - xmlLength) throw new InvalidDataException($"the property list at 0x{xmlAt:X} ({xmlLength:N0} bytes) lies outside the file");
        PlistNode? root;
        try { root = Plist.Read(src.Read(xmlAt, (int)xmlLength)).Root; }
        catch (Exception ex) when (ex is ToolError or FormatException or System.Xml.XmlException) { throw new InvalidDataException($"the property list does not parse: {ex.Message}"); }
        if (root is not PlistDict { } top || top["resource-fork"] is not PlistDict fork || fork["blkx"] is not PlistArray blkx)
            throw new InvalidDataException("the property list has no resource-fork blkx table");
        var list = new List<Partition>();
        foreach (var node in blkx.Items.Take(MaxPartitions))
        {
            if (node is not PlistDict d || d["Data"] is not PlistData { Value: var mish }) continue;
            var label = ((d["Name"] as PlistString ?? d["CFName"] as PlistString)?.Value ?? "").Trim();
            if (mish.Length < 204 || !mish.AsSpan().StartsWith("mish"u8)) { notes.Add($"partition {list.Count} ({label}): no block table"); continue; }
            long sectors = (long)BinaryPrimitives.ReadUInt64BigEndian(mish.AsSpan(16));
            long dataOffset = (long)BinaryPrimitives.ReadUInt64BigEndian(mish.AsSpan(24));
            uint count = BinaryPrimitives.ReadUInt32BigEndian(mish.AsSpan(200));
            if (count > MaxChunks || 204 + 40L * count > mish.Length || sectors < 0 || sectors > (1L << 40)) { notes.Add($"partition {list.Count} ({label}): a damaged block table"); continue; }
            var chunks = new Chunk[count];
            for (int i = 0; i < count; i++)
            {
                var c = mish.AsSpan(204 + 40 * i);
                chunks[i] = new(BinaryPrimitives.ReadUInt32BigEndian(c), (long)BinaryPrimitives.ReadUInt64BigEndian(c[8..]), (long)BinaryPrimitives.ReadUInt64BigEndian(c[16..]),
                    dataFork + dataOffset + (long)BinaryPrimitives.ReadUInt64BigEndian(c[24..]), (long)BinaryPrimitives.ReadUInt64BigEndian(c[32..]));
            }
            list.Add(new(list.Count, label, sectors, chunks));
        }
        return list;
    }

    /// <summary>One partition's decoded bytes, read on demand chunk by chunk; damaged chunks throw InvalidDataException.</summary>
    internal sealed class UdifStream(FsSource src, Partition partition) : Stream
    {
        private readonly Chunk[] _chunks = [.. partition.Chunks.Where(c => c.Type is not (0x7FFFFFFE or 0xFFFFFFFF) && c.Sectors > 0).OrderBy(c => c.Sector)];
        // Catalog and file reads alternate between chunks: decoded chunks are kept, least recently used dropped first.
        private const long CacheBytes = 64L << 20;
        private readonly Dictionary<int, LinkedListNode<(int Index, byte[] Data)>> _cache = [];
        private readonly LinkedList<(int Index, byte[] Data)> _recent = new();
        private long _cached;
        private long _position;

        public override bool CanRead => true;
        public override bool CanSeek => true;
        public override bool CanWrite => false;
        public override long Length { get; } = partition.Sectors * SectorSize;

        public override long Position
        {
            get => _position;
            set => _position = value is >= 0 ? value : throw new ArgumentOutOfRangeException(nameof(value));
        }

        public override int Read(byte[] buffer, int offset, int count) => Read(buffer.AsSpan(offset, count));

        public override int Read(Span<byte> buffer)
        {
            int done = 0;
            while (done < buffer.Length && _position < Length)
            {
                long sector = _position / SectorSize;
                int i = Find(sector);
                // A gap between chunks reads as zeros up to the next chunk.
                if (i < 0)
                {
                    long next = NextStart(sector) * SectorSize;
                    int zeros = (int)Math.Min(buffer.Length - done, Math.Min(next, Length) - _position);
                    buffer.Slice(done, zeros).Clear();
                    done += zeros;
                    _position += zeros;
                    continue;
                }
                if (!_cache.ContainsKey(i)) Prefetch(i);
                var data = Decoded(i);
                long within = _position - _chunks[i].Sector * SectorSize;
                int n = (int)Math.Min(buffer.Length - done, data.Length - within);
                data.AsSpan((int)within, n).CopyTo(buffer[done..]);
                done += n;
                _position += n;
            }
            return done;
        }

        private int Find(long sector)
        {
            int lo = 0, hi = _chunks.Length - 1;
            while (lo <= hi)
            {
                int mid = (lo + hi) >>> 1;
                var c = _chunks[mid];
                if (sector < c.Sector) hi = mid - 1;
                else if (sector >= c.Sector + c.Sectors) lo = mid + 1;
                else return mid;
            }
            return -1;
        }

        private long NextStart(long sector)
        {
            foreach (var c in _chunks)
                if (c.Sector > sector) return c.Sector;
            return long.MaxValue / SectorSize;
        }

        private byte[] Decoded(int i)
        {
            if (_cache.TryGetValue(i, out var hit))
            {
                _recent.Remove(hit);
                _recent.AddFirst(hit);
                return hit.Value.Data;
            }
            return Keep(i, Decode(i, Packed(i)));
        }

        // Chunks decoded at once on a miss; readers walk in allocation order, so the next ones are read soon.
        private const int Batch = 16;

        /// <summary>Decodes, in parallel, chunk <paramref name="i"/> and the uncached ones after it.</summary>
        private void Prefetch(int i)
        {
            var wanted = new List<int>();
            for (int k = i; k < _chunks.Length && k < i + Batch; k++)
                if (!_cache.ContainsKey(k)) wanted.Add(k);
            if (wanted.Count < 2) return;
            // The source stream is read in order; only decoding runs in parallel.
            var packed = wanted.Select(Packed).ToArray();
            var decoded = new byte[wanted.Count][];
            Parallel.For(0, wanted.Count, k => decoded[k] = Decode(wanted[k], packed[k]));
            for (int k = 0; k < wanted.Count; k++) Keep(wanted[k], decoded[k]);
        }

        private byte[] Packed(int i)
        {
            var c = _chunks[i];
            if (c.Sectors * SectorSize > MaxChunkBytes) throw new InvalidDataException($"a chunk of {c.Sectors * SectorSize:N0} bytes (the limit is {MaxChunkBytes:N0})");
            if (c.Type is 0 or 2) return [];
            if (c.Length < 0 || c.Length > MaxChunkBytes || c.Offset < 0 || c.Offset > src.Length - c.Length) throw new InvalidDataException($"chunk {i} at 0x{c.Offset:X} lies outside the file");
            return src.Read(c.Offset, (int)c.Length);
        }

        private byte[] Decode(int i, byte[] packed)
        {
            var c = _chunks[i];
            var output = new byte[c.Sectors * SectorSize];
            switch (c.Type)
            {
                case 0 or 2: break;
                case 1: packed.AsSpan(0, Math.Min(packed.Length, output.Length)).CopyTo(output); break;
                case 0x80000004: Adc(packed, output); break;
                case 0x80000005: FsCodec.Decode("zlib", packed, output); break;
                case 0x80000006: FsCodec.Decode("bzip2", packed, output); break;
                case 0x80000007:
                    if (Lzfse.Decode(packed, output) != output.Length) throw new InvalidDataException($"LZFSE chunk {i} decodes short of its {output.Length:N0} bytes");
                    break;
                case 0x80000008: FsCodec.Decode("xz", packed, output); break;
                default: throw new InvalidDataException($"chunk type {MethodName(c.Type)} is not read");
            }
            return output;
        }

        private byte[] Keep(int i, byte[] output)
        {
            while (_cached + output.Length > CacheBytes && _recent.Last is { } old)
            {
                _recent.RemoveLast();
                _cache.Remove(old.Value.Index);
                _cached -= old.Value.Data.Length;
            }
            _cache[i] = _recent.AddFirst((i, output));
            _cached += output.Length;
            return output;
        }

        /// <summary>Apple Data Compression: literal runs and back references of two or three bytes.</summary>
        internal static void Adc(ReadOnlySpan<byte> input, Span<byte> output)
        {
            int at = 0, o = 0;
            while (at < input.Length && o < output.Length)
            {
                byte b = input[at++];
                if ((b & 0x80) != 0)
                {
                    int n = Math.Min((b & 0x7F) + 1, Math.Min(input.Length - at, output.Length - o));
                    input.Slice(at, n).CopyTo(output[o..]);
                    at += n;
                    o += n;
                    continue;
                }
                int length, distance;
                if ((b & 0x40) != 0)
                {
                    if (at + 2 > input.Length) throw new InvalidDataException("damaged ADC data");
                    length = (b & 0x3F) + 4;
                    distance = (input[at] << 8 | input[at + 1]) + 1;
                    at += 2;
                }
                else
                {
                    if (at + 1 > input.Length) throw new InvalidDataException("damaged ADC data");
                    length = ((b & 0x3F) >> 2) + 3;
                    distance = ((b & 3) << 8 | input[at]) + 1;
                    at++;
                }
                if (distance > o) throw new InvalidDataException("an ADC reference before the start of the chunk");
                for (int k = 0; k < length && o < output.Length; k++, o++) output[o] = output[o - distance];
            }
        }

        public override long Seek(long offset, SeekOrigin origin) => Position = origin switch
        {
            SeekOrigin.Begin => offset, SeekOrigin.Current => _position + offset, _ => Length + offset,
        };

        public override void Flush() { }
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}
