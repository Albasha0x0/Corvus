using System.Buffers.Binary;
using System.Text;

namespace Corvus.Core.Firmware;

/// <summary>
/// HFS+ and HFSX volumes (Apple TN1150): the catalog's directory tree, file data forks through their extents and the
/// extents overflow file, symbolic links, hard links resolved to their file, and files compressed with decmpfs zlib, LZVN
/// or LZFSE (types 3, 4, 7, 8, 11, 12); other compression types are listed and named, not read.
/// </summary>
internal sealed class HfsPlusReader : IContainerReader
{
    public string Kind => "hfs+";

    private const int HeaderAt = 1024;

    /// <summary>A volume header signed H+ (version 4) or HX (version 5) with a power-of-two block size.</summary>
    public static bool Looks(ReadOnlySpan<byte> b)
    {
        if (b.Length < HeaderAt + 512) return false;
        var h = b[HeaderAt..];
        ushort sig = BinaryPrimitives.ReadUInt16BigEndian(h), version = BinaryPrimitives.ReadUInt16BigEndian(h[2..]);
        uint block = BinaryPrimitives.ReadUInt32BigEndian(h[40..]);
        return (sig == 0x482B && version == 4 || sig == 0x4858 && version == 5) && block >= 512 && (block & (block - 1)) == 0 && block <= 1 << 20;
    }

    // A disk image whose first chunk is stored raw shows a volume header at 1024: its koly trailer wins.
    public bool Accepts(ReadOnlySpan<byte> data, string name) => Looks(data) && !UdifReader.Looks(data);

    public ContainerContents Open(byte[] data, string name, bool allFiles, AnalysisLimits limits, CancellationToken ct) =>
        Read(FsSource.Of(data, name), allFiles, limits, ct);

    public ContainerContents? Open(Stream stream, string name, bool allFiles, AnalysisLimits limits, CancellationToken ct) =>
        Read(new FsSource(stream, 0, stream.Length, name), allFiles, limits, ct);

    private static ContainerContents Read(FsSource src, bool allFiles, AnalysisLimits limits, CancellationToken ct)
    {
        var header = src.Read(HeaderAt, 512);
        string kind = BinaryPrimitives.ReadUInt16BigEndian(header) == 0x4858 ? "hfsx" : "hfs+";
        return FsTree.Guard(src, () => new Volume(src, header, new FsTree(kind, allFiles, limits, ct)).Walk());
    }

    private readonly record struct Extent(uint Start, uint Count);

    private sealed record Fork(long Size, List<Extent> Extents);

    private sealed record Entry(string Name, byte[] Record);

    private sealed class Volume
    {
        private const uint RootId = 2, CatalogFileId = 4, AttributesFileId = 8;
        private const int MaxNodes = 1 << 22, MaxRecords = 4 << 20;

        private readonly FsSource _src;
        private readonly FsTree _tree;
        private readonly uint _blockSize, _totalBlocks;
        private readonly Dictionary<(uint File, byte Fork), List<(uint StartBlock, Extent[] Extents)>> _overflow = [];
        private readonly Dictionary<uint, List<Entry>> _children = [];
        private readonly Dictionary<uint, byte[]> _files = [];
        private readonly Dictionary<uint, byte[]> _decmpfs = [];
        private readonly HashSet<uint> _visited = [];
        private readonly List<(uint Block, Action Read)> _pending = [];
        private uint _privateFiles, _privateFolders;

        public Volume(FsSource src, byte[] h, FsTree tree)
        {
            _src = src;
            _tree = tree;
            _blockSize = U32(h, 40);
            _totalBlocks = U32(h, 44);
            if ((long)_blockSize * _totalBlocks > src.Length + _blockSize)
                tree.Notes.Add($"the volume declares {(long)_blockSize * _totalBlocks:N0} bytes; the image holds {src.Length:N0}");
            var extents = ForkAt(h, 192);
            foreach (var (key, data) in Leaves(extents, "extents"))
            {
                if (key.Length < 12 || data.Length < 64) continue;
                byte forkType = key[2];
                uint file = U32(key, 4), start = U32(key, 8);
                if (!_overflow.TryGetValue((file, forkType), out var list)) _overflow[(file, forkType)] = list = [];
                list.Add((start, ExtentsAt(data, 0)));
            }
            foreach (var (key, data) in Leaves(Overflowed(ForkAt(h, 272), CatalogFileId, 0), "catalog"))
            {
                if (key.Length < 8 || data.Length < 2) continue;
                uint parent = U32(key, 2);
                int length = BinaryPrimitives.ReadUInt16BigEndian(key.AsSpan(6));
                if (8 + 2 * length > key.Length) continue;
                var name = Encoding.BigEndianUnicode.GetString(key, 8, 2 * length);
                short type = (short)BinaryPrimitives.ReadUInt16BigEndian(data);
                if (type is 1 or 2)
                {
                    if (!_children.TryGetValue(parent, out var list)) _children[parent] = list = [];
                    list.Add(new(name, data));
                    if (type == 2 && data.Length >= 248) _files[U32(data, 8)] = data;
                    if (parent == RootId && type == 1 && data.Length >= 12)
                    {
                        if (name == "\0\0\0\0HFS+ Private Data") _privateFiles = U32(data, 8);
                        else if (name == ".HFS+ Private Directory Data\r") _privateFolders = U32(data, 8);
                    }
                }
                else if (type == 3 && parent == RootId && data.Length >= 10 && name.Length == 0)
                {
                    int n = BinaryPrimitives.ReadUInt16BigEndian(data.AsSpan(8));
                    if (10 + 2 * n <= data.Length) tree.Notes.Add($"{tree.Kind} volume '{Encoding.BigEndianUnicode.GetString(data, 10, 2 * n)}', {_blockSize:N0}-byte blocks, {_totalBlocks:N0} blocks");
                }
            }
            var attributes = ForkAt(h, 352);
            if (attributes.Size > 0)
                foreach (var (key, data) in Leaves(Overflowed(attributes, AttributesFileId, 0), "attributes"))
                {
                    // Key: length, pad, file id, start block, name length, name.
                    if (key.Length < 14 || data.Length < 16 || U32(data, 0) != 0x10) continue;
                    int n = BinaryPrimitives.ReadUInt16BigEndian(key.AsSpan(12));
                    if (14 + 2 * n > key.Length || Encoding.BigEndianUnicode.GetString(key, 14, 2 * n) != "com.apple.decmpfs") continue;
                    uint size = U32(data, 12);
                    if (16 + size <= data.Length) _decmpfs[U32(key, 4)] = data.AsSpan(16, (int)size).ToArray();
                }
        }

        private static uint U32(byte[] b, int at) => BinaryPrimitives.ReadUInt32BigEndian(b.AsSpan(at));

        private static Extent[] ExtentsAt(byte[] b, int at)
        {
            var list = new Extent[8];
            for (int i = 0; i < 8; i++) list[i] = new(U32(b, at + 8 * i), U32(b, at + 8 * i + 4));
            return list;
        }

        // ForkData: logical size, clump size, total blocks, eight extents.
        private static Fork ForkAt(byte[] b, int at) =>
            new((long)BinaryPrimitives.ReadUInt64BigEndian(b.AsSpan(at)), [.. ExtentsAt(b, at + 16).Where(e => e.Count > 0)]);

        /// <summary>The fork's extents with those the extents overflow file adds, in file order.</summary>
        private Fork Overflowed(Fork fork, uint file, byte forkType)
        {
            long blocks = fork.Extents.Sum(e => (long)e.Count), need = (fork.Size + _blockSize - 1) / _blockSize;
            if (blocks >= need || !_overflow.TryGetValue((file, forkType), out var more)) return fork;
            var all = new List<Extent>(fork.Extents);
            foreach (var (_, extents) in more.OrderBy(m => m.StartBlock))
                all.AddRange(extents.Where(e => e.Count > 0));
            return fork with { Extents = all };
        }

        /// <summary>The first <paramref name="n"/> bytes of a fork.</summary>
        private byte[] ReadFork(Fork fork, long n)
        {
            n = Math.Min(n, fork.Size);
            if (n < 0 || n > _tree.Limits.MaxItemBytes) throw new InvalidDataException($"{n:N0} bytes");
            var bytes = new byte[n];
            long at = 0;
            foreach (var e in fork.Extents)
            {
                if (at >= n) break;
                if ((long)e.Start + e.Count > _totalBlocks) throw new InvalidDataException($"an extent at block {e.Start:N0} passes the {_totalBlocks:N0} blocks of the volume");
                int take = (int)Math.Min((long)e.Count * _blockSize, n - at);
                _src.Read((long)e.Start * _blockSize, take).CopyTo(bytes, at);
                at += take;
            }
            if (at < n) throw new InvalidDataException($"the extents hold {at:N0} of {n:N0} bytes");
            return bytes;
        }

        /// <summary>Every leaf record (key without its length field, data) of a B-tree file, along the leaves' forward links.</summary>
        private IEnumerable<(byte[] Key, byte[] Data)> Leaves(Fork fork, string what)
        {
            if (fork.Size == 0) yield break;
            var head = ReadFork(fork, Math.Min(fork.Size, 512));
            if (head.Length < 14 + 106 || (sbyte)head[8] != 1) throw new InvalidDataException($"the {what} file has no B-tree header node");
            uint first = U32(head, 14 + 10);
            int nodeSize = BinaryPrimitives.ReadUInt16BigEndian(head.AsSpan(14 + 18));
            uint attributes = U32(head, 14 + 38);
            if (nodeSize is < 512 or > 32768 || (nodeSize & (nodeSize - 1)) != 0) throw new InvalidDataException($"the {what} B-tree has {nodeSize}-byte nodes");
            long nodes = fork.Size / nodeSize;
            var seen = new HashSet<uint>();
            long records = 0;
            for (uint node = first; node != 0; )
            {
                _tree.Token.ThrowIfCancellationRequested();
                if (node >= nodes || !seen.Add(node) || seen.Count > MaxNodes) throw new InvalidDataException($"the {what} B-tree's leaf chain reaches node {node:N0} of {nodes:N0} twice or out of range");
                var b = NodeAt(fork, node, nodeSize);
                if ((sbyte)b[8] != -1) throw new InvalidDataException($"{what} node {node:N0} in the leaf chain is not a leaf");
                int count = BinaryPrimitives.ReadUInt16BigEndian(b.AsSpan(10));
                for (int i = 0; i < count && ++records <= MaxRecords; i++)
                {
                    int start = BinaryPrimitives.ReadUInt16BigEndian(b.AsSpan(nodeSize - 2 * (i + 1)));
                    int end = BinaryPrimitives.ReadUInt16BigEndian(b.AsSpan(nodeSize - 2 * (i + 2)));
                    if (start < 14 || end <= start || end > nodeSize - 2 * (count + 1)) continue;
                    // Keys carry a 16-bit length (big keys, always set in HFS+); the data follows at an even offset.
                    int keyLength = (attributes & 2) != 0 ? BinaryPrimitives.ReadUInt16BigEndian(b.AsSpan(start)) : b[start];
                    int keyField = (attributes & 2) != 0 ? 2 : 1, dataAt = start + keyField + keyLength;
                    dataAt += dataAt & 1;
                    if (dataAt > end) continue;
                    yield return (b.AsSpan(start, keyField + keyLength).ToArray(), b.AsSpan(dataAt, end - dataAt).ToArray());
                }
                node = U32(b, 0);
            }
        }

        private byte[] NodeAt(Fork fork, uint node, int nodeSize)
        {
            long offset = (long)node * nodeSize;
            foreach (var e in fork.Extents)
            {
                long bytes = (long)e.Count * _blockSize;
                if (offset < bytes)
                {
                    if ((long)e.Start + e.Count > _totalBlocks) throw new InvalidDataException("a B-tree extent passes the volume");
                    return _src.Read((long)e.Start * _blockSize + offset, nodeSize);
                }
                offset -= bytes;
            }
            throw new InvalidDataException($"node {node:N0} lies past the B-tree's extents");
        }

        // Files are read in allocation order, so a compressed image decodes each chunk once; they are listed by path.
        public ContainerContents Walk()
        {
            Folder("", RootId, 0);
            foreach (var (_, read) in _pending.OrderBy(p => p.Block)) read();
            var contents = _tree.Done();
            return contents with
            {
                Items = [.. contents.Items.OrderBy(i => i.Name, StringComparer.Ordinal)],
                Entries = [.. (contents.Entries ?? []).OrderBy(e => e.Path, StringComparer.Ordinal)],
            };
        }

        private void Later(string path, Fork fork, Action read) => _pending.Add((fork.Extents.Count > 0 ? fork.Extents[0].Start : 0, () =>
        {
            try { read(); }
            catch (Exception ex) when (FsTree.Damaged(ex)) { _tree.Unreadable(path, ex); }
        }));

        private void Folder(string path, uint id, int depth)
        {
            if (depth > FsTree.MaxDepth || !_visited.Add(id) || !_children.TryGetValue(id, out var children)) return;
            foreach (var (stored, record) in children.OrderBy(c => c.Name, StringComparer.Ordinal))
            {
                _tree.Token.ThrowIfCancellationRequested();
                // The catalog keeps a POSIX ':' as '/'; names are decomposed (NFD) Unicode.
                var name = stored.Replace('/', ':').Normalize(NormalizationForm.FormC);
                if (!FsTree.UsableName(name) || id == RootId && (U32(record, 8) == _privateFiles || U32(record, 8) == _privateFolders) && _privateFiles + _privateFolders > 0) continue;
                var full = path.Length == 0 ? name : path + "/" + name;
                try
                {
                    short type = (short)BinaryPrimitives.ReadUInt16BigEndian(record);
                    if (type == 1) { if (record.Length >= 12) Folder(full, U32(record, 8), depth + 1); continue; }
                    if (record.Length < 248) throw new InvalidDataException("a short file record");
                    File(full, record, depth);
                }
                catch (Exception ex) when (FsTree.Damaged(ex)) { _tree.Unreadable(full, ex); }
            }
        }

        private void File(string path, byte[] record, int depth)
        {
            uint fileType = U32(record, 48), creator = U32(record, 52);
            int mode = BinaryPrimitives.ReadUInt16BigEndian(record.AsSpan(42));
            // Hard links: 'hlnk'/'hfs+' names iNode<n> in the private folder, 'fdrp'/'MACS' a folder dir_<n>.
            if (fileType == 0x686C6E6B && creator == 0x6866732B)
            {
                uint inode = U32(record, 44);
                var target = _children.GetValueOrDefault(_privateFiles)?.FirstOrDefault(c => c.Name == $"iNode{inode}");
                if (target == null || target.Record.Length < 248) throw new InvalidDataException($"hard link to iNode{inode}, which the catalog does not hold");
                record = target.Record;
                mode = BinaryPrimitives.ReadUInt16BigEndian(record.AsSpan(42));
            }
            else if (fileType == 0x66647270 && creator == 0x4D414353)
            {
                uint inode = U32(record, 44);
                if (_children.GetValueOrDefault(_privateFolders)?.FirstOrDefault(c => c.Name == $"dir_{inode}") is { } dir && dir.Record.Length >= 12)
                    Folder(path, U32(dir.Record, 8), depth + 1);
                return;
            }
            uint id = U32(record, 8);
            var data = Overflowed(ForkAt(record, 88), id, 0);
            if ((mode & 0xF000) == 0xA000)
            {
                _tree.Link(path, Encoding.UTF8.GetString(ReadFork(data, Math.Min(data.Size, 4096))), mode);
                return;
            }
            // UF_COMPRESSED in the owner flags: the data fork is empty and the decmpfs attribute holds the file.
            if ((record[41] & 0x20) != 0 && _decmpfs.TryGetValue(id, out var cmp) && cmp.Length >= 16 && BinaryPrimitives.ReadUInt32LittleEndian(cmp) == 0x636D7066)
            {
                uint type = BinaryPrimitives.ReadUInt32LittleEndian(cmp.AsSpan(4));
                long size = (long)BinaryPrimitives.ReadUInt64LittleEndian(cmp.AsSpan(8));
                if (type is not (3 or 4 or 7 or 8 or 11 or 12))
                {
                    _tree.Unreadable(path, new InvalidDataException($"decmpfs compression type {type} ({DecmpfsName(type)}) is not read; {size:N0} bytes"));
                    return;
                }
                var resource = Overflowed(ForkAt(record, 168), id, 0xFF);
                Later(path, resource, () => _tree.File(path, size, n => Decompress(type, cmp, resource, size, n), $"decmpfs {DecmpfsName(type)}", mode));
                return;
            }
            Later(path, data, () => _tree.File(path, data.Size, n => ReadFork(data, n), null, mode == 0 ? null : mode));
        }

        private static string DecmpfsName(uint type) => type switch { 3 or 4 => "zlib", 7 or 8 => "LZVN", 11 or 12 => "LZFSE", 1 or 9 or 10 => "uncompressed", _ => "unknown" };

        /// <summary>
        /// The first <paramref name="n"/> bytes of a decmpfs file: zlib, LZVN or LZFSE in the attribute (3, 7, 11) or in
        /// 64 KiB resource fork blocks (4, 8, 12).
        /// </summary>
        private byte[] Decompress(uint type, byte[] cmp, Fork resource, long size, long n)
        {
            if (size > _tree.Limits.MaxItemBytes) throw new InvalidDataException($"{size:N0} bytes");
            var output = new byte[size];
            if (type is 7 or 11) Block(type, cmp.AsSpan(16), output);
            else if (type is 8 or 12)
            {
                // The resource fork starts with block offsets, one more than the blocks; block i ends where i + 1 starts.
                var fork = ReadFork(resource, resource.Size);
                int blocks = (int)((size + 65535) / 65536);
                if (4L * (blocks + 1) > fork.Length) throw new InvalidDataException($"a decmpfs offset table of {blocks + 1:N0} entries past the resource fork");
                for (int i = 0; i < blocks && (long)i * 65536 < Math.Min(n, size); i++)
                {
                    uint from = BinaryPrimitives.ReadUInt32LittleEndian(fork.AsSpan(4 * i)), to = BinaryPrimitives.ReadUInt32LittleEndian(fork.AsSpan(4 * i + 4));
                    if (from > to || to > fork.Length) throw new InvalidDataException($"decmpfs block {i} lies outside the resource fork");
                    Block(type, fork.AsSpan((int)from, (int)(to - from)), output.AsSpan(i * 65536, (int)Math.Min(65536, size - (long)i * 65536)));
                }
            }
            else if (type == 3)
            {
                var body = cmp.AsSpan(16);
                // A first byte with its low nibble 0xF marks the rest as stored.
                if (body.Length > 0 && (body[0] & 0x0F) == 0x0F) body[1..Math.Min(body.Length, 1 + (int)size)].CopyTo(output);
                else FsCodec.Decode("zlib", body, output);
            }
            else
            {
                var fork = ReadFork(resource, resource.Size);
                // Resource fork header: data offset; the resource there is a length, then the block table.
                if (fork.Length < 0x104) throw new InvalidDataException("a short decmpfs resource fork");
                int dataAt = (int)BinaryPrimitives.ReadUInt32BigEndian(fork) + 4;
                if (dataAt + 4 > fork.Length) throw new InvalidDataException("the decmpfs block table lies outside the resource fork");
                int blocks = (int)BinaryPrimitives.ReadUInt32LittleEndian(fork.AsSpan(dataAt));
                if (blocks < 0 || (long)blocks * 65536 < size || dataAt + 4 + 8L * blocks > fork.Length) throw new InvalidDataException($"a decmpfs block table of {blocks:N0} blocks for {size:N0} bytes");
                for (int i = 0; i < blocks && (long)i * 65536 < Math.Min(n, size); i++)
                {
                    long offset = BinaryPrimitives.ReadUInt32LittleEndian(fork.AsSpan(dataAt + 4 + 8 * i)), length = BinaryPrimitives.ReadUInt32LittleEndian(fork.AsSpan(dataAt + 8 + 8 * i));
                    if (dataAt + offset + length > fork.Length) throw new InvalidDataException($"decmpfs block {i} lies outside the resource fork");
                    var block = fork.AsSpan((int)(dataAt + offset), (int)length);
                    var slot = output.AsSpan(i * 65536, (int)Math.Min(65536, size - (long)i * 65536));
                    if (block.Length > 0 && block[0] == 0xFF) block[1..Math.Min(block.Length, 1 + slot.Length)].CopyTo(slot);
                    else FsCodec.Decode("zlib", block, slot);
                }
            }
            return n >= size ? output : output.AsSpan(0, (int)n).ToArray();
        }

        // An LZVN block whose first byte is the end-of-stream opcode (0x06) is stored after it.
        private static void Block(uint type, ReadOnlySpan<byte> block, Span<byte> slot)
        {
            int written;
            if (type is 7 or 8 && block.Length > 0 && block[0] == 0x06)
            {
                written = Math.Min(block.Length - 1, slot.Length);
                block.Slice(1, written).CopyTo(slot);
            }
            else written = type is 7 or 8 ? Lzfse.DecodeLzvn(block, slot) : Lzfse.Decode(block, slot);
            if (written != slot.Length) throw new InvalidDataException($"a decmpfs {DecmpfsName(type)} block decodes to {written:N0} of {slot.Length:N0} bytes");
        }
    }
}
