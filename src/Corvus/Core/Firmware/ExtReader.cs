using System.Buffers.Binary;
using System.Text;

namespace Corvus.Core.Firmware;

/// <summary>ext2, ext3 and ext4 images read in ranges; uninitialized extents read as zeros.</summary>
internal sealed class ExtReader : IContainerReader
{
    public string Kind => "ext";

    public static bool Looks(ReadOnlySpan<byte> b) =>
        b.Length >= 2048 && BinaryPrimitives.ReadUInt16LittleEndian(b[(1024 + 56)..]) == 0xEF53
        // Block size 1 KiB to 64 KiB.
        && BinaryPrimitives.ReadUInt32LittleEndian(b[(1024 + 24)..]) <= 6
        && BinaryPrimitives.ReadUInt32LittleEndian(b[(1024 + 40)..]) > 0 && BinaryPrimitives.ReadUInt32LittleEndian(b[(1024 + 32)..]) > 0;

    public bool Accepts(ReadOnlySpan<byte> data, string name) => Looks(data);

    public ContainerContents Open(byte[] data, string name, bool allFiles, AnalysisLimits limits, CancellationToken ct) =>
        Read(FsSource.Of(data, name), allFiles, limits, ct);

    public ContainerContents? Open(Stream stream, string name, bool allFiles, AnalysisLimits limits, CancellationToken ct) =>
        Read(new FsSource(stream, 0, stream.Length, name), allFiles, limits, ct);

    private static ContainerContents Read(FsSource src, bool allFiles, AnalysisLimits limits, CancellationToken ct)
    {
        var sb = src.Read(1024, 1024);
        uint incompat = BinaryPrimitives.ReadUInt32LittleEndian(sb.AsSpan(96));
        uint compat = BinaryPrimitives.ReadUInt32LittleEndian(sb.AsSpan(92));
        // ext4: extents, 64bit or flex_bg; ext3: a journal.
        string kind = (incompat & 0x2C0) != 0 ? "ext4" : (compat & 4) != 0 ? "ext3" : "ext2";
        return FsTree.Guard(src, () => new Image(src, sb, new FsTree(kind, allFiles, limits, ct)).Walk());
    }

    private sealed class Image
    {
        private readonly FsSource _src;
        private readonly FsTree _tree;
        private readonly int _blockSize, _inodeSize, _descSize;
        private readonly uint _inodesPerGroup, _inodeCount, _firstDataBlock;
        private readonly long _blockCount;
        private readonly bool _fileType;
        private readonly long[] _inodeTables;
        private readonly HashSet<uint> _visited = [];

        public Image(FsSource src, byte[] sb, FsTree tree)
        {
            _src = src;
            _tree = tree;
            _inodeCount = U32(sb, 0);
            _blockCount = U32(sb, 4);
            _firstDataBlock = U32(sb, 20);
            _blockSize = 1024 << (int)U32(sb, 24);
            uint blocksPerGroup = U32(sb, 32);
            _inodesPerGroup = U32(sb, 40);
            uint rev = U32(sb, 76);
            _inodeSize = rev >= 1 ? BinaryPrimitives.ReadUInt16LittleEndian(sb.AsSpan(88)) : 128;
            uint incompat = U32(sb, 96);
            _fileType = (incompat & 2) != 0;
            bool is64 = (incompat & 0x80) != 0;
            if (is64) _blockCount |= (long)U32(sb, 0x150) << 32;
            _descSize = is64 ? Math.Max(32, (int)BinaryPrimitives.ReadUInt16LittleEndian(sb.AsSpan(0xFE))) : 32;
            if (_inodeSize < 128 || _inodeSize > _blockSize || (_inodeSize & (_inodeSize - 1)) != 0 || blocksPerGroup == 0 || _inodesPerGroup == 0)
                throw src.Malformed("ext superblock fields are out of range");
            long groups = (_blockCount - _firstDataBlock + blocksPerGroup - 1) / blocksPerGroup;
            if (groups <= 0 || groups > 1 << 22 || groups * _descSize > src.Length) throw src.Malformed($"ext superblock declares {groups:N0} block groups");
            // The group descriptors follow the superblock's block.
            var table = src.Read((_firstDataBlock + 1) * (long)_blockSize, (int)(groups * _descSize));
            _inodeTables = new long[groups];
            for (int g = 0; g < groups; g++)
            {
                long lo = U32(table, g * _descSize + 8);
                long hi = _descSize >= 64 ? U32(table, g * _descSize + 0x28) : 0;
                _inodeTables[g] = lo | hi << 32;
            }
            tree.Notes.Add($"{tree.Kind}, {_blockSize >> 10} KiB blocks, {_blockCount:N0} blocks, {_inodeCount:N0} inodes, volume '{Encoding.UTF8.GetString(sb, 120, 16).TrimEnd('\0')}'");
        }

        private static uint U32(byte[] b, int at) => BinaryPrimitives.ReadUInt32LittleEndian(b.AsSpan(at));

        private byte[] Inode(uint n)
        {
            if (n == 0 || n > _inodeCount) throw new InvalidDataException($"inode {n} of {_inodeCount}");
            uint group = (n - 1) / _inodesPerGroup, index = (n - 1) % _inodesPerGroup;
            if (group >= _inodeTables.Length) throw new InvalidDataException($"inode {n} is in group {group} of {_inodeTables.Length}");
            return _src.Read(_inodeTables[group] * _blockSize + (long)index * _inodeSize, Math.Min(_inodeSize, 256));
        }

        private static long Size(byte[] inode) => U32(inode, 4) | (long)U32(inode, 108) << 32;

        public ContainerContents Walk()
        {
            Directory("", 2, 0);
            return _tree.Done();
        }

        private void Directory(string path, uint n, int depth)
        {
            if (depth > FsTree.MaxDepth || !_visited.Add(n)) return;
            var inode = Inode(n);
            if ((BinaryPrimitives.ReadUInt16LittleEndian(inode) & 0xF000) != 0x4000) throw _src.Malformed($"{(path.Length == 0 ? "the root" : path)}: inode {n} is not a directory");
            long size = Size(inode);
            if (size > 256L << 20) throw new InvalidDataException($"a directory of {size:N0} bytes");
            var listing = Data(inode, size);
            // Inline directories start with the parent's inode number.
            int p = (U32(inode, 32) & 0x10000000) != 0 ? 4 : 0;
            var children = new List<(string Name, uint Inode)>();
            while (p + 8 <= listing.Length)
            {
                uint child = U32(listing, p);
                int recLen = BinaryPrimitives.ReadUInt16LittleEndian(listing.AsSpan(p + 4));
                int nameLen = _fileType ? listing[p + 6] : BinaryPrimitives.ReadUInt16LittleEndian(listing.AsSpan(p + 6));
                if (recLen < 8 || p + recLen > listing.Length && p + 8 + nameLen > listing.Length) break;
                if (child != 0 && p + 8 + nameLen <= listing.Length)
                {
                    var name = Encoding.UTF8.GetString(listing, p + 8, nameLen);
                    if (FsTree.UsableName(name)) children.Add((name, child));
                }
                p += recLen;
            }
            foreach (var (name, child) in children)
            {
                _tree.Token.ThrowIfCancellationRequested();
                var full = path.Length == 0 ? name : path + "/" + name;
                try
                {
                    var c = Inode(child);
                    long length = Size(c);
                    switch (BinaryPrimitives.ReadUInt16LittleEndian(c) & 0xF000)
                    {
                        case 0x4000: Directory(full, child, depth + 1); break;
                        case 0x8000: _tree.File(full, length, n => Data(c, n), mode: BinaryPrimitives.ReadUInt16LittleEndian(c)); break;
                        case 0xA000:
                            // A fast link keeps its target in the block pointers.
                            bool fast = length < 60 && (U32(c, 32) & 0x10080000) == 0;
                            var target = fast ? c.AsSpan(40, (int)length).ToArray() : Data(c, Math.Min(length, 4096));
                            _tree.Link(full, Encoding.UTF8.GetString(target), BinaryPrimitives.ReadUInt16LittleEndian(c));
                            break;
                    }
                }
                catch (Exception ex) when (FsTree.Damaged(ex)) { _tree.Unreadable(full, ex); }
            }
        }

        /// <summary>The first <paramref name="size"/> bytes of an inode's data.</summary>
        private byte[] Data(byte[] inode, long size)
        {
            if (size < 0 || size > _tree.Limits.MaxItemBytes) throw new InvalidDataException($"{size:N0} bytes");
            var bytes = new byte[size];
            uint flags = U32(inode, 32);
            if ((flags & 0x10000000) != 0)
            {
                // Inline data: the 60 bytes of the block pointers; a longer tail in an extended attribute is not read.
                inode.AsSpan(40, (int)Math.Min(size, 60)).CopyTo(bytes);
                if (size > 60) throw new InvalidDataException("inline data past 60 bytes lives in an extended attribute, which is not read");
                return bytes;
            }
            long blocks = (size + _blockSize - 1) / _blockSize;
            if ((flags & 0x80000) != 0) Extents(inode.AsSpan(40, 60).ToArray(), bytes, blocks, 0);
            else BlockMap(inode, bytes, blocks);
            return bytes;
        }

        /// <summary>Copies one file block (logical <paramref name="logical"/>) from physical block <paramref name="physical"/>.</summary>
        private void Copy(byte[] bytes, long logical, long physical, long count)
        {
            for (long i = 0; i < count; i++)
            {
                long at = (logical + i) * _blockSize;
                if (at >= bytes.Length) return;
                if (physical + i >= _blockCount) throw new InvalidDataException($"block {physical + i:N0} past the {_blockCount:N0} of the filesystem");
                int n = (int)Math.Min(_blockSize, bytes.Length - at);
                _src.Read((physical + i) * _blockSize, n).CopyTo(bytes, at);
            }
        }

        private void Extents(byte[] node, byte[] bytes, long blocks, int depth)
        {
            if (depth > 8 || BinaryPrimitives.ReadUInt16LittleEndian(node) != 0xF30A) throw new InvalidDataException("bad extent header");
            int entries = BinaryPrimitives.ReadUInt16LittleEndian(node.AsSpan(2));
            bool leaf = BinaryPrimitives.ReadUInt16LittleEndian(node.AsSpan(6)) == 0;
            for (int i = 0; i < entries && 12 + i * 12 + 12 <= node.Length; i++)
            {
                int e = 12 + i * 12;
                uint first = U32(node, e);
                if (leaf)
                {
                    int length = BinaryPrimitives.ReadUInt16LittleEndian(node.AsSpan(e + 4));
                    long start = (long)BinaryPrimitives.ReadUInt16LittleEndian(node.AsSpan(e + 6)) << 32 | U32(node, e + 8);
                    // Uninitialized: reads as zeros.
                    if (length > 32768) continue;
                    if (first < blocks) Copy(bytes, first, start, Math.Min(length, blocks - first));
                }
                else
                {
                    long child = U32(node, e + 4) | (long)BinaryPrimitives.ReadUInt16LittleEndian(node.AsSpan(e + 8)) << 32;
                    if (child >= _blockCount) throw new InvalidDataException("an extent index points past the filesystem");
                    Extents(_src.Read(child * _blockSize, _blockSize), bytes, blocks, depth + 1);
                }
            }
        }

        private void BlockMap(byte[] inode, byte[] bytes, long blocks)
        {
            long logical = 0;
            for (int i = 0; i < 12 && logical < blocks; i++, logical++)
                if (U32(inode, 40 + i * 4) is var b and not 0) Copy(bytes, logical, b, 1);
            for (int level = 1; level <= 3 && logical < blocks; level++)
                Indirect(U32(inode, 40 + (11 + level) * 4), level, bytes, ref logical, blocks);
        }

        /// <summary>An indirect block of <paramref name="level"/> (1 single, 2 double, 3 triple); a zero pointer is a hole.</summary>
        private void Indirect(uint block, int level, byte[] bytes, ref long logical, long blocks)
        {
            long span = 1;
            for (int i = 0; i < level; i++) span *= _blockSize / 4;
            if (block == 0) { logical += span; return; }
            if (block >= _blockCount) throw new InvalidDataException("an indirect block points past the filesystem");
            var pointers = _src.Read((long)block * _blockSize, _blockSize);
            for (int i = 0; i < _blockSize / 4 && logical < blocks; i++)
            {
                uint p = U32(pointers, i * 4);
                if (level == 1) { if (p != 0) Copy(bytes, logical, p, 1); logical++; }
                else Indirect(p, level - 1, bytes, ref logical, blocks);
            }
        }
    }
}
