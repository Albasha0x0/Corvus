using System.Buffers.Binary;
using System.Text;

namespace Corvus.Core.Firmware;

/// <summary>
/// squashfs 4.0 images (little endian, "hsqs"), every compressor (gzip, LZMA, LZO, xz, LZ4, Zstandard): the directory tree
/// from the inode and directory tables, file data from its blocks and fragment, sparse blocks as zeros; read in ranges.
/// </summary>
internal sealed class SquashfsReader : IContainerReader
{
    public string Kind => "squashfs";

    public static bool Looks(ReadOnlySpan<byte> b) =>
        b.Length >= 96 && b.StartsWith("hsqs"u8) && BinaryPrimitives.ReadUInt16LittleEndian(b[28..]) == 4
        && BinaryPrimitives.ReadUInt32LittleEndian(b[12..]) is var bs && bs >= 4096 && bs <= 1 << 20 && (bs & (bs - 1)) == 0;

    public bool Accepts(ReadOnlySpan<byte> data, string name) => Looks(data);

    public ContainerContents Open(byte[] data, string name, bool allFiles, AnalysisLimits limits, CancellationToken ct) =>
        Read(FsSource.Of(data, name), allFiles, limits, ct);

    public ContainerContents? Open(Stream stream, string name, bool allFiles, AnalysisLimits limits, CancellationToken ct) =>
        Read(new FsSource(stream, 0, stream.Length, name), allFiles, limits, ct);

    private const int MetadataBlock = 8192;

    public static ContainerContents Read(FsSource src, bool allFiles, AnalysisLimits limits, CancellationToken ct) =>
        Archives.LinuxAppPackages.Snap(FsTree.Guard(src, () => new Image(src, new FsTree("squashfs", allFiles, limits, ct) { Keep = Archives.LinuxAppPackages.Metadata }).Walk()));

    private sealed class Image
    {
        private readonly FsSource _src;
        private readonly FsTree _tree;
        private readonly string _codec;
        private readonly int _blockSize;
        private readonly long _inodeTable, _dirTable, _fragTable, _bytesUsed;
        private readonly uint _fragCount;
        private readonly ulong _root;
        private readonly Dictionary<long, (byte[] Data, long Next)> _meta = [];
        private readonly HashSet<ulong> _visited = [];

        public Image(FsSource src, FsTree tree)
        {
            _src = src;
            _tree = tree;
            var sb = src.Read(0, 96);
            _blockSize = (int)U32(sb, 12);
            _fragCount = U32(sb, 16);
            int compressor = BinaryPrimitives.ReadUInt16LittleEndian(sb.AsSpan(20));
            _codec = compressor switch { 1 => "zlib", 2 => "lzma", 3 => "lzo", 4 => "xz", 5 => "lz4", 6 => "zstd", _ => throw src.Malformed($"unknown squashfs compressor {compressor}") };
            _root = U64(sb, 32);
            _bytesUsed = (long)Math.Min(U64(sb, 40), (ulong)src.Length);
            _inodeTable = (long)U64(sb, 64);
            _dirTable = (long)U64(sb, 72);
            _fragTable = (long)U64(sb, 80);
            if (_inodeTable <= 0 || _dirTable < _inodeTable || _inodeTable >= src.Length || _dirTable >= src.Length) throw src.Malformed("squashfs table offsets lie outside the image");
            tree.Notes.Add($"squashfs 4.0, {_codec}, {_blockSize >> 10} KiB blocks, {U32(sb, 4):N0} inodes");
        }

        private static uint U32(byte[] b, int at) => BinaryPrimitives.ReadUInt32LittleEndian(b.AsSpan(at));
        private static ulong U64(byte[] b, int at) => BinaryPrimitives.ReadUInt64LittleEndian(b.AsSpan(at));

        public ContainerContents Walk()
        {
            var (type, _, inode) = Inode(_root);
            if (type is not (1 or 8)) throw _src.Malformed("the squashfs root inode is not a directory");
            Directory("", inode, type, 0);
            return _tree.Done();
        }

        /// <summary>One metadata block at <paramref name="at"/>: its bytes and where the next one starts.</summary>
        private (byte[] Data, long Next) Block(long at)
        {
            if (_meta.TryGetValue(at, out var cached)) return cached;
            var header = _src.Read(at, 2);
            int h = BinaryPrimitives.ReadUInt16LittleEndian(header);
            int size = h & 0x7FFF;
            if (size == 0 || size > MetadataBlock) throw _src.Malformed($"bad squashfs metadata block at 0x{at:X}");
            var raw = _src.Read(at + 2, size);
            byte[] data;
            if ((h & 0x8000) != 0) data = raw;
            else
            {
                var out8 = new byte[MetadataBlock];
                int n = FsCodec.Decode(_codec, raw, out8);
                data = out8[..n];
            }
            if (_meta.Count > 4096) _meta.Clear();
            return _meta[at] = (data, at + 2 + size);
        }

        /// <summary><paramref name="n"/> bytes of metadata from block <paramref name="block"/> (absolute) at <paramref name="offset"/>, across blocks.</summary>
        private byte[] Meta(ref long block, ref int offset, int n)
        {
            var result = new byte[n];
            int done = 0;
            while (done < n)
            {
                var (data, next) = Block(block);
                if (offset >= data.Length)
                {
                    if (offset > data.Length || data.Length == 0) throw _src.Malformed("a squashfs metadata reference points past its block");
                    block = next;
                    offset = 0;
                    continue;
                }
                int take = Math.Min(n - done, data.Length - offset);
                Buffer.BlockCopy(data, offset, result, done, take);
                done += take;
                offset += take;
            }
            return result;
        }

        /// <summary>The inode a reference names (block offset in the inode table, offset in the block): its type and reader position.</summary>
        private (int Type, int Mode, (long Block, int Offset) At) Inode(ulong reference)
        {
            long block = _inodeTable + (long)(reference >> 16);
            int offset = (int)(reference & 0xFFFF);
            var start = (block, offset);
            var h = Meta(ref block, ref offset, 16);
            return (BinaryPrimitives.ReadUInt16LittleEndian(h), BinaryPrimitives.ReadUInt16LittleEndian(h.AsSpan(2)), start);
        }

        private void Directory(string path, (long Block, int Offset) at, int type, int depth)
        {
            if (depth > FsTree.MaxDepth) { _tree.Notes.Add($"{path}: nested deeper than {FsTree.MaxDepth} directories; not read"); return; }
            long block = at.Block;
            int offset = at.Offset;
            Meta(ref block, ref offset, 16);
            uint startBlock;
            long listing;
            int listOffset;
            if (type == 1)
            {
                var d = Meta(ref block, ref offset, 16);
                startBlock = BinaryPrimitives.ReadUInt32LittleEndian(d);
                listing = BinaryPrimitives.ReadUInt16LittleEndian(d.AsSpan(8));
                listOffset = BinaryPrimitives.ReadUInt16LittleEndian(d.AsSpan(10));
            }
            else
            {
                var d = Meta(ref block, ref offset, 24);
                listing = BinaryPrimitives.ReadUInt32LittleEndian(d.AsSpan(4));
                startBlock = BinaryPrimitives.ReadUInt32LittleEndian(d.AsSpan(8));
                listOffset = BinaryPrimitives.ReadUInt16LittleEndian(d.AsSpan(18));
            }
            // the stored size counts 3 bytes for "." and ".." that are not in the table
            long remaining = listing - 3;
            long dirBlock = _dirTable + startBlock;
            int dirOffset = listOffset;
            var children = new List<(string Name, ulong Ref, int Type)>();
            while (remaining >= 12)
            {
                _tree.Token.ThrowIfCancellationRequested();
                var header = Meta(ref dirBlock, ref dirOffset, 12);
                remaining -= 12;
                uint count = BinaryPrimitives.ReadUInt32LittleEndian(header) + 1;
                uint inodeBlock = BinaryPrimitives.ReadUInt32LittleEndian(header.AsSpan(4));
                if (count > 256) throw _src.Malformed($"{path}/: a squashfs directory header lists {count} entries (at most 256)");
                for (uint i = 0; i < count && remaining >= 8; i++)
                {
                    var e = Meta(ref dirBlock, ref dirOffset, 8);
                    int nameSize = BinaryPrimitives.ReadUInt16LittleEndian(e.AsSpan(6)) + 1;
                    var name = Encoding.UTF8.GetString(Meta(ref dirBlock, ref dirOffset, nameSize));
                    remaining -= 8 + nameSize;
                    ulong reference = ((ulong)inodeBlock << 16) | BinaryPrimitives.ReadUInt16LittleEndian(e);
                    if (FsTree.UsableName(name)) children.Add((name, reference, BinaryPrimitives.ReadUInt16LittleEndian(e.AsSpan(4))));
                }
            }
            foreach (var (name, reference, _) in children)
            {
                var child = path.Length == 0 ? name : path + "/" + name;
                try
                {
                    var (childType, mode, childAt) = Inode(reference);
                    switch (childType)
                    {
                        // a directory reached twice is a loop in damaged tables
                        case 1 or 8: if (_visited.Add(reference)) Directory(child, childAt, childType, depth + 1); break;
                        case 2 or 9: File(child, childAt, childType, mode); break;
                        case 3 or 10: Symlink(child, childAt, mode); break;
                    }
                }
                catch (Exception ex) when (FsTree.Damaged(ex)) { _tree.Unreadable(child, ex); }
            }
        }

        /// <summary>The position after an inode's 16-byte common header, which may end in the next metadata block.</summary>
        private (long Block, int Offset) AfterHeader((long Block, int Offset) at)
        {
            var (block, offset) = at;
            Meta(ref block, ref offset, 16);
            return (block, offset);
        }

        private void Symlink(string path, (long Block, int Offset) at, int mode)
        {
            var (block, offset) = AfterHeader(at);
            var d = Meta(ref block, ref offset, 8);
            int size = (int)Math.Min(BinaryPrimitives.ReadUInt32LittleEndian(d.AsSpan(4)), 4096);
            _tree.Link(path, Encoding.UTF8.GetString(Meta(ref block, ref offset, size)), mode);
        }

        private void File(string path, (long Block, int Offset) at, int type, int mode)
        {
            var (block, offset) = AfterHeader(at);
            long blocksStart, size;
            uint fragment, fragOffset;
            if (type == 2)
            {
                var d = Meta(ref block, ref offset, 16);
                blocksStart = BinaryPrimitives.ReadUInt32LittleEndian(d);
                fragment = BinaryPrimitives.ReadUInt32LittleEndian(d.AsSpan(4));
                fragOffset = BinaryPrimitives.ReadUInt32LittleEndian(d.AsSpan(8));
                size = BinaryPrimitives.ReadUInt32LittleEndian(d.AsSpan(12));
            }
            else
            {
                var d = Meta(ref block, ref offset, 40);
                blocksStart = (long)BinaryPrimitives.ReadUInt64LittleEndian(d);
                size = (long)BinaryPrimitives.ReadUInt64LittleEndian(d.AsSpan(8));
                fragment = BinaryPrimitives.ReadUInt32LittleEndian(d.AsSpan(28));
                fragOffset = BinaryPrimitives.ReadUInt32LittleEndian(d.AsSpan(32));
            }
            bool hasFragment = fragment != 0xFFFFFFFF;
            long full = hasFragment ? size / _blockSize : (size + _blockSize - 1) / _blockSize;
            if (size < 0 || full > _src.Length) { _tree.Notes.Add($"{path}: a squashfs file of {size:N0} bytes cannot fit the image"); return; }
            // the block size list follows the inode; it is read now, while the metadata position is at hand
            var sizes = full > 0 && size <= _tree.Limits.MaxItemBytes ? Meta(ref block, ref offset, checked((int)full * 4)) : [];
            _tree.File(path, size, count =>
            {
                var bytes = new byte[count];
                long pos = blocksStart;
                for (long i = 0; i < full && i * _blockSize < count; i++)
                {
                    uint word = BinaryPrimitives.ReadUInt32LittleEndian(sizes.AsSpan((int)i * 4));
                    int stored = (int)(word & 0xFFFFFF);
                    int want = (int)Math.Min(_blockSize, count - i * _blockSize);
                    var into = bytes.AsSpan((int)(i * _blockSize), want);
                    if (stored == 0) continue; // a sparse block reads as zeros
                    var raw = _src.Read(pos, stored);
                    pos += stored;
                    if ((word & 0x1000000) != 0) raw.AsSpan(0, Math.Min(stored, want)).CopyTo(into);
                    else
                    {
                        var block8 = new byte[_blockSize];
                        int n = FsCodec.Decode(_codec, raw, block8);
                        block8.AsSpan(0, Math.Min(n, want)).CopyTo(into);
                    }
                }
                if (hasFragment && full * _blockSize < count)
                {
                    long tailAt = full * _blockSize;
                    var frag = Fragment(fragment);
                    int tail = (int)(size - tailAt);
                    if (fragOffset > frag.Length || tail > frag.Length - fragOffset) throw new InvalidDataException("the file's tail lies outside its squashfs fragment");
                    frag.AsSpan((int)fragOffset, (int)Math.Min(tail, count - tailAt)).CopyTo(bytes.AsSpan((int)tailAt));
                }
                return bytes;
            }, mode: mode);
        }

        private int _cachedFragment = -1;
        private byte[] _fragmentBytes = [];

        private byte[] Fragment(uint index)
        {
            if (index == _cachedFragment) return _fragmentBytes;
            if (index >= _fragCount) throw new InvalidDataException($"fragment {index} of {_fragCount}");
            // the fragment table: pointers to metadata blocks of 16-byte entries (start, size)
            var pointer = _src.Read(_fragTable + index / 512 * 8, 8);
            long block = (long)BinaryPrimitives.ReadUInt64LittleEndian(pointer);
            int offset = (int)(index % 512) * 16;
            var entry = Meta(ref block, ref offset, 16);
            long start = (long)BinaryPrimitives.ReadUInt64LittleEndian(entry);
            uint word = BinaryPrimitives.ReadUInt32LittleEndian(entry.AsSpan(8));
            int stored = (int)(word & 0xFFFFFF);
            if (start < 0 || start + stored > _bytesUsed) throw new InvalidDataException($"fragment {index} lies outside the image");
            var raw = _src.Read(start, stored);
            byte[] data;
            if ((word & 0x1000000) != 0) data = raw;
            else
            {
                var b = new byte[_blockSize];
                data = b[..FsCodec.Decode(_codec, raw, b)];
            }
            _cachedFragment = (int)index;
            return _fragmentBytes = data;
        }
    }
}
