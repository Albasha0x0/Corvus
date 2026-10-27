using System.Buffers.Binary;
using System.Text;

namespace Corvus.Core.Firmware;

/// <summary>cramfs images in either byte order, at offset 0 or after a 512-byte boot sector.</summary>
internal sealed class CramfsReader : IContainerReader
{
    public string Kind => "cramfs";

    private const uint Magic = 0x28CD3D45;

    /// <summary>The superblock's offset (0 or 512) and byte order; null when there is none.</summary>
    private static (int At, bool Big)? Find(ReadOnlySpan<byte> b)
    {
        foreach (int at in (int[])[0, 512])
        {
            if (b.Length < at + 76 || !b[(at + 16)..].StartsWith("Compressed ROMFS"u8)) continue;
            if (BinaryPrimitives.ReadUInt32LittleEndian(b[at..]) == Magic) return (at, false);
            if (BinaryPrimitives.ReadUInt32BigEndian(b[at..]) == Magic) return (at, true);
        }
        return null;
    }

    public bool Accepts(ReadOnlySpan<byte> data, string name) => Find(data) != null;

    public ContainerContents Open(byte[] data, string name, bool allFiles, AnalysisLimits limits, CancellationToken ct) =>
        Read(FsSource.Of(data, name), allFiles, limits, ct);

    public ContainerContents? Open(Stream stream, string name, bool allFiles, AnalysisLimits limits, CancellationToken ct) =>
        Read(new FsSource(stream, 0, stream.Length, name), allFiles, limits, ct);

    private static ContainerContents Read(FsSource src, bool allFiles, AnalysisLimits limits, CancellationToken ct) =>
        FsTree.Guard(src, () => new Image(src, new FsTree("cramfs", allFiles, limits, ct)).Walk());

    private sealed class Image
    {
        private const int Page = 4096;
        private readonly FsSource _src;
        private readonly FsTree _tree;
        private readonly bool _big;
        private readonly long _super;
        private readonly HashSet<long> _visited = [];

        public Image(FsSource src, FsTree tree)
        {
            _src = src;
            _tree = tree;
            var (at, big) = Find(src.ReadUpTo(0, 600)) ?? throw src.Malformed("no cramfs superblock");
            _big = big;
            // Offsets count from the image start, including a 512-byte boot sector before the superblock.
            _super = at;
            var sb = src.Read(at, 76);
            uint flags = U32(sb, 8);
            if ((flags & ~0x7FFu) != 0) tree.Notes.Add($"cramfs flags 0x{flags:X} include unknown ones");
            tree.Notes.Add($"cramfs, {(big ? "big" : "little")} endian, {U32(sb, 40):N0} files, '{Encoding.ASCII.GetString(sb, 48, 16).TrimEnd('\0')}'");
        }

        private uint U32(byte[] b, int at) => _big ? BinaryPrimitives.ReadUInt32BigEndian(b.AsSpan(at)) : BinaryPrimitives.ReadUInt32LittleEndian(b.AsSpan(at));
        private ushort U16(byte[] b, int at) => _big ? BinaryPrimitives.ReadUInt16BigEndian(b.AsSpan(at)) : BinaryPrimitives.ReadUInt16LittleEndian(b.AsSpan(at));

        /// <summary>An inode: mode, size, name length (bytes), data offset (bytes).</summary>
        private (int Mode, int Size, int NameLength, long Offset) Inode(byte[] b, int at)
        {
            int mode = U16(b, at);
            uint w1 = U32(b, at + 4), w2 = U32(b, at + 8);
            // Bitfields pack from the low bits on little endian, from the high bits on big endian.
            int size = (int)(_big ? w1 >> 8 : w1 & 0xFFFFFF);
            int nameLength = (int)(_big ? w2 >> 26 : w2 & 0x3F) * 4;
            long offset = (long)(_big ? w2 & 0x3FFFFFF : w2 >> 6) * 4;
            return (mode, size, nameLength, offset);
        }

        public ContainerContents Walk()
        {
            var root = Inode(_src.Read(_super + 64, 12), 0);
            if ((root.Mode & 0xF000) != 0x4000) throw _src.Malformed("the cramfs root inode is not a directory");
            Directory("", root.Offset, root.Size, 0);
            return _tree.Done();
        }

        private void Directory(string path, long offset, int size, int depth)
        {
            if (depth > FsTree.MaxDepth || !_visited.Add(offset)) return;
            if (offset == 0 || size == 0) return;
            var listing = _src.Read(offset, size);
            for (int p = 0; p + 12 <= listing.Length;)
            {
                _tree.Token.ThrowIfCancellationRequested();
                var (mode, length, nameLength, dataAt) = Inode(listing, p);
                if (nameLength == 0 || p + 12 + nameLength > listing.Length) throw _src.Malformed($"{path}/: a cramfs directory entry runs past its directory");
                var name = Encoding.UTF8.GetString(listing, p + 12, nameLength).TrimEnd('\0');
                p += 12 + nameLength;
                if (!FsTree.UsableName(name)) continue;
                var child = path.Length == 0 ? name : path + "/" + name;
                try
                {
                    switch (mode & 0xF000)
                    {
                        case 0x4000: Directory(child, dataAt, length, depth + 1); break;
                        case 0x8000: _tree.File(child, length, n => Data(dataAt, length, (int)n), mode: mode); break;
                        case 0xA000: _tree.Link(child, Encoding.UTF8.GetString(Data(dataAt, length, Math.Min(length, 4096))), mode); break;
                    }
                }
                catch (Exception ex) when (FsTree.Damaged(ex)) { _tree.Unreadable(child, ex); }
            }
        }

        /// <summary>The first <paramref name="count"/> bytes of a file of <paramref name="size"/>: one block pointer per page, then the pages.</summary>
        private byte[] Data(long offset, int size, int count)
        {
            var bytes = new byte[count];
            if (count == 0) return bytes;
            int pages = (count + Page - 1) / Page;
            var pointers = _src.Read(offset, pages * 4);
            long start = offset + (size + Page - 1) / Page * 4L;
            var page = new byte[Page];
            for (int i = 0; i < pages; i++)
            {
                uint ptr = U32(pointers, i * 4);
                int want = Math.Min(Page, count - i * Page);
                var into = bytes.AsSpan(i * Page, want);
                bool uncompressed = (ptr & 0x80000000) != 0, direct = (ptr & 0x40000000) != 0;
                long end = ptr & 0x3FFFFFFF;
                if (direct)
                {
                    // The block's own start; a compressed one begins with its length.
                    long at = end << 2;
                    if (uncompressed) _src.Read(at, want).CopyTo(into);
                    else
                    {
                        var head = _src.Read(at, 2);
                        int length = _big ? BinaryPrimitives.ReadUInt16BigEndian(head) : BinaryPrimitives.ReadUInt16LittleEndian(head);
                        Inflate(_src.Read(at + 2, length), page, into);
                    }
                    continue;
                }
                if (end < start) throw new InvalidDataException("a cramfs block pointer goes backwards");
                if (end == start) { start = end; continue; } // a hole
                var raw = _src.Read(start, (int)Math.Min(end - start, 2 * Page + 64));
                if (uncompressed) raw.AsSpan(0, Math.Min(raw.Length, want)).CopyTo(into);
                else Inflate(raw, page, into);
                start = end;
            }
            return bytes;
        }

        private static void Inflate(byte[] raw, byte[] page, Span<byte> into)
        {
            int n = FsCodec.Decode("zlib", raw, page);
            page.AsSpan(0, Math.Min(n, into.Length)).CopyTo(into);
        }
    }
}
