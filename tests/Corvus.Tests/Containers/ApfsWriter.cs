using System.Buffers.Binary;
using System.Text;
using Corvus.Core.Firmware;

namespace Corvus.Tests;

/// <summary>
/// Builds an APFS container (Apple File System Reference, 4 KiB blocks, one checkpoint): volumes with their object maps
/// and file-system trees, split into several leaves under an index node when the records pass one node. Files are
/// written in fragments, with holes, as hard links, symbolic links, FIFOs and decmpfs files.
/// </summary>
internal sealed class ApfsWriter
{
    public const int BlockSize = 4096;
    private const ulong RootDirectory = 2, FirstId = 16;

    private abstract record Item(string Path);
    private sealed record FileNode(string Path, byte[] Data, int Fragments, int HoleBlocks) : Item(Path);
    private sealed record LinkNode(string Path, string Target) : Item(Path);
    private sealed record HardLinkNode(string Path, string Existing) : Item(Path);
    private sealed record CompressedNode(string Path, byte[] Data, uint Type) : Item(Path);
    private sealed record FifoNode(string Path) : Item(Path);

    private sealed record VolumeSpec(string Name, bool Encrypted, List<Item> Nodes);

    private readonly List<VolumeSpec> _volumes = [new("Ledger", false, [])];
    private readonly List<byte[]> _blocks = [];

    private List<Item> Nodes => _volumes[^1].Nodes;

    /// <summary>Starts another volume; the first is named "Ledger".</summary>
    public ApfsWriter Volume(string name, bool encrypted = false) { _volumes.Add(new(name, encrypted, [])); return this; }
    public ApfsWriter File(string path, byte[] data, int fragments = 1) { Nodes.Add(new FileNode(path, data, fragments, 0)); return this; }
    /// <summary>A file whose first block is followed by <paramref name="holeBlocks"/> unallocated blocks.</summary>
    public ApfsWriter Sparse(string path, byte[] data, int holeBlocks) { Nodes.Add(new FileNode(path, data, 1, holeBlocks)); return this; }
    public ApfsWriter Link(string path, string target) { Nodes.Add(new LinkNode(path, target)); return this; }
    public ApfsWriter HardLink(string path, string existing) { Nodes.Add(new HardLinkNode(path, existing)); return this; }
    public ApfsWriter Compressed(string path, byte[] data, uint type) { Nodes.Add(new CompressedNode(path, data, type)); return this; }
    public ApfsWriter Fifo(string path) { Nodes.Add(new FifoNode(path)); return this; }

    private int Allocate()
    {
        _blocks.Add(new byte[BlockSize]);
        return _blocks.Count - 1;
    }

    // Data in consecutive blocks; returns the first.
    private ulong Write(ReadOnlySpan<byte> data)
    {
        int first = _blocks.Count;
        for (int at = 0; at < data.Length; at += BlockSize) data[at..Math.Min(data.Length, at + BlockSize)].CopyTo(_blocks[Allocate()]);
        return (ulong)first;
    }

    public byte[] Build()
    {
        Allocate();
        int containerOmap = Allocate(), containerTree = Allocate();
        var volumes = new List<(ulong Oid, ulong Paddr)>();
        for (int v = 0; v < _volumes.Count; v++) volumes.Add((1026 + (ulong)v, BuildVolume(_volumes[v])));

        var nx = _blocks[0];
        Header(nx, 1, 0x80000001, 0);
        U32(nx, 32, 0x4253584E);
        U32(nx, 36, BlockSize);
        U64(nx, 160, (ulong)containerOmap);
        for (int v = 0; v < volumes.Count; v++) U64(nx, 184 + 8 * v, volumes[v].Oid);
        ObjectMap(containerOmap, containerTree, volumes);
        U64(nx, 40, (ulong)_blocks.Count);
        Seal(nx);

        var image = new byte[_blocks.Count * BlockSize];
        for (int i = 0; i < _blocks.Count; i++) _blocks[i].CopyTo(image, i * BlockSize);
        return image;
    }

    private ulong BuildVolume(VolumeSpec spec)
    {
        int superblock = Allocate(), omap = Allocate(), omapTree = Allocate();
        var records = new List<(ulong Id, int Type, string Name, byte[] Key, byte[] Value)>();
        var folders = new Dictionary<string, ulong> { [""] = RootDirectory };
        var files = new Dictionary<string, ulong>();
        ulong next = FirstId;
        int fileCount = 0, folderCount = 0, linkCount = 0;

        ulong Folder(string path)
        {
            if (folders.TryGetValue(path, out var id)) return id;
            int slash = path.LastIndexOf('/');
            ulong parent = Folder(slash < 0 ? "" : path[..slash]);
            folders[path] = id = next++;
            folderCount++;
            records.Add(Inode(id, parent, 0x41ED, 0, null));
            records.Add(Entry(parent, path[(slash + 1)..], id, 4));
            return id;
        }

        records.Add(Inode(RootDirectory, 1, 0x41ED, 0, null));
        foreach (var node in spec.Nodes)
        {
            int slash = node.Path.LastIndexOf('/');
            ulong parent = Folder(slash < 0 ? "" : node.Path[..slash]);
            string name = node.Path[(slash + 1)..];
            if (node is HardLinkNode hard)
            {
                ulong target = files[hard.Existing];
                records.Add(Entry(parent, name, target, 8));
                continue;
            }
            ulong id = next++;
            files[node.Path] = id;
            switch (node)
            {
                case FileNode f:
                {
                    fileCount++;
                    records.Add(Inode(id, parent, 0x81A4, 0, (ulong)f.Data.Length + (ulong)f.HoleBlocks * BlockSize));
                    if (f.HoleBlocks > 0)
                    {
                        records.Add(Extent(id, 0, BlockSize, Write(f.Data.AsSpan(0, BlockSize))));
                        records.Add(Extent(id, (ulong)(1 + f.HoleBlocks) * BlockSize, (ulong)(f.Data.Length - BlockSize), Write(f.Data.AsSpan(BlockSize))));
                        break;
                    }
                    // Fragments are written apart, each after a spacer block.
                    int blocks = (f.Data.Length + BlockSize - 1) / BlockSize, per = Math.Max(1, (blocks + f.Fragments - 1) / f.Fragments);
                    for (int b = 0; b < blocks; b += per)
                    {
                        int from = b * BlockSize, to = Math.Min(f.Data.Length, (b + per) * BlockSize);
                        if (b > 0) Allocate();
                        records.Add(Extent(id, (ulong)from, (ulong)(to - from), Write(f.Data.AsSpan(from, to - from))));
                    }
                    break;
                }
                case LinkNode l:
                    linkCount++;
                    records.Add(Inode(id, parent, 0xA1ED, 0, null));
                    records.Add(Xattr(id, "com.apple.fs.symlink", 2, [.. Encoding.UTF8.GetBytes(l.Target), 0]));
                    break;
                case FifoNode:
                    fileCount++;
                    records.Add(Inode(id, parent, 0x11A4, 0, null));
                    break;
                case CompressedNode c:
                {
                    fileCount++;
                    var (attribute, resource) = HfsPlusWriter.Decmpfs(c.Data, c.Type);
                    records.Add(Inode(id, parent, 0x81A4, 0x20, null));
                    records.Add(Xattr(id, "com.apple.decmpfs", 2, attribute));
                    if (resource.Length > 0)
                    {
                        // The resource fork is an attribute in its own data stream.
                        ulong stream = next++;
                        var reference = new byte[48];
                        BinaryPrimitives.WriteUInt64LittleEndian(reference, stream);
                        BinaryPrimitives.WriteUInt64LittleEndian(reference.AsSpan(8), (ulong)resource.Length);
                        records.Add(Xattr(id, "com.apple.ResourceFork", 1, reference));
                        records.Add(Extent(stream, 0, (ulong)resource.Length, Write(resource)));
                    }
                    break;
                }
            }
            records.Add(Entry(parent, name, id, (ushort)(node is LinkNode ? 10 : node is FifoNode ? 1 : 8)));
        }

        var sorted = records.OrderBy(r => r.Id).ThenBy(r => r.Type).ThenBy(r => r.Name, StringComparer.Ordinal).Select(r => (r.Key, r.Value)).ToList();
        var mappings = new List<(ulong Oid, ulong Paddr)>();
        ulong root = FileSystemTree(sorted, mappings);
        ObjectMap(omap, omapTree, mappings);

        var sb = _blocks[superblock];
        Header(sb, 1026, 0xD, 0);
        U32(sb, 32, 0x42535041);
        U64(sb, 128, (ulong)omap);
        U64(sb, 136, root);
        U64(sb, 184, (ulong)fileCount);
        U64(sb, 192, (ulong)folderCount);
        U64(sb, 200, (ulong)linkCount);
        // APFS_FS_UNENCRYPTED.
        U64(sb, 264, spec.Encrypted ? 0UL : 1UL);
        Encoding.UTF8.GetBytes(spec.Name).CopyTo(sb, 704);
        Seal(sb);
        return (ulong)superblock;
    }

    // Leaves of variable-size records; several leaves get a root index node. Returns the root's virtual id.
    private ulong FileSystemTree(List<(byte[] Key, byte[] Value)> records, List<(ulong Oid, ulong Paddr)> mappings)
    {
        var leaves = new List<List<(byte[] Key, byte[] Value)>>();
        var leaf = new List<(byte[] Key, byte[] Value)>();
        int used = 56 + 40;
        foreach (var r in records)
        {
            int size = 8 + r.Key.Length + r.Value.Length;
            if (used + size > BlockSize && leaf.Count > 0) { leaves.Add(leaf); leaf = []; used = 56 + 40; }
            leaf.Add(r);
            used += size;
        }
        leaves.Add(leaf);
        ulong oid = 1100;
        if (leaves.Count == 1)
        {
            int block = Allocate();
            Node(_blocks[block], oid, 2, 3, 0, leaves[0], 0, 0);
            mappings.Add((oid, (ulong)block));
            return oid;
        }
        var index = new List<(byte[] Key, byte[] Value)>();
        foreach (var l in leaves)
        {
            int block = Allocate();
            ulong child = ++oid;
            Node(_blocks[block], child, 3, 2, 0, l, 0, 0);
            mappings.Add((child, (ulong)block));
            var value = new byte[8];
            BinaryPrimitives.WriteUInt64LittleEndian(value, child);
            index.Add((l[0].Key, value));
        }
        int rootBlock = Allocate();
        Node(_blocks[rootBlock], 1100, 2, 1, 1, index, 0, 0);
        mappings.Add((1100, (ulong)rootBlock));
        return 1100;
    }

    private void ObjectMap(int omap, int tree, List<(ulong Oid, ulong Paddr)> mappings)
    {
        var o = _blocks[omap];
        Header(o, (ulong)omap, 0x4000000B, 0);
        U64(o, 48, (ulong)tree);
        Seal(o);
        var records = mappings.OrderBy(m => m.Oid).Select(m =>
        {
            var key = new byte[16];
            BinaryPrimitives.WriteUInt64LittleEndian(key, m.Oid);
            BinaryPrimitives.WriteUInt64LittleEndian(key.AsSpan(8), 1);
            var value = new byte[16];
            BinaryPrimitives.WriteUInt32LittleEndian(value.AsSpan(4), BlockSize);
            BinaryPrimitives.WriteUInt64LittleEndian(value.AsSpan(8), m.Paddr);
            return (key, value);
        }).ToList();
        Node(_blocks[tree], (ulong)tree, 0x40000002, 7, 0, records, 16, 16);
    }

    /// <summary>A B-tree node: header, table of contents, keys forward, values back from the end (and btree_info at a root).</summary>
    private static void Node(byte[] b, ulong oid, uint type, ushort flags, ushort level, List<(byte[] Key, byte[] Value)> records, int keySize, int valueSize)
    {
        bool fixedSize = (flags & 4) != 0, root = (flags & 1) != 0;
        Header(b, oid, type, 0);
        BinaryPrimitives.WriteUInt16LittleEndian(b.AsSpan(32), flags);
        BinaryPrimitives.WriteUInt16LittleEndian(b.AsSpan(34), level);
        U32(b, 36, (uint)records.Count);
        int toc = records.Count * (fixedSize ? 4 : 8);
        BinaryPrimitives.WriteUInt16LittleEndian(b.AsSpan(42), (ushort)toc);
        int keysAt = 56 + toc, valuesEnd = BlockSize - (root ? 40 : 0), k = 0, v = 0;
        for (int i = 0; i < records.Count; i++)
        {
            var (key, value) = records[i];
            key.CopyTo(b, keysAt + k);
            v += value.Length;
            value.CopyTo(b, valuesEnd - v);
            int at = 56 + i * (fixedSize ? 4 : 8);
            if (fixedSize)
            {
                BinaryPrimitives.WriteUInt16LittleEndian(b.AsSpan(at), (ushort)k);
                BinaryPrimitives.WriteUInt16LittleEndian(b.AsSpan(at + 2), (ushort)v);
            }
            else
            {
                BinaryPrimitives.WriteUInt16LittleEndian(b.AsSpan(at), (ushort)k);
                BinaryPrimitives.WriteUInt16LittleEndian(b.AsSpan(at + 2), (ushort)key.Length);
                BinaryPrimitives.WriteUInt16LittleEndian(b.AsSpan(at + 4), (ushort)v);
                BinaryPrimitives.WriteUInt16LittleEndian(b.AsSpan(at + 6), (ushort)value.Length);
            }
            k += key.Length;
        }
        if (root)
        {
            U32(b, BlockSize - 40 + 4, BlockSize);
            U32(b, BlockSize - 40 + 8, (uint)keySize);
            U32(b, BlockSize - 40 + 12, (uint)valueSize);
        }
        Seal(b);
    }

    private static (ulong, int, string, byte[], byte[]) Inode(ulong id, ulong parent, ushort mode, uint bsdFlags, ulong? size)
    {
        var value = new byte[92 + (size == null ? 0 : 4 + 4 + 40)];
        BinaryPrimitives.WriteUInt64LittleEndian(value, parent);
        BinaryPrimitives.WriteUInt64LittleEndian(value.AsSpan(8), id);
        BinaryPrimitives.WriteUInt32LittleEndian(value.AsSpan(68), bsdFlags);
        BinaryPrimitives.WriteUInt16LittleEndian(value.AsSpan(80), mode);
        if (size is { } s)
        {
            // One extended field: INO_EXT_TYPE_DSTREAM (j_dstream_t, 40 bytes).
            BinaryPrimitives.WriteUInt16LittleEndian(value.AsSpan(92), 1);
            BinaryPrimitives.WriteUInt16LittleEndian(value.AsSpan(94), 40);
            value[96] = 8;
            BinaryPrimitives.WriteUInt16LittleEndian(value.AsSpan(98), 40);
            BinaryPrimitives.WriteUInt64LittleEndian(value.AsSpan(100), s);
        }
        return (id, 3, "", Key(id, 3, []), value);
    }

    private static (ulong, int, string, byte[], byte[]) Entry(ulong parent, string name, ulong id, ushort type)
    {
        var utf8 = Encoding.UTF8.GetBytes(name);
        var tail = new byte[4 + utf8.Length + 1];
        // Name length with its terminator in the low 10 bits; the hash above it is not checked by readers here.
        BinaryPrimitives.WriteUInt32LittleEndian(tail, (uint)(utf8.Length + 1));
        utf8.CopyTo(tail, 4);
        var value = new byte[18];
        BinaryPrimitives.WriteUInt64LittleEndian(value, id);
        BinaryPrimitives.WriteUInt16LittleEndian(value.AsSpan(16), type);
        return (parent, 9, name, Key(parent, 9, tail), value);
    }

    private static (ulong, int, string, byte[], byte[]) Xattr(ulong id, string name, ushort flags, byte[] data)
    {
        var utf8 = Encoding.UTF8.GetBytes(name);
        var tail = new byte[2 + utf8.Length + 1];
        BinaryPrimitives.WriteUInt16LittleEndian(tail, (ushort)(utf8.Length + 1));
        utf8.CopyTo(tail, 2);
        var value = new byte[4 + data.Length];
        BinaryPrimitives.WriteUInt16LittleEndian(value, flags);
        BinaryPrimitives.WriteUInt16LittleEndian(value.AsSpan(2), (ushort)data.Length);
        data.CopyTo(value, 4);
        return (id, 4, name, Key(id, 4, tail), value);
    }

    private static (ulong, int, string, byte[], byte[]) Extent(ulong stream, ulong logical, ulong length, ulong block)
    {
        var tail = new byte[8];
        BinaryPrimitives.WriteUInt64LittleEndian(tail, logical);
        var value = new byte[24];
        BinaryPrimitives.WriteUInt64LittleEndian(value, length);
        BinaryPrimitives.WriteUInt64LittleEndian(value.AsSpan(8), block);
        return (stream, 8, logical.ToString("D20"), Key(stream, 8, tail), value);
    }

    private static byte[] Key(ulong id, int type, byte[] tail)
    {
        var key = new byte[8 + tail.Length];
        BinaryPrimitives.WriteUInt64LittleEndian(key, id | (ulong)type << 60);
        tail.CopyTo(key, 8);
        return key;
    }

    private static void Header(byte[] b, ulong oid, uint type, uint subtype)
    {
        U64(b, 8, oid);
        U64(b, 16, 1);
        U32(b, 24, type);
        U32(b, 28, subtype);
    }

    private static void Seal(byte[] b) => U64(b, 0, ApfsReader.Checksum(b));

    private static void U32(byte[] b, int at, uint v) => BinaryPrimitives.WriteUInt32LittleEndian(b.AsSpan(at), v);
    private static void U64(byte[] b, int at, ulong v) => BinaryPrimitives.WriteUInt64LittleEndian(b.AsSpan(at), v);
}
