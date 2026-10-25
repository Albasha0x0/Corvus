using System.Buffers.Binary;
using System.IO.Compression;
using System.Text;
using Corvus.Tests.NativeFormats;

namespace Corvus.Tests;

/// <summary>
/// Builds an HFS+ volume (TN1150 layout, 4 KiB blocks and B-tree nodes): folders, files, symbolic links, hard links
/// through the private iNode folder, decmpfs zlib files (types 3 and 4) and files split past eight extents into the
/// extents overflow file. Catalog leaves are chained and indexed by one index node when there are several.
/// </summary>
internal sealed class HfsPlusWriter
{
    public const int BlockSize = 4096;
    private const int NodeSize = 4096;

    private abstract record Node(string Path);
    private sealed record FileNode(string Path, byte[] Data, int Fragments) : Node(Path);
    private sealed record LinkNode(string Path, string Target) : Node(Path);
    private sealed record HardLinkNode(string Path, string Inode) : Node(Path);
    private sealed record CompressedNode(string Path, byte[] Data, uint Type, byte[]? Encoded) : Node(Path);
    private sealed record MisplacedNode(string Path, long Size, uint Block) : Node(Path);

    private readonly List<Node> _nodes = [];
    private readonly Dictionary<string, byte[]> _inodes = [];

    public string VolumeName { get; init; } = "Ledger";

    /// <summary>A file; <paramref name="fragments"/> above 8 places it in that many separate extents.</summary>
    public HfsPlusWriter File(string path, byte[] data, int fragments = 1) { _nodes.Add(new FileNode(path, data, fragments)); return this; }
    public HfsPlusWriter Link(string path, string target) { _nodes.Add(new LinkNode(path, target)); return this; }

    /// <summary>A hard link to shared data, kept once as the private folder's iNode file.</summary>
    public HfsPlusWriter HardLink(string path, string inode, byte[] data) { _inodes[inode] = data; _nodes.Add(new HardLinkNode(path, inode)); return this; }

    /// <summary>A file whose one extent starts at <paramref name="block"/>, wherever that is.</summary>
    public HfsPlusWriter Misplaced(string path, long size, uint block) { _nodes.Add(new MisplacedNode(path, size, block)); return this; }

    /// <summary>
    /// A decmpfs file: types 3, 7 and 11 keep zlib, LZVN or LZFSE data in the attribute, types 4, 8 and 12 in 64 KiB
    /// resource fork blocks. <paramref name="encoded"/> replaces the attribute's data as given.
    /// </summary>
    public HfsPlusWriter Compressed(string path, byte[] data, uint type, byte[]? encoded = null) { _nodes.Add(new CompressedNode(path, data, type, encoded)); return this; }

    private readonly record struct Extent(uint Start, uint Count);

    public byte[] Build()
    {
        var blocks = new List<byte[]>();
        // Blocks 0-1: boot blocks and volume header; B-tree files and data follow.
        uint Allocate(byte[] bytes)
        {
            uint start = (uint)(2 + blocks.Count);
            for (int i = 0; i < Math.Max(1, (bytes.Length + BlockSize - 1) / BlockSize); i++)
            {
                var b = new byte[BlockSize];
                bytes.AsSpan(i * BlockSize, Math.Min(BlockSize, Math.Max(0, bytes.Length - i * BlockSize))).CopyTo(b);
                blocks.Add(b);
            }
            return start;
        }
        uint nextId = 16;
        var folders = new Dictionary<string, uint> { [""] = 2 };
        var catalog = new List<(byte[] Key, byte[] Data)>();
        var overflow = new List<(byte[] Key, byte[] Data)>();
        var attributes = new List<(byte[] Key, byte[] Data)>();

        uint Folder(string path)
        {
            if (folders.TryGetValue(path, out var id)) return id;
            int slash = path.LastIndexOf('/');
            uint parent = Folder(slash < 0 ? "" : path[..slash]);
            id = folders[path] = nextId++;
            catalog.Add((CatalogKey(parent, path[(slash + 1)..]), FolderRecord(id)));
            return id;
        }

        catalog.Add((CatalogKey(1, VolumeName), FolderRecord(2)));
        catalog.Add((CatalogKey(2, ""), Thread(1, VolumeName)));
        uint privateId = 0;
        var inodeIds = new Dictionary<string, uint>();
        if (_inodes.Count > 0)
        {
            privateId = nextId++;
            catalog.Add((CatalogKey(2, "\0\0\0\0HFS+ Private Data"), FolderRecord(privateId)));
            // The iNode file is named for the link number its hard links keep; here its own id.
            foreach (var (key, data) in _inodes)
            {
                uint id = inodeIds[key] = nextId++;
                catalog.Add((CatalogKey(privateId, $"iNode{id}"), FileRecord(id, 0x81A4, Fork(data.Length, [new(Allocate(data), Blocks(data.Length))]))));
            }
        }
        foreach (var node in _nodes)
        {
            int slash = node.Path.LastIndexOf('/');
            uint parent = Folder(slash < 0 ? "" : node.Path[..slash]);
            string name = node.Path[(slash + 1)..];
            uint id = nextId++;
            switch (node)
            {
                case FileNode f when f.Fragments > 1:
                {
                    // One block per extent with a gap block after each, so no two extents merge.
                    var extents = new List<Extent>();
                    for (int i = 0; i < f.Fragments; i++)
                    {
                        var part = f.Data.AsSpan(i * BlockSize, Math.Min(BlockSize, Math.Max(0, f.Data.Length - i * BlockSize))).ToArray();
                        extents.Add(new(Allocate(part), 1));
                        Allocate([]);
                    }
                    catalog.Add((CatalogKey(parent, name), FileRecord(id, 0x81A4, Fork(f.Data.Length, extents.Take(8)))));
                    for (int at = 8; at < extents.Count; at += 8)
                        overflow.Add((ExtentKey(0, id, (uint)at), ExtentRecord(extents.Skip(at).Take(8))));
                    break;
                }
                case FileNode f:
                    catalog.Add((CatalogKey(parent, name), FileRecord(id, 0x81A4, Fork(f.Data.Length, [new(Allocate(f.Data), Blocks(f.Data.Length))]))));
                    break;
                case MisplacedNode m:
                    catalog.Add((CatalogKey(parent, name), FileRecord(id, 0x81A4, Fork(m.Size, [new(m.Block, Blocks(m.Size))]))));
                    break;
                case LinkNode l:
                {
                    var target = Encoding.UTF8.GetBytes(l.Target);
                    catalog.Add((CatalogKey(parent, name), FileRecord(id, 0xA1ED, Fork(target.Length, [new(Allocate(target), 1)]), 0x736C6E6B, 0x72686170)));
                    break;
                }
                case HardLinkNode hard:
                    catalog.Add((CatalogKey(parent, name), FileRecord(id, 0x81A4, Fork(0, []), 0x686C6E6B, 0x6866732B, special: inodeIds[hard.Inode])));
                    break;
                case CompressedNode c:
                {
                    var (attr, resource) = Decmpfs(c.Data, c.Type, c.Encoded);
                    var rsrc = resource.Length == 0 ? Fork(0, []) : Fork(resource.Length, [new(Allocate(resource), Blocks(resource.Length))]);
                    catalog.Add((CatalogKey(parent, name), FileRecord(id, 0x81A4, Fork(0, []), ownerFlags: 0x20, resource: rsrc)));
                    attributes.Add((AttributeKey(id, "com.apple.decmpfs"), InlineAttribute(attr)));
                    break;
                }
            }
        }

        var extentsFile = BTree([.. overflow.OrderBy(r => r.Key, KeyOrder.Instance)], 10);
        var catalogFile = BTree([.. catalog.OrderBy(r => r.Key, KeyOrder.Instance)], 516);
        var attributesFile = BTree([.. attributes.OrderBy(r => r.Key, KeyOrder.Instance)], 266);
        uint extentsAt = Allocate(extentsFile), catalogAt = Allocate(catalogFile), attributesAt = Allocate(attributesFile);
        uint total = (uint)(2 + blocks.Count + 1);

        var image = new byte[total * BlockSize];
        var h = image.AsSpan(1024);
        BinaryPrimitives.WriteUInt16BigEndian(h, 0x482B);
        BinaryPrimitives.WriteUInt16BigEndian(h[2..], 4);
        BinaryPrimitives.WriteUInt32BigEndian(h[32..], (uint)_nodes.Count);
        BinaryPrimitives.WriteUInt32BigEndian(h[36..], (uint)folders.Count);
        BinaryPrimitives.WriteUInt32BigEndian(h[40..], BlockSize);
        BinaryPrimitives.WriteUInt32BigEndian(h[44..], total);
        BinaryPrimitives.WriteUInt32BigEndian(h[64..], nextId);
        Fork(extentsFile.Length, [new(extentsAt, Blocks(extentsFile.Length))]).CopyTo(h[192..]);
        Fork(catalogFile.Length, [new(catalogAt, Blocks(catalogFile.Length))]).CopyTo(h[272..]);
        Fork(attributesFile.Length, [new(attributesAt, Blocks(attributesFile.Length))]).CopyTo(h[352..]);
        for (int i = 0; i < blocks.Count; i++) blocks[i].CopyTo(image, (2 + i) * BlockSize);
        image.AsSpan(1024, 512).CopyTo(image.AsSpan(image.Length - 1024));
        return image;
    }

    private static uint Blocks(long bytes) => (uint)Math.Max(1, (bytes + BlockSize - 1) / BlockSize);

    private static byte[] Fork(long size, IEnumerable<Extent> extents)
    {
        var b = new byte[80];
        BinaryPrimitives.WriteUInt64BigEndian(b, (ulong)size);
        int i = 0;
        foreach (var e in extents)
        {
            BinaryPrimitives.WriteUInt32BigEndian(b.AsSpan(16 + 8 * i), e.Start);
            BinaryPrimitives.WriteUInt32BigEndian(b.AsSpan(20 + 8 * i), e.Count);
            BinaryPrimitives.WriteUInt32BigEndian(b.AsSpan(12), BinaryPrimitives.ReadUInt32BigEndian(b.AsSpan(12)) + e.Count);
            i++;
        }
        return b;
    }

    private static byte[] CatalogKey(uint parent, string name)
    {
        var chars = Encoding.BigEndianUnicode.GetBytes(name);
        var k = new byte[8 + chars.Length];
        BinaryPrimitives.WriteUInt16BigEndian(k, (ushort)(6 + chars.Length));
        BinaryPrimitives.WriteUInt32BigEndian(k.AsSpan(2), parent);
        BinaryPrimitives.WriteUInt16BigEndian(k.AsSpan(6), (ushort)name.Length);
        chars.CopyTo(k, 8);
        return k;
    }

    private static byte[] ExtentKey(byte forkType, uint file, uint startBlock)
    {
        var k = new byte[12];
        BinaryPrimitives.WriteUInt16BigEndian(k, 10);
        k[2] = forkType;
        BinaryPrimitives.WriteUInt32BigEndian(k.AsSpan(4), file);
        BinaryPrimitives.WriteUInt32BigEndian(k.AsSpan(8), startBlock);
        return k;
    }

    private static byte[] AttributeKey(uint file, string name)
    {
        var chars = Encoding.BigEndianUnicode.GetBytes(name);
        var k = new byte[14 + chars.Length];
        BinaryPrimitives.WriteUInt16BigEndian(k, (ushort)(12 + chars.Length));
        BinaryPrimitives.WriteUInt32BigEndian(k.AsSpan(4), file);
        BinaryPrimitives.WriteUInt16BigEndian(k.AsSpan(12), (ushort)name.Length);
        chars.CopyTo(k, 14);
        return k;
    }

    private static byte[] ExtentRecord(IEnumerable<Extent> extents) => Fork(0, extents)[16..];

    private static byte[] FolderRecord(uint id)
    {
        var r = new byte[88];
        BinaryPrimitives.WriteUInt16BigEndian(r, 1);
        BinaryPrimitives.WriteUInt32BigEndian(r.AsSpan(8), id);
        BinaryPrimitives.WriteUInt16BigEndian(r.AsSpan(42), 0x41ED);
        return r;
    }

    private static byte[] Thread(uint parent, string name)
    {
        var chars = Encoding.BigEndianUnicode.GetBytes(name);
        var r = new byte[10 + chars.Length];
        BinaryPrimitives.WriteUInt16BigEndian(r, 3);
        BinaryPrimitives.WriteUInt32BigEndian(r.AsSpan(4), parent);
        BinaryPrimitives.WriteUInt16BigEndian(r.AsSpan(8), (ushort)name.Length);
        chars.CopyTo(r, 10);
        return r;
    }

    private static byte[] FileRecord(uint id, ushort mode, byte[] data, uint type = 0, uint creator = 0, uint special = 0, byte ownerFlags = 0, byte[]? resource = null)
    {
        var r = new byte[248];
        BinaryPrimitives.WriteUInt16BigEndian(r, 2);
        BinaryPrimitives.WriteUInt32BigEndian(r.AsSpan(8), id);
        r[41] = ownerFlags;
        BinaryPrimitives.WriteUInt16BigEndian(r.AsSpan(42), mode);
        BinaryPrimitives.WriteUInt32BigEndian(r.AsSpan(44), special);
        BinaryPrimitives.WriteUInt32BigEndian(r.AsSpan(48), type);
        BinaryPrimitives.WriteUInt32BigEndian(r.AsSpan(52), creator);
        data.CopyTo(r, 88);
        (resource ?? Fork(0, [])).CopyTo(r, 168);
        return r;
    }

    private static byte[] InlineAttribute(byte[] data)
    {
        var r = new byte[16 + data.Length + (data.Length & 1)];
        BinaryPrimitives.WriteUInt32BigEndian(r, 0x10);
        BinaryPrimitives.WriteUInt32BigEndian(r.AsSpan(12), (uint)data.Length);
        data.CopyTo(r, 16);
        return r;
    }

    /// <summary>The com.apple.decmpfs attribute and the resource fork (empty for types 3, 7 and 11) of a compressed file.</summary>
    internal static (byte[] Attribute, byte[] Resource) Decmpfs(byte[] data, uint type, byte[]? encoded = null)
    {
        var header = new byte[16];
        BinaryPrimitives.WriteUInt32LittleEndian(header, 0x636D7066);
        BinaryPrimitives.WriteUInt32LittleEndian(header.AsSpan(4), type);
        BinaryPrimitives.WriteUInt64LittleEndian(header.AsSpan(8), (ulong)data.Length);
        if (type is 3 or 7 or 11) return ([.. header, .. encoded ?? (type == 3 ? Zlib(data) : type == 7 ? LzvnLiterals(data) : LzfseRaw(data))], []);
        return (header, type == 4 ? ResourceFork(data) : OffsetTableFork(data, type));
    }

    internal static byte[] Zlib(byte[] data)
    {
        var o = new MemoryStream();
        using (var z = new ZLibStream(o, CompressionLevel.Optimal, leaveOpen: true)) z.Write(data);
        return o.ToArray();
    }

    /// <summary>A resource fork holding the decmpfs block table: 64 KiB blocks, each zlib.</summary>
    /// <summary>An LZFSE stream of one raw (bvx-) block.</summary>
    internal static byte[] LzfseRaw(byte[] data)
    {
        var w = new ByteWriter(false);
        w.Bytes("bvx-"u8);
        w.U32((uint)data.Length);
        w.Bytes(data);
        w.Bytes("bvx$"u8);
        return w.ToArray();
    }

    /// <summary>An LZVN stream of literal runs (opcode 0xE0, up to 271 bytes each) and the end-of-stream opcode.</summary>
    internal static byte[] LzvnLiterals(byte[] data)
    {
        var o = new MemoryStream();
        for (int at = 0; at < data.Length;)
        {
            int n = Math.Min(271, data.Length - at);
            if (n >= 16) { o.WriteByte(0xE0); o.WriteByte((byte)(n - 16)); }
            else o.WriteByte((byte)(0xE0 | n));
            o.Write(data, at, n);
            at += n;
        }
        o.Write([6, 0, 0, 0, 0, 0, 0, 0]);
        return o.ToArray();
    }

    // Types 8 and 12: block offsets from the fork's start, one more than the blocks. LZVN keeps its first block stored after 0x06.
    private static byte[] OffsetTableFork(byte[] data, uint type)
    {
        var blocks = new List<byte[]>();
        for (int at = 0, i = 0; at < data.Length; at += 65536, i++)
        {
            var part = data.AsSpan(at, Math.Min(65536, data.Length - at)).ToArray();
            blocks.Add(type == 12 ? LzfseRaw(part) : i == 0 ? [0x06, .. part] : LzvnLiterals(part));
        }
        var w = new ByteWriter(false);
        uint offset = (uint)(4 * (blocks.Count + 1));
        foreach (var b in blocks) { w.U32(offset); offset += (uint)b.Length; }
        w.U32(offset);
        foreach (var b in blocks) w.Bytes(b);
        return w.ToArray();
    }

    private static byte[] ResourceFork(byte[] data)
    {
        var blocks = new List<byte[]>();
        for (int at = 0; at < data.Length; at += 65536) blocks.Add(Zlib(data.AsSpan(at, Math.Min(65536, data.Length - at)).ToArray()));
        var table = new ByteWriter();
        table.U32((uint)blocks.Count);
        uint offset = (uint)(4 + 8 * blocks.Count);
        foreach (var b in blocks) { table.U32(offset); table.U32((uint)b.Length); offset += (uint)b.Length; }
        foreach (var b in blocks) table.Bytes(b);
        var resource = table.ToArray();
        var fork = new byte[0x104 + resource.Length];
        BinaryPrimitives.WriteUInt32BigEndian(fork, 0x100);
        BinaryPrimitives.WriteUInt32BigEndian(fork.AsSpan(8), (uint)(4 + resource.Length));
        BinaryPrimitives.WriteUInt32BigEndian(fork.AsSpan(0x100), (uint)resource.Length);
        resource.CopyTo(fork, 0x104);
        return fork;
    }

    /// <summary>A B-tree file: header node, leaves chained in key order, and an index node over several leaves.</summary>
    private static byte[] BTree(List<(byte[] Key, byte[] Data)> records, int maxKey)
    {
        var leaves = new List<List<byte[]>> { new() };
        int used = 14 + 2;
        foreach (var (key, data) in records)
        {
            var rec = (byte[])[.. key, .. data];
            if (used + rec.Length + 2 > NodeSize) { leaves.Add([]); used = 14 + 2; }
            leaves[^1].Add(rec);
            used += rec.Length + 2;
        }
        bool index = leaves.Count > 1;
        int first = 1, nodes = 1 + leaves.Count + (index ? 1 : 0);
        var file = new byte[nodes * NodeSize];
        for (int i = 0; i < leaves.Count; i++)
        {
            uint fLink = i + 1 < leaves.Count ? (uint)(first + i + 1) : 0, bLink = i > 0 ? (uint)(first + i - 1) : 0;
            WriteNode(file.AsSpan((first + i) * NodeSize, NodeSize), fLink, bLink, -1, 1, leaves[i]);
        }
        uint root = records.Count == 0 ? 0 : (uint)first;
        if (index)
        {
            root = (uint)(first + leaves.Count);
            // Index records: each leaf's first key, then the leaf's node number.
            var pointers = leaves.Select((l, i) =>
            {
                int keyLength = BinaryPrimitives.ReadUInt16BigEndian(l[0]) + 2;
                var p = new byte[keyLength + 4];
                l[0].AsSpan(0, keyLength).CopyTo(p);
                BinaryPrimitives.WriteUInt32BigEndian(p.AsSpan(keyLength), (uint)(first + i));
                return p;
            }).ToList();
            WriteNode(file.AsSpan((int)root * NodeSize, NodeSize), 0, 0, 0, 2, pointers);
        }
        var header = file.AsSpan(0, NodeSize);
        header[8] = 1;
        BinaryPrimitives.WriteUInt16BigEndian(header[10..], 3);
        var rec0 = header[14..];
        BinaryPrimitives.WriteUInt16BigEndian(rec0, (ushort)(records.Count == 0 ? 0 : index ? 2 : 1));
        BinaryPrimitives.WriteUInt32BigEndian(rec0[2..], root);
        BinaryPrimitives.WriteUInt32BigEndian(rec0[6..], (uint)records.Count);
        BinaryPrimitives.WriteUInt32BigEndian(rec0[10..], records.Count == 0 ? 0 : (uint)first);
        BinaryPrimitives.WriteUInt32BigEndian(rec0[14..], records.Count == 0 ? 0 : (uint)(first + leaves.Count - 1));
        BinaryPrimitives.WriteUInt16BigEndian(rec0[18..], NodeSize);
        BinaryPrimitives.WriteUInt16BigEndian(rec0[20..], (ushort)maxKey);
        BinaryPrimitives.WriteUInt32BigEndian(rec0[22..], (uint)nodes);
        rec0[37] = 0xCF;
        BinaryPrimitives.WriteUInt32BigEndian(rec0[38..], 6);
        foreach (var (slot, value) in new[] { (1, 14), (2, 120), (3, 248), (4, 256) })
            BinaryPrimitives.WriteUInt16BigEndian(header[(NodeSize - 2 * slot)..], (ushort)value);
        return file;
    }

    private static void WriteNode(Span<byte> node, uint fLink, uint bLink, sbyte kind, byte height, List<byte[]> records)
    {
        BinaryPrimitives.WriteUInt32BigEndian(node, fLink);
        BinaryPrimitives.WriteUInt32BigEndian(node[4..], bLink);
        node[8] = (byte)kind;
        node[9] = height;
        BinaryPrimitives.WriteUInt16BigEndian(node[10..], (ushort)records.Count);
        int at = 14;
        for (int i = 0; i < records.Count; i++)
        {
            BinaryPrimitives.WriteUInt16BigEndian(node[(NodeSize - 2 * (i + 1))..], (ushort)at);
            records[i].CopyTo(node[at..]);
            at += records[i].Length;
        }
        BinaryPrimitives.WriteUInt16BigEndian(node[(NodeSize - 2 * (records.Count + 1))..], (ushort)at);
    }

    /// <summary>Byte order of the encoded keys after their length field (big-endian ids, then names): the order hdiutil writes.</summary>
    private sealed class KeyOrder : IComparer<byte[]>
    {
        public static readonly KeyOrder Instance = new();
        public int Compare(byte[]? x, byte[]? y) => x.AsSpan(2).SequenceCompareTo(y.AsSpan(2));
    }
}

/// <summary>
/// Wraps partitions in a UDIF disk image: each partition cut into 64 KiB chunks stored by the given methods in turn
/// (all-zero chunks as zero fill), a blkx table in the XML property list, and the koly trailer.
/// </summary>
internal static class UdifWriter
{
    public const int ChunkBytes = 65536;

    public static byte[] Build(IReadOnlyList<(string Name, byte[] Data)> partitions, params uint[] methods)
    {
        var fork = new MemoryStream();
        var tables = new List<(string Name, byte[] Mish)>();
        long sector = 0;
        int n = 0;
        foreach (var (name, data) in partitions)
        {
            var chunks = new List<(uint Type, long Sector, long Sectors, long Offset, long Length)>();
            for (int at = 0; at < data.Length; at += ChunkBytes)
            {
                var part = data.AsSpan(at, Math.Min(ChunkBytes, data.Length - at)).ToArray();
                uint type = part.All(b => b == 0) ? 2u : methods[n++ % methods.Length];
                var packed = type switch
                {
                    2 => [],
                    1 => part,
                    0x80000004 => Adc(part),
                    0x80000005 => HfsPlusWriter.Zlib(part),
                    0x80000006 => Bzip2(part),
                    0x80000007 => HfsPlusWriter.LzfseRaw(part),
                    _ => throw new ArgumentException($"method 0x{type:X8}"),
                };
                chunks.Add((type, at / 512, (part.Length + 511) / 512, fork.Position, packed.Length));
                fork.Write(packed);
            }
            var mish = new ByteWriter(true);
            mish.Bytes("mish"u8);
            mish.U32(1);
            mish.U64((ulong)sector);
            mish.U64((ulong)((data.Length + 511) / 512));
            mish.U64(0);
            mish.PadTo(200);
            mish.U32((uint)chunks.Count + 1);
            foreach (var c in chunks) { mish.U32(c.Type); mish.U32(0); mish.U64((ulong)c.Sector); mish.U64((ulong)c.Sectors); mish.U64((ulong)c.Offset); mish.U64((ulong)c.Length); }
            mish.U32(0xFFFFFFFF); mish.U32(0); mish.U64((ulong)((data.Length + 511) / 512)); mish.U64(0); mish.U64((ulong)fork.Position); mish.U64(0);
            tables.Add((name, mish.ToArray()));
            sector += (data.Length + 511) / 512;
        }
        var xml = new StringBuilder("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n")
            .Append("<plist version=\"1.0\"><dict><key>resource-fork</key><dict><key>blkx</key><array>");
        for (int i = 0; i < tables.Count; i++)
            xml.Append($"<dict><key>Attributes</key><string>0x0050</string><key>Data</key><data>{Convert.ToBase64String(tables[i].Mish)}</data>")
               .Append($"<key>ID</key><string>{i - 1}</string><key>Name</key><string>{tables[i].Name}</string></dict>");
        xml.Append("</array></dict></dict></plist>\n");
        long xmlAt = fork.Position;
        var xmlBytes = Encoding.UTF8.GetBytes(xml.ToString());
        fork.Write(xmlBytes);
        var koly = new ByteWriter(true);
        koly.Bytes("koly"u8);
        koly.U32(4);
        koly.U32(512);
        koly.U32(1);
        koly.U64(0);
        koly.U64(0);
        koly.U64((ulong)xmlAt);
        koly.PadTo(216);
        koly.U64((ulong)xmlAt);
        koly.U64((ulong)xmlBytes.Length);
        koly.PadTo(492);
        koly.U64((ulong)sector);
        koly.PadTo(512);
        fork.Write(koly.ToArray());
        return fork.ToArray();
    }

    /// <summary>ADC with literal runs only (at most 128 bytes each): what the decoder's plain path reads.</summary>
    private static byte[] Adc(byte[] data)
    {
        var o = new List<byte>();
        for (int at = 0; at < data.Length; at += 128)
        {
            int n = Math.Min(128, data.Length - at);
            o.Add((byte)(0x80 | (n - 1)));
            o.AddRange(data.AsSpan(at, n));
        }
        return [.. o];
    }

    private static byte[] Bzip2(byte[] data)
    {
        var o = new MemoryStream();
        using (var z = SharpCompress.Compressors.BZip2.BZip2Stream.Create(o, SharpCompress.Compressors.CompressionMode.Compress, false, true, false)) z.Write(data);
        return o.ToArray();
    }
}
