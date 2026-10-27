using System.Buffers.Binary;
using System.Text;

namespace Corvus.Core.Firmware;

/// <summary>APFS containers from the newest readable checkpoint; encrypted volumes are named, not read, snapshots counted.</summary>
internal sealed class ApfsReader : IContainerReader
{
    public string Kind => "apfs";

    private const uint ContainerMagic = 0x4253584E, VolumeMagic = 0x42535041;

    /// <summary>A container superblock ('NXSB') at block 0 with a power-of-two block size from 4 KiB to 64 KiB.</summary>
    public static bool Looks(ReadOnlySpan<byte> b)
    {
        if (b.Length < 4096 || BinaryPrimitives.ReadUInt32LittleEndian(b[32..]) != ContainerMagic) return false;
        uint block = BinaryPrimitives.ReadUInt32LittleEndian(b[36..]);
        return block is >= 4096 and <= 65536 && (block & (block - 1)) == 0;
    }

    public bool Accepts(ReadOnlySpan<byte> data, string name) => Looks(data) && !UdifReader.Looks(data);

    public ContainerContents Open(byte[] data, string name, bool allFiles, AnalysisLimits limits, CancellationToken ct) =>
        Read(FsSource.Of(data, name), allFiles, limits, ct);

    public ContainerContents? Open(Stream stream, string name, bool allFiles, AnalysisLimits limits, CancellationToken ct) =>
        Read(new FsSource(stream, 0, stream.Length, name), allFiles, limits, ct);

    private static ContainerContents Read(FsSource src, bool allFiles, AnalysisLimits limits, CancellationToken ct) =>
        FsTree.Guard(src, () => new Container(src, new FsTree("apfs", allFiles, limits, ct)).Walk());

    /// <summary>The Fletcher-64 checksum of an object: over its 32-bit words after the checksum field.</summary>
    internal static ulong Checksum(ReadOnlySpan<byte> block)
    {
        const ulong mod = 0xFFFFFFFF;
        ulong sum1 = 0, sum2 = 0;
        for (int i = 8; i + 4 <= block.Length; i += 4)
        {
            sum1 = (sum1 + BinaryPrimitives.ReadUInt32LittleEndian(block[i..])) % mod;
            sum2 = (sum2 + sum1) % mod;
        }
        ulong c1 = mod - (sum1 + sum2) % mod, c2 = mod - (sum1 + c1) % mod;
        return c2 << 32 | c1;
    }

    private static bool Valid(ReadOnlySpan<byte> block) =>
        BinaryPrimitives.ReadUInt64LittleEndian(block) == Checksum(block) && BinaryPrimitives.ReadUInt64LittleEndian(block) != 0;

    private readonly record struct Extent(ulong Logical, ulong Length, ulong Physical);

    private sealed record Inode(ulong Parent, ulong Stream, ushort Mode, uint BsdFlags, ulong Size);

    private sealed record Child(string Name, ulong Id, int Type);

    private sealed class Container
    {
        // Object types and flags (obj_phys_t.o_type).
        private const uint TypeMask = 0xFFFF, Physical = 0x40000000, Encrypted = 0x10000000;
        private const uint SuperblockType = 1, NodeType = 3, RootNodeType = 2, OmapType = 0xB, VolumeType = 0xD;
        private const ulong RootDirectory = 2;
        private const int MaxNodes = 1 << 22, MaxRecords = 8 << 20, MaxVolumes = 100;

        private readonly FsSource _src;
        private readonly FsTree _tree;
        private readonly int _blockSize;
        private readonly ulong _blocks, _xid;
        private readonly Dictionary<ulong, ulong> _containerMap;
        private readonly byte[] _superblock;
        private long _records;

        public Container(FsSource src, FsTree tree)
        {
            _src = src;
            _tree = tree;
            var first = src.Read(0, 4096);
            _blockSize = (int)BinaryPrimitives.ReadUInt32LittleEndian(first.AsSpan(36));
            if (_blockSize is < 4096 or > 65536 || (_blockSize & (_blockSize - 1)) != 0) throw new InvalidDataException($"a container block size of {_blockSize:N0} bytes");
            // Newest checkpoint first; one whose object map is damaged gives way to the one before it.
            var candidates = Checkpoints(src.Read(0, _blockSize));
            for (int i = 0; ; i++)
            {
                _superblock = candidates[i];
                _blocks = U64(_superblock, 40);
                _xid = U64(_superblock, 16);
                try
                {
                    _records = 0;
                    _containerMap = ObjectMap(U64(_superblock, 160), "container");
                    break;
                }
                catch (InvalidDataException ex) when (i + 1 < candidates.Count) { tree.Notes.Add($"checkpoint {_xid:N0} skipped: {ex.Message}"); }
            }
            if (_blocks * (ulong)_blockSize > (ulong)src.Length + (ulong)_blockSize)
                tree.Notes.Add($"the container declares {_blocks * (ulong)_blockSize:N0} bytes; the image holds {src.Length:N0}");
        }

        private static ulong U64(byte[] b, int at) => BinaryPrimitives.ReadUInt64LittleEndian(b.AsSpan(at));
        private static uint U32(byte[] b, int at) => BinaryPrimitives.ReadUInt32LittleEndian(b.AsSpan(at));
        private static ushort U16(byte[] b, int at) => BinaryPrimitives.ReadUInt16LittleEndian(b.AsSpan(at));

        /// <summary>The valid container superblocks of the checkpoint descriptor area and block 0, newest first.</summary>
        private List<byte[]> Checkpoints(byte[] block0)
        {
            var found = new List<byte[]>();
            if (Valid(block0)) found.Add(block0);
            uint descBlocks = U32(block0, 104);
            ulong descBase = U64(block0, 112);
            // A checkpoint area kept in a B-tree (high bit set) is not scanned; block 0 is used.
            if ((descBlocks & 0x80000000) == 0 && descBlocks <= 1 << 16)
                for (uint i = 0; i < descBlocks; i++)
                {
                    _tree.Token.ThrowIfCancellationRequested();
                    long at = (long)(descBase + i) * _blockSize;
                    if (at < 0 || at > _src.Length - _blockSize) break;
                    var b = _src.Read(at, _blockSize);
                    if ((U32(b, 24) & TypeMask) == SuperblockType && U32(b, 32) == ContainerMagic && Valid(b)) found.Add(b);
                }
            if (found.Count == 0) throw new InvalidDataException("no container superblock passes its checksum");
            return [.. found.DistinctBy(b => U64(b, 16)).OrderByDescending(b => U64(b, 16))];
        }

        private byte[] Block(ulong paddr, string what)
        {
            if (paddr == 0 || paddr >= _blocks) throw new InvalidDataException($"the {what} at block {paddr:N0} lies outside the container's {_blocks:N0} blocks");
            return _src.Read((long)paddr * _blockSize, _blockSize);
        }

        private byte[] Object(ulong paddr, string what)
        {
            var b = Block(paddr, what);
            if (!Valid(b)) throw new InvalidDataException($"the {what} at block {paddr:N0} fails its checksum");
            return b;
        }

        /// <summary>An object map's newest mapping at or before the checkpoint: virtual object id to physical block.</summary>
        private Dictionary<ulong, ulong> ObjectMap(ulong paddr, string what)
        {
            var omap = Object(paddr, $"{what} object map");
            if ((U32(omap, 24) & TypeMask) != OmapType) throw new InvalidDataException($"the {what} object map at block {paddr:N0} is another object type");
            var newest = new Dictionary<ulong, (ulong Xid, ulong Paddr)>();
            foreach (var (key, value) in Records(U64(omap, 48), null, $"{what} object map"))
            {
                if (key.Length < 16 || value.Length < 16) continue;
                ulong oid = BinaryPrimitives.ReadUInt64LittleEndian(key), xid = BinaryPrimitives.ReadUInt64LittleEndian(key.AsSpan(8));
                // OMAP_VAL_DELETED.
                if (xid > _xid || (BinaryPrimitives.ReadUInt32LittleEndian(value) & 1) != 0) continue;
                if (!newest.TryGetValue(oid, out var seen) || xid > seen.Xid) newest[oid] = (xid, BinaryPrimitives.ReadUInt64LittleEndian(value.AsSpan(8)));
            }
            return newest.ToDictionary(kv => kv.Key, kv => kv.Value.Paddr);
        }

        /// <summary>Every leaf record of the B-tree; child ids resolve through <paramref name="map"/> when given, else are physical blocks.</summary>
        private IEnumerable<(byte[] Key, byte[] Value)> Records(ulong root, Dictionary<ulong, ulong>? map, string what)
        {
            var seen = new HashSet<ulong>();
            var stack = new Stack<(ulong Id, int Depth)>();
            stack.Push((root, 0));
            int fixedKey = 0, fixedValue = 0;
            while (stack.Count > 0)
            {
                _tree.Token.ThrowIfCancellationRequested();
                var (id, depth) = stack.Pop();
                ulong paddr = map == null ? id : map.TryGetValue(id, out var p) ? p : throw new InvalidDataException($"the {what} node {id:N0} is not in the object map");
                if (!seen.Add(paddr) || seen.Count > MaxNodes || depth > 32) throw new InvalidDataException($"the {what} reaches block {paddr:N0} twice or too deep");
                var node = Object(paddr, $"{what} node");
                uint type = U32(node, 24) & TypeMask;
                if (type is not (NodeType or RootNodeType)) throw new InvalidDataException($"the {what} node at block {paddr:N0} is another object type");
                if ((U32(node, 24) & Encrypted) != 0) throw new InvalidDataException($"the {what} node at block {paddr:N0} is encrypted");
                ushort flags = U16(node, 32), level = U16(node, 34);
                uint count = U32(node, 36);
                bool isRoot = (flags & 1) != 0, leaf = (flags & 2) != 0, fixedSize = (flags & 4) != 0;
                if (isRoot)
                {
                    // btree_info_t closes the root node: flags, node size, key size, value size.
                    fixedKey = (int)U32(node, _blockSize - 40 + 8);
                    fixedValue = (int)U32(node, _blockSize - 40 + 12);
                }
                if (leaf != (level == 0)) throw new InvalidDataException($"the {what} node at block {paddr:N0} has level {level} and leaf flag {leaf}");
                int tableAt = 56 + U16(node, 40), tableLength = U16(node, 42);
                int keysAt = tableAt + tableLength, valuesEnd = _blockSize - (isRoot ? 40 : 0);
                if (keysAt > valuesEnd || (long)count * (fixedSize ? 4 : 8) > tableLength) throw new InvalidDataException($"the {what} node at block {paddr:N0} has a damaged table of contents");
                var children = new List<ulong>();
                for (int i = 0; i < count; i++)
                {
                    int k, kl, v, vl;
                    if (fixedSize)
                    {
                        (k, v) = (U16(node, tableAt + 4 * i), U16(node, tableAt + 4 * i + 2));
                        (kl, vl) = (fixedKey, leaf ? fixedValue : 8);
                    }
                    else (k, kl, v, vl) = (U16(node, tableAt + 8 * i), U16(node, tableAt + 8 * i + 2), U16(node, tableAt + 8 * i + 4), U16(node, tableAt + 8 * i + 6));
                    // BTOFF_INVALID marks a deleted value.
                    if (v == 0xFFFF) continue;
                    int keyAt = keysAt + k, valueAt = valuesEnd - v;
                    if (kl <= 0 || keyAt + kl > valuesEnd || valueAt < keysAt || valueAt + vl > valuesEnd) throw new InvalidDataException($"record {i} of the {what} node at block {paddr:N0} lies outside the node");
                    if (leaf)
                    {
                        if (++_records > MaxRecords) throw new InvalidDataException($"the {what} holds more than {MaxRecords:N0} records");
                        yield return (node.AsSpan(keyAt, kl).ToArray(), node.AsSpan(valueAt, vl).ToArray());
                    }
                    else if (vl >= 8) children.Add(U64(node, valueAt));
                }
                for (int i = children.Count - 1; i >= 0; i--) stack.Push((children[i], depth + 1));
            }
        }

        public ContainerContents Walk()
        {
            var volumes = new List<(string Name, Volume Volume)>();
            for (int i = 0; i < MaxVolumes; i++)
            {
                ulong oid = U64(_superblock, 184 + 8 * i);
                if (oid == 0) continue;
                try
                {
                    if (!_containerMap.TryGetValue(oid, out var paddr)) throw new InvalidDataException($"volume {i} (object {oid:N0}) is not in the container's object map");
                    var sb = Object(paddr, $"volume {i} superblock");
                    if ((U32(sb, 24) & TypeMask) != VolumeType || U32(sb, 32) != VolumeMagic) throw new InvalidDataException($"volume {i} at block {paddr:N0} is no volume superblock");
                    var name = Encoding.UTF8.GetString(sb.AsSpan(704, 256)).TrimEnd('\0');
                    int nul = name.IndexOf('\0');
                    if (nul >= 0) name = name[..nul];
                    ulong files = U64(sb, 184), directories = U64(sb, 192), symlinks = U64(sb, 200), snapshots = U64(sb, 216);
                    _tree.Notes.Add($"APFS volume '{name}': {files:N0} files, {directories:N0} directories, {symlinks:N0} symbolic links" +
                        (snapshots > 0 ? $", {snapshots:N0} snapshots (the current tree is listed)" : "") + ((U64(sb, 56) & 1) != 0 ? ", case-insensitive" : ""));
                    // APFS_FS_UNENCRYPTED clear: the file-system tree is encrypted.
                    if ((U64(sb, 264) & 1) == 0) { _tree.Notes.Add($"APFS volume '{name}' is encrypted; its files are not read"); continue; }
                    volumes.Add((name, new Volume(this, sb)));
                }
                catch (Exception ex) when (FsTree.Damaged(ex)) { _tree.Notes.Add($"APFS volume {i}: unreadable ({(ex is ToolError t ? t.Message : ex.Message)})"); }
            }
            // One volume with files lists at the top; several keep the volume name as the first path component.
            bool several = volumes.Count(v => v.Volume.HasFiles) > 1;
            for (int i = 0; i < volumes.Count; i++)
                volumes[i].Volume.Walk(!several ? "" : FsTree.UsableName(volumes[i].Name) ? volumes[i].Name : $"volume-{i}");
            var contents = _tree.Done();
            return contents with
            {
                Items = [.. contents.Items.OrderBy(i => i.Name, StringComparer.Ordinal)],
                Entries = [.. (contents.Entries ?? []).OrderBy(e => e.Path, StringComparer.Ordinal)],
            };
        }

        private sealed class Volume
        {
            // j_key_t types.
            private const int InodeRecord = 3, XattrRecord = 4, ExtentRecord = 8, DirectoryRecord = 9;
            // drec types (DT_*).
            private const int DirectoryEntry = 4;

            private readonly Container _c;
            private readonly Dictionary<ulong, Inode> _inodes = [];
            private readonly Dictionary<ulong, List<Child>> _children = [];
            private readonly Dictionary<ulong, Dictionary<string, (ushort Flags, byte[] Data)>> _xattrs = [];
            private readonly Dictionary<ulong, List<Extent>> _extents = [];
            private readonly HashSet<ulong> _visited = [];
            private readonly List<(ulong Block, Action Read)> _pending = [];

            public bool HasFiles => _children.ContainsKey(RootDirectory);

            public Volume(Container c, byte[] sb)
            {
                _c = c;
                var map = c.ObjectMap(U64(sb, 128), "volume");
                uint rootType = U32(sb, 116);
                bool physicalTree = (rootType & Physical) != 0;
                foreach (var (key, value) in c.Records(U64(sb, 136), physicalTree ? null : map, "file-system tree"))
                    Add(key, value);
                // A sealed volume keeps file extents in their own physical tree, keyed by stream id and logical address.
                ulong fext = U64(sb, 1032);
                if ((U64(sb, 56) & 0x20) != 0 && fext != 0)
                    foreach (var (key, value) in c.Records(fext, null, "file extent tree"))
                        if (key.Length >= 16 && value.Length >= 16)
                            AddExtent(BinaryPrimitives.ReadUInt64LittleEndian(key), BinaryPrimitives.ReadUInt64LittleEndian(key.AsSpan(8)), value);
            }

            private void Add(byte[] key, byte[] value)
            {
                if (key.Length < 8) return;
                ulong head = BinaryPrimitives.ReadUInt64LittleEndian(key);
                ulong id = head & 0x0FFFFFFFFFFFFFFF;
                int type = (int)(head >> 60);
                switch (type)
                {
                    case InodeRecord when value.Length >= 92:
                    {
                        ulong size = 0;
                        foreach (var (xtype, data) in Fields(value, 92))
                            // INO_EXT_TYPE_DSTREAM: j_dstream_t, whose first field is the logical size.
                            if (xtype == 8 && data.Length >= 8) size = BinaryPrimitives.ReadUInt64LittleEndian(data);
                        _inodes[id] = new(U64(value, 0), U64(value, 8), U16(value, 80), U32(value, 68), size);
                        break;
                    }
                    case DirectoryRecord when value.Length >= 18:
                    {
                        // Hashed keys hold a 10-bit name length with a 22-bit hash; keys of the first format hold a 16-bit length.
                        string? name = null;
                        uint lengthAndHash = key.Length >= 12 ? BinaryPrimitives.ReadUInt32LittleEndian(key.AsSpan(8)) : 0;
                        int hashed = (int)(lengthAndHash & 0x3FF), plain = key.Length >= 10 ? U16(key, 8) : 0;
                        if (key.Length >= 12 && 12 + hashed == key.Length) name = Name(key.AsSpan(12, hashed));
                        else if (key.Length >= 10 && 10 + plain == key.Length) name = Name(key.AsSpan(10, plain));
                        if (name == null) return;
                        if (!_children.TryGetValue(id, out var list)) _children[id] = list = [];
                        list.Add(new(name, U64(value, 0), U16(value, 16) & 0xF));
                        break;
                    }
                    case XattrRecord when key.Length >= 10 && value.Length >= 4:
                    {
                        int n = U16(key, 8);
                        if (10 + n > key.Length) return;
                        int length = U16(value, 2);
                        if (4 + length > value.Length) return;
                        if (!_xattrs.TryGetValue(id, out var names)) _xattrs[id] = names = [];
                        names[Name(key.AsSpan(10, n))] = (U16(value, 0), value.AsSpan(4, length).ToArray());
                        break;
                    }
                    case ExtentRecord when key.Length >= 16 && value.Length >= 16:
                        AddExtent(id, BinaryPrimitives.ReadUInt64LittleEndian(key.AsSpan(8)), value);
                        break;
                }
            }

            private void AddExtent(ulong stream, ulong logical, byte[] value)
            {
                if (!_extents.TryGetValue(stream, out var list)) _extents[stream] = list = [];
                // len_and_flags: the length in bytes in the low 56 bits; a physical block of 0 is a hole.
                list.Add(new(logical, U64(value, 0) & 0x00FFFFFFFFFFFFFF, U64(value, 8)));
            }

            private static string Name(ReadOnlySpan<byte> utf8)
            {
                int nul = utf8.IndexOf((byte)0);
                return Encoding.UTF8.GetString(nul >= 0 ? utf8[..nul] : utf8);
            }

            /// <summary>The extended fields (xf_blob_t) at <paramref name="at"/>: each type with its data, 8-byte aligned.</summary>
            private static List<(byte Type, byte[] Data)> Fields(byte[] value, int at)
            {
                var list = new List<(byte, byte[])>();
                if (at + 4 > value.Length) return list;
                int count = U16(value, at), dataAt = at + 4 + 4 * count;
                for (int i = 0; i < count && at + 8 + 4 * i <= value.Length; i++)
                {
                    byte type = value[at + 4 + 4 * i];
                    int size = U16(value, at + 4 + 4 * i + 2);
                    if (dataAt + size > value.Length) break;
                    list.Add((type, value.AsSpan(dataAt, size).ToArray()));
                    dataAt += (size + 7) & ~7;
                }
                return list;
            }

            public void Walk(string prefix)
            {
                Folder(prefix, RootDirectory, 0);
                foreach (var (_, read) in _pending.OrderBy(p => p.Block)) read();
            }

            private void Folder(string path, ulong id, int depth)
            {
                if (depth > FsTree.MaxDepth || !_visited.Add(id) || !_children.TryGetValue(id, out var children)) return;
                foreach (var child in children.OrderBy(c => c.Name, StringComparer.Ordinal))
                {
                    _c._tree.Token.ThrowIfCancellationRequested();
                    if (!FsTree.UsableName(child.Name)) continue;
                    var full = path.Length == 0 ? child.Name : path + "/" + child.Name;
                    try
                    {
                        if (child.Type == DirectoryEntry) Folder(full, child.Id, depth + 1);
                        else File(full, child.Id);
                    }
                    catch (Exception ex) when (FsTree.Damaged(ex)) { _c._tree.Unreadable(full, ex); }
                }
            }

            private void File(string path, ulong id)
            {
                if (!_inodes.TryGetValue(id, out var inode)) throw new InvalidDataException($"inode {id:N0}, which the tree does not hold");
                int kind = inode.Mode & 0xF000;
                var xattrs = _xattrs.GetValueOrDefault(id);
                if (kind == 0xA000)
                {
                    var target = xattrs?.GetValueOrDefault("com.apple.fs.symlink").Data ?? throw new InvalidDataException("a symbolic link without its target");
                    _c._tree.Link(path, Name(target), inode.Mode);
                    return;
                }
                if (kind is 0x1000 or 0x2000 or 0x6000 or 0xC000)
                {
                    _c._tree.Special(path, inode.Mode);
                    return;
                }
                if (kind != 0x8000) return;
                // UF_COMPRESSED in the BSD flags: the decmpfs attribute holds the file, or names the resource fork that does.
                if ((inode.BsdFlags & 0x20) != 0 && xattrs != null && xattrs.TryGetValue("com.apple.decmpfs", out var decmpfs))
                {
                    var cmp = Attribute(decmpfs);
                    if (Decmpfs.Header(cmp) is var (type, size))
                    {
                        if (!Decmpfs.Readable(type))
                        {
                            _c._tree.Unreadable(path, new InvalidDataException($"decmpfs compression type {type} ({Decmpfs.Name(type)}) is not read; {size:N0} bytes"));
                            return;
                        }
                        var fork = xattrs.GetValueOrDefault("com.apple.ResourceFork");
                        Later(path, fork.Data != null && (fork.Flags & 1) != 0 && fork.Data.Length >= 8 ? BinaryPrimitives.ReadUInt64LittleEndian(fork.Data) : inode.Stream, () =>
                            _c._tree.File(path, size, n => Decmpfs.Decode(type, cmp, () => fork.Data != null ? Attribute(fork) : [], size, n, _c._tree.Limits.MaxItemBytes),
                                $"decmpfs {Decmpfs.Name(type)}", inode.Mode));
                        return;
                    }
                }
                Later(path, inode.Stream, () => _c._tree.File(path, (long)inode.Size, n => Stream(inode.Stream, inode.Size, n), null, inode.Mode));
            }

            /// <summary>An attribute's bytes: embedded (XATTR_DATA_EMBEDDED) or in its own data stream (XATTR_DATA_STREAM).</summary>
            private byte[] Attribute((ushort Flags, byte[] Data) xattr)
            {
                if ((xattr.Flags & 1) == 0) return xattr.Data;
                // j_xattr_dstream_t: the stream id, then j_dstream_t with the logical size first.
                if (xattr.Data.Length < 16) throw new InvalidDataException("a short attribute stream reference");
                ulong size = BinaryPrimitives.ReadUInt64LittleEndian(xattr.Data.AsSpan(8));
                return Stream(BinaryPrimitives.ReadUInt64LittleEndian(xattr.Data), size, (long)Math.Min(size, long.MaxValue));
            }

            // Files are read in allocation order, so a compressed disk image decodes each chunk once.
            private void Later(string path, ulong stream, Action read)
            {
                ulong first = _extents.TryGetValue(stream, out var list) && list.Count > 0 ? list.Min(e => e.Physical) : 0;
                _pending.Add((first, () =>
                {
                    try { read(); }
                    catch (Exception ex) when (FsTree.Damaged(ex)) { _c._tree.Unreadable(path, ex); }
                }));
            }

            /// <summary>The first <paramref name="n"/> bytes of a data stream of <paramref name="size"/> bytes; holes read as zeros.</summary>
            private byte[] Stream(ulong stream, ulong size, long n)
            {
                n = (long)Math.Min((ulong)Math.Max(n, 0), size);
                if (n > _c._tree.Limits.MaxItemBytes) throw new InvalidDataException($"{n:N0} bytes");
                var bytes = new byte[n];
                if (n == 0) return bytes;
                int blockSize = _c._blockSize;
                foreach (var e in _extents.GetValueOrDefault(stream) ?? [])
                {
                    if (e.Logical >= (ulong)n || e.Physical == 0) continue;
                    ulong length = Math.Min(e.Length, (ulong)n - e.Logical);
                    if (e.Physical + (length + (ulong)blockSize - 1) / (ulong)blockSize > _c._blocks)
                        throw new InvalidDataException($"an extent at block {e.Physical:N0} passes the container's {_c._blocks:N0} blocks");
                    _c._src.Read((long)e.Physical * blockSize, bytes.AsSpan((int)e.Logical, (int)length));
                }
                return bytes;
            }
        }
    }
}
