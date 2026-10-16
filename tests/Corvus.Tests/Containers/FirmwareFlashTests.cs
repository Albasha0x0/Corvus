using System.Buffers.Binary;
using System.IO.Compression;
using System.Text;
using Corvus.Core;
using Corvus.Core.Firmware;
using static Corvus.Tests.FirmwareFilesystemTests;

namespace Corvus.Tests;

/// <summary>
/// Flash filesystems (JFFS2, UBI, UBIFS) written here node by node from the fixture tree, as the kernel lays them out
/// (CRCs, versions, sequence numbers): the newest version of each name and block wins, a deletion entry removes a name.
/// </summary>
public sealed class FirmwareFlashTests
{
    /// <summary>The fixture tree as (path, bytes) files and (path, target) links; directories are implied.</summary>
    private static (List<(string Path, byte[] Bytes)> Files, List<(string Path, string Target)> Links) Source()
    {
        var files = new List<(string, byte[])>
        {
            ("bin/busybox", Isa("mips32be.elf")), ("lib/libuci.so", Isa("armbe.elf")), ("etc/passwd", "root:x:0:0:root:/root:/bin/sh\n"u8.ToArray()),
            ("etc/empty", []), ("etc/config/large.conf", LargeConf()), ("www/index.html", "<html><body>router</body></html>\n"u8.ToArray()),
            ("usr/share/doc/deep/er/notes.txt", "deep file\n"u8.ToArray()),
        };
        return (files, [("sbin/init", "../bin/busybox")]);
    }

    /// <summary>Inode numbers for the tree: 1 is the root; directories, then files and links.</summary>
    private static (Dictionary<string, uint> Dirs, List<(uint Parent, string Name, uint Inode, string Path)> Names) Number(IEnumerable<string> paths)
    {
        var dirs = new Dictionary<string, uint> { [""] = 1 };
        var names = new List<(uint, string, uint, string)>();
        uint next = 2;
        foreach (var path in paths)
        {
            var parts = path.Split('/');
            for (int i = 0; i < parts.Length - 1; i++)
            {
                var dir = string.Join('/', parts[..(i + 1)]);
                if (dirs.ContainsKey(dir)) continue;
                dirs[dir] = next++;
                names.Add((dirs[string.Join('/', parts[..i])], parts[i], dirs[dir], dir));
            }
        }
        foreach (var path in paths)
        {
            int slash = path.LastIndexOf('/');
            names.Add((dirs[slash < 0 ? "" : path[..slash]], path[(slash + 1)..], next++, path));
        }
        return (dirs, names);
    }

    private static byte[] Zlib(byte[] data)
    {
        var o = new MemoryStream();
        using (var z = new ZLibStream(o, CompressionLevel.Optimal, leaveOpen: true)) z.Write(data);
        return o.ToArray();
    }

    private static byte[] Deflate(byte[] data)
    {
        var o = new MemoryStream();
        using (var z = new DeflateStream(o, CompressionLevel.Optimal, leaveOpen: true)) z.Write(data);
        return o.ToArray();
    }

    /// <summary>JFFS2's rtime coder (the kernel's jffs2_rtime_compress).</summary>
    private static byte[] Rtime(byte[] data)
    {
        var positions = new int[256];
        var o = new List<byte>();
        for (int pos = 0; pos < data.Length;)
        {
            byte value = data[pos++];
            int back = positions[value], run = 0;
            o.Add(value);
            positions[value] = pos;
            while (back < pos && pos < data.Length && data[pos] == data[back] && run < 255) { pos++; back++; run++; }
            o.Add((byte)run);
        }
        return [.. o];
    }

    internal static byte[] Jffs2(bool big)
    {
        var (files, links) = Source();
        var (_, names) = Number([.. files.Select(f => f.Path), .. links.Select(l => l.Path)]);
        var o = new MemoryStream();
        void U16(Span<byte> s, ushort v) { if (big) BinaryPrimitives.WriteUInt16BigEndian(s, v); else BinaryPrimitives.WriteUInt16LittleEndian(s, v); }
        void U32(Span<byte> s, uint v) { if (big) BinaryPrimitives.WriteUInt32BigEndian(s, v); else BinaryPrimitives.WriteUInt32LittleEndian(s, v); }
        void Node(ushort type, byte[] body, int crcOver, int crcAt)
        {
            var n = new byte[12 + body.Length];
            U16(n, 0x1985);
            U16(n.AsSpan(2), type);
            U32(n.AsSpan(4), (uint)n.Length);
            U32(n.AsSpan(8), Crc.Jffs2(n.AsSpan(0, 8)));
            body.CopyTo(n, 12);
            U32(n.AsSpan(crcAt), Crc.Jffs2(n.AsSpan(0, crcOver)));
            o.Write(n);
            while (o.Length % 4 != 0) o.WriteByte(0xFF);
        }
        void Dirent(uint parent, string name, uint version, uint ino, byte type)
        {
            var nameBytes = Encoding.UTF8.GetBytes(name);
            var b = new byte[28 + nameBytes.Length];
            U32(b, parent); U32(b.AsSpan(4), version); U32(b.AsSpan(8), ino);
            b[16] = (byte)nameBytes.Length; b[17] = type;
            U32(b.AsSpan(24), Crc.Jffs2(nameBytes));
            nameBytes.CopyTo(b, 28);
            Node(0xE001, b, 32, 32);
        }
        void Inode(uint ino, uint version, uint mode, uint size, uint offset, byte[] stored, uint dsize, byte codec)
        {
            var b = new byte[56 + stored.Length];
            U32(b, ino); U32(b.AsSpan(4), version); U32(b.AsSpan(8), mode); U32(b.AsSpan(16), size);
            U32(b.AsSpan(32), offset); U32(b.AsSpan(36), (uint)stored.Length); U32(b.AsSpan(40), dsize);
            b[44] = codec;
            U32(b.AsSpan(48), Crc.Jffs2(stored));
            stored.CopyTo(b, 56);
            Node(0xE002, b, 60, 64);
        }
        // a cleanmarker, as a freshly erased block starts
        var marker = new byte[12];
        U16(marker, 0x1985);
        U16(marker.AsSpan(2), 0x2003);
        U32(marker.AsSpan(4), 12);
        U32(marker.AsSpan(8), Crc.Jffs2(marker.AsSpan(0, 8)));
        o.Write(marker);
        foreach (var (parent, name, ino, path) in names)
        {
            var file = files.FirstOrDefault(f => f.Path == path);
            var link = links.FirstOrDefault(l => l.Path == path);
            byte type = file.Path != null ? (byte)8 : link.Path != null ? (byte)10 : (byte)4;
            Dirent(parent, name, 1, ino, type);
            if (type == 4) Inode(ino, 1, 0x41ED, 0, 0, [], 0, 0);
            else if (type == 10) { var t = Encoding.UTF8.GetBytes(link.Target); Inode(ino, 1, 0xA1FF, (uint)t.Length, 0, t, (uint)t.Length, 0); }
            else
            {
                uint version = 1;
                if (file.Bytes.Length == 0) Inode(ino, version, 0x81A4, 0, 0, [], 0, 0);
                for (int at = 0; at < file.Bytes.Length; at += 4096)
                {
                    var page = file.Bytes[at..Math.Min(file.Bytes.Length, at + 4096)];
                    // pages of the large file alternate zlib and rtime; others stay stored
                    bool large = path.EndsWith("large.conf", StringComparison.Ordinal);
                    var (stored, codec) = !large ? (page, (byte)0) : at / 4096 % 2 == 0 ? (Zlib(page), (byte)6) : (Rtime(page), (byte)2);
                    Inode(ino, version++, 0x81ED, (uint)file.Bytes.Length, (uint)at, stored, (uint)page.Length, codec);
                }
            }
        }
        // a file written, rewritten (a newer version of its only page), then a file deleted by a newer entry with inode 0
        var (rootFiles, next) = (1u, 100u);
        Dirent(rootFiles, "version.txt", 1, next, 8);
        Inode(next, 1, 0x81A4, 3, 0, "old"u8.ToArray(), 3, 0);
        Inode(next, 2, 0x81A4, 3, 0, "new"u8.ToArray(), 3, 0);
        Dirent(rootFiles, "gone.txt", 1, next + 1, 8);
        Inode(next + 1, 1, 0x81A4, 4, 0, "gone"u8.ToArray(), 4, 0);
        Dirent(rootFiles, "gone.txt", 2, 0, 8);
        // erased flash after the last node
        o.Write(Enumerable.Repeat((byte)0xFF, 4096).ToArray());
        return o.ToArray();
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Jffs2_keeps_the_newest_version_of_each_name_and_page(bool big)
    {
        var c = Containers.Open(Jffs2(big), "rootfs.jffs2", AnalysisLimits.Default, default, allFiles: true);
        Assert.Equal("jffs2", c.Kind);
        AssertTree(c, "version.txt 3");
        Assert.Equal("new", Encoding.ASCII.GetString(c.Items.Single(i => i.Name == "version.txt").Bytes));
        Assert.DoesNotContain(c.Entries!, e => e.Path == "gone.txt");
    }

    /// <summary>UBIFS nodes: a superblock in block 0, then inode, directory-entry and data nodes; block 2 holds stale copies.</summary>
    internal static byte[] Ubifs(int lebSize = 16384)
    {
        var (files, links) = Source();
        var (_, names) = Number([.. files.Select(f => f.Path), .. links.Select(l => l.Path)]);
        // block 1 onwards holds the live nodes, block 2 the stale ones
        var lebs = new List<MemoryStream> { new(), new(), new() };
        int live = 1;
        ulong seq = 1;
        void Node(int leb, byte type, byte[] body, ulong? sequence = null)
        {
            var o = lebs[leb];
            if (o.Length + 24 + body.Length > lebSize)
            {
                if (leb != live) throw new InvalidOperationException("stale block full");
                lebs.Add(o = new MemoryStream());
                live = lebs.Count - 1;
            }
            var n = new byte[24 + body.Length];
            BinaryPrimitives.WriteUInt32LittleEndian(n, 0x06101831);
            BinaryPrimitives.WriteUInt64LittleEndian(n.AsSpan(8), sequence ?? seq++);
            BinaryPrimitives.WriteUInt32LittleEndian(n.AsSpan(16), (uint)n.Length);
            n[20] = type;
            body.CopyTo(n, 24);
            BinaryPrimitives.WriteUInt32LittleEndian(n.AsSpan(4), Crc.Ubi(n.AsSpan(8)));
            o.Write(n);
            while (o.Length % 8 != 0) o.WriteByte(0);
        }
        byte[] Key(uint inum, uint type, uint low) { var k = new byte[16]; BinaryPrimitives.WriteUInt32LittleEndian(k, inum); BinaryPrimitives.WriteUInt32LittleEndian(k.AsSpan(4), type << 29 | low); return k; }
        void Ino(int leb, uint inum, uint mode, long size, byte[] data, uint links = 1, ulong? sequence = null)
        {
            var b = new byte[136 + data.Length];
            Key(inum, 0, 0).CopyTo(b, 0);
            BinaryPrimitives.WriteUInt64LittleEndian(b.AsSpan(24), (ulong)size);
            BinaryPrimitives.WriteUInt32LittleEndian(b.AsSpan(68), links);
            BinaryPrimitives.WriteUInt32LittleEndian(b.AsSpan(80), mode);
            BinaryPrimitives.WriteUInt32LittleEndian(b.AsSpan(88), (uint)data.Length);
            data.CopyTo(b, 136);
            Node(leb, 0, b, sequence);
        }
        void Dent(int leb, uint parent, string name, ulong inum, byte type, ulong? sequence = null)
        {
            var nb = Encoding.UTF8.GetBytes(name);
            var b = new byte[32 + nb.Length + 1];
            Key(parent, 2, (uint)name.GetHashCode() & 0x1FFFFFFF).CopyTo(b, 0);
            BinaryPrimitives.WriteUInt64LittleEndian(b.AsSpan(16), inum);
            b[25] = type;
            BinaryPrimitives.WriteUInt16LittleEndian(b.AsSpan(26), (ushort)nb.Length);
            nb.CopyTo(b, 32);
            Node(leb, 2, b, sequence);
        }
        void DataNode(int leb, uint inum, uint block, byte[] page, ushort codec, ulong? sequence = null)
        {
            var stored = codec switch { 2 => Deflate(page), 3 => ZstdPack(page), _ => page };
            var b = new byte[24 + stored.Length];
            Key(inum, 1, block).CopyTo(b, 0);
            BinaryPrimitives.WriteUInt32LittleEndian(b.AsSpan(16), (uint)page.Length);
            BinaryPrimitives.WriteUInt16LittleEndian(b.AsSpan(20), codec);
            stored.CopyTo(b, 24);
            Node(leb, 1, b, sequence);
        }
        // the superblock node: 4096 bytes, the logical block size at offset 36
        var sb = new byte[4096 - 24];
        BinaryPrimitives.WriteUInt32LittleEndian(sb.AsSpan(36 - 24), (uint)lebSize);
        Node(0, 6, sb);
        // stale nodes written first (lower sequence numbers) in block 2
        Ino(2, 1, 0x41ED, 0, []);
        foreach (var (parent, name, inum, path) in names)
        {
            var file = files.FirstOrDefault(f => f.Path == path);
            var link = links.FirstOrDefault(l => l.Path == path);
            byte type = file.Path != null ? (byte)0 : link.Path != null ? (byte)2 : (byte)1;
            Dent(live, parent, name, inum, type);
            if (type == 1) Ino(live, inum, 0x41ED, 0, []);
            else if (type == 2) Ino(live, inum, 0xA1FF, link.Target.Length, Encoding.UTF8.GetBytes(link.Target));
            else
            {
                Ino(live, inum, 0x81ED, file.Bytes.Length, []);
                // pages alternate deflate, Zstandard and stored
                for (int at = 0; at < file.Bytes.Length; at += 4096)
                    DataNode(live, inum, (uint)(at / 4096), file.Bytes[at..Math.Min(file.Bytes.Length, at + 4096)], (ushort)(at / 4096 % 3 == 2 ? 0 : at / 4096 % 3 == 1 ? 3 : 2));
            }
        }
        // version.txt: an old block in block 2 (lower sequence), the new one later; gone.txt deleted by a later entry with inode 0
        Ino(2, 200, 0x81A4, 3, [], sequence: 0);
        DataNode(2, 200, 0, "old"u8.ToArray(), 0, sequence: 0);
        Dent(2, 1, "version.txt", 200, 0, sequence: 0);
        DataNode(live, 200, 0, "new"u8.ToArray(), 0);
        Dent(live, 1, "gone.txt", 201, 0);
        Ino(live, 201, 0x81A4, 4, []);
        Dent(live, 1, "gone.txt", 0, 0);
        var image = new byte[lebs.Count * lebSize];
        image.AsSpan().Fill(0xFF);
        for (int i = 0; i < lebs.Count; i++) lebs[i].ToArray().CopyTo(image, i * lebSize);
        return image;
    }

    private static byte[] ZstdPack(byte[] page)
    {
        using var z = new ZstdSharp.Compressor();
        return z.Wrap(page).ToArray();
    }

    [Fact]
    public void Ubifs_keeps_the_newest_node_by_sequence_number()
    {
        var c = Containers.Open(Ubifs(), "rootfs.ubifs", AnalysisLimits.Default, default, allFiles: true);
        Assert.Equal("UBIFS", c.Kind);
        AssertTree(c, "version.txt 3");
        Assert.Equal("new", Encoding.ASCII.GetString(c.Items.Single(i => i.Name == "version.txt").Bytes));
    }

    /// <summary>
    /// A UBI image of 64 KiB erase blocks: the volume table (two copies), a dynamic "rootfs" volume holding <paramref name="rootfs"/>,
    /// a static "kernel" volume, one block rewritten (the older copy has a lower sequence number) and one erased block.
    /// </summary>
    internal static byte[] Ubi(byte[] rootfs, byte[] kernel)
    {
        const int Peb = 65536, VidAt = 64, DataAt = 128, LebSize = Peb - DataAt;
        var blocks = new List<byte[]>();
        ulong seq = 10;
        byte[] Ec()
        {
            var b = new byte[Peb];
            b.AsSpan().Fill(0xFF);
            "UBI#"u8.CopyTo(b);
            b[4] = 1;
            BinaryPrimitives.WriteUInt64BigEndian(b.AsSpan(8), 1);
            BinaryPrimitives.WriteUInt32BigEndian(b.AsSpan(16), VidAt);
            BinaryPrimitives.WriteUInt32BigEndian(b.AsSpan(20), DataAt);
            BinaryPrimitives.WriteUInt32BigEndian(b.AsSpan(24), 0x1234);
            b.AsSpan(28, 32).Clear();
            BinaryPrimitives.WriteUInt32BigEndian(b.AsSpan(60), Crc.Ubi(b.AsSpan(0, 60)));
            return b;
        }
        void Leb(uint volume, uint lnum, byte type, ReadOnlySpan<byte> data, uint usedEbs = 0, ulong? sequence = null)
        {
            var b = Ec();
            var v = b.AsSpan(VidAt, 64);
            v.Clear();
            "UBI!"u8.CopyTo(v);
            v[4] = 1; v[5] = type;
            BinaryPrimitives.WriteUInt32BigEndian(v[8..], volume);
            BinaryPrimitives.WriteUInt32BigEndian(v[12..], lnum);
            if (type == 2) { BinaryPrimitives.WriteUInt32BigEndian(v[20..], (uint)data.Length); BinaryPrimitives.WriteUInt32BigEndian(v[24..], usedEbs); }
            BinaryPrimitives.WriteUInt64BigEndian(v[40..], sequence ?? seq++);
            BinaryPrimitives.WriteUInt32BigEndian(v[60..], Crc.Ubi(v[..60]));
            data.CopyTo(b.AsSpan(DataAt));
            blocks.Add(b);
        }
        var table = new byte[128 * 172];
        void Record(int id, string name, byte type, int reserved)
        {
            var r = table.AsSpan(id * 172, 172);
            BinaryPrimitives.WriteUInt32BigEndian(r, (uint)reserved);
            BinaryPrimitives.WriteUInt32BigEndian(r[4..], 1);
            r[12] = type;
            BinaryPrimitives.WriteUInt16BigEndian(r[14..], (ushort)name.Length);
            Encoding.ASCII.GetBytes(name).CopyTo(r[16..]);
            BinaryPrimitives.WriteUInt32BigEndian(r[168..], Crc.Ubi(r[..168]));
        }
        Record(0, "rootfs", 1, (rootfs.Length + LebSize - 1) / LebSize + 2);
        Record(1, "kernel", 2, 1);
        Leb(0x7FFFEFFF, 0, 1, table);
        Leb(0x7FFFEFFF, 1, 1, table);
        int count = (rootfs.Length + LebSize - 1) / LebSize;
        // block 0 written once before (stale), then the real copy
        Leb(0, 0, 1, new byte[LebSize], sequence: 1);
        for (int i = 0; i < count; i++) Leb(0, (uint)i, 1, rootfs.AsSpan(i * LebSize, Math.Min(LebSize, rootfs.Length - i * LebSize)));
        Leb(1, 0, 2, kernel, usedEbs: 1);
        blocks.Add(Ec()); // erased: no volume header
        return [.. blocks.SelectMany(b => b)];
    }

    [Fact]
    public void Ubi_rebuilds_volumes_that_open_as_ubifs()
    {
        var ubifs = Ubifs();
        var kernel = Isa("mips32be.elf");
        var c = Containers.Open(Ubi(ubifs, kernel), "flash.ubi", AnalysisLimits.Default, default);
        Assert.Equal("UBI", c.Kind);
        Assert.Equal(["rootfs", "kernel"], c.Entries!.Select(e => e.Path));
        Assert.Equal(kernel, c.Items.Single(i => i.Name == "kernel").Bytes);
        var rootfs = c.Items.Single(i => i.Name == "rootfs").Bytes;
        Assert.Equal(ubifs, rootfs.AsSpan(0, ubifs.Length).ToArray());
        AssertTree(Containers.Open(rootfs, "rootfs", AnalysisLimits.Default, default, allFiles: true), "version.txt 3");
    }

    [Fact]
    [FuzzEntry(typeof(Jffs2Reader), typeof(UbiReader), typeof(UbifsReader), typeof(Crc))]
    public void Fuzzed_flash_images_never_throw_unexpectedly()
    {
        foreach (var (name, seed) in new[] { ("x.jffs2", Jffs2(false)), ("x.jffs2", Jffs2(true)), ("x.ubifs", Ubifs()), ("x.ubi", Ubi(Ubifs(), Isa("armbe.elf"))) })
        {
            var failures = FormatFuzz.Run(seed, b => { try { Containers.Open(b, name, AnalysisLimits.Default, default, allFiles: true); } catch (ToolError) { } }, 300);
            Assert.True(failures.Count == 0, name + ": " + string.Join("\n", failures.Take(20)));
        }
    }
}
