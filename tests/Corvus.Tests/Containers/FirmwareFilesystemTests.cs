using System.IO.Compression;
using System.Text;
using Corvus.Core;
using Corvus.Core.Firmware;

namespace Corvus.Tests;

/// <summary>
/// Firmware filesystems read in process: images built by the Linux tools that write each format (FirmwareFixtures/build.sh)
/// list the same files as the source tree (and as unsquashfs -lls), with the same bytes; streamed reads equal in-memory ones.
/// </summary>
public sealed class FirmwareFilesystemTests
{
    internal static string FixtureDir => Path.Combine(AppContext.BaseDirectory, "Containers", "FirmwareFixtures");

    /// <summary>A fixture image, ungzipped.</summary>
    internal static byte[] FsFixture(string name)
    {
        using var z = new GZipStream(File.OpenRead(Path.Combine(FixtureDir, name + ".gz")), CompressionMode.Decompress);
        var o = new MemoryStream();
        z.CopyTo(o);
        return o.ToArray();
    }

    /// <summary>The source tree's regular files: path and size (tree.list).</summary>
    internal static List<string> Tree() => [.. File.ReadAllLines(Path.Combine(FixtureDir, "tree.list")).Where(l => l.Length > 0)];

    internal static byte[] LargeConf()
    {
        var sb = new StringBuilder();
        for (int i = 0; i < 6000; i++) sb.Append($"option entry_{i:D5} value_{i * 7 % 9973:D5}\n");
        return Encoding.ASCII.GetBytes(sb.ToString());
    }

    internal static byte[] Isa(string name) => File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory, "Engines", "IsaFixtures", name));

    private static List<string> Files(ContainerContents c) =>
        [.. c.Entries!.Where(e => e.Detail == null).Select(e => $"{e.Path} {e.Size}").Order(StringComparer.Ordinal)];

    /// <summary>Same files and bytes as the source tree (with <paramref name="extra"/> files); the symbolic link with its target.</summary>
    internal static void AssertTree(ContainerContents c, params string[] extra)
    {
        Assert.Equal(Tree().Concat(extra).Order(StringComparer.Ordinal), Files(c));
        var items = c.Items.ToDictionary(i => i.Name, i => i.Bytes);
        Assert.Equal(LargeConf(), items["etc/config/large.conf"]);
        Assert.Equal(Isa("mips32be.elf"), items["bin/busybox"]);
        Assert.Equal(Isa("armbe.elf"), items["lib/libuci.so"]);
        Assert.Equal("root:x:0:0:root:/root:/bin/sh\n", Encoding.ASCII.GetString(items["etc/passwd"]));
        Assert.Contains(c.Entries!, e => e.Path == "sbin/init" && e.Detail == "symbolic link to ../bin/busybox");
    }

    public static TheoryData<string> Compressors => new() { "gzip", "lzma", "lzo", "lz4", "xz", "zstd" };

    [Theory]
    [MemberData(nameof(Compressors))]
    public void Squashfs_lists_what_unsquashfs_lists(string compressor)
    {
        var image = FsFixture($"squashfs-{compressor}.img");
        var c = Containers.Open(image, "rootfs.squashfs", AnalysisLimits.Default, default, allFiles: true);
        Assert.Equal("squashfs", c.Kind);
        AssertTree(c);
        // unsquashfs -lls: every file and link, by path and size
        var reference = File.ReadAllLines(Path.Combine(FixtureDir, $"squashfs-{compressor}.img.list"))
            .Where(l => l[0] is '-' or 'l')
            .Select(l => l.Split(' ', StringSplitOptions.RemoveEmptyEntries))
            .Select(f => $"{f[5]["squashfs-root/".Length..]} {(f[0][0] == 'l' ? "-> " + f[7] : f[2])}").Order(StringComparer.Ordinal);
        var ours = c.Entries!.Select(e => $"{e.Path} {(e.Detail is { } d ? "-> " + d["symbolic link to ".Length..] : e.Size.ToString())}").Order(StringComparer.Ordinal);
        Assert.Equal(reference, ours);
        // the permission bits unsquashfs prints (rwx triplets)
        var modes = File.ReadAllLines(Path.Combine(FixtureDir, $"squashfs-{compressor}.img.list")).Where(l => l[0] is '-' or 'l')
            .Select(l => l.Split(' ', StringSplitOptions.RemoveEmptyEntries))
            .ToDictionary(f => f[5]["squashfs-root/".Length..], f => Convert.ToString(f[0][1..10].Select((ch, i) => ch == '-' ? 0 : 1 << (8 - i)).Sum(), 8));
        Assert.All(c.Entries!, e => Assert.Equal(modes[e.Path], e.Mode));
        // read from a stream, the same listing and bytes
        var streamed = new SquashfsReader().Open(new MemoryStream(image), "rootfs.squashfs", true, AnalysisLimits.Default, default)!;
        Assert.Equal(c.Entries!.Select(e => e.Path), streamed.Entries!.Select(e => e.Path));
        Assert.Equal(c.Items.Select(i => Blob.Sha256(i.Bytes)), streamed.Items.Select(i => Blob.Sha256(i.Bytes)));
    }

    /// <summary>
    /// A squashfs 4.0 image with stored (uncompressed) metadata blocks whose symbolic link and file inodes start 8 and 4 bytes
    /// before the end of a metadata block, so each inode's common header continues in the next block.
    /// </summary>
    internal static byte[] SquashfsWithHeadersAcrossBlocks(byte[] content)
    {
        const int Meta = 8192, BlockSize = 4096, DataAt = 96;
        var inodes = new byte[3 * Meta];
        void Header(int at, int type, int number)
        {
            BitConverter.TryWriteBytes(inodes.AsSpan(at), (ushort)type);
            BitConverter.TryWriteBytes(inodes.AsSpan(at + 2), (ushort)(type == 3 ? 0x1FF : 0x1ED));
            BitConverter.TryWriteBytes(inodes.AsSpan(at + 12), number);
        }
        int linkAt = Meta - 8, fileAt = 2 * Meta - 4;
        var target = "../bin/busybox"u8.ToArray();
        Header(linkAt, 3, 2);
        BitConverter.TryWriteBytes(inodes.AsSpan(linkAt + 16), 1);
        BitConverter.TryWriteBytes(inodes.AsSpan(linkAt + 20), target.Length);
        target.CopyTo(inodes, linkAt + 24);
        Header(fileAt, 2, 3);
        BitConverter.TryWriteBytes(inodes.AsSpan(fileAt + 16), DataAt);
        BitConverter.TryWriteBytes(inodes.AsSpan(fileAt + 20), uint.MaxValue);
        BitConverter.TryWriteBytes(inodes.AsSpan(fileAt + 28), content.Length);
        BitConverter.TryWriteBytes(inodes.AsSpan(fileAt + 32), content.Length | 0x1000000);
        // the directory listing: one header per inode block, then its entries
        var dir = new MemoryStream();
        void Entry(int block, int offset, int type, string name)
        {
            foreach (var v in new[] { 0, block * (Meta + 2), 2 }) dir.Write(BitConverter.GetBytes(v));
            dir.Write(BitConverter.GetBytes((ushort)offset));
            dir.Write(BitConverter.GetBytes((short)0));
            dir.Write(BitConverter.GetBytes((ushort)type));
            dir.Write(BitConverter.GetBytes((ushort)(name.Length - 1)));
            dir.Write(Encoding.ASCII.GetBytes(name));
        }
        Entry(0, linkAt, 3, "init");
        Entry(1, fileAt % Meta, 2, "data.bin");
        Header(0, 1, 1);
        BitConverter.TryWriteBytes(inodes.AsSpan(20), 2);
        BitConverter.TryWriteBytes(inodes.AsSpan(24), (ushort)(dir.Length + 3));
        static byte[] Stored(byte[] data, int size)
        {
            var o = new MemoryStream();
            for (int at = 0; at < data.Length; at += size)
            {
                int n = Math.Min(size, data.Length - at);
                o.Write(BitConverter.GetBytes((ushort)(n | 0x8000)));
                o.Write(data, at, n);
            }
            return o.ToArray();
        }
        var inodeTable = Stored(inodes, Meta);
        var dirTable = Stored(dir.ToArray(), Meta);
        long inodeAt = DataAt + content.Length, dirAt = inodeAt + inodeTable.Length, end = dirAt + dirTable.Length;
        var sb = new byte[96];
        "hsqs"u8.CopyTo(sb);
        BitConverter.TryWriteBytes(sb.AsSpan(4), 3);
        BitConverter.TryWriteBytes(sb.AsSpan(12), BlockSize);
        BitConverter.TryWriteBytes(sb.AsSpan(20), (ushort)1);
        BitConverter.TryWriteBytes(sb.AsSpan(22), (ushort)12);
        BitConverter.TryWriteBytes(sb.AsSpan(26), (ushort)1);
        BitConverter.TryWriteBytes(sb.AsSpan(28), (ushort)4);
        BitConverter.TryWriteBytes(sb.AsSpan(40), end);
        foreach (var at in new[] { 48, 56, 80, 88 }) BitConverter.TryWriteBytes(sb.AsSpan(at), end);
        BitConverter.TryWriteBytes(sb.AsSpan(64), inodeAt);
        BitConverter.TryWriteBytes(sb.AsSpan(72), dirAt);
        return [.. sb, .. content, .. inodeTable, .. dirTable];
    }

    [Fact]
    public void Squashfs_inode_headers_continue_in_the_next_metadata_block()
    {
        var content = Encoding.ASCII.GetBytes(new string('x', 100));
        var c = Containers.Open(SquashfsWithHeadersAcrossBlocks(content), "rootfs.squashfs", AnalysisLimits.Default, default, allFiles: true);
        Assert.DoesNotContain(c.Notes, n => n.Contains("unreadable", StringComparison.Ordinal));
        Assert.Contains(c.Entries!, e => e.Path == "init" && e.Detail == "symbolic link to ../bin/busybox");
        Assert.Equal(content, c.Items.Single(i => i.Name == "data.bin").Bytes);
    }

    [Theory]
    [InlineData("cramfs-le.img", "cramfs")]
    [InlineData("cramfs-be.img", "cramfs")]
    [InlineData("cpio-newc.cpio", "cpio")]
    [InlineData("cpio-odc.cpio", "cpio")]
    [InlineData("cpio-bin.cpio", "cpio")]
    public void Image_lists_the_source_tree(string fixture, string kind)
    {
        var image = FsFixture(fixture);
        var c = Containers.Open(image, fixture, AnalysisLimits.Default, default, allFiles: true);
        Assert.Equal(kind, c.Kind);
        AssertTree(c);
        var streamed = Containers.ReaderFor(image, fixture)!.Open(new MemoryStream(image), fixture, true, AnalysisLimits.Default, default)!;
        Assert.Equal(c.Items.Select(i => Blob.Sha256(i.Bytes)), streamed.Items.Select(i => Blob.Sha256(i.Bytes)));
    }

    /// <summary>A file over 1 MiB is classified by its start: a large program is extracted, a large data file only listed.</summary>
    [Fact]
    public void Large_files_are_classified_by_their_start()
    {
        var elf = new byte[3 << 20];
        Isa("mips32be.elf").CopyTo(elf, 0);
        var text = Encoding.ASCII.GetBytes(string.Concat(Enumerable.Repeat("log line\n", 300_000)));
        var o = new MemoryStream();
        void Entry(string n, byte[] b, uint mode)
        {
            o.Write(Encoding.ASCII.GetBytes($"070701{0:X8}{mode:X8}{0:X8}{0:X8}{1:X8}{0:X8}{b.Length:X8}{0:X8}{0:X8}{0:X8}{0:X8}{n.Length + 1:X8}{0:X8}{n}\0"));
            while (o.Length % 4 != 0) o.WriteByte(0);
            o.Write(b);
            while (o.Length % 4 != 0) o.WriteByte(0);
        }
        Entry("bin/large", elf, 0x81ED);
        Entry("var/log.txt", text, 0x81A4);
        Entry("TRAILER!!!", [], 0);
        var c = Containers.Open(o.ToArray(), "big.cpio", AnalysisLimits.Default, default);
        Assert.Equal(["bin/large", "var/log.txt"], c.Entries!.Select(e => e.Path));
        Assert.Equal(elf, Assert.Single(c.Items).Bytes);
    }

    [Theory]
    [InlineData("ext2.img", "ext2")]
    [InlineData("ext4.img", "ext4")]
    public void Ext_lists_the_source_tree(string fixture, string kind) => Image_lists_the_source_tree(fixture, kind);

    [Theory]
    [InlineData("fat12.img", "FAT12")]
    [InlineData("fat16.img", "FAT16")]
    [InlineData("fat32.img", "FAT32")]
    public void Fat_lists_the_source_tree_with_long_names(string fixture, string kind)
    {
        var image = FsFixture(fixture);
        var c = Containers.Open(image, fixture, AnalysisLimits.Default, default, allFiles: true);
        Assert.Equal(kind, c.Kind);
        Assert.Equal(Tree().Append("Long File Name.txt 30").Order(StringComparer.Ordinal), Files(c));
        Assert.Equal(LargeConf(), c.Items.Single(i => i.Name == "etc/config/large.conf").Bytes);
        Assert.Equal(Isa("mips32be.elf"), c.Items.Single(i => i.Name == "bin/busybox").Bytes);
    }

    [Fact]
    [FuzzEntry(typeof(ExtReader), typeof(FatReader))]
    public void Fuzzed_ext_and_fat_never_throw_unexpectedly()
    {
        foreach (var f in new[] { "ext2.img", "ext4.img", "fat12.img", "fat32.img" })
        {
            var failures = FormatFuzz.Run(FsFixture(f), b => { try { Containers.Open(b, f, AnalysisLimits.Default, default, allFiles: true); } catch (ToolError) { } }, 300);
            Assert.True(failures.Count == 0, f + ": " + string.Join("\n", failures.Take(20)));
        }
    }

    [Fact]
    [FuzzEntry(typeof(CramfsReader))]
    public void Fuzzed_cramfs_never_throws_unexpectedly()
    {
        foreach (var f in new[] { "cramfs-le.img", "cramfs-be.img" })
        {
            var failures = FormatFuzz.Run(FsFixture(f), b => { try { Containers.Open(b, f, AnalysisLimits.Default, default, allFiles: true); } catch (ToolError) { } }, 300);
            Assert.True(failures.Count == 0, string.Join("\n", failures.Take(20)));
        }
    }

    [Fact]
    [FuzzEntry(typeof(SquashfsReader), typeof(FsCodec))]
    public void Fuzzed_squashfs_never_throws_unexpectedly()
    {
        foreach (var c in new[] { "gzip", "lzo" })
        {
            var failures = FormatFuzz.Run(FsFixture($"squashfs-{c}.img"), b => { try { Containers.Open(b, "x.squashfs", AnalysisLimits.Default, default, allFiles: true); } catch (ToolError) { } }, 300);
            Assert.True(failures.Count == 0, string.Join("\n", failures.Take(20)));
        }
    }
}
