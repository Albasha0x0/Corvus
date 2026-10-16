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
        // read from a stream, the same listing and bytes
        var streamed = new SquashfsReader().Open(new MemoryStream(image), "rootfs.squashfs", true, AnalysisLimits.Default, default)!;
        Assert.Equal(c.Entries!.Select(e => e.Path), streamed.Entries!.Select(e => e.Path));
        Assert.Equal(c.Items.Select(i => Blob.Sha256(i.Bytes)), streamed.Items.Select(i => Blob.Sha256(i.Bytes)));
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
