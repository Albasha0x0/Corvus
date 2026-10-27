using System.IO.Compression;
using System.Text;
using Corvus.Core;
using Corvus.Core.Disks;

namespace Corvus.Tests;

/// <summary>Optical disc images (ISO 9660, Joliet, UDF) and virtual disks (VHD fixed and dynamic, VHDX) with MBR / GPT partitions, NTFS and FAT volumes.</summary>
public sealed class DiskImageTests
{
    private static byte[] Fixture(string name)
    {
        using var z = new GZipStream(File.OpenRead(Path.Combine(AppContext.BaseDirectory, "Containers", "DiskFixtures", name + ".gz")), CompressionMode.Decompress);
        var o = new MemoryStream();
        z.CopyTo(o);
        return o.ToArray();
    }

    private static ContainerContents Open(string name) => Containers.Open(Fixture(name), name, AnalysisLimits.Default, default, allFiles: true);

    private static List<string> Paths(ContainerContents c) => [.. c.Entries!.Select(e => $"{e.Path} {e.Size}").Order(StringComparer.Ordinal)];

    [Fact]
    public void Disc_images_list_their_tree_as_7zip_does()
    {
        // 7-Zip 24 lists the same names and sizes for each image.
        Assert.Equal(["DOCS/AFOLDE~1/QUARTE~1.TXT 11", "DOCS/SETUP.ZIP 139", "README.TXT 19"], Paths(Open("iso9660.iso")));
        string[] tree = ["docs/a folder with a long name/Quarterly Report (final).txt 11", "docs/setup.zip 139", "readme.txt 19"];
        Assert.Equal(tree, Paths(Open("joliet.iso")));
        var udf = Open("udf.iso");
        Assert.Equal("UDF", udf.Kind);
        Assert.Equal(tree, Paths(udf));
        Assert.Equal("hello from the disc", Encoding.ASCII.GetString(udf.Items.Single(i => i.Name == "readme.txt").Bytes));
    }

    [Fact]
    public void A_vhdx_disk_gives_the_files_of_its_ntfs_and_fat_partitions()
    {
        var c = Open("disk-gpt.vhdx");
        Assert.Equal("VHDX", c.Kind);
        Assert.Equal(["partition1/docs/a folder with a long name/Quarterly Report (final).txt 11", "partition1/docs/setup.zip 122",
            "partition1/docs/setup.zip:Zone.Identifier 26", "partition1/packed/repeated.txt 20000", "partition1/readme.txt 21", "partition2/fat-readme.txt 21"], Paths(c));
        // LZNT1.
        Assert.Equal(new string('A', 20000), Encoding.ASCII.GetString(c.Items.Single(i => i.Name == "partition1/packed/repeated.txt").Bytes));
        Assert.Contains("ZoneId=3", Encoding.ASCII.GetString(c.Items.Single(i => i.Name == "partition1/docs/setup.zip:Zone.Identifier").Bytes));
        Assert.Contains(c.Notes, n => n.Contains("volume 'CORVUS'", StringComparison.Ordinal));
    }

    [Fact]
    public void Fixed_and_dynamic_vhd_disks_read_the_same_partitions()
    {
        foreach (var name in new[] { "disk-mbr.vhd", "disk-mbr-dynamic.vhd" })
        {
            var c = Open(name);
            Assert.Equal(["partition2/fat-readme.txt 21"], Paths(c));
            Assert.Contains(c.Notes, n => n.Contains("partition 1 (NTFS / exFAT): no file system", StringComparison.Ordinal));
        }
        Assert.StartsWith("VHD (dynamic)", Open("disk-mbr-dynamic.vhd").Kind, StringComparison.Ordinal);
    }

    [Fact]
    public void A_streamed_disk_reads_like_one_in_memory()
    {
        var bytes = Fixture("disk-gpt.vhdx");
        using var s = new MemoryStream(bytes, writable: false);
        var streamed = new VirtualDiskReader().Open(s, "d.vhdx", allFiles: false, AnalysisLimits.Default, default)!;
        Assert.Equal(Paths(Open("disk-gpt.vhdx")), Paths(streamed));
    }

    [Fact]
    [FuzzEntry(typeof(Iso9660Reader), typeof(VirtualDiskReader), typeof(NtfsReader), typeof(DiskVolumes))]
    public void Fuzzed_disk_images_never_throw_past_a_tool_error()
    {
        // The NTFS volume alone, read out of the VHDX's first partition.
        var volume = new byte[8 << 20];
        using (var disk = DiskStream.Open(Core.Firmware.FsSource.Of(Fixture("disk-gpt.vhdx"), "d"))!)
        {
            disk.Position = 1 << 20;
            disk.ReadExactly(volume);
        }
        foreach (var (name, seed) in new[] { ("a.iso", Fixture("joliet.iso")), ("u.iso", Fixture("udf.iso")), ("v.vhd", Fixture("disk-mbr-dynamic.vhd")), ("n.img", volume) })
        {
            var failures = FormatFuzz.Run(seed, b =>
            {
                try { Containers.Open(b, name, AnalysisLimits.Default, default, allFiles: true); } catch (ToolError) { }
            }, 100);
            Assert.True(failures.Count == 0, name + ": " + string.Join("\n", failures.Take(20)));
        }
    }
}
