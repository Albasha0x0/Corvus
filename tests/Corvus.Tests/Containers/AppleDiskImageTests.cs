using System.Security.Cryptography;
using System.Text;
using Corvus.Core;
using Corvus.Core.Firmware;
using Corvus.Native.Providers;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>Apple disk images (UDIF) and HFS+ volumes, built by <see cref="HfsPlusWriter"/> and <see cref="UdifWriter"/>.</summary>
public sealed class AppleDiskImageTests(ITestOutputHelper output)
{
    private const uint Raw = 1, Adc = 0x80000004, Zlib = 0x80000005, Bzip2 = 0x80000006, Lzfse = 0x80000007;

    private static byte[] Bytes(int n, int seed)
    {
        var b = new byte[n];
        new Random(seed).NextBytes(b);
        return b;
    }

    private static readonly byte[] Text = Encoding.ASCII.GetBytes(string.Concat(Enumerable.Range(0, 9000).Select(i => $"ledger entry {i}\n")));

    private static HfsPlusWriter Volume() => new HfsPlusWriter()
        .File("Ledger.app/Contents/Info.plist", Encoding.ASCII.GetBytes("<plist/>"))
        .File("Ledger.app/Contents/MacOS/Ledger", Bytes(300_000, 1))
        .File("Ledger.app/Contents/Resources/split.bin", Bytes(11 * HfsPlusWriter.BlockSize - 100, 2), fragments: 11)
        .Link("Applications", "/Applications")
        .HardLink("Ledger.app/Contents/Resources/shared.dat", "iNode42", Bytes(5000, 3))
        .HardLink("Ledger.app/Contents/Resources/shared-copy.dat", "iNode42", Bytes(5000, 3))
        .Compressed("Ledger.app/Contents/Resources/inline.txt", Encoding.ASCII.GetBytes(string.Concat(Enumerable.Repeat("balance ", 400))), 3)
        .Compressed("Ledger.app/Contents/Resources/blocks.txt", Text, 4)
        .File("Notes/a/b.txt", [1, 2, 3])
        .File("Notes/résumé.txt", [4]);

    private static Dictionary<string, (long Size, string? Detail, byte[]? Bytes)> Listing(ContainerContents c)
    {
        var items = c.Items.ToDictionary(i => i.Name, i => i.Bytes);
        return c.Entries!.ToDictionary(e => e.Path, e => (e.Size, e.Detail, items.GetValueOrDefault(e.Path)));
    }

    private static void AssertVolume(ContainerContents c)
    {
        var l = Listing(c);
        Assert.Equal(Encoding.ASCII.GetBytes("<plist/>"), l["Ledger.app/Contents/Info.plist"].Bytes);
        Assert.Equal(Bytes(300_000, 1), l["Ledger.app/Contents/MacOS/Ledger"].Bytes);
        Assert.Equal(Bytes(11 * HfsPlusWriter.BlockSize - 100, 2), l["Ledger.app/Contents/Resources/split.bin"].Bytes);
        Assert.Equal("symbolic link to /Applications", l["Applications"].Detail);
        Assert.Equal(Bytes(5000, 3), l["Ledger.app/Contents/Resources/shared.dat"].Bytes);
        Assert.Equal(Bytes(5000, 3), l["Ledger.app/Contents/Resources/shared-copy.dat"].Bytes);
        Assert.Equal(string.Concat(Enumerable.Repeat("balance ", 400)), Encoding.ASCII.GetString(l["Ledger.app/Contents/Resources/inline.txt"].Bytes!));
        Assert.Equal(Text, l["Ledger.app/Contents/Resources/blocks.txt"].Bytes);
        Assert.Equal([1, 2, 3], l["Notes/a/b.txt"].Bytes);
        // Decomposed names read as composed ones.
        Assert.Equal([4], l["Notes/résumé.txt"].Bytes);
        Assert.DoesNotContain(l.Keys, k => k.Contains("iNode", StringComparison.Ordinal) || k.Contains("Private", StringComparison.Ordinal));
        Assert.Equal(10, l.Count);
    }

    [Fact]
    public void An_HFS_volume_lists_its_files_links_hard_links_and_compressed_files()
    {
        var c = Containers.Open(Volume().Build(), "ledger.hfs", AnalysisLimits.Default, default, allFiles: true);
        Assert.Equal("hfs+", c.Kind);
        AssertVolume(c);
        Assert.Contains(c.Notes, n => n.StartsWith("hfs+ volume 'Ledger'", StringComparison.Ordinal));
    }

    [Fact]
    public void A_catalog_of_several_leaves_lists_every_file()
    {
        var w = new HfsPlusWriter();
        for (int i = 0; i < 300; i++) w.File($"entries/entry-{i:D3}.txt", Encoding.ASCII.GetBytes($"entry {i}"));
        var c = Containers.Open(w.Build(), "many.hfs", AnalysisLimits.Default, default, allFiles: true);
        Assert.Equal(300, c.Entries!.Count);
        Assert.Equal("entry 299", Encoding.ASCII.GetString(c.Items.Single(i => i.Name == "entries/entry-299.txt").Bytes));
    }

    [Fact]
    public void A_disk_image_opens_its_HFS_partition_in_place_through_every_chunk_method()
    {
        var volume = Volume().Build();
        var dmg = UdifWriter.Build([("Protective Master Boot Record (MBR : 0)", new byte[512]), ("disk image (Apple_HFS : 1)", volume)], Raw, Zlib, Bzip2, Adc);
        var c = Containers.Open(dmg, "Ledger.dmg", AnalysisLimits.Default, default, allFiles: true);
        Assert.Equal("dmg (hfs+)", c.Kind);
        AssertVolume(c);
        Assert.StartsWith("UDIF disk image, 2 partitions", c.Notes[0], StringComparison.Ordinal);
        Assert.Contains("chunks: ADC, bzip2, raw, zero, zlib", c.Notes[0], StringComparison.Ordinal);
        Assert.Contains(c.Notes, n => n.StartsWith("partition 0 (Protective Master Boot Record (MBR : 0), 512 bytes)", StringComparison.Ordinal));
    }

    [Fact]
    public void A_disk_image_read_from_a_stream_equals_one_read_from_bytes()
    {
        var dmg = UdifWriter.Build([("disk image (Apple_HFS : 0)", Volume().Build())], Zlib);
        using var stream = new MemoryStream(dmg, writable: false);
        var streamed = new UdifReader().Open(stream, "Ledger.dmg", true, AnalysisLimits.Default, default)!;
        AssertVolume(streamed);
    }

    [Fact]
    public void A_disk_image_reads_its_LZFSE_chunks()
    {
        var dmg = UdifWriter.Build([("disk image (Apple_HFS : 0)", Volume().Build())], Lzfse, Zlib);
        var c = Containers.Open(dmg, "Ledger.dmg", AnalysisLimits.Default, default, allFiles: true);
        AssertVolume(c);
        Assert.Contains("chunks: LZFSE, zlib", c.Notes[0], StringComparison.Ordinal);
    }

    [Fact]
    public void Files_compressed_with_LZVN_or_LZFSE_read_from_the_attribute_and_the_resource_fork()
    {
        var small = LzfseTests.LedgerText(2000);
        var large = Encoding.ASCII.GetBytes(string.Concat(Enumerable.Range(0, 12000).Select(i => $"ledger entry {i}\n")));
        // The attribute of lzvn-apple.txt is Apple's encoding (bvxn) of the same text.
        var c = Containers.Open(new HfsPlusWriter()
            .Compressed("lzvn.txt", small, 7)
            .Compressed("lzvn-blocks.txt", large, 8)
            .Compressed("lzfse.txt", small, 11)
            .Compressed("lzfse-blocks.txt", large, 12)
            .Compressed("lzvn-apple.txt", small, 11, LzfseTests.Fixture("small.lzfse"))
            .Build(), "ledger.hfs", AnalysisLimits.Default, default, allFiles: true);
        var l = Listing(c);
        Assert.True(large.Length > 2 * 65536);
        foreach (var name in new[] { "lzvn.txt", "lzfse.txt", "lzvn-apple.txt" }) Assert.Equal(small, l[name].Bytes);
        foreach (var name in new[] { "lzvn-blocks.txt", "lzfse-blocks.txt" }) Assert.Equal(large, l[name].Bytes);
        Assert.Equal("decmpfs LZVN", l["lzvn-blocks.txt"].Detail);
    }

    [Fact]
    public void ADC_back_references_copy_earlier_output()
    {
        // "abc", then a two-byte reference (length 3, distance 3) and a three-byte one (length 4, distance 6).
        byte[] input = [0x82, (byte)'a', (byte)'b', (byte)'c', 0x00, 0x02, 0x40, 0x00, 0x05];
        var output = new byte[10];
        UdifReader.UdifStream.Adc(input, output);
        Assert.Equal("abcabcabca", Encoding.ASCII.GetString(output));
    }

    [Fact]
    public void A_file_extent_past_the_volume_is_named_and_the_other_files_are_kept()
    {
        var image = new HfsPlusWriter().File("good.txt", [1, 2]).Misplaced("bad.bin", 9000, 1_000_000).Build();
        var c = Containers.Open(image, "damaged.hfs", AnalysisLimits.Default, default, allFiles: true);
        Assert.Equal([1, 2], c.Items.Single(i => i.Name == "good.txt").Bytes);
        Assert.Contains(c.Notes, n => n.StartsWith("bad.bin: unreadable (an extent at block 1,000,000 passes the", StringComparison.Ordinal));
    }

    [Fact]
    [FuzzEntry(typeof(HfsPlusReader), typeof(UdifReader))]
    public void Fuzzed_HFS_volumes_and_disk_images_never_throw_unexpectedly()
    {
        var hfs = new HfsPlusWriter().File("a/b.txt", [1, 2, 3]).Link("l", "/x").Compressed("c.txt", Text[..3000], 3).Build();
        var dmg = UdifWriter.Build([("disk image (Apple_HFS : 0)", hfs)], Zlib, Raw);
        foreach (var (seed, name) in new[] { (hfs, "x.hfs"), (dmg, "x.dmg") })
        {
            var failures = FormatFuzz.Run(seed, b => { try { Containers.Open(b, name, AnalysisLimits.Default, default, allFiles: true); } catch (ToolError) { } }, 300);
            Assert.True(failures.Count == 0, name + ": " + string.Join("\n", failures.Take(20)));
        }
    }

    // 7-Zip extracts every file of the image's HFS+ volume under a folder named for the volume.
    [Trait("Speed", "Slow")]
    [RequiresRealDataFact("CORVUS_DMG_DIR", "CORVUS_ARCHIVE_LISTER")]
    public void Real_disk_images_hold_the_files_7_Zip_extracts()
    {
        var tool = ExternalTools.Locate(ExternalTools.ArchiveLister)!.Value.Path;
        var limits = new AnalysisLimits { MaxItemBytes = 1L << 30, MaxTotalBytes = 1L << 34, MaxItems = 100_000 };
        var images = Directory.GetFiles(RealData.Path("CORVUS_DMG_DIR"), "*.dmg").Order(StringComparer.Ordinal).ToList();
        Assert.NotEmpty(images);
        using var dir = new TempDir();
        foreach (var image in images)
        {
            var sw = System.Diagnostics.Stopwatch.StartNew();
            var c = Containers.Open(File.ReadAllBytes(image), Path.GetFileName(image), limits, default, allFiles: true);
            long ms = sw.ElapsedMilliseconds;
            var target = dir.File(Path.GetFileNameWithoutExtension(image));
            var run = ExternalTools.Run(tool, ExternalTools.Arguments(ExternalTools.ArchiveLister, "extract", ("file", image), ("output", target)), TimeSpan.FromMinutes(10), 1 << 20, default);
            Assert.True(run.ExitCode == 0, run.Stderr + run.Text);
            var root = Directory.GetDirectories(target).Single();
            var expected = Directory.EnumerateFileSystemEntries(root, "*", SearchOption.AllDirectories)
                .Select(p => new FileInfo(p)).Where(f => f.LinkTarget != null || !f.Attributes.HasFlag(FileAttributes.Directory))
                .Select(f => (Path.GetRelativePath(root, f.FullName).Replace('\\', '/').Normalize(NormalizationForm.FormC), f))
                .ToDictionary(p => p.Item1, p => p.f.LinkTarget != null ? "link" : Convert.ToHexStringLower(SHA256.HashData(File.ReadAllBytes(p.f.FullName))));
            var items = c.Items.ToDictionary(i => i.Name, i => i.Bytes);
            var ours = c.Entries!.ToDictionary(e => e.Path, e => e.Detail?.StartsWith("symbolic link", StringComparison.Ordinal) == true ? "link" : Convert.ToHexStringLower(SHA256.HashData(items[e.Path])));
            output.WriteLine($"{Path.GetFileName(image)}: {c.Kind}, {ours.Count} entries in {ms} ms");
            Assert.Equal(expected.OrderBy(p => p.Key, StringComparer.Ordinal), ours.OrderBy(p => p.Key, StringComparer.Ordinal));
            Remove(target);
        }
    }

    // 7-Zip keeps the volume's read-only modes as read-only attributes, which block deletion.
    private static void Remove(string folder)
    {
        foreach (var path in Directory.EnumerateFileSystemEntries(folder, "*", new EnumerationOptions { RecurseSubdirectories = true, AttributesToSkip = 0 }))
            try { File.SetAttributes(path, FileAttributes.Normal); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
        Directory.Delete(folder, recursive: true);
    }
}
