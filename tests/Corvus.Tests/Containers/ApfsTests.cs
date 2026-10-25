using System.Security.Cryptography;
using System.Text;
using Corvus.Core;
using Corvus.Core.Firmware;
using Corvus.Native.Providers;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>APFS containers, raw and inside Apple disk images.</summary>
public sealed class ApfsTests(ITestOutputHelper output)
{
    private static byte[] Bytes(int n, int seed)
    {
        var b = new byte[n];
        new Random(seed).NextBytes(b);
        return b;
    }

    private static readonly byte[] Text = Encoding.ASCII.GetBytes(string.Concat(Enumerable.Range(0, 12000).Select(i => $"ledger entry {i}\n")));

    private static ApfsWriter Container() => new ApfsWriter()
        .File("Ledger.app/Contents/Info.plist", Encoding.ASCII.GetBytes("<plist/>"))
        .File("Ledger.app/Contents/MacOS/Ledger", Bytes(300_000, 1), fragments: 5)
        .Sparse("Ledger.app/Contents/Resources/sparse.bin", Bytes(ApfsWriter.BlockSize + 100, 2), holeBlocks: 3)
        .Link("Applications", "/Applications")
        .HardLink("Ledger.app/Contents/Resources/info-copy.plist", "Ledger.app/Contents/Info.plist")
        .Compressed("Notes/zlib.txt", Text[..2000], 3)
        .Compressed("Notes/zlib-blocks.txt", Text, 4)
        .Compressed("Notes/lzvn.txt", Text[..2000], 7)
        .Compressed("Notes/lzvn-blocks.txt", Text, 8)
        .Compressed("Notes/lzfse.txt", Text[..2000], 11)
        .Compressed("Notes/lzfse-blocks.txt", Text, 12)
        .Fifo("Notes/pipe")
        .File("Notes/résumé.txt", [4]);

    private static Dictionary<string, (long Size, string? Detail, byte[]? Bytes)> Listing(ContainerContents c)
    {
        var items = c.Items.ToDictionary(i => i.Name, i => i.Bytes);
        return c.Entries!.ToDictionary(e => e.Path, e => (e.Size, e.Detail, items.GetValueOrDefault(e.Path)));
    }

    private static void AssertContainer(ContainerContents c, string prefix = "")
    {
        var l = Listing(c);
        Assert.Equal(Encoding.ASCII.GetBytes("<plist/>"), l[prefix + "Ledger.app/Contents/Info.plist"].Bytes);
        Assert.Equal(Bytes(300_000, 1), l[prefix + "Ledger.app/Contents/MacOS/Ledger"].Bytes);
        var sparse = Bytes(ApfsWriter.BlockSize + 100, 2);
        Assert.Equal([.. sparse[..ApfsWriter.BlockSize], .. new byte[3 * ApfsWriter.BlockSize], .. sparse[ApfsWriter.BlockSize..]], l[prefix + "Ledger.app/Contents/Resources/sparse.bin"].Bytes!);
        Assert.Equal("symbolic link to /Applications", l[prefix + "Applications"].Detail);
        Assert.Equal(Encoding.ASCII.GetBytes("<plist/>"), l[prefix + "Ledger.app/Contents/Resources/info-copy.plist"].Bytes);
        foreach (var name in new[] { "zlib", "lzvn", "lzfse" })
        {
            Assert.Equal(Text[..2000], l[$"{prefix}Notes/{name}.txt"].Bytes);
            Assert.Equal(Text, l[$"{prefix}Notes/{name}-blocks.txt"].Bytes);
        }
        Assert.Equal("decmpfs LZVN", l[prefix + "Notes/lzvn-blocks.txt"].Detail);
        Assert.Equal(("FIFO (named pipe)", (byte[]?)null), (l[prefix + "Notes/pipe"].Detail, l[prefix + "Notes/pipe"].Bytes));
        Assert.Equal([4], l[prefix + "Notes/résumé.txt"].Bytes);
        Assert.Equal(13, l.Count(e => e.Key.StartsWith(prefix, StringComparison.Ordinal)));
    }

    [Fact]
    public void A_container_lists_its_files_links_hard_links_FIFOs_and_compressed_files()
    {
        var c = Containers.Open(Container().Build(), "ledger.apfs", AnalysisLimits.Default, default, allFiles: true);
        Assert.Equal("apfs", c.Kind);
        AssertContainer(c);
        Assert.Contains("APFS volume 'Ledger': 11 files, 5 directories, 1 symbolic links", c.Notes);
        Assert.True(Text.Length > 2 * 65536);
    }

    [Fact]
    public void A_tree_of_several_leaves_lists_every_file()
    {
        var w = new ApfsWriter();
        for (int i = 0; i < 300; i++) w.File($"entries/entry-{i:D3}.txt", Encoding.ASCII.GetBytes($"entry {i}"));
        var c = Containers.Open(w.Build(), "many.apfs", AnalysisLimits.Default, default, allFiles: true);
        Assert.Equal(300, c.Entries!.Count);
        Assert.Equal("entry 299", Encoding.ASCII.GetString(c.Items.Single(i => i.Name == "entries/entry-299.txt").Bytes));
    }

    [Fact]
    public void Several_volumes_list_under_their_names_and_an_encrypted_one_is_named()
    {
        var image = Container().Volume("Data").File("report.txt", [7]).Volume("Vault", encrypted: true).File("secret.txt", [8]).Build();
        var c = Containers.Open(image, "ledger.apfs", AnalysisLimits.Default, default, allFiles: true);
        AssertContainer(c, "Ledger/");
        Assert.Equal([7], c.Items.Single(i => i.Name == "Data/report.txt").Bytes);
        Assert.DoesNotContain(c.Entries!, e => e.Path.Contains("secret", StringComparison.Ordinal));
        Assert.Contains("APFS volume 'Vault' is encrypted; its files are not read", c.Notes);
    }

    [Fact]
    public void A_disk_image_opens_its_APFS_partition_in_place()
    {
        var dmg = UdifWriter.Build([("disk image (Apple_APFS : 0)", Container().Build())], 0x80000005);
        var c = Containers.Open(dmg, "Ledger.dmg", AnalysisLimits.Default, default, allFiles: true);
        Assert.Equal("dmg (apfs)", c.Kind);
        AssertContainer(c);
    }

    [Fact]
    public void A_container_read_from_a_stream_equals_one_read_from_bytes()
    {
        using var stream = new MemoryStream(Container().Build(), writable: false);
        AssertContainer(new ApfsReader().Open(stream, "ledger.apfs", true, AnalysisLimits.Default, default)!);
    }

    [Fact]
    [FuzzEntry(typeof(ApfsReader))]
    public void Fuzzed_containers_never_throw_unexpectedly()
    {
        var seed = new ApfsWriter().File("a/b.txt", [1, 2, 3]).Link("l", "/x").Compressed("c.txt", Text[..3000], 3).Fifo("p").Build();
        var failures = FormatFuzz.Run(seed, b => { try { Containers.Open(b, "x.apfs", AnalysisLimits.Default, default, allFiles: true); } catch (ToolError) { } }, 300);
        Assert.True(failures.Count == 0, string.Join("\n", failures.Take(20)));
    }

    private static readonly string Empty = Convert.ToHexStringLower(SHA256.HashData([]));

    // 7-Zip extracts each file of the volume at the top of the output folder. It extracts decmpfs files empty, so those are
    // checked for their declared size; for a volume with snapshots it extracts a snapshot's tree, so that volume's current
    // tree is checked by its file count.
    [Trait("Speed", "Slow")]
    [RequiresRealDataFact("CORVUS_APFS_DIR", "CORVUS_ARCHIVE_LISTER")]
    public void Real_containers_hold_the_files_7_Zip_extracts()
    {
        var tool = ExternalTools.Locate(ExternalTools.ArchiveLister)!.Value.Path;
        var limits = new AnalysisLimits { MaxItemBytes = 1L << 30, MaxTotalBytes = 1L << 34, MaxItems = 100_000 };
        var images = Directory.GetFiles(RealData.Path("CORVUS_APFS_DIR")).Order(StringComparer.Ordinal).ToList();
        Assert.NotEmpty(images);
        using var dir = new TempDir();
        var problems = new List<string>();
        foreach (var image in images)
        {
            var sw = System.Diagnostics.Stopwatch.StartNew();
            ContainerContents c;
            try { c = Containers.Open(File.ReadAllBytes(image), Path.GetFileName(image), limits, default, allFiles: true); }
            catch (ToolError ex) { output.WriteLine($"{Path.GetFileName(image)}: {ex.Code} {ex.Message}"); continue; }
            long ms = sw.ElapsedMilliseconds;
            output.WriteLine($"{Path.GetFileName(image)}: {c.Kind}, {c.Entries?.Count} entries in {ms} ms; {string.Join(" | ", c.Notes.Take(6))}");
            var target = dir.File(Path.GetFileNameWithoutExtension(image));
            var run = ExternalTools.Run(tool, ExternalTools.Arguments(ExternalTools.ArchiveLister, "extract", ("file", image), ("output", target)), TimeSpan.FromMinutes(10), 1 << 20, default);
            if (run.ExitCode != 0 || !Directory.Exists(target)) { output.WriteLine($"  7-Zip: exit {run.ExitCode}"); continue; }
            var items = c.Items.ToDictionary(i => i.Name, i => i.Bytes);
            if (c.Notes.FirstOrDefault(n => n.Contains(" snapshots ", StringComparison.Ordinal)) is { } volume)
            {
                long files = long.Parse(System.Text.RegularExpressions.Regex.Match(volume, @"([\d,]+) files").Groups[1].Value.Replace(",", ""));
                if (files != items.Count) problems.Add($"{Path.GetFileName(image)}: {items.Count} files of {files}");
                continue;
            }
            var expected = Directory.EnumerateFileSystemEntries(target, "*", SearchOption.AllDirectories)
                .Select(p => new FileInfo(p)).Where(f => f.LinkTarget != null || !f.Attributes.HasFlag(FileAttributes.Directory))
                .ToDictionary(f => Path.GetRelativePath(target, f.FullName).Replace('\\', '/'), f => f.LinkTarget != null ? "link" : Convert.ToHexStringLower(SHA256.HashData(File.ReadAllBytes(f.FullName))));
            var ours = c.Entries!.ToDictionary(e => e.Path, e => (e.Detail, Hash: e.Detail?.StartsWith("symbolic link", StringComparison.Ordinal) == true ? "link"
                : Convert.ToHexStringLower(SHA256.HashData(items.GetValueOrDefault(e.Path) ?? []))));
            foreach (var (path, hash) in expected.OrderBy(p => p.Key, StringComparer.Ordinal))
                if (!ours.TryGetValue(path, out var mine)) problems.Add($"{Path.GetFileName(image)}: {path} missing");
                else if (mine.Detail?.StartsWith("decmpfs", StringComparison.Ordinal) == true && hash == Empty)
                {
                    if (items[path].Length != c.Entries!.Single(e => e.Path == path).Size || items[path].Length == 0) problems.Add($"{Path.GetFileName(image)}: {path} decodes short");
                }
                else if (mine.Hash != hash) problems.Add($"{Path.GetFileName(image)}: {path} differs ({mine.Detail})");
            foreach (var path in ours.Keys.Except(expected.Keys).Order(StringComparer.Ordinal))
                problems.Add($"{Path.GetFileName(image)}: {path} extra ({ours[path].Detail})");
        }
        foreach (var p in problems.Take(80)) output.WriteLine(p);
        Assert.Empty(problems);
    }
}
