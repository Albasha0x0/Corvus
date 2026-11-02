using System.Formats.Tar;
using System.IO.Compression;
using Corvus.Core;

namespace Corvus.Tests;

/// <summary>tar and compressed tars as containers: entries listed, binaries extracted, bombs stopped at the limits.</summary>
public sealed class ArchiveReaderTests
{
    internal static byte[] TarGz(params (string Name, byte[] Bytes)[] files)
    {
        using var output = new MemoryStream();
        using (var gzip = new GZipStream(output, CompressionLevel.Fastest, leaveOpen: true))
        using (var tar = new TarWriter(gzip, TarEntryFormat.Ustar, leaveOpen: true))
            foreach (var (name, bytes) in files)
                tar.WriteEntry(new UstarTarEntry(TarEntryType.RegularFile, name) { DataStream = new MemoryStream(bytes) });
        return output.ToArray();
    }

    [Fact]
    public void Tar_gz_lists_entries_and_extracts_binaries()
    {
        var data = TarGz(("package/lib/app.dll", File.ReadAllBytes(Env.FixturePath)), ("package/README.md", "# hello"u8.ToArray()));
        var some = Containers.Open(data, "pkg.tgz", AnalysisLimits.Default, default);
        Assert.Equal("tar.gz", some.Kind);
        Assert.Equal(["package/lib/app.dll", "package/README.md"], some.Entries!.Select(e => e.Path));
        Assert.Equal("package/lib/app.dll", Assert.Single(some.Items).Name);
        Assert.Equal(2, Containers.Open(data, "pkg.tgz", AnalysisLimits.Default, default, allFiles: true).Items.Count);
    }

    [Fact]
    public void One_oversize_entry_stays_listed_and_the_others_are_read()
    {
        var data = TarGz(("big.bin", new byte[2 * 1024 * 1024]), ("small.txt", "ok"u8.ToArray()));
        var opened = Containers.Open(data, "mixed.tgz", new AnalysisLimits { MaxItemBytes = 1024 * 1024 }, default, allFiles: true);
        Assert.Equal(["big.bin", "small.txt"], opened.Entries!.Select(e => e.Path));
        Assert.Equal("small.txt", Assert.Single(opened.Items).Name);
        var note = Assert.Single(opened.Notes);
        Assert.Contains("1,048,576-byte", note);
        Assert.Contains("big.bin", note);
        Assert.StartsWith("item limit:", note);
    }

    [Fact]
    public void The_total_limit_leaves_every_later_entry_listed_and_unread()
    {
        var data = TarGz(("a.bin", new byte[600]), ("b.bin", new byte[600]), ("c.txt", "ok"u8.ToArray()));
        var opened = Containers.Open(data, "total.tgz", new AnalysisLimits { MaxTotalBytes = 1000 }, default, allFiles: true);
        Assert.Equal(["a.bin"], opened.Items.Select(i => i.Name));
        Assert.All(opened.Entries!.Skip(1), e => Assert.Equal("over the total limit; not read", e.Detail));
        var note = Assert.Single(opened.Notes, n => n.StartsWith("total limit:"));
        Assert.Contains("2 file(s) not extracted (from b.bin)", note);
    }

    [Fact]
    public void The_item_count_limit_counts_the_entries_cut()
    {
        var data = TarGz(("a.txt", "a"u8.ToArray()), ("b.txt", "b"u8.ToArray()), ("c.txt", "c"u8.ToArray()));
        var opened = Containers.Open(data, "count.tgz", new AnalysisLimits { MaxItems = 1 }, default, allFiles: true);
        Assert.Equal(3, opened.Entries!.Count);
        var note = Assert.Single(opened.Notes, n => n.StartsWith("item count limit:"));
        Assert.Contains("1-file; 2 file(s) not extracted", note);
        Assert.DoesNotContain(AnalysisLimits.RaiseVariable, note);
    }

    [Fact]
    public void The_reached_note_names_the_limit_value_count_cut_and_the_variable()
    {
        var note = AnalysisLimits.Reached("total", "4,096-byte", 3, "x.bin");
        Assert.Equal("total limit: 4,096-byte; 3 file(s) not extracted (from x.bin). " + AnalysisLimits.RaiseVariable
            + " raises it (megabytes of the item cap, up to 65536).", note);
    }

    [Theory]
    [InlineData(null, 512L, null)]
    [InlineData("1024", 1024L, null)]
    [InlineData("256", 256L, null)]
    [InlineData("65536", 65536L, null)]
    [InlineData("0", 512L, "0")]
    [InlineData("70000", 512L, "70000")]
    [InlineData("lots", 512L, "lots")]
    public void The_item_cap_variable_is_parsed_and_a_rejected_value_is_named(string? raw, long megabytes, string? rejected)
    {
        var (bytes, bad) = AnalysisLimits.ParseCap(raw);
        Assert.Equal(megabytes << 20, bytes);
        Assert.Equal(rejected, bad);
    }

    [Fact]
    public void Hundreds_of_notes_show_the_first_twenty_and_one_counting_line()
    {
        var notes = Enumerable.Range(0, 300).Select(i => $"entry{i}: damaged").ToList();
        var report = new Corvus.Services.Analysis.UnpackService.UnpackReport("a.tgz", "archive", "out", [], notes);
        var text = Corvus.Tools.ContainerText.Unpack(report, 0, 10);
        Assert.Equal(20, text.Split((char)10).Count(l => l.StartsWith("Note: entry")));
        Assert.Contains("Note: 280 more not shown (", text);
        Assert.Equal(21, Corvus.Tools.ContainerText.CappedNotes(notes).Count);
    }

    /// <summary>
    /// a.txt, b.txt, c.txt; b.txt's size field holds a base-256 value past 2^63,
    /// its checksum kept valid.
    /// </summary>
    private static byte[] TarWithOverflowingSize()
    {
        var output = new MemoryStream();
        using (var tar = new TarWriter(output, TarEntryFormat.Ustar, leaveOpen: true))
            foreach (var name in new[] { "a.txt", "b.txt", "c.txt" })
                tar.WriteEntry(new UstarTarEntry(TarEntryType.RegularFile, name) { DataStream = new MemoryStream(System.Text.Encoding.UTF8.GetBytes(name + " data")) });
        var data = output.ToArray();
        const int header = 1024;
        data[header + 124] = 0x80;
        for (int i = 125; i < 136; i++) data[header + i] = 0xFF;
        for (int i = 148; i < 156; i++) data[header + i] = (byte)' ';
        int sum = 0;
        for (int i = 0; i < 512; i++) sum += data[header + i];
        System.Text.Encoding.ASCII.GetBytes(Convert.ToString(sum, 8).PadLeft(6, '0') + "\0 ").CopyTo(data, header + 148);
        return data;
    }

    [Fact]
    public void A_tar_entry_whose_size_overflows_is_named_damaged_and_the_others_are_listed()
    {
        var contents = Containers.Open(TarWithOverflowingSize(), "app.tar", AnalysisLimits.Default, default, allFiles: true);
        Assert.Equal(["a.txt", "b.txt", "c.txt"], contents.Entries!.Select(e => e.Path));
        Assert.Equal("damaged (OverflowException at 0x400); size unknown", contents.Entries![1].Detail);
        Assert.Equal(["a.txt", "c.txt"], contents.Items.Select(i => i.Name));
        Assert.Contains("b.txt: damaged (OverflowException at 0x400)", contents.Notes);
    }

    [Fact]
    public void A_zip_entry_whose_sizes_overflow_its_data_is_named_damaged_and_the_others_are_extracted()
    {
        var output = new MemoryStream();
        using (var zip = new ZipArchive(output, ZipArchiveMode.Create, leaveOpen: true))
            foreach (var name in new[] { "a.txt", "b.txt", "c.txt" })
                using (var s = zip.CreateEntry(name, CompressionLevel.NoCompression).Open()) s.Write(System.Text.Encoding.UTF8.GetBytes(name + " data"));
        var data = output.ToArray();
        // The second central directory record: both sizes far past the file.
        int record = Enumerable.Range(0, data.Length - 4).Where(i => data.AsSpan(i, 4).SequenceEqual((ReadOnlySpan<byte>)[0x50, 0x4B, 1, 2])).ElementAt(1);
        BitConverter.GetBytes(0x7FFFFFF0u).CopyTo(data, record + 20);
        BitConverter.GetBytes(0x7FFFFFF0u).CopyTo(data, record + 24);
        var contents = Containers.Open(data, "app.zip", AnalysisLimits.Default, default, allFiles: true);
        Assert.Equal(["a.txt", "c.txt"], contents.Items.Select(i => i.Name));
        Assert.Contains("b.txt: damaged (A local file header is corrupt)", contents.Notes);
    }

    [Fact]
    [FuzzEntry(typeof(Core.Archives.ArchiveReader))]
    public void Fuzzed_archives_never_throw_past_a_tool_error()
    {
        var files = new[] { ("lib/app.dll", ContainerFixtures.Module("App")), ("README.md", "# hello"u8.ToArray()) };
        var tgz = TarGz(files);
        using var plain = new MemoryStream();
        using (var gzip = new GZipStream(new MemoryStream(tgz), CompressionMode.Decompress)) gzip.CopyTo(plain);
        var reader = new Core.Archives.ArchiveReader();
        void Read(byte[] b)
        {
            if (!reader.Accepts(b, "x")) return;
            try { reader.Open(b, "x", allFiles: true, AnalysisLimits.Default, default); }
            catch (ToolError) { }
        }
        var failures = FormatFuzz.Run(tgz, Read, 300);
        failures.AddRange(FormatFuzz.Run(plain.ToArray(), Read, 300));
        Assert.True(failures.Count == 0, string.Join("\n", failures.Take(10)));
    }
}
