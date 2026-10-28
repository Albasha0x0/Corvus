using System.Formats.Tar;
using System.IO.Compression;
using Corvus.Core;

namespace Corvus.Tests;

/// <summary>tar and compressed tars as containers: entries listed, binaries extracted, bombs stopped at the limits.</summary>
public sealed class ArchiveReaderTests
{
    private static byte[] TarGz(params (string Name, byte[] Bytes)[] files)
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
    public void A_bomb_stops_at_the_item_limit_naming_the_entry()
    {
        var data = TarGz(("zeros.bin", new byte[2 * 1024 * 1024]));
        var error = Assert.Throws<ToolError>(() => Containers.Open(data, "bomb.tgz", new AnalysisLimits { MaxItemBytes = 1024 * 1024 }, default, allFiles: true));
        Assert.Equal(ErrorCode.LimitExceeded, error.Code);
        Assert.Contains("zeros.bin", error.Message);
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
    public void A_zip_entry_whose_sizes_overflow_its_data_is_named_and_the_others_are_extracted()
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
        Assert.Contains(contents.Notes, n => n.StartsWith("Skipped b.txt:", StringComparison.Ordinal));
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
