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
