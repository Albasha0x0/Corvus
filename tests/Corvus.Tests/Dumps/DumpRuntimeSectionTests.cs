using Corvus.Services;

namespace Corvus.Tests;

/// <summary>The changes view gives one summary row for a section written at run time.</summary>
public sealed class DumpRuntimeSectionTests
{
    private static byte[] Tail(int length) => Enumerable.Repeat((byte)0x90, length).ToArray();

    private static IReadOnlyList<MinidumpService.ModuleChange> Rows(RuntimeSectionImage image)
    {
        using var service = new MinidumpService();
        return service.Changes(image.DumpPath, image.ImageDir, image.ModuleName, 0, 1000, CancellationToken.None).Rows;
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void A_section_without_raw_data_gets_one_summary_row(bool is64)
    {
        using var dir = new TempDir();
        var image = RuntimeSectionFixtures.NoRawData(dir, is64, ".rt", Tail(0x300), true, false);

        var row = Assert.Single(Rows(image), r => r.Kind == "section");

        Assert.Equal(".rt", row.Section);
        Assert.Equal($"0x{image.SectionRva:X}", row.Rva);
        Assert.StartsWith("no raw data in the file; 768 of ", row.Description);
        Assert.EndsWith("bytes written at run time", row.Description);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void A_written_tail_gets_one_summary_row_with_its_byte_count(bool is64)
    {
        using var dir = new TempDir();
        var image = RuntimeSectionFixtures.ShortRawData(dir, is64, ".rt", [0x55, 0xC3], Tail(0x300));

        var row = Assert.Single(Rows(image), r => r.Kind == "section");

        Assert.StartsWith("raw data ends at 0x", row.Description);
        Assert.EndsWith("; 258 bytes past it written", row.Description);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void Uncaptured_bytes_are_named_on_the_summary_row(bool is64)
    {
        using var dir = new TempDir();
        var probe = RuntimeSectionFixtures.NoRawData(dir, is64, ".rt", Tail(0x2000), false, true);
        int page = (int)(probe.SectionRva / 0x1000);
        var image = RuntimeSectionFixtures.NoRawData(dir, is64, ".rt", Tail(0x2000), false, true, [page + 1]);

        var row = Assert.Single(Rows(image), r => r.Kind == "section");

        Assert.EndsWith("; 4096 bytes not captured", row.Description);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void The_summary_row_comes_before_the_section_rows(bool is64)
    {
        using var dir = new TempDir();
        var image = RuntimeSectionFixtures.NoRawData(dir, is64, ".rt", Tail(0x300), true, false);

        var rows = Rows(image).Where(r => r.Section == ".rt").ToList();

        Assert.Equal("section", rows[0].Kind);
    }
}
