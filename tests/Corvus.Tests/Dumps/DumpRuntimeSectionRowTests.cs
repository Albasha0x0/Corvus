using Corvus.Services;

namespace Corvus.Tests;

public sealed class DumpRuntimeSectionRowTests
{
    private static MinidumpService.CheckedModule Row(string dump)
    {
        using var service = new MinidumpService();
        return service.Modules(dump, null, 0, 10).Rows.Single();
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void A_module_with_a_section_without_raw_data_names_it_on_its_row(bool is64)
    {
        using var dir = new TempDir();
        var image = RuntimeSectionFixtures.NoRawData(dir, is64, ".rt", Enumerable.Repeat((byte)0x90, 0x40).ToArray(), true, false);
        var section = Assert.Single(Row(image.DumpPath).RuntimeSections!);
        Assert.Equal(".rt", section.Name);
        Assert.Equal("code", section.Kind);
        Assert.Equal(0x40, section.BytesWritten);
    }

    [Fact]
    public void A_module_without_one_has_an_empty_runtime_section_list()
    {
        using var dir = new TempDir();
        var image = RuntimeSectionFixtures.NoRawData(dir, true, ".rt", new byte[0x40], false, true);
        Assert.Empty(Row(image.DumpPath).RuntimeSections!);
    }

    [Theory]
    [InlineData(true, false)]
    [InlineData(false, false)]
    [InlineData(true, true)]
    [InlineData(false, true)]
    public void A_module_whose_header_page_is_not_captured_has_unknown_runtime_sections(bool is64, bool shortRaw)
    {
        using var dir = new TempDir();
        var tail = Enumerable.Repeat((byte)0x90, 0x40).ToArray();
        var image = shortRaw
            ? RuntimeSectionFixtures.ShortRawData(dir, is64, ".rt", [0x55, 0xC3], tail, uncapturedPages: [0])
            : RuntimeSectionFixtures.NoRawData(dir, is64, ".rt", tail, true, false, [0]);
        Assert.Null(Row(image.DumpPath).RuntimeSections);
    }
}
