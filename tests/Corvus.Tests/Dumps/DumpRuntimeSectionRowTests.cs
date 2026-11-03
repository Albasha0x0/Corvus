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
    public void A_module_without_one_has_no_runtime_sections()
    {
        using var dir = new TempDir();
        var image = RuntimeSectionFixtures.NoRawData(dir, true, ".rt", new byte[0x40], false, true);
        Assert.Null(Row(image.DumpPath).RuntimeSections);
    }
}
