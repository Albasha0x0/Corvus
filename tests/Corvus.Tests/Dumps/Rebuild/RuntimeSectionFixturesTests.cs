using Corvus.Native.Dump;
using Corvus.Native.Pe;

namespace Corvus.Tests;

/// <summary>Images with sections written at run time, read back through the PE and minidump readers.</summary>
public sealed class RuntimeSectionFixturesTests
{
    private static readonly byte[] Written = [0x48, 0x31, 0xC0, 0xC3, 0x90, 0x90, 0x90, 0x90];

    private static PeFile FileOf(RuntimeSectionImage image) =>
        PeFile.FromBytes(File.ReadAllBytes(Path.Combine(image.ImageDir, image.ModuleName)));

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void A_section_without_raw_data_is_zero_in_the_file_and_written_in_the_dump(bool is64)
    {
        using var dir = new TempDir();
        var image = RuntimeSectionFixtures.NoRawData(dir, is64, ".rt", Written, executable: true, writable: false);
        var section = FileOf(image).Sections.First(s => s.Name == ".rt");
        using var dump = MinidumpFile.Open(image.DumpPath);
        var read = new byte[Written.Length];

        Assert.Equal(0u, section.RawSize);
        Assert.Equal((uint)Written.Length, section.VirtualSize);
        Assert.Equal(image.SectionRva, section.Rva);
        Assert.Equal(read.Length, dump.ReadMemory(image.Base + image.SectionRva, read));
        Assert.Equal(Written, read);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void A_short_raw_data_section_has_its_tail_written_in_the_dump(bool is64)
    {
        byte[] raw = [0x55, 0x8B, 0xEC, 0xC3];
        using var dir = new TempDir();
        var image = RuntimeSectionFixtures.ShortRawData(dir, is64, ".rt", raw, Written);
        var section = FileOf(image).Sections.First(s => s.Name == ".rt");
        using var dump = MinidumpFile.Open(image.DumpPath);
        var read = new byte[raw.Length + Written.Length];

        Assert.True(section.RawSize > 0);
        Assert.True(section.RawSize < section.VirtualSize + 0x200);
        Assert.Equal((uint)read.Length, section.VirtualSize);
        Assert.Equal(read.Length, dump.ReadMemory(image.Base + image.SectionRva, read));
        Assert.Equal([.. raw, .. Written], read);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void Pages_left_out_are_absent_from_the_dump(bool is64)
    {
        using var dir = new TempDir();
        var image = RuntimeSectionFixtures.NoRawData(dir, is64, ".rt", new byte[0x2000], true, false, [3]);
        using var dump = MinidumpFile.Open(image.DumpPath);
        var one = new byte[1];

        Assert.Equal(0x2000u, image.SectionRva);
        Assert.Equal(1, dump.ReadMemory(image.Base + image.SectionRva, one));
        Assert.Equal(0, dump.ReadMemory(image.Base + image.SectionRva + 0x1000, one));
    }
}
