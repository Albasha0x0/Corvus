using Corvus.Native.Dump;
using Corvus.Native.Dump.Rebuild;
using Corvus.Native.Pe;

namespace Corvus.Tests;

public sealed class RuntimeSectionsTests
{
    private static IReadOnlyList<RuntimeSection> Run(RuntimeSectionImage image)
    {
        using var dump = MinidumpFile.Open(image.DumpPath);
        var target = dump.Modules.First(m => m.Base == image.Base);
        var captured = CapturedImageReader.Read(dump, new RebuildTarget(image.ModuleName, target.Base, target.Size, ModuleOrigin.Listed), CancellationToken.None)!;
        var file = PeFile.FromBytes(File.ReadAllBytes(Path.Combine(image.ImageDir, image.ModuleName)));
        return RuntimeSections.Find(captured.Image, captured, file);
    }

    private static byte[] Tail(int length, byte fill = 0x90) => Enumerable.Repeat(fill, length).ToArray();

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void A_section_without_raw_data_written_in_memory_is_reported(bool is64)
    {
        using var dir = new TempDir();
        var image = RuntimeSectionFixtures.NoRawData(dir, is64, ".rt", Tail(0x40), false, false);
        var found = Assert.Single(Run(image));
        Assert.Equal(".rt", found.Name);
        Assert.Equal(image.SectionRva, found.Rva);
        Assert.Equal(0u, found.RawSize);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void A_written_tail_is_reported_with_its_byte_count(bool is64)
    {
        using var dir = new TempDir();
        var image = RuntimeSectionFixtures.ShortRawData(dir, is64, ".rt", [0x55, 0xC3], Tail(0x300));
        var found = Assert.Single(Run(image));
        // Raw data is padded to 0x200, so 0x302 mapped bytes leave 0x102 past it.
        Assert.Equal(0x102, found.WrittenBytes);
        Assert.Equal(0, found.UnknownBytes);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void An_all_zero_tail_is_not_reported(bool is64)
    {
        using var dir = new TempDir();
        var image = RuntimeSectionFixtures.NoRawData(dir, is64, ".rt", Tail(0x40, 0), false, true);
        Assert.Empty(Run(image));
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void Pages_not_captured_are_counted_as_unknown(bool is64)
    {
        using var dir = new TempDir();
        var probe = RuntimeSectionFixtures.NoRawData(dir, is64, ".rt", Tail(0x2000), false, true);
        int page = (int)(probe.SectionRva / 0x1000);
        var image = RuntimeSectionFixtures.NoRawData(dir, is64, ".rt", Tail(0x2000), false, true, [page + 1]);
        var found = Assert.Single(Run(image));
        Assert.Equal(0x1000, found.WrittenBytes);
        Assert.Equal(0x1000, found.UnknownBytes);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void A_writable_executable_section_is_code(bool is64)
    {
        using var dir = new TempDir();
        var image = RuntimeSectionFixtures.NoRawData(dir, is64, ".rt", Tail(0x40), true, true);
        Assert.True(Assert.Single(Run(image)).IsCode);
    }
}
