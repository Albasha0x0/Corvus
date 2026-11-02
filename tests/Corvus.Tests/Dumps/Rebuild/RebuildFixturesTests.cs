using System.Buffers.Binary;
using Corvus.Native.Pe;

namespace Corvus.Tests;

/// <summary>The synthetic PE builder read back through the PE reader.</summary>
public sealed class RebuildFixturesTests
{
    private static PeSpec Spec(bool is64) => new(is64,
    [
        new SectionSpec(".text", 0x60000020, [0x90, 0x90, 0xC3, 0xCC]),
        new SectionSpec(".data", 0xC0000040, new byte[0x20]),
    ],
    [new PointerSite(".data", 0x08, 0x1000), new PointerSite(".data", 0x10, 0x1002)]);

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void A_built_image_reads_back_with_its_sections_and_relocations(bool is64)
    {
        var spec = Spec(is64);
        var pe = PeFile.FromBytes(RebuildFixtures.Pe(spec));

        Assert.Equal(is64, pe.Is64Bit);
        Assert.Equal(spec.Base, pe.ImageBase);
        Assert.Equal([".text", ".data", ".reloc"], pe.Sections.Select(s => s.Name));
        Assert.Equal([0x1000u, 0x2000u, 0x3000u], pe.Sections.Select(s => s.Rva));
        Assert.Equal([0x2008u, 0x2010u], pe.RelocationRvas);
    }

    [Fact]
    public void The_mapped_form_holds_each_section_at_its_virtual_address()
    {
        var spec = Spec(true);
        var mapped = RebuildFixtures.Mapped(RebuildFixtures.Pe(spec));

        Assert.Equal(new byte[] { 0x90, 0x90, 0xC3, 0xCC }, mapped.AsSpan(0x1000, 4).ToArray());
        Assert.Equal(spec.Base + 0x1000, BinaryPrimitives.ReadUInt64LittleEndian(mapped.AsSpan(0x2008)));
        Assert.Equal((byte)'M', mapped[0]);
    }
}
