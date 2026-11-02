using System.Buffers.Binary;
using Corvus.Native.Dump;
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

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void A_built_image_lists_its_imports_and_exports(bool is64)
    {
        var spec = Spec(is64) with
        {
            Exports = [new ExportSpec("Zeta", 0x1002), new ExportSpec("Alpha", 0x1000)],
            Imports = [new ImportSpec("one.dll", ["Open", "Read"]), new ImportSpec("two.dll", ["Close"])],
        };
        var built = RebuildFixtures.Build(spec);
        var pe = PeFile.FromBytes(built.Bytes);
        uint width = is64 ? 8u : 4u;
        var mapped = RebuildFixtures.Mapped(built.Bytes);

        Assert.Equal([("Alpha", 0x1000u), ("Zeta", 0x1002u)], pe.Exports.Select(e => (e.Name!, e.Rva)));
        Assert.Equal(["one.dll!Open", "one.dll!Read", "two.dll!Close"], pe.Imports.Select(i => $"{i.Module}!{i.Name}"));
        Assert.Equal(pe.Imports.Select(i => i.SlotRva), built.IatSlots.Values);
        Assert.Equal(built.IatSlots["one.dll!Open"] + width, built.IatSlots["one.dll!Read"]);
        Assert.NotEqual(0u, BinaryPrimitives.ReadUInt32LittleEndian(mapped.AsSpan((int)built.IatSlots["two.dll!Close"])));
    }

    [Fact]
    public void A_module_placed_at_another_base_has_its_pointers_moved_by_the_delta()
    {
        var spec = Spec(true);
        var image = RebuildFixtures.Build(spec);
        using var dir = new TempDir();
        ulong moved = spec.Base + 0x40000000;
        using var dump = RebuildFixtures.Dump(dir, new Placed("moved.dll", image, moved));

        Assert.True(dump.TryReadU64(moved + 0x2008, out var first));
        Assert.True(dump.TryReadU64(moved + 0x2010, out var second));
        Assert.Equal(moved + 0x1000, first);
        Assert.Equal(moved + 0x1002, second);
    }

    [Fact]
    public void An_import_slot_holds_the_address_of_the_export_it_names()
    {
        var exporter = RebuildFixtures.Build(Spec(true) with { ImageBase = 0x180000000, Exports = [new ExportSpec("Alpha", 0x1002)] });
        var importer = RebuildFixtures.Build(Spec(true) with { Imports = [new ImportSpec("lib.dll", ["Alpha"])] });
        using var dir = new TempDir();
        using var dump = RebuildFixtures.Dump(dir, new Placed("lib.dll", exporter, 0x7FF700000000), new Placed("app.exe", importer, 0x140000000));

        Assert.True(dump.TryReadU64(0x140000000UL + importer.IatSlots["lib.dll!Alpha"], out var slot));
        Assert.Equal(0x7FF700000000UL + 0x1002UL, slot);
    }

    [Fact]
    public void An_omitted_page_reads_as_missing()
    {
        var image = RebuildFixtures.Build(Spec(true));
        using var dir = new TempDir();
        using var dump = RebuildFixtures.Dump(dir, new Placed("gap.dll", image, 0x140000000, OmittedPages: [0x2000]));
        var one = new byte[1];

        Assert.Equal(1, dump.ReadMemory(0x140000000 + 0x1000, one));
        Assert.Equal(0, dump.ReadMemory(0x140000000 + 0x2008, one));
    }
}