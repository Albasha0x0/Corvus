using System.Buffers.Binary;
using Corvus.Native.Dump.Rebuild;

namespace Corvus.Tests;

/// <summary>Every range where a rebuilt image differs from its file is listed with the bytes on both sides.</summary>
public sealed class ImageChangesTests
{
    private static readonly RebuildTarget Target = new("probe.dll", 0x140000000UL, 0, ModuleOrigin.Listed);

    private static PeSpec Spec(int textSize = 0x40, IReadOnlyList<ImportSpec>? imports = null)
    {
        var code = new byte[textSize];
        Array.Fill(code, (byte)0x90);
        return new PeSpec(true, [new SectionSpec(".text", 0x60000020, code), new SectionSpec(".data", 0xC0000040, new byte[0x40])],
            [new PointerSite(".data", 8, 0x1000)], Imports: imports);
    }

    private static CapturedImage Capture(byte[] mapped, params int[] omittedPages)
    {
        var pages = new bool[mapped.Length / 0x1000];
        Array.Fill(pages, true);
        foreach (int page in omittedPages) pages[page] = false;
        return new CapturedImage(Target, mapped, pages, "mapped");
    }

    [Fact]
    public void Every_differing_range_is_listed_with_both_sides_bytes()
    {
        var file = RebuildFixtures.Pe(Spec());
        var mapped = RebuildFixtures.Mapped(file);
        mapped[0x1004] = 0xCC;
        mapped[0x100A] = 0xCD;
        mapped[0x1030] = 0xEB;

        var set = ImageChanges.Compare(mapped, Capture(mapped), file);

        Assert.Equal(2, set.Total);
        Assert.False(set.Truncated);
        var first = set.Ranges[0];
        Assert.Equal(".text", first.Section);
        Assert.Equal("0x1004", first.Rva);
        Assert.Equal(7, first.Length);
        Assert.Equal("differs", first.State);
        Assert.True(first.Code);
        Assert.Equal("90909090909090", first.FileBytes);
        Assert.Equal("cc9090909090cd", first.MemoryBytes[..14]);
        Assert.Equal("0x1030", set.Ranges[1].Rva);
        Assert.Equal("eb", set.Ranges[1].MemoryBytes);
    }

    [Fact]
    public void Relocated_and_import_slots_are_not_reported()
    {
        var built = RebuildFixtures.Build(Spec(imports: [new ImportSpec("kernel32.dll", ["Sleep"])]));
        uint slot = built.IatSlots["kernel32.dll!Sleep"];
        // The fixture leaves the import address table directory empty; the file
        // declares the slot as one.
        int nt = BinaryPrimitives.ReadInt32LittleEndian(built.Bytes.AsSpan(0x3C));
        BinaryPrimitives.WriteUInt32LittleEndian(built.Bytes.AsSpan(nt + 24 + 112 + 12 * 8), slot);
        BinaryPrimitives.WriteUInt32LittleEndian(built.Bytes.AsSpan(nt + 24 + 112 + 12 * 8 + 4), 8);
        var mapped = RebuildFixtures.Mapped(built.Bytes);
        mapped[0x2008] ^= 0xFF;
        mapped[0x2009] ^= 0xFF;
        mapped[slot] ^= 0xFF;
        mapped[slot + 1] ^= 0xFF;

        var set = ImageChanges.Compare(mapped, Capture(mapped), built.Bytes);

        Assert.Empty(set.Ranges);
        Assert.Equal(0, set.Total);
    }

    [Fact]
    public void An_uncaptured_page_is_an_unknown_range_not_a_difference()
    {
        var file = RebuildFixtures.Pe(Spec(0x2000));
        var mapped = RebuildFixtures.Mapped(file);
        mapped[0x1010] = 0xCC;
        mapped[0x2010] = 0xCC;

        var set = ImageChanges.Compare(mapped, Capture(mapped, 2), file);

        Assert.Equal(2, set.Total);
        Assert.Equal("differs", set.Ranges[0].State);
        Assert.Equal("0x1010", set.Ranges[0].Rva);
        var unknown = set.Ranges[1];
        Assert.Equal("unknown", unknown.State);
        Assert.Equal("0x2000", unknown.Rva);
        Assert.Equal(0x1000, unknown.Length);
        Assert.Equal("", unknown.MemoryBytes);
    }
}
