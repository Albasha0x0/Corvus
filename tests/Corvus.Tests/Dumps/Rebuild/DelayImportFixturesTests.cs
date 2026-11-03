using System.Buffers.Binary;
using System.Text;

namespace Corvus.Tests;

/// <summary>The delay-load import fixture read back by hand from its bytes.</summary>
public sealed class DelayImportFixturesTests
{
    private static PeSpec Spec(bool is64) => new(is64, [new SectionSpec(".text", 0x60000020, [0x90, 0xC3])]);

    private static IReadOnlyList<DelayImportSpec> Imports() =>
    [
        new("one.dll", [DelayFunction.Named("Alpha"), DelayFunction.ByOrdinal(7)]),
        new("two.dll", [DelayFunction.Named("Beta")]),
    ];

    private static int RawAt(byte[] file, uint rva)
    {
        int nt = BinaryPrimitives.ReadInt32LittleEndian(file.AsSpan(0x3C));
        int count = BinaryPrimitives.ReadUInt16LittleEndian(file.AsSpan(nt + 6));
        int optional = BinaryPrimitives.ReadUInt16LittleEndian(file.AsSpan(nt + 20));
        for (int i = 0; i < count; i++)
        {
            int h = nt + 24 + optional + 40 * i;
            uint va = BinaryPrimitives.ReadUInt32LittleEndian(file.AsSpan(h + 12));
            uint size = BinaryPrimitives.ReadUInt32LittleEndian(file.AsSpan(h + 8));
            uint raw = BinaryPrimitives.ReadUInt32LittleEndian(file.AsSpan(h + 20));
            if (rva >= va && rva < va + size) return (int)(raw + rva - va);
        }
        throw new InvalidOperationException($"RVA {rva:X} is in no section.");
    }

    private static string Ascii(byte[] file, uint rva)
    {
        int at = RawAt(file, rva);
        int end = Array.IndexOf(file, (byte)0, at);
        return Encoding.ASCII.GetString(file, at, end - at);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void A_built_image_lists_its_delay_load_descriptor_and_slots(bool is64)
    {
        var built = DelayImportFixtures.Build(Spec(is64), Imports());
        var file = built.Bytes;
        int width = is64 ? 8 : 4;
        int nt = BinaryPrimitives.ReadInt32LittleEndian(file.AsSpan(0x3C));
        int dir = nt + 24 + (is64 ? 112 : 96) + 13 * 8;

        Assert.Equal(built.DirectoryRva, BinaryPrimitives.ReadUInt32LittleEndian(file.AsSpan(dir)));
        Assert.Equal(96u, BinaryPrimitives.ReadUInt32LittleEndian(file.AsSpan(dir + 4)));
        Assert.Equal(["one.dll", "two.dll"], built.Descriptors.Select(d => d.Module));

        foreach (var d in built.Descriptors)
        {
            int at = RawAt(file, d.DescriptorRva);
            Assert.Equal(1u, BinaryPrimitives.ReadUInt32LittleEndian(file.AsSpan(at)));
            Assert.Equal(d.DllNameRva, BinaryPrimitives.ReadUInt32LittleEndian(file.AsSpan(at + 4)));
            Assert.Equal(d.ModuleHandleRva, BinaryPrimitives.ReadUInt32LittleEndian(file.AsSpan(at + 8)));
            Assert.Equal(d.AddressTableRva, BinaryPrimitives.ReadUInt32LittleEndian(file.AsSpan(at + 12)));
            Assert.Equal(d.NameTableRva, BinaryPrimitives.ReadUInt32LittleEndian(file.AsSpan(at + 16)));
            Assert.Equal(d.Module, Ascii(file, d.DllNameRva));
        }

        var alpha = built.Slot("one.dll!Alpha");
        Assert.Equal(built.Descriptors[0].AddressTableRva, alpha.SlotRva);
        Assert.Equal(built.Descriptors[0].AddressTableRva + (uint)width, built.Slot("one.dll!#7").SlotRva);
        uint entry = BinaryPrimitives.ReadUInt32LittleEndian(file.AsSpan(RawAt(file, alpha.NameEntryRva)));
        Assert.Equal("Alpha", Ascii(file, entry + 2));
        ulong ordinalEntry = is64
            ? BinaryPrimitives.ReadUInt64LittleEndian(file.AsSpan(RawAt(file, built.Slot("one.dll!#7").NameEntryRva)))
            : BinaryPrimitives.ReadUInt32LittleEndian(file.AsSpan(RawAt(file, built.Slot("one.dll!#7").NameEntryRva)));
        Assert.Equal((is64 ? 0x8000000000000000UL : 0x80000000UL) | 7, ordinalEntry);

        var mapped = RebuildFixtures.Mapped(file);
        ulong b = Spec(is64).Base;
        ulong stored = is64
            ? BinaryPrimitives.ReadUInt64LittleEndian(mapped.AsSpan((int)alpha.SlotRva))
            : BinaryPrimitives.ReadUInt32LittleEndian(mapped.AsSpan((int)alpha.SlotRva));
        Assert.Equal(b + alpha.StubRva, stored);
    }

    [Fact]
    public void A_resolved_slot_holds_the_written_address_and_the_others_keep_their_stub()
    {
        var built = DelayImportFixtures.Build(Spec(true), Imports());
        var mapped = RebuildFixtures.Mapped(built.Bytes);
        var beta = built.Slot("two.dll!Beta");
        var alpha = built.Slot("one.dll!Alpha");

        DelayImportFixtures.WriteResolved(mapped, true, beta, 0x7FF800001000UL);

        Assert.Equal(0x7FF800001000UL, BinaryPrimitives.ReadUInt64LittleEndian(mapped.AsSpan((int)beta.SlotRva)));
        Assert.Equal(0x140000000UL + alpha.StubRva, BinaryPrimitives.ReadUInt64LittleEndian(mapped.AsSpan((int)alpha.SlotRva)));
    }
}
