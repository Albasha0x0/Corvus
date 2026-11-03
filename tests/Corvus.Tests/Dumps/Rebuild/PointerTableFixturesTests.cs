using System.Buffers.Binary;
using Corvus.Native.Dump;

namespace Corvus.Tests;

/// <summary>The pointer-table fixtures read back from their dump and image files.</summary>
public sealed class PointerTableFixturesTests
{
    public static TheoryData<bool, SlotPlacement> Cases => new()
    {
        { true, SlotPlacement.PastRawData },
        { false, SlotPlacement.PastRawData },
        { true, SlotPlacement.NoRawData },
        { false, SlotPlacement.NoRawData },
    };

    private static ulong Read(IProcessMemory memory, ulong address, bool is64)
    {
        var buffer = new byte[is64 ? 8 : 4];
        Assert.Equal(buffer.Length, memory.ReadMemory(address, buffer));
        return is64 ? BinaryPrimitives.ReadUInt64LittleEndian(buffer) : BinaryPrimitives.ReadUInt32LittleEndian(buffer);
    }

    [Theory]
    [MemberData(nameof(Cases))]
    public void A_filled_table_holds_provider_export_addresses_in_the_dump(bool is64, SlotPlacement placement)
    {
        using var dir = new TempDir();
        var table = PointerTableFixtures.Table(dir, is64, placement, 8);
        using var dump = MinidumpFile.Open(table.DumpPath);

        Assert.Equal(8, table.SlotRvas.Count);
        Assert.Equal(8, table.Expected.Count);
        int width = is64 ? 8 : 4;
        for (int i = 0; i < table.SlotRvas.Count; i++)
        {
            ulong value = Read(dump, table.MainBase + table.SlotRvas[i], is64);
            Assert.Equal(table.Values[i], value);
            Assert.False(value >= table.MainBase && value < table.MainBase + 0x10000);
        }
        Assert.Equal(0UL, Read(dump, table.MainBase + table.SlotRvas[^1] + (uint)width, is64));
        Assert.Equal(
            [
                "provider.dll!Alpha", "provider.dll!Beta", "provider.dll!Delta", "provider.dll!Gamma",
                "provider.dll!#6", "third.dll!Target", "provider.dll!Alpha", "provider.dll!Beta",
            ],
            table.Expected);

        var providerBase = dump.Modules.First(m => m.FileName == PointerTableFixtures.Provider).Base;
        Assert.Equal(providerBase + 0x1000, table.Values[0]);
        Assert.Equal(providerBase + 0x1040, table.Values[4]);
    }

    [Theory]
    [MemberData(nameof(Cases))]
    public void The_file_holds_zeros_where_the_dump_holds_the_table(bool is64, SlotPlacement placement)
    {
        using var dir = new TempDir();
        var table = PointerTableFixtures.Table(dir, is64, placement, 4);
        var file = File.ReadAllBytes(Path.Combine(table.ImageFolder, table.MainName));
        var mapped = RebuildFixtures.Mapped(file);
        var section = PointerTableFixtures.Sections(file).First(s => s.Rva == table.DataRva);

        Assert.Equal(table.DataRawSize, section.RawSize);
        Assert.True(section.RawSize < section.VirtualSize);
        if (placement == SlotPlacement.NoRawData) Assert.Equal(0u, section.RawSize);
        foreach (uint rva in table.SlotRvas)
        {
            Assert.True(rva - section.Rva >= section.RawSize);
            Assert.True(mapped.AsSpan((int)rva, is64 ? 8 : 4).ToArray().All(b => b == 0));
        }
    }

    [Theory]
    [MemberData(nameof(Cases))]
    public void A_single_export_address_sits_between_ordinary_values(bool is64, SlotPlacement placement)
    {
        using var dir = new TempDir();
        var table = PointerTableFixtures.Single(dir, is64, placement);
        using var dump = MinidumpFile.Open(table.DumpPath);
        uint slot = Assert.Single(table.SlotRvas);
        uint width = is64 ? 8u : 4u;

        Assert.Equal(["provider.dll!Beta"], table.Expected);
        Assert.Equal(table.Values[0], Read(dump, table.MainBase + slot, is64));
        Assert.NotEqual(0UL, Read(dump, table.MainBase + slot - width, is64));
        Assert.NotEqual(0UL, Read(dump, table.MainBase + slot + width, is64));
    }

    [Theory]
    [MemberData(nameof(Cases))]
    public void Self_slots_point_into_the_main_image(bool is64, SlotPlacement placement)
    {
        using var dir = new TempDir();
        var table = PointerTableFixtures.IntoSelf(dir, is64, placement, 4);
        using var dump = MinidumpFile.Open(table.DumpPath);

        Assert.Equal(["main.dll!MainA", "main.dll!MainB", "main.dll!MainC", "main.dll!MainA"], table.Expected);
        for (int i = 0; i < table.SlotRvas.Count; i++)
        {
            ulong value = Read(dump, table.MainBase + table.SlotRvas[i], is64);
            Assert.InRange(value, table.MainBase + 0x1000, table.MainBase + 0x1FFF);
        }
    }

    [Fact]
    public void The_provider_exports_one_function_by_ordinal_and_one_forwarded()
    {
        using var dir = new TempDir();
        var table = PointerTableFixtures.Table(dir, true, SlotPlacement.PastRawData, 1);
        var pe = Corvus.Native.Pe.PeFile.FromBytes(File.ReadAllBytes(Path.Combine(table.ImageFolder, PointerTableFixtures.Provider)));

        Assert.Contains(pe.Exports, e => e.Name is null && e.Ordinal == 6);
        Assert.Contains(pe.Exports, e => e.Name == "Fwd" && e.ForwardedTo == "third.Target");
    }

    [Fact]
    public void Omitted_pages_are_left_out_of_the_dump()
    {
        using var dir = new TempDir();
        var table = PointerTableFixtures.Table(dir, true, SlotPlacement.PastRawData, 2, [0x2000]);
        using var dump = MinidumpFile.Open(table.DumpPath);
        var buffer = new byte[8];

        Assert.Equal(0, dump.ReadMemory(table.MainBase + table.SlotRvas[0], buffer));
    }

    [Fact]
    public void Slots_that_do_not_fit_the_section_are_refused()
    {
        using var dir = new TempDir();
        Assert.Throws<ArgumentException>(() => PointerTableFixtures.Table(dir, true, SlotPlacement.PastRawData, 500));
    }
}
