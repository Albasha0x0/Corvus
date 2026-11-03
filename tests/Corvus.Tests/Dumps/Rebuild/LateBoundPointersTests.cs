using Corvus.Native.Dump;
using Corvus.Native.Dump.Rebuild;
using Corvus.Native.Pe;

namespace Corvus.Tests;

/// <summary>Export addresses a module fills into data its file leaves zero are found as runs.</summary>
public sealed class LateBoundPointersTests : IDisposable
{
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    public static TheoryData<bool, SlotPlacement> Cases => new()
    {
        { true, SlotPlacement.PastRawData },
        { false, SlotPlacement.PastRawData },
        { true, SlotPlacement.NoRawData },
        { false, SlotPlacement.NoRawData },
    };

    private static IReadOnlyList<LateBoundRun> Scan(PointerTable table)
    {
        using var dump = MinidumpFile.Open(table.DumpPath);
        var target = RebuildTarget.Of(dump.Modules.First(m => m.FileName == table.MainName));
        var captured = CapturedImageReader.Read(dump, target, CancellationToken.None)!;
        var file = PeFile.Open(Path.Combine(table.ImageFolder, table.MainName));
        return LateBoundPointers.Find(captured.Image, captured, file, dump, new ExportMap(dump));
    }

    [Theory]
    [MemberData(nameof(Cases))]
    public void A_filled_table_is_one_run_with_its_names(bool is64, SlotPlacement placement)
    {
        var table = PointerTableFixtures.Table(_dir, is64, placement, 4);

        var run = Assert.Single(Scan(table));

        Assert.Equal(table.MainName, run.Module);
        Assert.True(run.IsTable);
        Assert.Equal(table.SlotRvas, run.SlotRvas);
        Assert.Equal(table.Expected, run.Names);
    }

    [Theory]
    [MemberData(nameof(Cases))]
    public void A_forwarded_export_is_named_by_its_final_export(bool is64, SlotPlacement placement)
    {
        var table = PointerTableFixtures.Table(_dir, is64, placement, 6);

        var run = Assert.Single(Scan(table));

        Assert.Equal("third.dll!Target", run.Names[5]);
    }

    [Theory]
    [MemberData(nameof(Cases))]
    public void An_ordinal_export_is_named_by_its_ordinal(bool is64, SlotPlacement placement)
    {
        var table = PointerTableFixtures.Table(_dir, is64, placement, 5);

        var run = Assert.Single(Scan(table));

        Assert.Equal("provider.dll!#6", run.Names[4]);
    }

    [Theory]
    [MemberData(nameof(Cases))]
    public void A_single_pointer_is_not_a_table(bool is64, SlotPlacement placement)
    {
        var table = PointerTableFixtures.Single(_dir, is64, placement);

        var run = Assert.Single(Scan(table));

        Assert.False(run.IsTable);
        Assert.Equal(table.SlotRvas, run.SlotRvas);
        Assert.Equal(table.Expected, run.Names);
    }

    [Theory]
    [MemberData(nameof(Cases))]
    public void Pointers_into_the_image_itself_are_left_out(bool is64, SlotPlacement placement)
    {
        var table = PointerTableFixtures.IntoSelf(_dir, is64, placement, 4);

        Assert.Empty(Scan(table));
    }

    [Theory]
    [MemberData(nameof(Cases))]
    public void A_page_not_captured_ends_a_run(bool is64, SlotPlacement placement)
    {
        var probe = PointerTableFixtures.Table(_dir, is64, placement, 4);
        var table = PointerTableFixtures.Table(_dir, is64, placement, 4, [probe.DataRva]);

        Assert.Empty(Scan(table));
    }

    // Grows the file's raw data of the table section to rawSize; the fixture left the section's file bytes zero past 0x200.
    private static PeFile ScanFile(PointerTable table, uint rawSize, bool fillSlots = false)
    {
        string path = Path.Combine(table.ImageFolder, table.MainName);
        var bytes = File.ReadAllBytes(path);
        var row = PointerTableFixtures.Sections(bytes).First(s => s.Rva == table.DataRva);
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(row.Header + 16), rawSize);
        if (fillSlots)
        {
            foreach (uint rva in table.SlotRvas) bytes[row.RawAt + (rva - table.DataRva)] = 0x77;
        }
        return PeFile.FromBytes(bytes, path);
    }

    private static IReadOnlyList<LateBoundRun> Scan(PointerTable table, PeFile file, bool fileHasRawData = true)
    {
        using var dump = MinidumpFile.Open(table.DumpPath);
        var target = RebuildTarget.Of(dump.Modules.First(m => m.FileName == table.MainName));
        var captured = CapturedImageReader.Read(dump, target, CancellationToken.None)!;
        return LateBoundPointers.Find(captured.Image, captured, file, dump, new ExportMap(dump), fileHasRawData);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void Slots_inside_the_raw_data_are_found_when_the_file_holds_zeros(bool is64)
    {
        var table = PointerTableFixtures.Table(_dir, is64, SlotPlacement.PastRawData, 4);

        var run = Assert.Single(Scan(table, ScanFile(table, 0x1000)));

        Assert.Equal(table.SlotRvas, run.SlotRvas);
        Assert.Equal(table.Expected, run.Names);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void Slots_whose_file_bytes_are_not_zero_are_left_out(bool is64)
    {
        var table = PointerTableFixtures.Table(_dir, is64, SlotPlacement.PastRawData, 4);

        Assert.Empty(Scan(table, ScanFile(table, 0x1000, fillSlots: true)));
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void A_table_across_the_end_of_short_raw_data_is_one_run(bool is64)
    {
        var table = PointerTableFixtures.Table(_dir, is64, SlotPlacement.PastRawData, 6);
        uint rawSize = table.SlotRvas[2] - table.DataRva;

        var run = Assert.Single(Scan(table, ScanFile(table, rawSize)));

        Assert.Equal(table.SlotRvas, run.SlotRvas);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void Without_a_file_the_raw_data_of_the_image_is_not_scanned(bool is64)
    {
        var table = PointerTableFixtures.Table(_dir, is64, SlotPlacement.PastRawData, 4);

        Assert.Empty(Scan(table, ScanFile(table, 0x1000), fileHasRawData: false));
    }
}
