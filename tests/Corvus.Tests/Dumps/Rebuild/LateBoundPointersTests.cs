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
}
