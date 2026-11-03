using System.Globalization;
using Corvus.Services;

namespace Corvus.Tests;

/// <summary>Pointers a module fills into zero-initialized data are listed as pointer rows.</summary>
public sealed class DumpPointerRowTests : IDisposable
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

    private static List<MinidumpService.ModuleChange> Rows(PointerTable table)
    {
        using var service = new MinidumpService();
        return service.Changes(table.DumpPath, table.ImageFolder, table.MainName, 0, 200, default).Rows.ToList();
    }

    private static uint Rva(MinidumpService.ModuleChange row) => uint.Parse(row.Rva[2..], NumberStyles.HexNumber);

    [Theory]
    [MemberData(nameof(Cases))]
    public void A_late_bound_table_is_one_pointer_row_with_its_names(bool is64, SlotPlacement placement)
    {
        var table = PointerTableFixtures.Table(_dir, is64, placement, 6);

        var row = Assert.Single(Rows(table), r => r.Kind == "pointer");

        Assert.Equal(table.SlotRvas[0], Rva(row));
        Assert.Equal(table.SlotRvas.Count * (is64 ? 8 : 4), row.Length);
        Assert.Equal($"6 slots: {string.Join(", ", table.Expected)}", row.Description);
    }

    [Theory]
    [MemberData(nameof(Cases))]
    public void A_table_past_eight_names_counts_the_rest(bool is64, SlotPlacement placement)
    {
        var table = PointerTableFixtures.Table(_dir, is64, placement, 11);

        var row = Assert.Single(Rows(table), r => r.Kind == "pointer");

        Assert.Equal($"11 slots: {string.Join(", ", table.Expected.Take(8))}, and 3 more", row.Description);
    }

    [Theory]
    [MemberData(nameof(Cases))]
    public void A_single_late_bound_pointer_is_one_row(bool is64, SlotPlacement placement)
    {
        var table = PointerTableFixtures.Single(_dir, is64, placement);

        var row = Assert.Single(Rows(table), r => r.Kind == "pointer");

        Assert.Equal(table.Expected[0], row.Description);
        Assert.Equal(table.Expected[0], row.Name);
        Assert.Equal(table.SlotRvas[0], Rva(row));
    }

    [Theory]
    [MemberData(nameof(Cases))]
    public void Covered_data_rows_are_not_repeated(bool is64, SlotPlacement placement)
    {
        var table = PointerTableFixtures.Table(_dir, is64, placement, 6);
        uint end = table.SlotRvas[^1] + (is64 ? 8u : 4u);

        var rows = Rows(table);

        Assert.DoesNotContain(rows, r => r.Kind == "data" && Rva(r) < end && Rva(r) + (uint)r.Length > table.SlotRvas[0]);
    }

    [Theory]
    [MemberData(nameof(Cases))]
    public void Rows_stay_in_address_order(bool is64, SlotPlacement placement)
    {
        var table = PointerTableFixtures.Table(_dir, is64, placement, 6);

        var starts = Rows(table).Select(Rva).ToList();

        Assert.Equal(starts.Order().ToList(), starts);
    }

    [Theory]
    [MemberData(nameof(Cases))]
    public void A_table_in_pages_not_captured_gives_no_pointer_row(bool is64, SlotPlacement placement)
    {
        var probe = PointerTableFixtures.Table(_dir, is64, placement, 6);
        var table = PointerTableFixtures.Table(_dir, is64, placement, 6, [probe.SlotRvas[0] & ~0xFFFu]);

        Assert.DoesNotContain(Rows(table), r => r.Kind == "pointer");
    }
}
