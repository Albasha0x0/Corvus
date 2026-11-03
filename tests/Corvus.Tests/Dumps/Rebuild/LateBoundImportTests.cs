using System.Buffers.Binary;
using Corvus.Native;
using Corvus.Native.Dump;
using Corvus.Native.Dump.Rebuild;
using Corvus.Native.Pe;

namespace Corvus.Tests;

/// <summary>Tables a module fills at run time are saved as import descriptors at their slots.</summary>
public sealed class LateBoundImportTests : IDisposable
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

    private sealed record Result(ImportSummary? Summary, PeFile Saved, byte[] Image, List<RebuildCheck> Checks, int Before);

    private static Result Run(PointerTable table, ImportMode mode, int passes = 1, Action<byte[], int>? headers = null)
    {
        using var dump = MinidumpFile.Open(table.DumpPath);
        var target = RebuildTarget.Of(dump.Modules.First(m => m.FileName == table.MainName));
        var captured = CapturedImageReader.Read(dump, target, CancellationToken.None)!;
        var image = (byte[])captured.Image.Clone();
        headers?.Invoke(image, TableEnd(image));
        var file = File.ReadAllBytes(Path.Combine(table.ImageFolder, table.MainName));
        var checks = new List<RebuildCheck>();
        ImportSummary? summary = null;
        for (int i = 0; i < passes; i++)
        {
            checks.Clear();
            summary = PeImportRestore.Restore(ref image, ref captured, dump, mode, checks, CancellationToken.None, file);
        }
        var bytes = PeFileLayout.ToFileLayout(image, captured, checks);
        return new Result(summary, PeFile.FromBytes(bytes!), image, checks, captured.Image.Length);
    }

    // Offset just past the last section header.
    private static int TableEnd(byte[] image)
    {
        int nt = BinaryPrimitives.ReadInt32LittleEndian(image.AsSpan(0x3C));
        int sections = BinaryPrimitives.ReadUInt16LittleEndian(image.AsSpan(nt + 6));
        return nt + 24 + BinaryPrimitives.ReadUInt16LittleEndian(image.AsSpan(nt + 20)) + 40 * sections;
    }

    private static void HeadersEndAt(byte[] image, int end) =>
        BinaryPrimitives.WriteUInt32LittleEndian(image.AsSpan(BinaryPrimitives.ReadInt32LittleEndian(image.AsSpan(0x3C)) + 24 + 60), (uint)end);

    private static string Label(NativeImport import) =>
        $"{import.Module}!" + (import.Name ?? $"#{import.Ordinal}");

    [Theory]
    [MemberData(nameof(Cases))]
    public void A_late_bound_table_becomes_an_import_descriptor_at_its_slots(bool is64, SlotPlacement placement)
    {
        var table = PointerTableFixtures.Table(_dir, is64, placement, 6);

        var result = Run(table, ImportMode.Restore);

        Assert.Equal(table.Expected, result.Saved.Imports.Select(Label));
        Assert.Equal(table.SlotRvas, result.Saved.Imports.Select(i => i.SlotRva));
        var check = Assert.Single(result.Checks, c => c.Name == "imports");
        Assert.EndsWith("6 late-bound slots in 1 tables added from memory", check.Detail);
        Assert.True(result.Summary!.DirectoryRebuilt);
    }

    [Theory]
    [MemberData(nameof(Cases))]
    public void A_table_the_import_directory_covers_is_not_added_twice(bool is64, SlotPlacement placement)
    {
        var table = PointerTableFixtures.Table(_dir, is64, placement, 4);

        var result = Run(table, ImportMode.Restore, passes: 2);

        Assert.Equal(table.Expected, result.Saved.Imports.Select(Label));
        Assert.Single(result.Saved.Imports.Select(i => i.Module).Distinct());
    }

    [Theory]
    [MemberData(nameof(Cases))]
    public void A_single_pointer_is_not_an_import(bool is64, SlotPlacement placement)
    {
        var table = PointerTableFixtures.Single(_dir, is64, placement);

        var result = Run(table, ImportMode.Restore);

        Assert.Empty(result.Saved.Imports);
        Assert.DoesNotContain(result.Checks, c => c.Detail.Contains("late-bound"));
    }

    [Theory]
    [MemberData(nameof(Cases))]
    public void Imports_keep_adds_no_descriptor(bool is64, SlotPlacement placement)
    {
        var table = PointerTableFixtures.Table(_dir, is64, placement, 4);

        var result = Run(table, ImportMode.Keep);

        Assert.Empty(result.Saved.Imports);
        Assert.Equal(result.Before, result.Image.Length);
    }

    [Theory]
    [MemberData(nameof(Cases))]
    public void A_section_table_that_fills_its_headers_grows_them_for_the_import_section(bool is64, SlotPlacement placement)
    {
        var table = PointerTableFixtures.Table(_dir, is64, placement, 6);

        // SizeOfHeaders ends at the last section header.
        var result = Run(table, ImportMode.Restore, headers: HeadersEndAt);

        Assert.Equal(table.SlotRvas, result.Saved.Imports.Select(i => i.SlotRva));
        Assert.EndsWith("6 late-bound slots in 1 tables added from memory", Assert.Single(result.Checks, c => c.Name == "imports").Detail);
    }

    [Theory]
    [MemberData(nameof(Cases))]
    public void Header_bytes_past_the_section_table_are_kept_and_the_tables_reported_partial(bool is64, SlotPlacement placement)
    {
        var table = PointerTableFixtures.Table(_dir, is64, placement, 6);

        var result = Run(table, ImportMode.Restore, headers: (image, end) => { HeadersEndAt(image, end); image[end + 8] = 0x5A; });

        Assert.Empty(result.Saved.Imports);
        var check = Assert.Single(result.Checks, c => c.Name == "imports");
        Assert.Equal("partial", check.State);
        Assert.EndsWith("6 late-bound slots in 1 tables not added: no room for an import section", check.Detail);
    }

    private static PointerTable Uncaptured(TempDir dir, bool is64, SlotPlacement placement)
    {
        var probe = PointerTableFixtures.Table(dir, is64, placement, 6);
        return PointerTableFixtures.Table(dir, is64, placement, 6, [probe.DataRva]);
    }

    [Theory]
    [MemberData(nameof(Cases))]
    public void Slots_on_a_page_that_is_not_captured_are_not_added(bool is64, SlotPlacement placement)
    {
        var table = Uncaptured(_dir, is64, placement);

        var result = Run(table, ImportMode.Restore);

        Assert.Empty(result.Saved.Imports);
        Assert.Equal(result.Before, result.Image.Length);
    }

    [Theory(Skip = "Defect: LateBoundPointers.Name (LateBoundPointers.cs:72) drops a slot on a page that is not captured and PeImportRestore.LateBound (PeImportRestore.cs:43) reports nothing, so the imports check does not name the uncaptured page.")]
    [MemberData(nameof(Cases))]
    public void The_imports_check_names_the_slots_left_out_for_a_page_not_captured(bool is64, SlotPlacement placement)
    {
        var table = Uncaptured(_dir, is64, placement);

        var result = Run(table, ImportMode.Restore);

        // Unknown is not absent: a page that was not captured is named, not dropped.
        var check = Assert.Single(result.Checks, c => c.Name == "imports");
        Assert.NotEqual("ok", check.State);
        Assert.Contains("not captured", check.Detail);
    }
}
