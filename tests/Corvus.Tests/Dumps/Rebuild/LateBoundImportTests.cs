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

    private static Result Run(PointerTable table, ImportMode mode, int passes = 1)
    {
        using var dump = MinidumpFile.Open(table.DumpPath);
        var target = RebuildTarget.Of(dump.Modules.First(m => m.FileName == table.MainName));
        var captured = CapturedImageReader.Read(dump, target, CancellationToken.None)!;
        var image = (byte[])captured.Image.Clone();
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
}
