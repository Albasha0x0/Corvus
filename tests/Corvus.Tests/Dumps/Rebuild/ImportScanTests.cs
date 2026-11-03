using Corvus.Native.Dump.Rebuild;

namespace Corvus.Tests;

/// <summary>Import address table slots found without an import directory.</summary>
public sealed class ImportScanTests : IDisposable
{
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    [Fact]
    public void Slots_are_found_from_the_iat_directory_when_the_import_directory_is_gone()
    {
        var (dump, app) = ImportScanFixtures.Build(_dir, ["Alpha", "Beta"], iatDirectory: true);
        using var _ = dump;
        var captured = ImportScanFixtures.Capture(dump, "app.exe");

        var result = ImportScan.Find(captured.Image, captured, new ExportMap(dump));

        Assert.Equal("directory", result!.Source);
        Assert.Equal([new ImportSlot(app.IatSlots["lib.dll!Alpha"], "lib.dll!Alpha"), new ImportSlot(app.IatSlots["lib.dll!Beta"], "lib.dll!Beta")], result.Slots);
        Assert.Equal(0, result.Unnamed);
    }

    [Fact]
    public void Without_any_directory_a_scan_finds_the_runs_of_named_pointers()
    {
        var (dump, app) = ImportScanFixtures.Build(_dir, ["Alpha", "Beta"], iatDirectory: false);
        using var _ = dump;
        var captured = ImportScanFixtures.Capture(dump, "app.exe");

        var result = ImportScan.Find(captured.Image, captured, new ExportMap(dump));

        Assert.Equal("scan", result!.Source);
        var run = Assert.Single(result.Runs);
        Assert.Equal("lib.dll", run.Module);
        Assert.Equal(["lib.dll!Alpha", "lib.dll!Beta"], run.Slots.Select(s => s.Name));
        Assert.Equal(app.IatSlots["lib.dll!Alpha"], run.Slots[0].Rva);
    }

    [Fact]
    public void A_lone_pointer_into_a_module_is_not_taken_for_a_slot()
    {
        var (dump, _) = ImportScanFixtures.Build(_dir, ["Alpha"], iatDirectory: false);
        using var _d = dump;
        var captured = ImportScanFixtures.Capture(dump, "app.exe");

        Assert.Null(ImportScan.Find(captured.Image, captured, new ExportMap(dump)));
    }
}
