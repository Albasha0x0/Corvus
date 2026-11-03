using Corvus.Native.Dump.Rebuild;

namespace Corvus.Tests;

/// <summary>Import slots found by a scan, without pointers into the image itself.</summary>
public sealed class ImportGateTests : IDisposable
{
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    [Fact]
    public void A_scan_run_ends_at_a_pointer_into_the_image()
    {
        var (dump, _) = ImportGateFixtures.Build(_dir, false);
        using var held = dump;
        var captured = ImportScanFixtures.Capture(dump, "app.exe");

        var result = ImportScan.Find(captured.Image, captured, new ExportMap(dump));

        var run = Assert.Single(result!.Runs);
        Assert.Equal(["lib.dll!Alpha", "lib.dll!Beta"], run.Slots.Select(s => s.Name));
    }


    [Fact]
    public void A_scan_limited_to_a_section_ignores_runs_elsewhere()
    {
        var (dump, _) = ImportGateFixtures.Build(_dir, false);
        using var held = dump;
        var captured = ImportScanFixtures.Capture(dump, "app.exe");

        Assert.Null(ImportScan.Find(captured.Image, captured, new ExportMap(dump), 0x1000));
    }

}
