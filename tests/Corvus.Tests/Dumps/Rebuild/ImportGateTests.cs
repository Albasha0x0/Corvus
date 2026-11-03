using Corvus.Native.Dump.Rebuild;
using Corvus.Native.Pe;

namespace Corvus.Tests;

/// <summary>The import scan runs only where the file of the same build had an import directory.</summary>
public sealed class ImportGateTests : IDisposable
{
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    private RebuiltModule Rebuild(bool fileDirectory)
    {
        var (dump, folder) = ImportGateFixtures.Build(_dir, fileDirectory);
        using var held = dump;
        var options = RebuildOptions.Default with { ImageDirectories = folder };
        return ModuleRebuild.Rebuild(dump, RebuildTarget.Of(dump.Modules.First(m => m.FileName == "app.exe")), options, CancellationToken.None);
    }

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


    [Fact]
    public void An_image_whose_file_has_no_import_directory_gets_no_section()
    {
        var m = Rebuild(false);

        var check = m.Checks.First(c => c.Name == "imports");
        Assert.Equal("skipped", check.State);
        Assert.Equal("the file has no import directory", check.Detail);
        Assert.DoesNotContain(PeFile.FromBytes(m.Bytes).Sections, s => s.Name == ".idata2");
        Assert.Null(m.Imports);
    }


    [Fact]
    public void The_disk_check_finds_the_file_of_an_image_left_without_a_directory()
    {
        var m = Rebuild(false);

        Assert.NotNull(m.Disk);
        Assert.DoesNotContain(m.Checks, c => c.Name == "disk" && c.State == "skipped");
    }


    [Fact]
    public void An_import_directory_zeroed_in_memory_is_rebuilt_when_the_file_has_one()
    {
        var m = Rebuild(true);

        Assert.True(m.Imports!.DirectoryRebuilt);
        Assert.Contains(PeFile.FromBytes(m.Bytes).Sections, s => s.Name == ".idata2");
    }


    [Fact]
    public void A_scan_built_directory_is_reported_as_partial_and_the_file_is_still_found()
    {
        var m = Rebuild(true);

        var check = m.Checks.First(c => c.Name == "imports");
        Assert.Equal("partial", check.State);
        Assert.Equal("import directory rebuilt from 2 address table slots", check.Detail);
        Assert.NotNull(m.Disk);
        Assert.DoesNotContain(m.Checks, c => c.Name == "disk" && c.State == "skipped");
    }
}
