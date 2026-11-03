using Corvus.Native.Dump.Rebuild;
using Corvus.Native.Pe;

namespace Corvus.Tests;

/// <summary>An import directory rebuilt from the address table slots of an image that lost its own.</summary>
public sealed class ImportDirectoryRebuildTests : IDisposable
{
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    private (ImportSummary? Summary, byte[] File, List<RebuildCheck> Checks) Restore(bool iatDirectory)
    {
        var (dump, _) = ImportScanFixtures.Build(_dir, ["Alpha", "Beta"], iatDirectory);
        using var _d = dump;
        var captured = ImportScanFixtures.Capture(dump, "app.exe");
        var image = (byte[])captured.Image.Clone();
        var checks = new List<RebuildCheck>();
        var summary = PeImportRestore.Restore(ref image, ref captured, dump, ImportMode.Restore, checks, CancellationToken.None);
        return (summary, PeFileLayout.ToFileLayout(image, captured, checks), checks);
    }

    [Fact]
    public void An_image_without_an_import_directory_gets_one_from_its_address_table()
    {
        var (summary, file, checks) = Restore(false);

        Assert.True(summary!.DirectoryRebuilt);
        Assert.Equal(2, summary.Resolved);
        var check = checks.First(c => c.Name == "imports");
        Assert.Equal("partial", check.State);
        Assert.Equal("import directory rebuilt from 2 address table slots", check.Detail);
        Assert.Contains(PeFile.FromBytes(file).Sections, s => s.Name == ".idata2");
    }

    [Fact]
    public void The_rebuilt_directory_names_the_functions_the_slots_point_at()
    {
        var (_, file, checks) = Restore(true);

        Assert.Contains("import directory rebuilt from 2 address table slots", checks.First(c => c.Name == "imports").Detail);
        var imports = PeFile.FromBytes(file).Imports;
        Assert.Equal(["Alpha", "Beta"], imports.Select(i => i.Name));
        Assert.All(imports, i => Assert.Equal("lib.dll", i.Module));
    }
}
