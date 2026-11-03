using Corvus.Native.Dump.Rebuild;

namespace Corvus.Tests;

/// <summary>Finding the PDB named by the CodeView record of a rebuilt module.</summary>
public sealed class ModuleSymbolsTests
{
    private static byte[] Module(uint age) => PdbTests.TinyImage(PdbBuilder.Sample().Guid, age, "synth.pdb");

    [Fact]
    public void A_pdb_in_an_image_directory_is_found_by_its_guid_and_age()
    {
        using var dir = new TempDir();
        File.WriteAllBytes(dir.File("synth.pdb"), PdbBuilder.Sample().Msf().Build());

        var result = ModuleSymbols.Find(Module(3), dir.Path, download: false, default);

        Assert.Equal("found", result.Status);
        Assert.Equal(Path.GetFullPath(dir.File("synth.pdb")), result.PdbPath);
    }

    [Fact]
    public void A_pdb_of_another_age_is_reported_as_a_mismatch()
    {
        using var dir = new TempDir();
        File.WriteAllBytes(dir.File("synth.pdb"), PdbBuilder.Sample().Msf().Build());

        var result = ModuleSymbols.Find(Module(9), dir.Path, download: false, default);

        Assert.Equal("mismatch", result.Status);
        Assert.Null(result.PdbPath);
        Assert.Contains("different age", result.Reason);
    }

    [Fact]
    public void Download_is_refused_offline_with_the_reason()
    {
        using var dir = new TempDir();

        var result = ModuleSymbols.Find(Module(3), dir.Path, download: true, default, offline: true);

        Assert.Equal("refused", result.Status);
        Assert.Contains("CORVUS_OFFLINE", result.Reason);
        Assert.NotEmpty(result.Looked);
    }
}
