using Corvus.Native.Dump.Rebuild;

namespace Corvus.Tests;

/// <summary>The disk check of a rebuilt image names why no file was compared.</summary>
public sealed class DiskCompareReasonTests : IDisposable
{
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    private RebuiltModule Rebuild(Func<RebuildTarget, RebuildTarget> target, string folder)
    {
        var built = RebuildFixtures.Build(new PeSpec(true, [new SectionSpec(".text", 0x60000020, new byte[0x40])]));
        using var dump = RebuildFixtures.Dump(_dir, new Placed("probe.dll", built, 0x140000000UL));
        var options = RebuildOptions.Default with { ImageDirectories = folder };
        return ModuleRebuild.Rebuild(dump, target(RebuildTarget.Of(dump.Modules[0])), options, CancellationToken.None);
    }

    [Fact]
    public void A_module_with_no_recorded_path_says_it_has_no_file_on_disk()
    {
        string folder = Directory.CreateDirectory(_dir.File("empty")).FullName;

        var m = Rebuild(t => t with { Path = null }, folder);

        var check = Assert.Single(m.Checks, c => c.Name == "disk");
        Assert.Equal("skipped", check.State);
        Assert.Equal("the module has no file on disk (loaded from memory)", check.Detail);
    }

    [Fact]
    public void A_module_with_a_recorded_path_names_the_places_searched()
    {
        string folder = Directory.CreateDirectory(_dir.File("other")).FullName;

        var m = Rebuild(t => t, folder);

        var check = Assert.Single(m.Checks, c => c.Name == "disk");
        Assert.StartsWith("no file of the same build found; searched", check.Detail);
        Assert.Contains(folder, check.Detail);
    }
}
