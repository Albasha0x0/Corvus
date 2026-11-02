using Corvus.Native.Dump;
using Corvus.Native.Dump.Rebuild;

namespace Corvus.Tests;

/// <summary>PE headers found in captured memory that no listed module covers.</summary>
public sealed class UnlistedImagesTests : IDisposable
{
    private const ulong Listed = 0x180000000UL;
    private const ulong Hidden = 0x190000000UL;
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    private static PeBuilt Image() => RebuildFixtures.Build(new PeSpec(true,
        [new SectionSpec(".text", 0x60000020, [0x90, 0xC3])]));

    [Fact]
    public void A_PE_header_outside_the_module_list_is_found()
    {
        using var dump = RebuildFixtures.Dump(_dir,
            new Placed("listed.dll", Image(), Listed),
            new Placed("hidden.dll", Image(), Hidden, Listed: false));

        var found = Assert.Single(UnlistedImages.Find(dump, default));

        Assert.Equal(Hidden, found.Base);
        Assert.Equal("image-190000000.dll", found.Name);
        Assert.Equal(ModuleOrigin.Unlisted, found.Origin);
        Assert.Equal(found.Base, Assert.Single(ModuleRebuild.Select(dump, "unlisted", default)).Base);
    }

    [Fact]
    public void Bytes_that_only_start_with_MZ_are_not_an_image()
    {
        var builder = SyntheticCrash.Builder();
        var bytes = new byte[0x1000];
        bytes[0] = (byte)'M';
        bytes[1] = (byte)'Z';
        builder.Memory.Add((Hidden, bytes));
        builder.Memory.Sort((a, b) => a.Start.CompareTo(b.Start));
        var path = _dir.File("mz.dmp");
        File.WriteAllBytes(path, builder.Build());
        using var dump = MinidumpFile.Open(path);

        Assert.Empty(UnlistedImages.Find(dump, default));
    }

    [Fact]
    public void A_listed_module_is_not_found_again()
    {
        using var dump = RebuildFixtures.Dump(_dir, new Placed("listed.dll", Image(), Listed));

        Assert.Empty(UnlistedImages.Find(dump, default));
    }
}
