using Corvus.Native.Dump;
using Corvus.Native.Dump.Rebuild;

namespace Corvus.Tests;

/// <summary>A module list entry is mapped by the loader, whatever its section table says.</summary>
public sealed class ModuleListCaptureTests : IDisposable
{
    private const ulong Base = 0x1_8000_0000UL;
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    [Fact]
    public void A_listed_module_with_equal_alignments_is_reported_mapped()
    {
        var image = RebuildFixtures.Build(new PeSpec(true, [new SectionSpec(".text", 0x60000020, [0x55, 0xC3])],
            FileAlignment: 0x1000, SectionAlignment: 0x1000));
        using var dump = RebuildFixtures.Dump(_dir, new Placed("same.dll", image, Base));
        var target = Assert.Single(ModuleRebuild.Select(dump, "same.dll", default));
        var checks = new List<RebuildCheck>();

        var captured = CapturedImageReader.Read(dump, target, default, checks);

        Assert.Equal("mapped", captured!.InputLayout);
        var check = Assert.Single(checks);
        Assert.Equal(("capture", "ok"), (check.Name, check.State));
        Assert.StartsWith("mapped (loaded module), ", check.Detail);
    }

    [Fact]
    public void A_listed_module_without_raw_data_is_reported_mapped()
    {
        var image = RebuildFixtures.Build(new PeSpec(true, [new SectionSpec(".bss", 0xC0000080, [])]));
        using var dump = RebuildFixtures.Dump(_dir, new Placed("bss.dll", image, Base));
        var target = Assert.Single(ModuleRebuild.Select(dump, "bss.dll", default));
        var checks = new List<RebuildCheck>();

        CapturedImageReader.Read(dump, target, default, checks);

        Assert.Equal("ok", Assert.Single(checks).State);
    }
}
