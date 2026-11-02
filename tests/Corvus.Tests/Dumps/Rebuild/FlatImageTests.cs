using Corvus.Native.Dump.Rebuild;

namespace Corvus.Tests;

/// <summary>Modules held in memory as the bytes of their file.</summary>
public sealed class FlatImageTests : IDisposable
{
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    private static PeSpec Spec() => new(true,
    [
        new SectionSpec(".text", 0x60000020, Enumerable.Range(1, 0x300).Select(i => (byte)i).ToArray()),
        new SectionSpec(".data", 0xC0000040, Enumerable.Range(1, 0x1200).Select(i => (byte)(i * 7)).ToArray()),
    ]);

    [Fact]
    public void An_image_held_in_file_layout_rebuilds_into_the_original_file()
    {
        var original = RebuildFixtures.Pe(Spec());
        // The fixture drops a final partial page, so the file bytes are padded to whole pages.
        var built = RebuildFixtures.Build(Spec());
        built = built with { Bytes = [.. built.Bytes, .. new byte[(0x1000 - built.Bytes.Length % 0x1000) % 0x1000]] };
        using var dump = RebuildFixtures.Dump(_dir, new Placed("flat.dll", built, 0x180000000, ImageLayout.Flat));
        var target = Assert.Single(ModuleRebuild.Select(dump, "flat.dll", default));

        var rebuilt = ModuleRebuild.Rebuild(dump, target,
            RebuildOptions.Default with { Layout = OutputLayout.File, Base = BaseMode.Preferred, CompareWithDisk = false }, default);

        Assert.Null(rebuilt.Refused);
        Assert.Equal("flat", rebuilt.InputLayout);
        Assert.Equal(original, rebuilt.Bytes);
        Assert.Contains(rebuilt.Checks, c => c.Name == "layout" && c.State == "ok");
        Assert.Contains(rebuilt.Checks, c => c.Name == "parse" && c.State == "ok");
    }
}