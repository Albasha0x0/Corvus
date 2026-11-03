using Corvus.Native.Dump.Rebuild;

namespace Corvus.Tests;

/// <summary>Whether memory holds an image mapped by a loader or the bytes of its file.</summary>
public sealed class LayoutDetectTests
{
    private const ulong Base = 0x140000000;

    private static PeBuilt Image(params SectionSpec[] sections) => RebuildFixtures.Build(new PeSpec(true, sections));

    private static SectionSpec[] Code() =>
    [
        new SectionSpec(".text", 0x60000020, [0x55, 0x48, 0x89, 0xE5, 0xC3, 0x90, 0x90, 0x90]),
        new SectionSpec(".data", 0xC0000040, [1, 2, 3, 4, 5, 6, 7, 8]),
    ];

    private static (CapturedImage? Image, List<RebuildCheck> Checks) Capture(PeBuilt image, ImageLayout layout)
    {
        // The fixture drops a final partial page, so the file bytes are padded to whole pages.
        if (layout == ImageLayout.Flat) image = image with { Bytes = [.. image.Bytes, .. new byte[(0x1000 - image.Bytes.Length % 0x1000) % 0x1000]] };
        using var dir = new TempDir();
        using var dump = RebuildFixtures.Dump(dir, new Placed("probe.dll", image, Base, layout));
        var target = new RebuildTarget("probe.dll", Base, 0, ModuleOrigin.Unlisted);
        var checks = new List<RebuildCheck>();
        return (CapturedImageReader.Read(dump, target, CancellationToken.None, checks), checks);
    }

    [Fact]
    public void A_loader_mapped_image_is_detected_as_mapped()
    {
        var (captured, checks) = Capture(Image(Code()), ImageLayout.Mapped);

        Assert.Equal("mapped", captured!.InputLayout);
        var check = Assert.Single(checks);
        Assert.Equal(("capture", "ok"), (check.Name, check.State));
        Assert.StartsWith("mapped, ", check.Detail);
    }

    [Fact]
    public void File_bytes_held_in_memory_are_detected_as_flat()
    {
        var (captured, checks) = Capture(Image(Code()), ImageLayout.Flat);

        Assert.Equal("flat", captured!.InputLayout);
        var check = Assert.Single(checks);
        Assert.Equal("ok", check.State);
        Assert.StartsWith("flat, ", check.Detail);
    }

    [Fact]
    public void An_image_with_no_raw_data_to_compare_is_reported_unknown()
    {
        var (captured, checks) = Capture(Image(new SectionSpec(".bss", 0xC0000080, [])), ImageLayout.Mapped);

        Assert.Equal("unknown", captured!.InputLayout);
        var check = Assert.Single(checks);
        Assert.Equal("unknown", check.State);
        Assert.Contains("no section with raw data", check.Detail);
    }
}