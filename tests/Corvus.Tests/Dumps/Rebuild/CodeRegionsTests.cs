using Corvus.Native.Dump;
using Corvus.Native.Dump.Rebuild;

namespace Corvus.Tests;

/// <summary>Executable regions with no image are read with their bytes and captured-page map.</summary>
public sealed class CodeRegionsTests : IDisposable
{
    private const ulong Image = 0x7FF6_1000_0000, Private = 0x2000_0000_0000, Second = 0x2000_0001_0000;
    private const uint Rx = 0x20, ImageType = 0x1000000;
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    // One image region and one private executable region; its second page is
    // not captured.
    private MinidumpFile Dump(params (ulong Base, ulong Size)[] extra)
    {
        var b = new MinidumpBuilder { FullMemory = true };
        b.Memory.Add((Image, new byte[0x1000]));
        b.Regions.Add(new MinidumpBuilder.Region(Image, 0x1000, Rx, Type: ImageType));
        var code = new byte[0x1000];
        code[0] = 0x55;
        code[1] = 0xC3;
        b.Memory.Add((Private, code));
        b.Regions.Add(new MinidumpBuilder.Region(Private, 0x2000, Rx));
        foreach (var (at, size) in extra)
            b.Regions.Add(new MinidumpBuilder.Region(at, size, Rx));
        b.Memory.Sort((x, y) => x.Start.CompareTo(y.Start));
        var path = _dir.File($"code-{Guid.NewGuid():N}.dmp");
        File.WriteAllBytes(path, b.Build());
        return MinidumpFile.Open(path);
    }

    [Fact]
    public void An_executable_region_with_no_image_is_read_with_its_bytes()
    {
        using var dump = Dump();

        var set = CodeRegions.Read(dump, default);

        var region = Assert.Single(set.Regions);
        Assert.Equal(Private, region.Base);
        Assert.Equal(0x2000UL, region.Size);
        Assert.Equal(Rx, region.Protect);
        Assert.Equal([0x55, 0xC3], region.Bytes[..2]);
        Assert.Equal([true, false], region.Captured);
        Assert.All(region.Bytes[0x1000..], b => Assert.Equal(0, b));
        Assert.Contains(set.Notes, n => n.Contains("captured-page map", StringComparison.Ordinal));
    }

    [Fact]
    public void An_image_region_is_not_read_as_a_code_region()
    {
        using var dump = Dump();

        var set = CodeRegions.Read(dump, default);

        Assert.DoesNotContain(set.Regions, r => r.Base == Image);
    }

    [Fact]
    public void A_region_past_the_total_bound_is_named_in_the_notes()
    {
        using var dump = Dump((Second, 0x2000));

        var set = CodeRegions.Read(dump, 256, 0x3000, default);

        Assert.Equal([Private], set.Regions.Select(r => r.Base));
        Assert.Contains(set.Notes, n => n.Contains("1 region(s)", StringComparison.Ordinal) && n.Contains("12288 bytes in total", StringComparison.Ordinal));
    }
}
