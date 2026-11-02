using System.Buffers.Binary;
using Corvus.Native.Dump.Rebuild;

namespace Corvus.Tests;

/// <summary>The file a module was loaded from is found on disk and checked to be the same build.</summary>
public sealed class DiskFindTests : IDisposable
{
    private const uint Stamp = 0x5F5E1234;
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    private static byte[] Image(uint stamp)
    {
        var bytes = RebuildFixtures.Pe(new PeSpec(true, [new SectionSpec(".text", 0x60000020, [0x90, 0xC3])]));
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(BinaryPrimitives.ReadInt32LittleEndian(bytes.AsSpan(0x3C)) + 8), stamp);
        return bytes;
    }

    private RebuiltModule Rebuild(uint diskStamp, out string folder)
    {
        folder = Directory.CreateDirectory(_dir.File("bin")).FullName;
        File.WriteAllBytes(Path.Combine(folder, "probe.dll"), Image(diskStamp));
        var built = new PeBuilt(Image(Stamp), new Dictionary<string, uint>());
        using var dump = RebuildFixtures.Dump(_dir, new Placed("probe.dll", built, 0x180000000UL));
        var options = RebuildOptions.Default with { ImageDirectories = $"{_dir.File("missing")};{folder}" };
        return ModuleRebuild.Rebuild(dump, RebuildTarget.Of(dump.Modules[0]), options, CancellationToken.None);
    }

    [Fact]
    public void The_file_of_the_same_build_is_found_through_the_image_directories()
    {
        var m = Rebuild(Stamp, out var folder);

        Assert.Equal(Path.Combine(folder, "probe.dll"), m.Disk?.File);
        Assert.True(m.Disk!.SameBuild);
        Assert.Equal(0, m.Disk.DifferingBytes);
        Assert.Equal("ok", Assert.Single(m.Checks, c => c.Name == "disk").State);
    }

    [Fact]
    public void A_file_of_another_build_is_not_used()
    {
        var m = Rebuild(Stamp + 1, out var folder);

        Assert.Null(m.Disk);
        var check = Assert.Single(m.Checks, c => c.Name == "disk");
        Assert.Equal("skipped", check.State);
        Assert.Contains(folder, check.Detail);
    }
}
