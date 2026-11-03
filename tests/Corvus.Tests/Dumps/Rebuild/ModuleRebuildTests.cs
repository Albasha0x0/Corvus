using System.Buffers.Binary;
using Corvus.Native.Dump.Rebuild;

namespace Corvus.Tests;

/// <summary>One rebuild runs every stage in order and takes the preferred base from the file of the same build.</summary>
public sealed class ModuleRebuildTests : IDisposable
{
    private const ulong Loaded = 0x180000000UL;
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    private static PeSpec Spec() => new(true,
    [
        new SectionSpec(".text", 0x60000020, [0x90, 0x90, 0xC3, 0xCC]),
        new SectionSpec(".data", 0xC0000040, new byte[0x20]),
    ],
    [new PointerSite(".data", 0x08, 0x1000)]);

    private RebuiltModule Rebuild(bool withFile)
    {
        string folder = Directory.CreateDirectory(_dir.File("bin")).FullName;
        if (withFile) File.WriteAllBytes(Path.Combine(folder, "fixture.dll"), RebuildFixtures.Pe(Spec()));
        using var dump = RebuildFixtures.Dump(_dir, new Placed("fixture.dll", RebuildFixtures.Build(Spec()), Loaded));
        var options = RebuildOptions.Default with { Base = BaseMode.Preferred, ImageDirectories = folder };
        return ModuleRebuild.Rebuild(dump, RebuildTarget.Of(dump.Modules[0]), options, CancellationToken.None);
    }

    [Fact]
    public void The_checks_of_one_rebuild_follow_the_stage_order()
    {
        var m = Rebuild(true);

        Assert.Equal(["capture", "headers", "relocations", "imports", "loader patches", "layout", "parse", "disk"], m.Checks.Select(c => c.Name));
        Assert.Equal("ok", m.Checks.Single(c => c.Name == "capture").State);
        Assert.Equal("ok", m.Checks.Single(c => c.Name == "headers").State);
    }

    [Fact]
    public void The_preferred_base_comes_from_the_file_of_the_same_build()
    {
        var m = Rebuild(true);

        var relocations = m.Checks.Single(c => c.Name == "relocations");
        Assert.Equal("ok", relocations.State);
        int nt = BinaryPrimitives.ReadInt32LittleEndian(m.Bytes!.AsSpan(0x3C));
        Assert.Equal(Spec().Base, BinaryPrimitives.ReadUInt64LittleEndian(m.Bytes.AsSpan(nt + 24 + 24)));
    }

    [Fact]
    public void Without_a_file_the_preferred_base_is_unknown_and_the_headers_are_skipped()
    {
        var m = Rebuild(false);

        Assert.Equal("unknown", m.Checks.Single(c => c.Name == "relocations").State);
        Assert.Equal("skipped", m.Checks.Single(c => c.Name == "headers").State);
    }
}
