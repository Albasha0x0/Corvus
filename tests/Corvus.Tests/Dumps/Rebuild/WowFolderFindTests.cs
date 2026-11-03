using System.Buffers.Binary;
using Corvus.Native.Dump.Rebuild;

namespace Corvus.Tests;

/// <summary>A module recorded under the system folder takes its same-build file from the WOW64 folder.</summary>
public sealed class WowFolderFindTests : IDisposable
{
    private readonly TempDir _dir = new();

    public void Dispose()
    {
        DiskCompare.SystemFolders.Value = null;
        _dir.Dispose();
    }

    private static PeSpec Spec() => new(true,
    [
        new SectionSpec(".text", 0x60000020, [0x90, 0x90, 0xC3, 0xCC]),
        new SectionSpec(".data", 0xC0000040, new byte[0x20]),
    ],
    [new PointerSite(".data", 0x08, 0x1000)]);

    [Fact]
    public void A_file_only_in_the_wow64_folder_gives_the_preferred_base_and_the_comparison()
    {
        string system = Directory.CreateDirectory(_dir.File("system")).FullName;
        string wow = Directory.CreateDirectory(_dir.File("wow")).FullName;
        File.WriteAllBytes(Path.Combine(wow, "probe.dll"), RebuildFixtures.Pe(Spec()));
        DiskCompare.SystemFolders.Value = (system, wow);
        using var dump = RebuildFixtures.Dump(_dir, new Placed(Path.Combine(system, "probe.dll"), RebuildFixtures.Build(Spec()), 0x180000000UL));
        var options = RebuildOptions.Default with { Base = BaseMode.Preferred };

        var m = ModuleRebuild.Rebuild(dump, RebuildTarget.Of(dump.Modules[0]), options, CancellationToken.None);

        Assert.Equal(Path.Combine(wow, "probe.dll"), m.Disk?.File);
        Assert.Equal("ok", m.Checks.Single(c => c.Name == "relocations").State);
        int nt = BinaryPrimitives.ReadInt32LittleEndian(m.Bytes!.AsSpan(0x3C));
        Assert.Equal(Spec().Base, BinaryPrimitives.ReadUInt64LittleEndian(m.Bytes.AsSpan(nt + 24 + 24)));
    }
}
