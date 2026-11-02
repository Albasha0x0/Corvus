using System.Buffers.Binary;
using Corvus.Native.Dump.Rebuild;

namespace Corvus.Tests;

/// <summary>Modules rebuilt in file layout from a synthetic minidump.</summary>
public sealed class FileLayoutTests : IDisposable
{
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    private static PeSpec Spec() => new(true,
    [
        new SectionSpec(".text", 0x60000020, Enumerable.Range(1, 0x300).Select(i => (byte)i).ToArray()),
        new SectionSpec(".data", 0xC0000040, Enumerable.Range(1, 0x1200).Select(i => (byte)(i * 7)).ToArray()),
    ]);

    private RebuiltModule Rebuild(Placed placed)
    {
        using var dump = RebuildFixtures.Dump(_dir, placed);
        var target = Assert.Single(ModuleRebuild.Select(dump, placed.Name, default));
        return ModuleRebuild.Rebuild(dump, target, RebuildOptions.Default with { Layout = OutputLayout.File, Base = BaseMode.Preferred, CompareWithDisk = false }, default);
    }

    [Fact]
    public void A_mapped_module_rebuilt_in_file_layout_matches_the_original_file()
    {
        var original = RebuildFixtures.Pe(Spec());
        var rebuilt = Rebuild(new Placed("lay.dll", RebuildFixtures.Build(Spec()), 0x180000000));

        Assert.Null(rebuilt.Refused);
        Assert.Equal(original, rebuilt.Bytes);
        Assert.Contains(rebuilt.Checks, c => c.Name == "layout" && c.State == "ok" && c.Detail.Contains("overlay"));
        Assert.Contains(rebuilt.Checks, c => c.Name == "parse" && c.State == "ok");
    }

    [Fact]
    public void A_section_with_missing_pages_is_written_with_zeros_and_reported_partial()
    {
        var built = RebuildFixtures.Build(Spec());
        var rebuilt = Rebuild(new Placed("gap.dll", built, 0x180000000, OmittedPages: [0x3000]));

        var layout = Assert.Single(rebuilt.Checks, c => c.Name == "layout");
        Assert.Equal("partial", layout.State);
        Assert.Contains(".data 512 bytes", layout.Detail);
        int nt = BinaryPrimitives.ReadInt32LittleEndian(rebuilt.Bytes.AsSpan(0x3C));
        int table = nt + 24 + BinaryPrimitives.ReadUInt16LittleEndian(rebuilt.Bytes.AsSpan(nt + 20));
        int raw = (int)BinaryPrimitives.ReadUInt32LittleEndian(rebuilt.Bytes.AsSpan(table + 40 + 20));
        Assert.Equal(RebuildFixtures.Pe(Spec()).AsSpan(raw, 0x1000).ToArray(), rebuilt.Bytes.AsSpan(raw, 0x1000).ToArray());
        Assert.All(rebuilt.Bytes.AsSpan(raw + 0x1000, 0x200).ToArray(), b => Assert.Equal(0, b));
    }
}