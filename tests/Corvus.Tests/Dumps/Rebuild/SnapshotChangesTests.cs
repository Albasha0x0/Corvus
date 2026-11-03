using System.Buffers.Binary;
using Corvus.Native.Dump.Rebuild;

namespace Corvus.Tests;

/// <summary>One module compared across two dumps lists the ranges that differ.</summary>
public sealed class SnapshotChangesTests : IDisposable
{
    private const ulong Loaded = 0x180000000UL;
    private static readonly RebuildTarget Target = new("probe.dll", Loaded, 0, ModuleOrigin.Listed);
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    private static PeBuilt Build(Action<byte[]>? edit = null)
    {
        var code = new byte[0x40];
        Array.Fill(code, (byte)0x90);
        edit?.Invoke(code);
        return RebuildFixtures.Build(new PeSpec(true, [new SectionSpec(".text", 0x60000020, code), new SectionSpec(".data", 0xC0000040, new byte[0x40])]));
    }

    [Fact]
    public void A_run_changed_between_two_dumps_is_one_range()
    {
        using var before = RebuildFixtures.Dump(_dir, new Placed("probe.dll", Build(), Loaded));
        using var after = RebuildFixtures.Dump(_dir, new Placed("probe.dll", Build(c => { c[4] = 0xCC; c[6] = 0xCD; }), Loaded));

        var set = SnapshotChanges.Compare(before, after, Target);

        Assert.Equal("compared", set.State);
        var range = Assert.Single(set.Ranges);
        Assert.Equal(1, set.Total);
        Assert.Equal(".text", range.Section);
        Assert.Equal("0x1004", range.Rva);
        Assert.Equal(3, range.Length);
        Assert.Equal("differs", range.State);
        Assert.True(range.Code);
        Assert.Equal("909090", range.Before);
        Assert.Equal("cc90cd", range.After);
    }

    [Fact]
    public void A_module_of_another_build_is_refused_with_the_reason()
    {
        var other = Build();
        int nt = BinaryPrimitives.ReadInt32LittleEndian(other.Bytes.AsSpan(0x3C));
        BinaryPrimitives.WriteUInt32LittleEndian(other.Bytes.AsSpan(nt + 8), 0x12345678);
        using var before = RebuildFixtures.Dump(_dir, new Placed("probe.dll", Build(), Loaded));
        using var after = RebuildFixtures.Dump(_dir, new Placed("probe.dll", other, Loaded));

        var set = SnapshotChanges.Compare(before, after, Target);

        Assert.Equal("refused", set.State);
        Assert.Contains("different build", set.Reason);
        Assert.Contains("0x12345678", set.Reason);
        Assert.Empty(set.Ranges);
    }

    [Fact]
    public void A_page_missing_from_one_dump_is_an_unknown_range()
    {
        using var before = RebuildFixtures.Dump(_dir, new Placed("probe.dll", Build(), Loaded));
        using var after = RebuildFixtures.Dump(_dir, new Placed("probe.dll", Build(c => c[4] = 0xCC), Loaded, OmittedPages: [0x2000]));

        var set = SnapshotChanges.Compare(before, after, Target);

        Assert.Equal("compared", set.State);
        Assert.Equal(2, set.Total);
        Assert.Equal("differs", set.Ranges[0].State);
        var unknown = set.Ranges[1];
        Assert.Equal("unknown", unknown.State);
        Assert.Equal(".data", unknown.Section);
        Assert.Equal("0x2000", unknown.Rva);
        Assert.Equal("", unknown.Before);
        Assert.Equal("", unknown.After);
    }
}
