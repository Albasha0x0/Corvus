using System.Buffers.Binary;
using Corvus.Native.Dump;
using Corvus.Native.Dump.Rebuild;

namespace Corvus.Tests;

/// <summary>Loader relocations undone or kept when a module is rebuilt.</summary>
public sealed class RelocationTests : IDisposable
{
    private const ulong Loaded = 0x180000000UL;
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    private static PeSpec Spec() => new(true,
    [
        new SectionSpec(".text", 0x60000020, [0x90, 0x90, 0xC3, 0xCC]),
        new SectionSpec(".data", 0xC0000040, new byte[0x20]),
    ],
    [new PointerSite(".data", 0x08, 0x1000), new PointerSite(".data", 0x10, 0x1002)]);

    private RebuiltModule Rebuild(BaseMode mode, params uint[] omitted)
    {
        var image = RebuildFixtures.Build(Spec());
        string folder = Directory.CreateDirectory(_dir.File("bin")).FullName;
        File.WriteAllBytes(Path.Combine(folder, "fixture.dll"), image.Bytes);
        using var dump = RebuildFixtures.Dump(_dir, new Placed("fixture.dll", image, Loaded, OmittedPages: omitted));
        var options = RebuildOptions.Default with { Base = mode, CompareWithDisk = false, Layout = OutputLayout.Mapped, ImageDirectories = folder };
        return ModuleRebuild.Rebuild(dump, RebuildTarget.Of(dump.Modules[0]), options, CancellationToken.None);
    }

    private static ulong At(RebuiltModule m, int offset) => BinaryPrimitives.ReadUInt64LittleEndian(m.Bytes!.AsSpan(offset));

    [Fact]
    public void A_module_loaded_at_another_base_gets_its_preferred_addresses_back()
    {
        var m = Rebuild(BaseMode.Preferred);

        Assert.Equal(Spec().Base + 0x1000, At(m, 0x2008));
        Assert.Equal(Spec().Base + 0x1002, At(m, 0x2010));
        var check = Assert.Single(m.Checks, c => c.Name == "relocations");
        Assert.Equal("ok", check.State);
        Assert.StartsWith("2 sites undone", check.Detail);
    }

    [Fact]
    public void A_relocation_on_a_page_not_captured_is_counted_as_skipped()
    {
        var m = Rebuild(BaseMode.Preferred, 0x2000);

        Assert.Equal(0UL, At(m, 0x2008));
        var check = Assert.Single(m.Checks, c => c.Name == "relocations");
        Assert.Equal("partial", check.State);
        Assert.Contains("2 skipped", check.Detail);
    }

    [Fact]
    public void The_loaded_base_mode_records_the_base_the_module_ran_at()
    {
        var m = Rebuild(BaseMode.Loaded);

        Assert.Equal(Loaded + 0x1000, At(m, 0x2008));
        int nt = BinaryPrimitives.ReadInt32LittleEndian(m.Bytes!.AsSpan(0x3C));
        Assert.Equal(Loaded, BinaryPrimitives.ReadUInt64LittleEndian(m.Bytes.AsSpan(nt + 24 + 24)));
        var check = Assert.Single(m.Checks, c => c.Name == "relocations");
        Assert.Equal(("ok", "kept at the loaded base"), (check.State, check.Detail));
    }

    private (byte[] Image, List<RebuildCheck> Checks) ApplyToRewrittenHeader(PeRelocations.PreferredBase preferred)
    {
        var image = RebuildFixtures.Build(Spec());
        using var dump = RebuildFixtures.Dump(_dir, new Placed("fixture.dll", image, Loaded));
        var captured = CapturedImageReader.Read(dump, RebuildTarget.Of(dump.Modules[0]), CancellationToken.None)!;
        var mapped = (byte[])captured.Image.Clone();
        int nt = BinaryPrimitives.ReadInt32LittleEndian(mapped.AsSpan(0x3C));
        BinaryPrimitives.WriteUInt64LittleEndian(mapped.AsSpan(nt + 24 + 24), Loaded);
        var checks = new List<RebuildCheck>();
        PeRelocations.Apply(mapped, captured, BaseMode.Preferred, checks, preferred);
        return (mapped, checks);
    }

    [Fact]
    public void A_header_rewritten_to_the_loaded_base_is_undone_to_the_known_preferred_base()
    {
        var (image, checks) = ApplyToRewrittenHeader(PeRelocations.PreferredBase.FromFile(Spec().Base));

        Assert.Equal(Spec().Base + 0x1000, BinaryPrimitives.ReadUInt64LittleEndian(image.AsSpan(0x2008)));
        int nt = BinaryPrimitives.ReadInt32LittleEndian(image.AsSpan(0x3C));
        Assert.Equal(Spec().Base, BinaryPrimitives.ReadUInt64LittleEndian(image.AsSpan(nt + 24 + 24)));
        Assert.Equal("ok", Assert.Single(checks).State);
    }

    [Fact]
    public void An_unknown_preferred_base_leaves_the_image_at_the_loaded_base()
    {
        var (image, checks) = ApplyToRewrittenHeader(PeRelocations.PreferredBase.Unknown);

        Assert.Equal(Loaded + 0x1000, BinaryPrimitives.ReadUInt64LittleEndian(image.AsSpan(0x2008)));
        var check = Assert.Single(checks);
        Assert.Equal("unknown", check.State);
        Assert.StartsWith("preferred base unknown", check.Detail);
    }
}
