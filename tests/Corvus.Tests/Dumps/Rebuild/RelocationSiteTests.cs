using System.Buffers.Binary;
using Corvus.Native.Dump;
using Corvus.Native.Dump.Rebuild;

namespace Corvus.Tests;

/// <summary>Relocation sites undone only where the loader applied them.</summary>
public sealed class RelocationSiteTests : IDisposable
{
    private const ulong Loaded = 0x180000000UL;
    private const int First = 0x2008, Second = 0x2010;
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    private static PeSpec Spec() => new(true,
    [
        new SectionSpec(".text", 0x60000020, [0x90, 0x90, 0xC3, 0xCC]),
        new SectionSpec(".data", 0xC0000040, new byte[0x20]),
    ],
    [new PointerSite(".data", 0x08, 0x1000), new PointerSite(".data", 0x10, 0x1002)]);

    private (byte[] Image, RebuildCheck Check) Run(bool withFile, Action<byte[]>? mutate = null)
    {
        var file = RebuildFixtures.Build(Spec());
        using var dump = RebuildFixtures.Dump(_dir, new Placed("fixture.dll", file, Loaded));
        var captured = CapturedImageReader.Read(dump, RebuildTarget.Of(dump.Modules[0]), CancellationToken.None)!;
        var mapped = (byte[])captured.Image.Clone();
        mutate?.Invoke(mapped);
        var checks = new List<RebuildCheck>();
        var preferred = PeRelocations.PreferredBase.FromFile(Spec().Base, withFile ? file.Bytes : null);
        PeRelocations.Apply(mapped, captured, BaseMode.Preferred, checks, preferred);
        return (mapped, Assert.Single(checks));
    }

    private static void Put(byte[] image, int at, ulong value) => BinaryPrimitives.WriteUInt64LittleEndian(image.AsSpan(at), value);

    private static ulong At(byte[] image, int at) => BinaryPrimitives.ReadUInt64LittleEndian(image.AsSpan(at));

    private static void AsInFile(byte[] image)
    {
        Put(image, First, Spec().Base + 0x1000);
        Put(image, Second, Spec().Base + 0x1002);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void An_image_the_loader_did_not_relocate_keeps_its_bytes_and_the_check_names_it(bool withFile)
    {
        var (image, check) = Run(withFile, AsInFile);

        Assert.Equal(Spec().Base + 0x1000, At(image, First));
        Assert.Equal(Spec().Base + 0x1002, At(image, Second));
        Assert.Equal("skipped", check.State);
        Assert.Contains("not relocated", check.Detail);
        Assert.Contains("2 sites kept as in the file", check.Detail);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void An_image_whose_sites_were_applied_gets_them_undone(bool withFile)
    {
        var (image, check) = Run(withFile);

        Assert.Equal(Spec().Base + 0x1000, At(image, First));
        Assert.Equal(Spec().Base + 0x1002, At(image, Second));
        Assert.Equal("ok", check.State);
        Assert.StartsWith("2 sites undone, 0 kept as in the file, 0 changed at run time", check.Detail);
    }

    [Fact]
    public void A_site_that_changed_at_run_time_is_kept_and_counted()
    {
        ulong other = 0x7FFE00001234UL;
        var (image, check) = Run(true, i => Put(i, Second, other));

        Assert.Equal(Spec().Base + 0x1000, At(image, First));
        Assert.Equal(other, At(image, Second));
        Assert.StartsWith("1 sites undone, 0 kept as in the file, 1 changed at run time", check.Detail);
    }

    [Fact]
    public void A_site_still_holding_the_file_value_among_applied_sites_is_kept_and_counted()
    {
        var (image, check) = Run(true, i => Put(i, Second, Spec().Base + 0x1002));

        Assert.Equal(Spec().Base + 0x1002, At(image, Second));
        Assert.StartsWith("1 sites undone, 1 kept as in the file, 0 changed at run time", check.Detail);
    }
}