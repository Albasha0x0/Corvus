using System.Buffers.Binary;
using Corvus.Native.Dump.Rebuild;

namespace Corvus.Tests;

/// <summary>The parse check of a rebuilt image with a CLR header.</summary>
public sealed class PeVerifyTests
{
    private static RebuildCheck Parse(byte[] pe)
    {
        var checks = new List<RebuildCheck>();
        PeVerify.Check(pe, new RebuildTarget("m.dll", 0x180000000, (uint)pe.Length, ModuleOrigin.Listed), checks);
        return Assert.Single(checks);
    }

    private static byte[] Edited(Action<byte[], int> edit)
    {
        var pe = ManagedHeaderFixtures.Managed(false);
        edit(pe, ManagedHeaderFixtures.TextAt(pe));
        return pe;
    }

    [Fact]
    public void A_valid_clr_header_passes_the_parse_check()
    {
        Assert.Equal("ok", Parse(ManagedHeaderFixtures.Managed(false)).State);
    }

    [Fact]
    public void A_native_image_passes_the_parse_check()
    {
        var pe = RebuildFixtures.Pe(new PeSpec(true, [new SectionSpec(".text", 0x60000020, new byte[0x100])]));

        Assert.Equal("ok", Parse(pe).State);
    }

    [Fact]
    public void A_clr_header_with_a_zero_size_fails_the_parse_check()
    {
        var check = Parse(Edited((pe, at) => BinaryPrimitives.WriteUInt32LittleEndian(pe.AsSpan(at), 0)));

        Assert.Equal("failed", check.State);
        Assert.Contains("size is 0", check.Detail);
    }

    [Fact]
    public void A_clr_header_without_a_metadata_rva_fails_the_parse_check()
    {
        var check = Parse(Edited((pe, at) => BinaryPrimitives.WriteUInt32LittleEndian(pe.AsSpan(at + 8), 0)));

        Assert.Equal("failed", check.State);
        Assert.Contains("no metadata", check.Detail);
    }

    [Fact]
    public void A_metadata_rva_outside_the_image_fails_the_parse_check()
    {
        var check = Parse(Edited((pe, at) => BinaryPrimitives.WriteUInt32LittleEndian(pe.AsSpan(at + 8), 0x900000)));

        Assert.Equal("failed", check.State);
        Assert.Contains("outside the image", check.Detail);
    }

    [Fact]
    public void A_metadata_root_without_the_signature_fails_the_parse_check()
    {
        var check = Parse(Edited((pe, at) => pe[at + (int)(ManagedHeaderFixtures.MetadataRva - ManagedHeaderFixtures.ClrRva)] = 0));

        Assert.Equal("failed", check.State);
        Assert.Contains("BSJB", check.Detail);
    }
}
