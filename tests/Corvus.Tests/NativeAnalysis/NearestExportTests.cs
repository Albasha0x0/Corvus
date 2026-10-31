using Corvus.Tools;

namespace Corvus.Tests;

/// <summary>resolve_address names the export before an address only when it is near.</summary>
public sealed class NearestExportTests
{
    [Fact]
    public void A_nearby_export_is_named_with_its_offset()
    {
        Assert.Equal("  nearest export before it: Foo + 0x10", NativeTools.NearestExportLine(0x1000, 0x1010, "Foo"));
    }

    [Fact]
    public void An_exact_export_address_is_named_without_an_offset()
    {
        Assert.Equal("  export Foo", NativeTools.NearestExportLine(0x1000, 0x1000, "Foo"));
    }

    [Fact]
    public void The_reach_limit_is_inclusive()
    {
        Assert.NotNull(NativeTools.NearestExportLine(0x1000, 0x2000, "Foo"));
        Assert.Null(NativeTools.NearestExportLine(0x1000, 0x2001, "Foo"));
    }

    [Fact]
    public void A_distant_export_is_not_reported_as_a_name()
    {
        Assert.Null(NativeTools.NearestExportLine(0x1000, 0x1000 + 0x447DF0, "Foo"));
    }
}
