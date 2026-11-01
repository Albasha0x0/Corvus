using Corvus.Native.Providers;
using Corvus.Tools;

namespace Corvus.Tests;

public sealed class EngineXrefRowTests
{
    [Fact]
    public void A_call_through_a_pointer_slot_is_one_row_with_the_call_kind()
    {
        // Fixture: an engine reports a call through an import slot as Call and as Read at one site.
        var rows = NativeEngineCode.OnePerSite(
        [
            new NativeXref(0x2000, 0x5000, NativeXrefKind.Read, 0x2000),
            new NativeXref(0x2000, 0x5008, NativeXrefKind.Call, 0x2000),
            new NativeXref(0x2010, 0x5000, NativeXrefKind.Read, 0x2000),
            new NativeXref(0x2010, 0x5000, NativeXrefKind.Write, 0x2000),
        ], new HashSet<uint> { 0x5000 });
        Assert.Equal([(0x2000u, NativeXrefKind.Call), (0x2010u, NativeXrefKind.Read), (0x2010u, NativeXrefKind.Write)], rows.Select(r => (r.FromRva, r.Kind)));
    }

    [Fact]
    public void A_read_of_data_at_a_call_site_stays()
    {
        // Fixture: the read at the call's site targets data, not an import slot.
        var rows = NativeEngineCode.OnePerSite(
        [
            new NativeXref(0x2000, 0x3000, NativeXrefKind.Call, 0x2000),
            new NativeXref(0x2000, 0x6000, NativeXrefKind.Read, 0x2000),
        ], new HashSet<uint> { 0x5000 });
        Assert.Equal(2, rows.Count);
    }
}
