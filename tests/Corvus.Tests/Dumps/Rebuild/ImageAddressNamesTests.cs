using System.Buffers.Binary;
using Corvus.Native.Dump.Rebuild;

namespace Corvus.Tests;

/// <summary>Names for code and data addresses of a mapped image.</summary>
public sealed class ImageAddressNamesTests
{
    private const uint Code = 0x60000020;
    private const uint Data = 0xC0000040;

    private static byte[] Pdata(params (uint Begin, uint End)[] entries)
    {
        var raw = new byte[entries.Length * 12];
        for (int i = 0; i < entries.Length; i++)
        {
            BinaryPrimitives.WriteUInt32LittleEndian(raw.AsSpan(12 * i), entries[i].Begin);
            BinaryPrimitives.WriteUInt32LittleEndian(raw.AsSpan(12 * i + 4), entries[i].End);
        }
        return raw;
    }

    private static ImageAddressNames Names(bool is64, byte[]? pdata)
    {
        var sections = new List<SectionSpec> { new(".text", Code, new byte[0x100]), new(".data", Data, new byte[0x100]) };
        if (pdata is not null) sections.Add(new SectionSpec(".pdata", 0x40000040, pdata));
        var spec = new PeSpec(is64, sections, Exports: [new ExportSpec("Start", 0x1000), new ExportSpec("Table", 0x2010)]);
        return ImageAddressNames.For(RebuildFixtures.Mapped(RebuildFixtures.Pe(spec)), spec.Base);
    }

    [Fact]
    public void A_code_address_is_named_by_its_pdata_function()
    {
        var names = Names(true, Pdata((0x1000, 0x1040), (0x1040, 0x1080)));
        Assert.Equal("Start", names.NameAt(0x1020));
        Assert.Equal("sub_140001040", names.NameAt(0x1044));
    }

    [Fact]
    public void A_data_address_is_named_by_the_export_below_it()
    {
        var names = Names(true, Pdata((0x1000, 0x1040)));
        Assert.Equal("Table+0x8", names.NameAt(0x2018));
        Assert.Equal(".data+0x4", names.NameAt(0x2004));
    }

    [Fact]
    public void Without_pdata_the_name_is_marked_approximate()
    {
        var names = Names(false, null);
        Assert.False(names.HasFunctionTable);
        Assert.Equal("~Start+0x20", names.NameAt(0x1020));
    }
}
