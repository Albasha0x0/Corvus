using System.Buffers.Binary;
using Corvus.Native.Dump;
using Corvus.Native.Dump.Rebuild;

namespace Corvus.Tests;

/// <summary>The delay-load import directory read from a mapped image.</summary>
public sealed class DelayImportReadTests
{
    private static PeSpec Spec(bool is64) => new(is64, [new SectionSpec(".text", 0x60000020, [0x90, 0xC3])]);

    private static CapturedImage Capture(PeSpec spec, byte[] mapped, params uint[] missingPages)
    {
        var pages = Enumerable.Repeat(true, mapped.Length / 0x1000).ToArray();
        foreach (uint rva in missingPages) pages[rva / 0x1000] = false;
        return new CapturedImage(new RebuildTarget("app.exe", spec.Base, (uint)mapped.Length, ModuleOrigin.Listed), mapped, pages, "mapped");
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void Delay_load_slots_are_listed_with_their_names_and_states(bool is64)
    {
        var spec = Spec(is64);
        var built = DelayImportFixtures.Build(spec, [
            new("one.dll", [DelayFunction.Named("Alpha"), DelayFunction.ByOrdinal(7)]),
            new("two.dll", [DelayFunction.Named("Beta")]),
        ]);
        var mapped = RebuildFixtures.Mapped(built.Bytes);
        DelayImportFixtures.WriteResolved(mapped, is64, built.Slot("one.dll!#7"), 0x7000_0000);

        var list = PeDelayImports.Read(mapped, Capture(spec, mapped));

        Assert.False(list.Truncated);
        Assert.Equal(65536, list.Limit);
        Assert.Equal(["one.dll", "two.dll"], list.Modules.Select(m => m.Module));
        Assert.All(list.Modules, m => Assert.Equal("ok", m.State));
        Assert.Equal(built.Descriptors[0].DescriptorRva, list.Modules[0].Descriptor);
        var one = list.Modules[0].Slots;
        Assert.Equal(("Alpha", (int?)null, "unresolved"), (one[0].Function, one[0].Ordinal, one[0].State));
        Assert.Equal(built.Slot("one.dll!Alpha").SlotRva, one[0].Rva);
        Assert.Equal((null, 7, "resolved"), (one[1].Function, one[1].Ordinal, one[1].State));
        Assert.Equal(0x7000_0000UL, one[1].Value);
        Assert.Equal(("Beta", "unresolved"), (list.Modules[1].Slots[0].Function, list.Modules[1].Slots[0].State));
    }

    [Fact]
    public void A_name_table_on_an_uncaptured_page_is_reported_unknown()
    {
        var spec = Spec(true);
        var built = DelayImportFixtures.Build(spec, [
            new("one.dll", [DelayFunction.Named(new string('x', 9000))]),
            new("two.dll", [DelayFunction.Named("Beta")]),
        ]);
        var mapped = RebuildFixtures.Mapped(built.Bytes);
        var two = built.Descriptors[1];

        var list = PeDelayImports.Read(mapped, Capture(spec, mapped, two.NameTableRva));

        Assert.Equal(2, list.Modules.Count);
        Assert.Equal(two.DescriptorRva, list.Modules[1].Descriptor);
        Assert.Equal("unknown", list.Modules[1].State);
        var slot = Assert.Single(list.Modules[1].Slots);
        Assert.Equal(("unknown", (string?)null), (slot.State, slot.Function));
    }

    [Fact]
    public void A_va_based_descriptor_is_read_from_the_image_base()
    {
        var spec = Spec(false);
        var built = DelayImportFixtures.Build(spec, [new("one.dll", [DelayFunction.Named("Alpha"), DelayFunction.ByOrdinal(9)])]);
        var mapped = RebuildFixtures.Mapped(built.Bytes);
        var d = built.Descriptors[0];
        uint b = (uint)spec.Base;
        void Put(uint at, uint value) => BinaryPrimitives.WriteUInt32LittleEndian(mapped.AsSpan((int)at), value);
        Put(d.DescriptorRva, 0);
        Put(d.DescriptorRva + 4, d.DllNameRva + b);
        Put(d.DescriptorRva + 8, d.ModuleHandleRva + b);
        Put(d.DescriptorRva + 12, d.AddressTableRva + b);
        Put(d.DescriptorRva + 16, d.NameTableRva + b);
        uint first = BinaryPrimitives.ReadUInt32LittleEndian(mapped.AsSpan((int)d.NameTableRva));
        Put(d.NameTableRva, first + b);

        var list = PeDelayImports.Read(mapped, Capture(spec, mapped));

        var module = Assert.Single(list.Modules);
        Assert.Equal(("one.dll", "ok"), (module.Module, module.State));
        Assert.Equal(["Alpha", null], module.Slots.Select(s => s.Function));
        Assert.Equal(9, module.Slots[1].Ordinal);
        Assert.All(module.Slots, s => Assert.Equal("unresolved", s.State));
    }
}
