using NetDecompilerMcp.Native.Calls;
using NetDecompilerMcp.Native.Code;
using NetDecompilerMcp.Native.NativeAot;
using NetDecompilerMcp.Services;
using T = NetDecompilerMcp.Tests.NativeAotTypeTests;

namespace NetDecompilerMcp.Tests;

public class NativeAotDispatchTests
{
    [Theory]
    [InlineData((ushort)9, false)]
    [InlineData((ushort)16, false)]
    [InlineData((ushort)16, true)]
    public void Cells_InterfaceSlotAndMethod(ushort major, bool is32)
    {
        var w = T.Build(major, is32, dispatchCells: true);
        var dispatch = w.Aot.Dispatch;
        Assert.Equal(NativeAotStage.Complete, dispatch.Stage.Status);
        Assert.Equal(w.Cells, dispatch.Cells.Select(c => c.Rva));
        var first = dispatch.CellAt(w.Cells[0])!;
        Assert.Equal((w.Speaker, 0, "Speak"), (first.Interface, first.Slot, first.Method));
        var third = dispatch.CellAt(w.Cells[2])!;
        Assert.Equal((1, (string?)null, $"MT_{w.Speaker:X}::slot1"), (third.Slot, third.Method, third.Target));
        Assert.Equal([new NativeAotImplementation(w.Dog, "Sample.Zoo.Dog", T.SpeakCode)], dispatch.Implementers(w.Speaker, 0));
        Assert.Equal(T.SealedCode, Assert.Single(dispatch.Implementers(w.Speaker, 1)).Code);
        Assert.Equal(3, w.Aot.Summary().Counts["dispatchCells"]);
    }

    [Fact]
    public void Cells_NamedAndResolvedAsCallTargets()
    {
        var w = T.Build(16, dispatchCells: true);
        var built = NativeAotNames.Build(w.Aot);
        Assert.Equal($"__InterfaceDispatchCell_MT_{w.Speaker:X}__Speak", built.Names[w.Cells[0]]);
        Assert.Equal($"__InterfaceDispatchCell_MT_{w.Speaker:X}__Speak_{w.Cells[1]:X}", built.Names[w.Cells[1]]);
        Assert.Contains("interface dispatch cell: MT_", built.Comments[w.Cells[0]]);
        Assert.Contains("1 implementation(s) known: Sample.Zoo.Dog", built.Comments[w.Cells[0]]);
        Assert.Equal(3, built.Report.DispatchCells);

        // lea r11, [rip + cell]; call [r11]: the implementations of the cell's interface slot.
        var index = NativeCodeIndex.Build(w.Aot.Image, new CodeIndexOptions { SymbolStarts = [T.InterfaceCaller] });
        uint call = T.InterfaceCaller + 7;
        var site = CallTargets.At(CallAnalysis.For(index), call, deep: false)!;
        Assert.Equal(("interface_dispatch", "virtual_possible"), (site.Mechanism, site.Status));
        var target = Assert.Single(site.Targets);
        Assert.Equal((T.SpeakCode, "interface_dispatch_cell", "possible"), (target.Address, target.Basis, target.Confidence));
        Assert.Contains($"Sample.Zoo.Dog: MT_{w.Speaker:X}::Speak through the interface dispatch cell", target.Evidence);
    }
}
