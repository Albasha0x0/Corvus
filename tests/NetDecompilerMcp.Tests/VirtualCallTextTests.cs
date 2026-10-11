using NetDecompilerMcp.Tools;
using static NetDecompilerMcp.Tools.NativeVirtualCallTools;

namespace NetDecompilerMcp.Tests;

/// <summary>find_virtual_calls answers in text (the fields stay in the structured content).</summary>
public sealed class VirtualCallTextTests
{
    [Fact]
    public void Report_reads_as_text_with_one_line_per_site_and_its_targets()
    {
        var report = new VirtualCallReport("app.dll", 3, 1, 1, 1, 4, 120, 5, 3, 0, false,
        [
            new("0x180001010", "Base_g+0x4", "exact", null, "this", "Base", 0, 0, "0x180003000", false, false, 1, ["Mid::f @ 0x180001100"]),
            new("0x180001020", "CallBase+0x3", "possible", null, "unknown", "Base", 1, 8, null, true, true, 2, ["Base::g @ 0x180001040", "Leaf::g @ 0x180001080"]),
            new("0x180001030", "UnknownReceiver+0x8", "unresolved", "receiver_unknown", "unknown", null, 1, 0, null, false, false, 0, []),
        ], null, ["a note"]);
        var text = NativeVirtualCallTools.Text(report);
        Assert.StartsWith("app.dll: 3 virtual call sites (1 exact, 1 possible, 1 unresolved); 4 virtual edges beside 120 direct call edges; 5 RTTI classes", text);
        Assert.Contains("  0x180001010  Base_g+0x4  call  exact  Base slot 0, receiver from this\n      -> Mid::f @ 0x180001100", text.ReplaceLineEndings("\n"));
        Assert.Contains("  0x180001020  CallBase+0x3  jump  possible  Base slot 1 (vfptr +0x8), receiver from unknown; overrides through a virtual base not included", text);
        Assert.Contains("  0x180001030  UnknownReceiver+0x8  call  unresolved (receiver_unknown)  class unknown slot 1", text);
        Assert.Contains("Note: a note", text);
        Assert.DoesNotContain("{", text);
    }
}
