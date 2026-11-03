using Corvus.Native;
using Corvus.Native.Dump.Rebuild;

namespace Corvus.Tests;

/// <summary>Changed data groups by the module its new values point at.</summary>
public sealed class ChangePatternsDataTests
{
    private static ChangeShapeInput Data(ulong address, string? target, string section = ".data")
        => new("m.dll", section, "data", address, 8, new byte[8], NativeArch.X64, target);

    [Fact]
    public void Pointers_into_one_module_form_one_group()
    {
        var group = Assert.Single(ChangePatterns.Group([
            Data(0x1000, "kernel32.dll!CreateFileW"),
            Data(0x1008, "kernel32.dll+0x10"),
            Data(0x1010, "kernel32.dll!ReadFile"),
        ]));
        Assert.Equal(3, group.Count);
        Assert.Equal("pointers into kernel32.dll", group.Shape);
    }

    [Fact]
    public void Values_that_are_not_pointers_form_their_own_group()
    {
        var groups = ChangePatterns.Group([
            Data(0x1000, "not a pointer"),
            Data(0x1008, "kernel32.dll+0x10"),
            Data(0x1010, "not a pointer"),
            Data(0x1018, "unbacked"),
            Data(0x1020, "committed memory"),
        ]);
        Assert.Equal(4, groups.Count);
        var plain = Assert.Single(groups, g => g.Shape == "values that are not pointers");
        Assert.Equal(2, plain.Count);
    }

    [Fact]
    public void Data_and_code_rows_never_share_a_group()
    {
        byte[] ret = [0xC3];
        var groups = ChangePatterns.Group([
            Data(0x1000, "kernel32.dll+0x10"),
            new ChangeShapeInput("m.dll", ".data", "code", 0x2000, 1, ret, NativeArch.X64, "kernel32.dll+0x10"),
        ]);
        Assert.Equal(2, groups.Count);
    }
}
