using Corvus.Native;
using Corvus.Native.Dump.Rebuild;

namespace Corvus.Tests;

/// <summary>Changed code with one instruction shape forms one group.</summary>
public sealed class ChangePatternsTests
{
    // Encodes mov rax, gs:[0x30]; jmp qword ptr [rax+disp32].
    private static byte[] Stub64(int disp)
        => [0x65, 0x48, 0x8B, 0x04, 0x25, 0x30, 0x00, 0x00, 0x00, 0xFF, 0xA0, .. BitConverter.GetBytes(disp)];

    // Encodes mov eax, imm32; jmp rel32.
    private static byte[] Stub32(int imm, int rel)
        => [0xB8, .. BitConverter.GetBytes(imm), 0xE9, .. BitConverter.GetBytes(rel)];

    private static ChangeShapeInput Code(ulong address, byte[] bytes, NativeArch machine, string? target = null, string kind = "code")
        => new("m.sys", ".text", kind, address, bytes.Length, bytes, machine, target);

    [Fact]
    public void Stubs_with_one_shape_and_different_offsets_form_one_group()
    {
        var rows = Enumerable.Range(0, 5).Select(i => Code(0x1000UL + (ulong)i * 0x20, Stub64(0x100 + i * 8), NativeArch.X64)).ToList();
        var group = Assert.Single(ChangePatterns.Group(rows));
        Assert.Equal(5, group.Count);
        Assert.Equal(0x1000UL, group.FirstAddress);
        Assert.Equal(0x1080UL, group.LastAddress);
        Assert.Equal(5L * rows[0].Length, group.TotalBytes);
        Assert.Equal(0, group.FirstIndex);
        Assert.Contains("gs:[N]", group.Shape);
        Assert.Contains("jmp qword ptr [rax+N]", group.Shape);
    }

    [Fact]
    public void Different_instruction_shapes_form_separate_groups()
    {
        byte[] ret = [0xC3];
        var groups = ChangePatterns.Group([
            Code(0x2000, Stub64(8), NativeArch.X64),
            Code(0x1000, ret, NativeArch.X64),
            Code(0x3000, Stub64(16), NativeArch.X64),
            Code(0x4000, ret, NativeArch.X64, target: "module"),
        ]);
        Assert.Equal(3, groups.Count);
        Assert.Equal([0x1000UL, 0x2000UL, 0x4000UL], groups.Select(g => g.FirstAddress));
        Assert.Equal([1, 2, 1], groups.Select(g => g.Count));
    }

    [Fact]
    public void Undecodable_code_groups_by_length()
    {
        // 0x06 is invalid in 64-bit mode.
        var groups = ChangePatterns.Group([
            Code(0x1000, [0x06, 0x06], NativeArch.X64),
            Code(0x2000, [0x06, 0x07], NativeArch.X64),
            Code(0x3000, [0x06, 0x06, 0x06], NativeArch.X64),
        ]);
        Assert.Equal(2, groups.Count);
        Assert.Equal(2, groups[0].Count);
        Assert.Equal("undecoded 2 bytes", groups[0].Shape);
    }

    [Fact]
    public void Stubs_in_a_32_bit_image_group_by_shape()
    {
        var group = Assert.Single(ChangePatterns.Group([
            Code(0x401000, Stub32(1, 0x10), NativeArch.X86),
            Code(0x401100, Stub32(7, 0x2000), NativeArch.X86),
        ]));
        Assert.Equal(2, group.Count);
        Assert.StartsWith("mov eax,N", group.Shape);
    }

    [Fact]
    public void Other_kinds_group_by_kind_and_length()
    {
        var groups = ChangePatterns.Group([
            Code(0x1000, new byte[8], NativeArch.X64, kind: "data"),
            Code(0x1100, new byte[8], NativeArch.X64, kind: "data"),
            Code(0x1200, new byte[16], NativeArch.X64, kind: "data"),
        ]);
        Assert.Equal([2, 1], groups.Select(g => g.Count));
    }

    [Fact]
    public void Code_that_was_not_captured_groups_as_unread()
    {
        var row = new ChangeShapeInput("m.sys", ".text", "code", 0x1000, 32, [], NativeArch.X64, null);
        Assert.Equal("unread 32 bytes", Assert.Single(ChangePatterns.Group([row])).Shape);
    }

    [Fact]
    public void Arm64_branches_with_different_offsets_form_one_group()
    {
        var groups = ChangePatterns.Group([
            Code(0x1000, [0x10, 0x00, 0x00, 0x94], NativeArch.Arm64),
            Code(0x2000, [0x20, 0x00, 0x00, 0x94], NativeArch.Arm64),
        ]);
        Assert.Equal(2, Assert.Single(groups).Count);
    }

    [Fact]
    public void An_empty_list_gives_no_groups()
        => Assert.Empty(ChangePatterns.Group([]));
}
