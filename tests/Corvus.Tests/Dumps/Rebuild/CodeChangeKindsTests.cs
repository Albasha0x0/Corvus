using Corvus.Native.Dump.Rebuild;

namespace Corvus.Tests;

/// <summary>A changed code range is described as a jump or call with its target, or as bytes.</summary>
public sealed class CodeChangeKindsTests
{
    private static readonly byte[] Original = [0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x10, 0x90, 0x90, 0x90, 0x90];

    [Fact]
    public void A_rel32_jump_over_a_function_start_is_described_with_its_target()
    {
        byte[] jump = [0xE9, 0xFB, 0x0F, 0x00, 0x00];
        var change = CodeChangeKinds.Describe(jump, Original, 0x401000, is64: false);
        Assert.Equal("jump", change.Kind);
        Assert.Equal(0x402000UL, change.Target);
        Assert.False(change.Indirect);

        byte[] call = [0xE8, 0xFB, 0x0F, 0x00, 0x00];
        Assert.Equal("call", CodeChangeKinds.Describe(call, Original, 0x401000, is64: true).Kind);
        byte[] shortJump = [0xEB, 0x10];
        Assert.Equal(0x401012UL, CodeChangeKinds.Describe(shortJump, Original, 0x401000, is64: true).Target);
    }

    [Fact]
    public void An_indirect_jump_through_a_pointer_reports_the_pointer_address()
    {
        byte[] rip = [0xFF, 0x25, 0xFA, 0x0F, 0x00, 0x00];
        var x64 = CodeChangeKinds.Describe(rip, Original, 0x140001000, is64: true);
        Assert.Equal("jump", x64.Kind);
        Assert.Equal(0x140002000UL, x64.Target);
        Assert.True(x64.Indirect);

        byte[] absolute = [0xFF, 0x25, 0x00, 0x30, 0x40, 0x00];
        var x86 = CodeChangeKinds.Describe(absolute, Original, 0x401000, is64: false);
        Assert.Equal(0x403000UL, x86.Target);
        Assert.True(x86.Indirect);
    }

    [Fact]
    public void A_load_of_an_address_then_a_jump_or_a_push_then_a_return_names_the_address()
    {
        byte[] mov = [0x48, 0xB8, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0xFF, 0xE0];
        Assert.Equal(0x1122334455667788UL, CodeChangeKinds.Describe(mov, Original, 0x1000, is64: true).Target);
        byte[] push = [0x68, 0x00, 0x50, 0x40, 0x00, 0xC3];
        var change = CodeChangeKinds.Describe(push, Original, 0x401000, is64: false);
        Assert.Equal("jump", change.Kind);
        Assert.Equal(0x405000UL, change.Target);
    }

    [Fact]
    public void Other_changed_bytes_are_described_as_bytes()
    {
        byte[] other = [0x90, 0x90, 0xCC];
        var change = CodeChangeKinds.Describe(other, Original, 0x401000, is64: false);
        Assert.Equal("bytes", change.Kind);
        Assert.Null(change.Target);
        Assert.Equal("bytes", CodeChangeKinds.Describe(Original, Original, 0x401000, is64: false).Kind);
        Assert.Equal("bytes", CodeChangeKinds.Describe([], Original, 0x401000, is64: false).Kind);
    }
}
