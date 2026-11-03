using Corvus.Native;
using Corvus.Native.Dump.Rebuild;

namespace Corvus.Tests;

/// <summary>A changed x86 or x64 code range is shown as instructions from a real boundary.</summary>
public sealed class CodeChangeTextTests
{
    private static string? Names(ulong address) => address == 0x401020 ? "target_fn" : null;

    [Fact]
    public void A_changed_range_inside_an_instruction_is_decoded_from_its_start()
    {
        // mov eax, 0x11223344 (B8 44 33 22 11) then nop; only the immediate changes.
        byte[] file = [0x90, 0xB8, 0x44, 0x33, 0x22, 0x11, 0x90];
        byte[] memory = [0x90, 0xB8, 0x55, 0x33, 0x22, 0x11, 0x90];
        var text = CodeChangeText.Describe(memory, file, 0x401000, NativeArch.X64, 0, Names);
        Assert.Equal("mov eax, 11223355h; nop", text);
    }

    [Fact]
    public void Three_instructions_are_shown_with_their_targets_named()
    {
        byte[] file = [0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90];
        // nop; call 0x401020; ret; nop
        byte[] memory = [0x90, 0xE8, 0x1A, 0x00, 0x00, 0x00, 0xC3, 0x90];
        var text = CodeChangeText.Describe(memory, file, 0x401000, NativeArch.X64, 0, Names);
        Assert.Equal("call target_fn; ret; nop", text);
    }

    [Fact]
    public void Without_a_known_start_the_text_says_so()
    {
        byte[] file = [0x90, 0x90, 0x90];
        byte[] memory = [0x90, 0xC3, 0x90];
        var text = CodeChangeText.Describe(memory, file, 0x401000, NativeArch.X64, -1, Names);
        Assert.Equal("ret; nop (from the range start)", text);
    }

    [Fact]
    public void Bytes_that_do_not_decode_return_null()
    {
        byte[] file = [0x90, 0x90];
        byte[] memory = [0x90, 0x06];
        Assert.Null(CodeChangeText.Describe(memory, file, 0x401000, NativeArch.X64, -1, Names));
        Assert.Null(CodeChangeText.Describe(memory, file, 0x401000, NativeArch.Arm64, 0, Names));
    }

    [Fact]
    public void A_32_bit_range_is_decoded_with_32_bit_registers()
    {
        byte[] file = [0x55, 0x8B, 0xEC, 0x90];
        byte[] memory = [0x55, 0x8B, 0xE5, 0x90];
        var text = CodeChangeText.Describe(memory, file, 0x401000, NativeArch.X86, 0, Names);
        Assert.Equal("mov esp, ebp; nop", text);
    }

    [Theory]
    [InlineData(NativeArch.X86)]
    [InlineData(NativeArch.X64)]
    public void File_bytes_that_do_not_decode_keep_the_range_start_suffix(NativeArch machine)
    {
        // Regression for 5f8b7e2b5: the suffix was dropped though decoding began at the range start.
        byte[] file = [0x0F, 0x04, 0x90, 0x90];
        byte[] memory = [0x0F, 0x04, 0x90, 0xC3];
        var text = CodeChangeText.Describe(memory, file, 0x401000, machine, 0, Names);
        Assert.Equal("ret " + CodeChangeText.FromRangeStart, text);
    }

    [Theory]
    [InlineData(NativeArch.X86)]
    [InlineData(NativeArch.X64)]
    public void A_known_start_at_the_file_end_keeps_the_range_start_suffix(NativeArch machine)
    {
        byte[] file = [0x90, 0x90];
        byte[] memory = [0x90, 0x90, 0xC3];
        var text = CodeChangeText.Describe(memory, file, 0x401000, machine, 2, Names);
        Assert.Equal("ret " + CodeChangeText.FromRangeStart, text);
    }

    [Theory]
    [InlineData(NativeArch.X86)]
    [InlineData(NativeArch.X64)]
    public void A_known_start_before_the_range_has_no_suffix(NativeArch machine)
    {
        byte[] file = [0xB8, 0, 0, 0, 0, 0xC3];
        byte[] memory = [0xB8, 0, 0x44, 0, 0, 0xC3];
        Assert.Equal("mov eax, 4400h; ret", CodeChangeText.Describe(memory, file, 0x401000, machine, 0, Names));
    }

    [Theory]
    [InlineData(NativeArch.X86)]
    [InlineData(NativeArch.X64)]
    public void Memory_changed_before_the_range_decodes_from_the_range_start(NativeArch machine)
    {
        // The lead-in holds an earlier change inside the instruction that holds the range start.
        byte[] file = [0xB8, 0, 0, 0, 0, 0xC3, 0x90];
        byte[] memory = [0xB9, 0, 0, 0xC3, 0x90, 0xC3, 0x90];
        var text = CodeChangeText.Describe(memory, file, 0x401000, machine, 0, Names, rangeStart: 3);
        Assert.Equal("ret; nop; ret " + CodeChangeText.FromRangeStart, text);
    }
}
