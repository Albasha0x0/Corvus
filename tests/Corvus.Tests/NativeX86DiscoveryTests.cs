using System.Buffers.Binary;
using Iced.Intel;
using Corvus.Native;
using Corvus.Native.Code;
using static Iced.Intel.AssemblerRegisters;

namespace Corvus.Tests;

/// <summary>x86 / x64 discovery shapes: retpoline thunks, position-independent and hoisted-base switch tables, PLT stubs, tail-jump targets.</summary>
public class NativeX86DiscoveryTests
{
    private const uint Code = CodeTestImage.SyntheticCodeRva;
    private const uint Data = CodeTestImage.SyntheticDataRva;

    private static (byte[] Bytes, Func<Label, uint> Rva) Assemble(int bitness, Action<Assembler> build)
    {
        var a = new Assembler(bitness);
        build(a);
        var stream = new MemoryStream();
        ulong imageBase = bitness == 64 ? 0x140000000UL : 0x10000000UL;
        var result = a.Assemble(new StreamCodeWriter(stream), imageBase + Code, BlockEncoderOptions.ReturnNewInstructionOffsets);
        return (stream.ToArray(), label => (uint)(result.GetLabelRIP(label) - imageBase));
    }

    [Theory]
    [InlineData(64, false)]
    [InlineData(32, false)]
    [InlineData(64, true)]
    public void Retpoline_thunks_return_and_their_capture_target_is_no_function(int bitness, bool returnThunk)
    {
        Label thunk = default, capture = default, loop = default, after = default, callee = default;
        var (code, rva) = Assemble(bitness, a =>
        {
            thunk = a.CreateLabel(); capture = a.CreateLabel(); loop = a.CreateLabel(); after = a.CreateLabel(); callee = a.CreateLabel();
            // caller: call thunk, then code that must still be reached
            a.call(thunk);
            a.Label(ref after);
            a.call(callee);
            a.ret();
            a.int3();
            a.Label(ref thunk);
            a.call(capture);
            a.Label(ref loop);
            a.pause();
            a.lfence();
            a.jmp(loop);
            a.int3();
            a.Label(ref capture);
            if (returnThunk) a.lea(rsp, __[rsp + 8]);
            else if (bitness == 64) a.mov(__qword_ptr[rsp], r11);
            else a.mov(__dword_ptr[esp], eax);
            a.ret();
            a.int3();
            a.Label(ref callee);
            a.xor(eax, eax);
            a.ret();
        });
        var index = NativeCodeIndex.Build(CodeTestImage.Synthetic(bitness == 64 ? NativeArch.X64 : NativeArch.X86, code, entry: Code, format: ImageFormat.Elf));
        var f = index.FunctionByStart(rva(thunk))!;
        Assert.False(f.Flags.HasFlag(FunctionFlags.NoReturn));
        Assert.Null(index.FunctionByStart(rva(capture)));
        Assert.True(f.End > rva(capture), "the thunk covers its capture code");
        Assert.NotNull(index.FunctionByStart(rva(callee)));
        Assert.False(index.FunctionByStart(Code)!.Flags.HasFlag(FunctionFlags.NoReturn));
    }

    [Fact]
    public void A_short_jump_over_nops_is_alignment_fill_not_a_function()
    {
        // f: call g; ret; then GNU as fill "jmp +13; 13 x nop" up to g
        byte[] code = [0xE8, 0x10, 0, 0, 0, 0xC3, 0xEB, 0x0D, .. Enumerable.Repeat((byte)0x90, 13), 0x31, 0xC0, 0xC3];
        var index = NativeCodeIndex.Build(CodeTestImage.Synthetic(NativeArch.X86, code, entry: Code, format: ImageFormat.Elf));
        Assert.Equal([Code, Code + 0x15], index.Functions.Select(f => f.Start));
    }
}
