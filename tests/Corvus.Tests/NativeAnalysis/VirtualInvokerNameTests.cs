using Iced.Intel;
using Corvus.Native;
using Corvus.Native.Code;
using static Iced.Intel.AssemblerRegisters;

namespace Corvus.Tests;

public class VirtualInvokerNameTests
{
    private const ulong Base = 0x140000000UL;
    private const uint Helper = 0x1040;

    private static byte[] Assemble(int bitness, uint rva, Action<Assembler> build)
    {
        var a = new Assembler(bitness);
        build(a);
        var stream = new MemoryStream();
        a.Assemble(new StreamCodeWriter(stream), Base + rva);
        return stream.ToArray();
    }

    private static bool X64(Action<Assembler> build) =>
        VirtualInvokerShape.Matches(Assemble(64, Helper, build), true, Base + Helper);

    private static bool X86(Action<Assembler> build) =>
        VirtualInvokerShape.Matches(Assemble(32, Helper, build), false, Base + Helper);

    private static NativeCodeIndex IndexWithHelper(Action<Assembler> helper, NativeExport[]? extra = null)
    {
        var code = new byte[0x80];
        Array.Fill(code, (byte)0xCC);
        Assemble(64, 0x1000, a =>
        {
            a.sub(rsp, 0x28);
            a.mov(rdx, rcx);
            a.mov(ecx, 25);
            a.call(Base + Helper);
            a.add(rsp, 0x28); a.ret();
        }).CopyTo(code, 0);
        Assemble(64, Helper, helper).CopyTo(code, Helper - 0x1000);
        var exports = new List<NativeExport> { new("Caller", 1, 0x1000, null) };
        if (extra != null) exports.AddRange(extra);
        return NativeCodeIndex.Build(CodeTestImage.Synthetic(NativeArch.X64, code, exports: exports.ToArray()));
    }

    private static void Standard(Assembler a)
    {
        a.mov(rax, __qword_ptr[rdx]);
        a.shl(ecx, 4);
        a.movsxd(rcx, ecx);
        a.add(rax, rcx);
        a.mov(rcx, rdx);
        a.jmp(__qword_ptr[rax + 0x138]);
    }

    // The helper is not exported; it is found only as the caller's call target.
    [Fact]
    public void A_slot_indexed_vtable_tail_call_helper_is_named_by_its_rva()
    {
        var index = IndexWithHelper(Standard);

        Assert.Equal("VirtualSlotInvoker_1040", index.FunctionAt(Helper)!.Name);
        Assert.Equal("Caller", index.FunctionAt(0x1000)!.Name);
    }

    [Fact]
    public void An_exported_helper_keeps_its_export_name()
    {
        var index = IndexWithHelper(Standard, [new NativeExport("Invoke", 2, Helper, null)]);

        Assert.Equal("Invoke", index.FunctionAt(Helper)!.Name);
    }

    [Fact]
    public void A_helper_that_jumps_through_a_rip_relative_slot_is_not_matched()
    {
        Assert.False(X64(a =>
        {
            a.mov(rax, __qword_ptr[rcx]);
            a.shl(edx, 3);
            a.add(rax, rdx);
            a.db(0xFF, 0x25, 0x00, 0x01, 0x00, 0x00);
        }));
    }

    [Fact]
    public void A_helper_without_a_slot_scale_is_not_matched()
    {
        Assert.False(X64(a =>
        {
            a.mov(rax, __qword_ptr[rcx]);
            a.add(rax, rdx);
            a.jmp(__qword_ptr[rax + 0x30]);
        }));
    }

    [Fact]
    public void A_helper_with_an_entry_offset_below_0x20_is_not_matched()
    {
        Assert.False(X64(a =>
        {
            a.mov(rax, __qword_ptr[rcx]);
            a.shl(edx, 3);
            a.add(rax, rdx);
            a.jmp(__qword_ptr[rax + 0x10]);
        }));
    }

    [Fact]
    public void A_helper_with_a_negative_entry_offset_is_not_matched()
    {
        Assert.False(X64(a =>
        {
            a.mov(rax, __qword_ptr[rcx]);
            a.shl(edx, 3);
            a.add(rax, rdx);
            a.jmp(__qword_ptr[rax - 8]);
        }));
    }

    [Fact]
    public void A_helper_that_jumps_through_an_unrelated_register_is_not_matched()
    {
        Assert.False(X64(a =>
        {
            a.mov(rax, __qword_ptr[rcx]);
            a.shl(edx, 4);
            a.add(rax, rdx);
            a.jmp(__qword_ptr[r8 + 0x30]);
        }));
    }

    [Fact]
    public void A_helper_that_jumps_through_a_stack_slot_is_not_matched()
    {
        Assert.False(X64(a =>
        {
            a.mov(rax, __qword_ptr[rcx]);
            a.shl(edx, 4);
            a.add(rax, rdx);
            a.mov(r9, __qword_ptr[rax + 0x40]);
            a.jmp(__qword_ptr[rsp + 0x20]);
        }));
    }

    [Fact]
    public void An_x86_helper_with_a_four_byte_slot_scale_is_matched()
    {
        Assert.True(X86(a =>
        {
            a.mov(eax, __dword_ptr[ecx]);
            a.shl(edx, 2);
            a.add(eax, edx);
            a.jmp(__dword_ptr[eax + 0x40]);
        }));
    }

    [Fact]
    public void An_x86_helper_with_a_thirty_two_byte_slot_scale_is_not_matched()
    {
        Assert.False(X86(a =>
        {
            a.mov(eax, __dword_ptr[ecx]);
            a.shl(edx, 5);
            a.add(eax, edx);
            a.jmp(__dword_ptr[eax + 0x40]);
        }));
    }
}
