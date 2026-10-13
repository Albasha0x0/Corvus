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
    public void I386_pic_plt_stubs_are_import_thunks_and_carry_no_return()
    {
        const uint Text = NativeFormats.ElfWriter.TextRva, Plt = Text + 0x20;
        // f: call puts@plt; call abort@plt; then code nothing reaches
        var text = new byte[0x20];
        text.AsSpan().Fill(0xCC);
        byte[] f = [0xE8, 0, 0, 0, 0, 0xE8, 0, 0, 0, 0, 0xB8, 1, 0, 0, 0, 0xC3];
        BinaryPrimitives.WriteInt32LittleEndian(f.AsSpan(1), (int)(Plt + 16 - (Text + 5)));
        BinaryPrimitives.WriteInt32LittleEndian(f.AsSpan(6), (int)(Plt + 32 - (Text + 10)));
        f.CopyTo(text, 0);
        var w = new NativeFormats.ElfWriter { Is64 = false, Machine = NativeFormats.ElfWriter.EmX86, Entry = Text, Text = text, PltImports = ["puts", "abort"] };
        var index = NativeCodeIndex.Build(Native.Elf.ElfFile.FromBytes(w.Build(), "pic.so"));
        Assert.Equal(Plt, w.PltRva);
        var abort = index.FunctionByStart(Plt + 32)!;
        Assert.Equal("abort", abort.ThunkImport?.Name);
        Assert.True(abort.Flags.HasFlag(FunctionFlags.NoReturn));
        Assert.Equal("puts", index.FunctionByStart(Plt + 16)!.ThunkImport?.Name);
        Assert.Equal(Text + 10, index.FunctionByStart(Text)!.End);
    }

    [Fact]
    public void Tail_jump_only_targets_outside_the_function_become_functions_but_cold_blocks_do_not()
    {
        Label leaf = default, cold = default, entry = default, after = default;
        var (code, rva) = Assemble(64, a =>
        {
            leaf = a.CreateLabel(); cold = a.CreateLabel(); entry = a.CreateLabel(); after = a.CreateLabel();
            a.jmp(entry);
            a.int3();
            // a leaf only ever tail-jumped to, before the function that jumps to it
            a.Label(ref leaf);
            a.lea(eax, __[rdi + 1]);
            a.ret();
            a.int3();
            // out-of-line code of the function below: it pops the function's own saves
            a.Label(ref cold);
            a.mov(eax, -1);
            a.pop(rbx);
            a.ret();
            a.int3();
            a.Label(ref entry);
            a.push(rbx);
            a.test(edi, edi);
            a.je(cold);
            a.cmp(edi, 5);
            a.je(after);
            a.pop(rbx);
            a.jmp(leaf);
            a.Label(ref after);
            a.xor(eax, eax);
            a.pop(rbx);
            a.ret();
        });
        var index = NativeCodeIndex.Build(CodeTestImage.Synthetic(NativeArch.X64, code, entry: Code, format: ImageFormat.Elf));
        Assert.NotNull(index.FunctionByStart(rva(leaf)));
        Assert.Null(index.FunctionByStart(rva(cold)));
        Assert.Contains(index.RefsTo(rva(leaf)), x => x.Kind == XrefKind.TailCall);
    }

    [Fact]
    public void A_short_jump_over_nops_is_alignment_fill_not_a_function()
    {
        // f: call g; ret; then GNU as fill "jmp +13; 13 x nop" up to g
        byte[] code = [0xE8, 0x10, 0, 0, 0, 0xC3, 0xEB, 0x0D, .. Enumerable.Repeat((byte)0x90, 13), 0x31, 0xC0, 0xC3];
        var index = NativeCodeIndex.Build(CodeTestImage.Synthetic(NativeArch.X86, code, entry: Code, format: ImageFormat.Elf));
        Assert.Equal([Code, Code + 0x15], index.Functions.Select(f => f.Start));
    }

    [Theory]
    [InlineData(0)] // lea r15, [rip+table] hoisted before a loop; movsxd rax, [r15 + rcx*4]; add rax, r15; jmp rax
    [InlineData(1)] // lea rax, [rip+table]; movsxd rdx, [rax + rdi*4]; add rax, rdx; jmp rax (the base is the jump register)
    [InlineData(2)] // the bound compares the memory the index is reloaded from: cmp dword [rdi], 2; ja; mov edx, [rdi]
    public void X64_relative_switch_tables_with_a_hoisted_base_or_an_indirect_bound(int form)
    {
        const uint Table = Data + 0x40;
        Label dflt = default, loop = default;
        var cases = new Label[3];
        var lea = (Register reg) => Instruction.Create(Iced.Intel.Code.Lea_r64_m, reg, new MemoryOperand(Register.RIP, (long)(0x140000000UL + Table), 8));
        var (code, rva) = Assemble(64, a =>
        {
            dflt = a.CreateLabel(); loop = a.CreateLabel();
            for (int i = 0; i < 3; i++) cases[i] = a.CreateLabel();
            switch (form)
            {
                case 0:
                    a.AddInstruction(lea(Register.R15));
                    a.Label(ref loop);
                    a.movzx(eax, __byte_ptr[r14]);
                    a.lea(ecx, __[rax - 0x61]);
                    a.cmp(ecx, 2);
                    a.ja(dflt);
                    a.movsxd(rax, __dword_ptr[r15 + rcx * 4]);
                    a.add(rax, r15);
                    a.jmp(rax);
                    break;
                case 1:
                    a.cmp(edi, 2);
                    a.ja(dflt);
                    a.AddInstruction(lea(Register.RAX));
                    a.mov(edi, edi);
                    a.movsxd(rdx, __dword_ptr[rax + rdi * 4]);
                    a.add(rax, rdx);
                    a.jmp(rax);
                    break;
                default:
                    a.cmp(__dword_ptr[rdi], 2);
                    a.mov(eax, -1);
                    a.ja(dflt);
                    a.mov(edx, __dword_ptr[rdi]);
                    a.AddInstruction(lea(Register.RAX));
                    a.movsxd(rdx, __dword_ptr[rax + rdx * 4]);
                    a.add(rax, rdx);
                    a.jmp(rax);
                    break;
            }
            for (int i = 0; i < 3; i++)
            {
                a.Label(ref cases[i]);
                a.inc(r14);
                if (form == 0) a.jmp(loop); else a.ret();
            }
            a.Label(ref dflt);
            a.xor(eax, eax);
            a.ret();
        });
        var data = new byte[0x100];
        for (int i = 0; i < 3; i++) BinaryPrimitives.WriteInt32LittleEndian(data.AsSpan(0x40 + i * 4), (int)(rva(cases[i]) - Table));
        var index = NativeCodeIndex.Build(CodeTestImage.Synthetic(NativeArch.X64, code, data, entry: Code, format: ImageFormat.Elf));
        var sw = Assert.Single(index.GetGraph(index.FunctionByStart(Code)!).Switches);
        Assert.Equal(Table, sw.TableRva);
        Assert.Equal(cases.Select(rva), sw.Targets);
        Assert.Equal(rva(dflt), sw.Default);
    }

    [Theory]
    [InlineData(0)] // get_pc_thunk.bx; mov eax, [ebx + eax*4 + k]; add eax, ebx; jmp eax
    [InlineData(1)] // get_pc_thunk.dx; add edx, [edx + eax*4 + k]; jmp edx
    [InlineData(2)] // call $+5; pop ebp; mov eax, [ebp + eax*4 + k]; lea eax, [eax + ebp]; jmp eax, bound before the GOT setup
    [InlineData(3)] // get_pc_thunk.bx; the index scaled by lea before the load; the GOT pointer copied to esi
    [InlineData(4)] // bound on the memory the index is reloaded from; the target exchanged into the jump register
    [InlineData(5)] // the index scaled and masked before the load: and ecx, 8 bounds it to 3 entries
    [InlineData(6)] // a byte compared in memory, then loaded: cmp byte [esi], 2; ja; movzx ecx, byte [esi]
    [InlineData(7)] // the GOT pointer spilled to the stack and reloaded (past a push) into another register for the dispatch
    [InlineData(8)] // a byte element compared in memory, then loaded: cmp byte [eax + esi], 2; ja; movzx ecx, byte [eax + esi]
    public void I386_position_independent_switch_tables_resolve(int form)
    {
        const uint Got = Data, Table = Data + 0x40;
        Label thunk = default, dflt = default, next = default;
        var cases = new Label[3];
        var (code, rva) = Assemble(32, a =>
        {
            thunk = a.CreateLabel(); dflt = a.CreateLabel(); next = a.CreateLabel();
            for (int i = 0; i < 3; i++) cases[i] = a.CreateLabel();
            a.mov(eax, __dword_ptr[esp + 4]);
            var got = form switch { 1 => edx, 2 => ebp, 3 => esi, _ => ebx };
            if (form == 2)
            {
                a.cmp(eax, 2);
                a.ja(dflt);
                a.call(next);
                a.Label(ref next);
                a.pop(ebp);
            }
            else
            {
                a.call(thunk);
                a.Label(ref next);
            }
            a.add(form == 3 ? ebx : got, 0x7777); // patched below: GOT - next
            if (form == 3) a.mov(esi, ebx);
            if (form == 4) { a.cmp(__dword_ptr[esp + 4], 2); a.ja(dflt); a.mov(ecx, __dword_ptr[esp + 4]); }
            else if (form == 5) { a.lea(ecx, __[eax * 4]); a.and(ecx, 8); }
            else if (form == 7) { a.mov(__dword_ptr[esp + 8], ebx); a.xor(ebx, ebx); a.push(ecx); a.cmp(eax, 2); a.ja(dflt); a.mov(edx, __dword_ptr[esp + 12]); a.pop(ecx); }
            else if (form == 6) { a.mov(esi, eax); a.cmp(__byte_ptr[esi], 2); a.ja(dflt); a.movzx(ecx, __byte_ptr[esi]); }
            else if (form == 8) { a.xor(esi, esi); a.cmp(__byte_ptr[eax + esi], 2); a.ja(dflt); a.movzx(ecx, __byte_ptr[eax + esi]); }
            else if (form != 2) { a.cmp(eax, 2); a.ja(dflt); }
            switch (form)
            {
                case 7: a.mov(eax, __dword_ptr[edx + eax * 4 + (int)(Table - Got)]); a.add(eax, edx); a.jmp(eax); break;
                case 8:
                case 6: a.mov(eax, __dword_ptr[ebx + ecx * 4 + (int)(Table - Got)]); a.add(eax, ebx); a.jmp(eax); break;
                case 4: a.mov(eax, __dword_ptr[ebx + ecx * 4 + (int)(Table - Got)]); a.add(eax, ebx); a.xchg(eax, edx); a.jmp(edx); break;
                case 5: a.mov(eax, __dword_ptr[ebx + ecx + (int)(Table - Got)]); a.add(eax, ebx); a.jmp(eax); break;
                case 1: a.add(edx, __dword_ptr[edx + eax * 4 + (int)(Table - Got)]); a.jmp(edx); break;
                case 2: a.mov(eax, __dword_ptr[ebp + eax * 4 + (int)(Table - Got)]); a.lea(eax, __[eax + ebp]); a.jmp(eax); break;
                case 3: a.lea(ecx, __[eax * 4]); a.mov(eax, __dword_ptr[esi + ecx + (int)(Table - Got)]); a.add(eax, esi); a.jmp(eax); break;
                default: a.mov(eax, __dword_ptr[ebx + eax * 4 + (int)(Table - Got)]); a.add(eax, ebx); a.jmp(eax); break;
            }
            for (int i = 0; i < 3; i++) { a.Label(ref cases[i]); a.mov(eax, i + 1); a.ret(); }
            a.Label(ref dflt);
            a.xor(eax, eax);
            a.ret();
            a.Label(ref thunk);
            a.mov(form == 1 ? edx : ebx, __dword_ptr[esp]);
            a.ret();
        });
        int add = code.AsSpan().IndexOf([(byte)0x77, (byte)0x77, (byte)0, (byte)0]);
        BinaryPrimitives.WriteUInt32LittleEndian(code.AsSpan(add), Got - rva(next));
        var data = new byte[0x100];
        for (int i = 0; i < 3; i++) BinaryPrimitives.WriteInt32LittleEndian(data.AsSpan(0x40 + i * 4), (int)(rva(cases[i]) - Got));
        var index = NativeCodeIndex.Build(CodeTestImage.Synthetic(NativeArch.X86, code, data, entry: Code, format: ImageFormat.Elf));
        var sw = Assert.Single(index.GetGraph(index.FunctionByStart(Code)!).Switches);
        Assert.Equal(Table, sw.TableRva);
        Assert.Equal(cases.Select(rva), sw.Targets);
        Assert.Equal(form == 5 ? null : rva(dflt), sw.Default);
    }
}
