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

    private const uint PicText = NativeFormats.ElfWriter.TextRva, PicPlt = PicText + 0x20;

    /// <summary>
    /// An i386 PIC shared object: f calls puts@plt and abort@plt, then code nothing reaches; at +0x10 a get_pc_thunk.bx
    /// and at +0x18 a call to it.
    /// </summary>
    private static (Native.Elf.ElfFile Image, NativeFormats.ElfWriter Writer) PicPltImage()
    {
        var text = new byte[0x20];
        text.AsSpan().Fill(0xCC);
        byte[] f = [0xE8, 0, 0, 0, 0, 0xE8, 0, 0, 0, 0, 0xB8, 1, 0, 0, 0, 0xC3];
        BinaryPrimitives.WriteInt32LittleEndian(f.AsSpan(1), (int)(PicPlt + 16 - (PicText + 5)));
        BinaryPrimitives.WriteInt32LittleEndian(f.AsSpan(6), (int)(PicPlt + 32 - (PicText + 10)));
        f.CopyTo(text, 0);
        byte[] thunk = [0x8B, 0x1C, 0x24, 0xC3, 0xCC, 0xCC, 0xCC, 0xCC, 0xE8, 0xF3, 0xFF, 0xFF, 0xFF];
        thunk.CopyTo(text, 0x10);
        var w = new NativeFormats.ElfWriter { Is64 = false, Machine = NativeFormats.ElfWriter.EmX86, Entry = PicText, Text = text, PltImports = ["puts", "abort"] };
        return (Native.Elf.ElfFile.FromBytes(w.Build(), "pic.so"), w);
    }

    [Fact]
    public void I386_pic_plt_stubs_are_import_thunks_and_carry_no_return()
    {
        var (image, w) = PicPltImage();
        var index = NativeCodeIndex.Build(image);
        Assert.Equal(PicPlt, w.PltRva);
        var abort = index.FunctionByStart(PicPlt + 32)!;
        Assert.Equal("abort", abort.ThunkImport?.Name);
        Assert.True(abort.Flags.HasFlag(FunctionFlags.NoReturn));
        Assert.Equal("puts", index.FunctionByStart(PicPlt + 16)!.ThunkImport?.Name);
        Assert.Equal(PicText + 10, index.FunctionByStart(PicText)!.End);
    }

    [Fact]
    public void A_thunk_query_ignores_register_values_an_earlier_walk_left()
    {
        var (image, w) = PicPltImage();
        var dec = new X86Decoder(image, new ImageCode(image), []);
        dec.BeginFunction();
        Assert.True(dec.Decode(PicText + 0x18, out _)); // call get_pc_thunk.bx: ebx known from here on
        Assert.Equal(w.PltSlotRva(0), dec.ThunkSlot(PicPlt + 16, _ => true));
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
    public void X64_pe_without_pdata_finds_unreferenced_functions_after_nop_padding()
    {
        // entry: ret; nop fill; then a function nothing references (an EFI application built with GCC has no .pdata)
        byte[] code = [0x31, 0xC0, 0xC3, 0x0F, 0x1F, 0x00, 0x66, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x53, 0x8D, 0x47, 0x01, 0x5B, 0xC3];
        var index = NativeCodeIndex.Build(CodeTestImage.Synthetic(NativeArch.X64, code, entry: Code));
        Assert.NotNull(index.FunctionByStart(Code + 0x10));
    }

    [Fact]
    public void X64_pe_gap_scan_skips_nops_after_int3_padding()
    {
        // .pdata functions at 0x1000 and 0x1010; between them ret, int3, then nop fill (as NativeAOT pads)
        byte[] code = [0x31, 0xC0, 0xC3, 0xCC, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x8D, 0x47, 0x01, 0xC3];
        var unwind = Data;
        var index = NativeCodeIndex.Build(CodeTestImage.Synthetic(NativeArch.X64, code, data: [1, 0, 0, 0], entry: Code,
            pdata: [new RuntimeFunction(Code, Code + 3, unwind), new RuntimeFunction(Code + 0x10, Code + 0x14, unwind)]));
        Assert.Equal([Code, Code + 0x10], index.Functions.Select(f => f.Start));
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void NativeAot_funclets_join_their_method(bool aot)
    {
        // a method and, right after it, a handler funclet ("sub rsp, n" first) with its own .pdata entry; the byte after each
        // entry's unwind codes holds the NativeAOT function kind (0 method, 1 handler)
        byte[] code = [0x48, 0x83, 0xEC, 0x28, 0x31, 0xC0, 0x48, 0x83, 0xC4, 0x28, 0xC3,
                       0x48, 0x83, 0xEC, 0x28, 0xB8, 0x01, 0, 0, 0, 0x48, 0x83, 0xC4, 0x28, 0xC3];
        byte[] data = new byte[0x40];
        data[0] = 1; data[8] = 1; data[12] = 1;
        var image = CodeTestImage.Synthetic(NativeArch.X64, code, data, entry: Code,
            pdata: [new RuntimeFunction(Code, Code + 11, Data), new RuntimeFunction(Code + 11, Code + 25, Data + 8)],
            exports: aot ? [new NativeExport("DotNetRuntimeDebugHeader", 1, Data + 0x20, null)] : []);
        var index = NativeCodeIndex.Build(image);
        if (!aot)
        {
            Assert.Equal([Code, Code + 11], index.Functions.Select(f => f.Start));
            return;
        }
        var method = Assert.Single(index.Functions);
        Assert.Equal(Code + 11, Assert.Single(method.Chunks).Start);
        Assert.Same(method, index.FunctionAt(Code + 20));
    }

    [Fact]
    public void Arm64_tail_jump_only_targets_become_functions_but_cold_blocks_do_not()
    {
        uint[] words =
        [
            0x14000006,             // b main
            0x11000400, 0xD65F03C0, // leaf: add w0, w0, #1; ret
            0x12800000, 0xA8C17BFD, 0xD65F03C0, // cold: mov w0, #-1; ldp x29, x30, [sp], #16; ret
            0xA9BF7BFD,             // main: stp x29, x30, [sp, #-16]!
            0x35000040,             // cbnz w0, +8
            0x17FFFFFB,             // b cold
            0xA8C17BFD,             // ldp x29, x30, [sp], #16
            0x7100141F,             // cmp w0, #5
            0x54000040,             // b.eq +8
            0x17FFFFF5,             // b leaf
            0x52800000, 0xD65F03C0, // mov w0, #0; ret
        ];
        var code = new byte[words.Length * 4];
        for (int i = 0; i < words.Length; i++) BinaryPrimitives.WriteUInt32LittleEndian(code.AsSpan(i * 4), words[i]);
        var index = NativeCodeIndex.Build(CodeTestImage.Synthetic(NativeArch.Arm64, code, entry: Code, format: ImageFormat.Elf));
        Assert.NotNull(index.FunctionByStart(Code + 4));
        Assert.Null(index.FunctionByStart(Code + 12));
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
    [InlineData(9)] // the index scaled into another frame slot (mov eax, [ebp-8]; shl eax, 2; mov [ebp-12], eax), bounded in the first, reloaded scaled
    [InlineData(10)] // the GOT pointer spilled, the slot reused on a path decoded first; the dispatch block reloads it on the path that kept it
    [InlineData(11)] // a byte element at a large GOT offset compared, then loaded: cmp byte [ebx + eax*2 + k], 2; ja; movzx ecx, byte [ebx + eax*2 + k]
    public void I386_position_independent_switch_tables_resolve(int form)
    {
        const uint Got = Data, Table = Data + 0x40;
        Label thunk = default, dflt = default, next = default, disp = default;
        var cases = new Label[3];
        var (code, rva) = Assemble(32, a =>
        {
            thunk = a.CreateLabel(); dflt = a.CreateLabel(); next = a.CreateLabel(); disp = a.CreateLabel();
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
            else if (form == 11) { a.cmp(__byte_ptr[ebx + eax * 2 + 0x123456], 2); a.ja(dflt); a.movzx(ecx, __byte_ptr[ebx + eax * 2 + 0x123456]); }
            else if (form == 10)
            {
                a.mov(__dword_ptr[esp + 8], ebx); a.test(ecx, ecx); a.jne(disp); a.mov(__dword_ptr[esp + 8], ecx); a.xor(eax, eax); a.ret();
                a.Label(ref disp); a.cmp(eax, 2); a.ja(dflt); a.mov(edx, __dword_ptr[esp + 8]);
            }
            else if (form == 9)
            {
                a.mov(__dword_ptr[ebp - 8], eax); a.mov(eax, __dword_ptr[ebp - 8]); a.shl(eax, 2); a.mov(__dword_ptr[ebp - 12], eax);
                a.xor(eax, eax); a.cmp(__dword_ptr[ebp - 8], 2); a.ja(dflt); a.mov(ecx, __dword_ptr[ebp - 12]);
            }
            else if (form != 2) { a.cmp(eax, 2); a.ja(dflt); }
            switch (form)
            {
                case 7:
                case 10: a.mov(eax, __dword_ptr[edx + eax * 4 + (int)(Table - Got)]); a.add(eax, edx); a.jmp(eax); break;
                case 8:
                case 11:
                case 6: a.mov(eax, __dword_ptr[ebx + ecx * 4 + (int)(Table - Got)]); a.add(eax, ebx); a.jmp(eax); break;
                case 4: a.mov(eax, __dword_ptr[ebx + ecx * 4 + (int)(Table - Got)]); a.add(eax, ebx); a.xchg(eax, edx); a.jmp(edx); break;
                case 5:
                case 9: a.mov(eax, __dword_ptr[ebx + ecx + (int)(Table - Got)]); a.add(eax, ebx); a.jmp(eax); break;
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

    /// <summary>
    /// A PE function reached only through "mov [ecx], offset handler" reads an array inside a large structure
    /// ([eax + ecx*4 + 0x41000], an unrelocated displacement past 64 KB, and lea of such an offset): plausible code, so the
    /// handler is a function.
    /// </summary>
    [Fact]
    public void An_address_taken_function_indexing_a_large_structure_verifies()
    {
        Label handler = default;
        var (code, rva) = Assemble(32, a =>
        {
            handler = a.CreateLabel();
            a.mov(ecx, __dword_ptr[esp + 4]);
            a.mov(__dword_ptr[ecx], 0x77777777);
            a.ret();
            a.int3();
            a.Label(ref handler);
            a.push(ebx);
            a.mov(eax, __dword_ptr[esp + 8]);
            a.mov(ecx, __dword_ptr[esp + 12]);
            a.mov(eax, __dword_ptr[eax + ecx * 4 + 0x41000]);
            a.lea(edx, __[ecx * 4 + 0x41000]);
            a.pop(ebx);
            a.ret();
        });
        int imm = code.AsSpan().IndexOf([(byte)0x77, (byte)0x77, (byte)0x77, (byte)0x77]);
        BinaryPrimitives.WriteUInt32LittleEndian(code.AsSpan(imm), 0x10000000 + rva(handler));
        var index = NativeCodeIndex.Build(CodeTestImage.Synthetic(NativeArch.X86, code, entry: Code));
        Assert.True(index.FunctionByStart(rva(handler)) is { } f && (f.Sources & FunctionSource.CodeAddress) != 0);
    }

    /// <summary>x86 PE: a function nothing references and without a frame prologue, right after known code and its int3 padding.</summary>
    [Fact]
    public void X86_pe_gap_scan_takes_code_after_int3_padding()
    {
        Label dead = default;
        var (code, rva) = Assemble(32, a =>
        {
            dead = a.CreateLabel();
            a.xor(eax, eax);
            a.ret();
            for (int k = 0; k < 13; k++) a.int3();
            a.Label(ref dead);
            a.mov(eax, __dword_ptr[ecx + 0x18]);
            a.test(eax, eax);
            a.ret();
        });
        var index = NativeCodeIndex.Build(CodeTestImage.Synthetic(NativeArch.X86, code, entry: Code));
        Assert.Equal(16u, rva(dead) - Code);
        Assert.True(index.FunctionByStart(rva(dead)) is { } f && (f.Sources & FunctionSource.CodeGap) != 0);
    }
}
