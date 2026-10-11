using System.Buffers.Binary;
using System.Text;
using Iced.Intel;
using NetDecompilerMcp.Native;
using NetDecompilerMcp.Native.Code;
using static Iced.Intel.AssemblerRegisters;

namespace NetDecompilerMcp.Tests;

/// <summary>Code analysis on synthetic images (assembled with Iced) and two small system DLLs.</summary>
public class NativeCodeTests
{
    private const uint Code = CodeTestImage.SyntheticCodeRva;
    private const uint Data = CodeTestImage.SyntheticDataRva;
    private const ulong Base64 = 0x140000000UL;
    private const ulong Base32 = 0x10000000UL;

    /// <summary>Assembles at the synthetic code RVA; returns the bytes and a label -> RVA function.</summary>
    private static (byte[] Bytes, Func<Label, uint> Rva) Assemble(int bitness, Action<Assembler> build)
    {
        var a = new Assembler(bitness);
        build(a);
        ulong imageBase = bitness == 64 ? Base64 : Base32;
        var stream = new MemoryStream();
        var result = a.Assemble(new StreamCodeWriter(stream), imageBase + Code, BlockEncoderOptions.ReturnNewInstructionOffsets);
        return (stream.ToArray(), label => (uint)(result.GetLabelRIP(label) - imageBase));
    }

    /// <summary>An x64 RIP-relative instruction to an absolute RVA of the synthetic image.</summary>
    private static Instruction Rip(Iced.Intel.Code code, Register reg, uint rva) =>
        Instruction.Create(code, reg, new MemoryOperand(Register.RIP, (long)(Base64 + rva), 8));

    private static Instruction RipMem(Iced.Intel.Code code, uint rva) =>
        Instruction.Create(code, new MemoryOperand(Register.RIP, (long)(Base64 + rva), 8));

    private static NativeImport Import(string module, string name, uint slot) => new(module, name, null, 0, slot, false);

    private static Label L(Assembler a) => a.CreateLabel();

    [Fact]
    public void Disassembly_names_imports_functions_and_strings()
    {
        Label main = default, helper = default;
        var (code, rva) = Assemble(64, a =>
        {
            main = L(a); helper = L(a);
            a.Label(ref main);
            a.sub(rsp, 0x28);
            a.AddInstruction(Rip(Iced.Intel.Code.Lea_r64_m, Register.RCX, Data + 0x100));
            a.call(helper);
            a.xor(ecx, ecx);
            a.AddInstruction(RipMem(Iced.Intel.Code.Call_rm64, Data));
            a.db(0xFF, 0xFF, 0xFF, 0xFF); // not code: ExitProcess does not return
            a.Label(ref helper);
            a.ret();
        });
        var data = new byte[0x200];
        Encoding.ASCII.GetBytes("Hello, world\0").CopyTo(data, 0x100);
        var image = CodeTestImage.Synthetic(NativeArch.X64, code, data, [Import("KERNEL32.dll", "ExitProcess", Data)], entry: Code);
        var index = NativeCodeIndex.Build(image);

        Assert.Equal(CodeSupport.Full, index.Support);
        Assert.Equal([rva(main), rva(helper)], index.Functions.Select(f => f.Start));
        var f = index.FunctionByStart(rva(main))!;
        Assert.Equal(FunctionSource.EntryPoint, f.Sources);
        Assert.Equal(0, (int)(f.Flags & FunctionFlags.InvalidCode));

        var lines = index.DisassembleFunction(f, 100, out bool truncated);
        Assert.False(truncated);
        var text = string.Join("\n", lines.Select(l => l.Label ?? $"{l.Line!.Text} ; {l.Line.Comment}"));
        Assert.Contains($"call   sub_{rva(helper):X}", text);
        Assert.Contains("KERNEL32!ExitProcess", text);
        Assert.Contains("\"Hello, world\"", text);
        Assert.DoesNotContain("(bad)", text);

        var graph = index.GetGraph(f);
        Assert.Single(graph.Blocks);
        Assert.Equal(BlockEnd.NoReturnCall, graph.Blocks[0].EndKind);

        // cross-references: call, import call, string address
        Assert.Contains(index.RefsTo(rva(helper)), x => x.Kind == XrefKind.Call);
        Assert.Contains(index.RefsTo(Data), x => x.Kind == XrefKind.ImportCall);
        Assert.Contains(index.RefsTo(Data + 0x100), x => x.Kind == XrefKind.Address);
        Assert.Equal("Hello, world", index.ReadString(index.StringAt(Data + 0x100)!.Value));
        var callees = index.Callees(f);
        Assert.Contains(callees, c => c.Function?.Start == rva(helper));
        Assert.Contains(callees, c => c.Import?.Name == "ExitProcess");
        Assert.Contains(index.Callers(image.Imports[0]), c => c.Caller == f);
    }

    [Fact]
    public void Instruction_facts_report_flow_targets_and_rip_relative_operands()
    {
        var (code, _) = Assemble(64, a =>
        {
            a.AddInstruction(Rip(Iced.Intel.Code.Mov_r32_rm32, Register.EAX, Data + 8));
            a.AddInstruction(Instruction.Create(Iced.Intel.Code.Mov_rm32_r32, new MemoryOperand(Register.RIP, (long)(Base64 + Data + 12), 8), Register.EAX));
            a.ret();
        });
        var index = NativeCodeIndex.Build(CodeTestImage.Synthetic(NativeArch.X64, code, entry: Code));
        var read = index.Decode(Code)!;
        Assert.Equal(FlowKind.Next, read.Flow);
        Assert.Equal(Data + 8, read.MemoryTarget);
        Assert.True(read.MemoryIsRipRelative);
        Assert.Equal(OperandAccess.Read, read.MemoryAccess);
        var write = index.Decode(Code + (uint)read.Length)!;
        Assert.Equal(OperandAccess.Write, write.MemoryAccess);
        Assert.Contains(index.RefsTo(Data + 12), x => x.Kind == XrefKind.Write);
        Assert.Equal(FlowKind.Return, index.Decode(Code + (uint)(read.Length + write.Length))!.Flow);
    }

    /// <summary>MSVC x64: lea rdx, __ImageBase; cmp ecx, n; ja default; movsxd rax, ecx; mov ecx, [rdx+rax*4+table]; add rcx, rdx; jmp rcx.</summary>
    private static (CodeTestImage Image, uint Jump, uint[] Cases) MsvcSwitch(bool bounded)
    {
        Label start = default, dflt = default, jump = default;
        var cases = new Label[4];
        var (code, rva) = Assemble(64, a =>
        {
            start = L(a); dflt = L(a); jump = L(a);
            for (int i = 0; i < cases.Length; i++) cases[i] = L(a);
            a.Label(ref start);
            a.AddInstruction(Rip(Iced.Intel.Code.Lea_r64_m, Register.RDX, 0));
            if (bounded)
            {
                a.cmp(ecx, cases.Length - 1);
                a.ja(dflt);
            }
            a.movsxd(rax, ecx);
            a.mov(ecx, __dword_ptr[rdx + rax * 4 + (int)(Data + 0x40)]);
            a.add(rcx, rdx);
            a.Label(ref jump);
            a.jmp(rcx);
            for (int i = 0; i < cases.Length; i++)
            {
                a.Label(ref cases[i]);
                a.mov(eax, i + 10);
                a.ret();
            }
            a.Label(ref dflt);
            a.xor(eax, eax);
            a.ret();
        });
        var data = new byte[0x100];
        for (int i = 0; i < cases.Length; i++) BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(0x40 + i * 4), rva(cases[i]));
        var image = CodeTestImage.Synthetic(NativeArch.X64, code, data, entry: Code);
        return (image, rva(jump), cases.Select(rva).ToArray());
    }

    [Fact]
    public void Switch_x64_msvc_table_is_resolved_from_the_bound()
    {
        var (image, jump, cases) = MsvcSwitch(bounded: true);
        var index = NativeCodeIndex.Build(image);
        var f = Assert.Single(index.Functions);
        var graph = index.GetGraph(f);
        var table = Assert.Single(graph.Switches);
        Assert.Equal(jump, table.JumpRva);
        Assert.Equal(Data + 0x40, table.TableRva);
        Assert.Equal(4, table.EntryCount);
        Assert.Equal(cases, table.Targets);
        Assert.Empty(graph.UnresolvedJumps);
        Assert.Equal(0, (int)(f.Flags & FunctionFlags.UnresolvedJumps));
        var dispatch = graph.BlockAt(jump)!;
        Assert.Equal(BlockEnd.Switch, dispatch.EndKind);
        Assert.Equal(cases, dispatch.Successors.Where(e => e.Kind == EdgeKind.Switch).Select(e => e.To));
        foreach (var c in cases)
        {
            Assert.Contains(index.RefsTo(c), x => x.Kind == XrefKind.SwitchCase && x.From == jump);
            Assert.Contains(graph.BlockAt(c)!.Predecessors, e => e.Kind == EdgeKind.Switch);
        }
        Assert.Contains(index.RefsTo(Data + 0x40), x => x.Kind == XrefKind.JumpTable);
    }

    [Fact]
    public void Decoders_are_chosen_by_instruction_set()
    {
        var image = CodeTestImage.Synthetic(NativeArch.X64, [0xC3], entry: Code);
        var dec = CodeDecoders.Create(image, new ImageCode(image), []);
        Assert.IsType<X86Decoder>(dec);
        Assert.True(dec.Is64);
        dec.BeginRun(IndexBound.None);
        Assert.True(dec.Decode(Code, out var ret));
        Assert.Equal(FlowKind.Return, ret.Flow);
        Assert.Throws<NotSupportedException>(() => CodeDecoders.Create(CodeTestImage.Synthetic(NativeArch.Mips, [0, 0, 0, 0]), null, []));
    }

    [Fact]
    public void Switch_without_a_bound_is_reported_unresolved_not_guessed()
    {
        var (image, jump, cases) = MsvcSwitch(bounded: false);
        var index = NativeCodeIndex.Build(image);
        var f = index.FunctionByStart(Code)!;
        var graph = index.GetGraph(f);
        Assert.Empty(graph.Switches);
        Assert.Equal([jump], graph.UnresolvedJumps.Select(u => u.Rva));
        Assert.NotEqual(0, (int)(f.Flags & FunctionFlags.UnresolvedJumps));
        Assert.Equal(BlockEnd.IndirectJump, graph.BlockAt(jump)!.EndKind);
        Assert.All(cases, c => Assert.Null(graph.BlockAt(c)));
    }

    [Fact]
    public void Switch_x86_absolute_table_with_relocations()
    {
        Label start = default, dflt = default, jump = default;
        var cases = new Label[3];
        uint tableRva = Data + 0x20;
        var (code, rva) = Assemble(32, a =>
        {
            start = L(a); dflt = L(a); jump = L(a);
            for (int i = 0; i < cases.Length; i++) cases[i] = L(a);
            a.Label(ref start);
            a.mov(eax, __dword_ptr[esp + 4]);
            a.cmp(eax, 2);
            a.ja(dflt);
            a.Label(ref jump);
            a.jmp(__dword_ptr[eax * 4 + (int)(Base32 + tableRva)]);
            for (int i = 0; i < cases.Length; i++)
            {
                a.Label(ref cases[i]);
                a.mov(eax, i + 1);
                a.ret();
            }
            a.Label(ref dflt);
            a.xor(eax, eax);
            a.ret();
        });
        var data = new byte[0x100];
        var relocs = new List<uint> { rva(jump) + 3 }; // FF 24 85 disp32
        for (int i = 0; i < cases.Length; i++)
        {
            BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(0x20 + i * 4), (uint)Base32 + rva(cases[i]));
            relocs.Add(tableRva + (uint)i * 4);
        }
        var index = NativeCodeIndex.Build(CodeTestImage.Synthetic(NativeArch.X86, code, data, relocations: relocs, entry: Code));
        var graph = index.GetGraph(index.FunctionByStart(Code)!);
        var table = Assert.Single(graph.Switches);
        Assert.Equal(tableRva, table.TableRva);
        Assert.Equal(cases.Select(rva), table.Targets);
        // the table entries are data pointers, not function starts
        Assert.Single(index.Functions);
    }

    [Fact]
    public void Tail_calls_and_import_thunks()
    {
        Label caller = default, thunk = default, tail = default, target = default;
        var (code, rva) = Assemble(64, a =>
        {
            caller = L(a); thunk = L(a); tail = L(a); target = L(a);
            a.Label(ref caller);
            a.sub(rsp, 0x28);
            a.call(thunk);
            a.call(target);
            a.add(rsp, 0x28);
            a.jmp(tail); // tail call
            a.int3();
            a.Label(ref thunk);
            a.AddInstruction(RipMem(Iced.Intel.Code.Jmp_rm64, Data + 8));
            a.int3();
            a.Label(ref tail);
            a.call(target);
            a.jmp(target); // tail call to a function that is also called
            a.int3();
            a.Label(ref target);
            a.ret();
        });
        // .pdata for the caller only: its jump to "tail" leaves its range into code no entry covers (a leaf function)
        var data = new byte[0x100];
        data[0x40] = 0x01;
        var pdata = new[] { new RuntimeFunction(rva(caller), rva(thunk), Data + 0x40) };
        var image = CodeTestImage.Synthetic(NativeArch.X64, code, data, imports: [Import("KERNEL32.dll", "Sleep", Data + 8)], pdata: pdata, entry: Code);
        var index = NativeCodeIndex.Build(image);
        Assert.Equal(FunctionSource.TailJump, index.FunctionByStart(rva(tail))!.Sources);
        var t = index.FunctionByStart(rva(thunk))!;
        Assert.NotEqual(0, (int)(t.Flags & FunctionFlags.Thunk));
        Assert.Equal("j_Sleep", t.Name);
        Assert.Equal("Sleep", t.ThunkImport!.Name);
        Assert.NotNull(index.FunctionByStart(rva(tail)));

        var c = index.FunctionByStart(rva(caller))!;
        var graph = index.GetGraph(c);
        Assert.Equal([rva(tail)], graph.TailCalls);
        Assert.Contains(graph.Blocks, b => b.EndKind == BlockEnd.TailCall);
        Assert.Contains(index.RefsTo(rva(tail)), x => x.Kind == XrefKind.TailCall && index.FunctionAt(x.From) == c);
        // callers of the import go through the thunk
        Assert.Contains(index.Callers(image.Imports[0]), s => s.Caller == c);
        Assert.Contains(index.Callees(c), s => s.Function == t && s.Import?.Name == "Sleep");
        // the tail-called function does not absorb its target
        var tf = index.FunctionByStart(rva(tail))!;
        Assert.Equal(rva(target), index.GetGraph(tf).TailCalls.Single());
        var tree = index.CallTree(c, 3, callers: false);
        Assert.Contains(tree.Children, n => n.Function == tf);
        Assert.Contains(index.CallTree(index.FunctionByStart(rva(target))!, 3, callers: true).Children, n => n.Function == c);
    }

    [Fact]
    public void Jump_thunk_target_is_a_function()
    {
        Label main = default, stub = default, target = default;
        var (code, rva) = Assemble(64, a =>
        {
            main = L(a); stub = L(a); target = L(a);
            a.Label(ref main);
            a.call(stub);
            a.ret();
            a.Label(ref stub);
            a.jmp(target); // a function that is only a jump
            a.int3();
            a.Label(ref target);
            a.xor(eax, eax);
            a.ret();
        });
        var index = NativeCodeIndex.Build(CodeTestImage.Synthetic(NativeArch.X64, code, entry: Code));
        Assert.Equal(FunctionSource.TailJump, index.FunctionByStart(rva(target))!.Sources);
        Assert.Equal([rva(target)], index.GetGraph(index.FunctionByStart(rva(stub))!).TailCalls);
    }

    [Fact]
    public void X86_finally_block_called_in_its_function_stays_part_of_it()
    {
        Label main = default, fin = default, done = default;
        var (code, rva) = Assemble(32, a =>
        {
            main = L(a); fin = L(a); done = L(a);
            a.Label(ref main);
            a.push(ebp);
            a.mov(ebp, esp);
            a.sub(esp, 0x20);
            a.mov(__dword_ptr[ebp - 4], -2); // leave the guarded block
            a.call(fin);                     // run the __finally block
            a.jmp(done);
            a.Label(ref fin);
            a.cmp(__dword_ptr[ebp - 0x1C], 0);
            a.ret();
            a.Label(ref done);
            a.mov(esp, ebp);
            a.pop(ebp);
            a.ret();
        });
        var index = NativeCodeIndex.Build(CodeTestImage.Synthetic(NativeArch.X86, code, entry: Code));
        var f = Assert.Single(index.Functions);
        Assert.Equal(f, index.FunctionAt(rva(fin)));
        Assert.Contains(index.GetGraph(f).Blocks, b => b.Start == rva(fin));
        Assert.Contains(index.RefsTo(rva(fin)), x => x.Kind == XrefKind.Call);
    }

    [Fact]
    public void X86_exception_filter_reached_through_data_is_a_funclet()
    {
        Label main = default, filter = default;
        uint scopeTable = Data + 0x10;
        var (code, rva) = Assemble(32, a =>
        {
            main = L(a); filter = L(a);
            a.Label(ref main);
            a.push(ebp);
            a.mov(ebp, esp);
            a.push((int)(Base32 + scopeTable)); // push offset scope table
            a.call(__dword_ptr[(int)(Base32 + Data)]);
            a.mov(esp, ebp);
            a.pop(ebp);
            a.ret();
            a.int3();
            a.Label(ref filter);
            a.mov(eax, __dword_ptr[ebp - 0x14]); // the parent's frame
            a.mov(eax, __dword_ptr[eax]);
            a.ret();
        });
        var data = new byte[0x100];
        // scope table entry: enclosing level, filter, handler
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(0x10), 0xFFFFFFFE);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(0x14), (uint)Base32 + rva(filter));
        uint pushImm = rva(main) + 4; // 55 8b ec 68 imm32
        var relocs = new[] { pushImm, rva(main) + 3 + 5 + 2, scopeTable + 4 };
        var image = CodeTestImage.Synthetic(NativeArch.X86, code, data, [Import("KERNEL32.dll", "Sleep", Data)], relocations: relocs, entry: Code);
        var index = NativeCodeIndex.Build(image);
        var f = index.FunctionByStart(rva(filter))!;
        Assert.Equal(FunctionSource.DataPointer, f.Sources);
        Assert.NotEqual(0, (int)(f.Flags & FunctionFlags.Funclet));
        Assert.Equal(0, (int)(index.FunctionByStart(rva(main))!.Flags & FunctionFlags.Funclet));
        Assert.Contains(index.RefsTo(rva(filter)), x => x.Kind == XrefKind.Pointer && x.From == scopeTable + 4);
    }

    [Fact]
    public void Data_that_decodes_as_code_is_not_made_a_function()
    {
        Label main = default;
        uint guid = Code + 0x40;
        var (code, rva) = Assemble(32, a =>
        {
            main = L(a);
            a.Label(ref main);
            a.push((int)(Base32 + guid)); // push offset of data in the code section
            a.call(__dword_ptr[(int)(Base32 + Data)]);
            a.ret();
        });
        var bytes = new byte[0x60];
        code.CopyTo(bytes, 0);
        // a GUID: decodes as "sub [ecx+ebx*2-7A2647Ah], cl; inc ebp; mov ds:[0E9A9922Bh], eax; ..."
        byte[] g = [0x28, 0x8C, 0x59, 0x86, 0x9B, 0x5D, 0xF8, 0x45, 0xA3, 0x2B, 0x92, 0xA9, 0xE9, 0x9D, 0x96, 0x23];
        g.CopyTo(bytes, 0x40);
        var relocs = new[] { rva(main) + 1, rva(main) + 5 + 2 };
        var image = CodeTestImage.Synthetic(NativeArch.X86, bytes, imports: [Import("KERNEL32.dll", "Sleep", Data)], relocations: relocs, entry: Code);
        var index = NativeCodeIndex.Build(image);
        Assert.Single(index.Functions);
        Assert.Contains(index.RefsTo(guid), x => x.Kind == XrefKind.Address);
    }

    [Fact]
    public void Noreturn_propagates_from_imports_and_traps()
    {
        Label main = default, fatal = default, fastfail = default, after = default;
        var (code, rva) = Assemble(64, a =>
        {
            main = L(a); fatal = L(a); fastfail = L(a); after = L(a);
            a.Label(ref main);
            a.test(ecx, ecx);
            a.jne(after);
            a.call(fatal);
            a.db(0x0F, 0xFF); // garbage after a call that does not return
            a.Label(ref after);
            a.call(fastfail);
            a.db(0xD6, 0xD6);
            a.Label(ref fatal);
            a.sub(rsp, 0x28);
            a.mov(ecx, 3);
            a.AddInstruction(RipMem(Iced.Intel.Code.Call_rm64, Data));
            a.int3();
            a.Label(ref fastfail);
            a.mov(ecx, 7);
            a.@int(0x29);
        });
        var image = CodeTestImage.Synthetic(NativeArch.X64, code, imports: [Import("api-ms-win-crt-runtime-l1-1-0.dll", "abort", Data)], entry: Code);
        var index = NativeCodeIndex.Build(image);
        Assert.NotEqual(0, (int)(index.FunctionByStart(rva(fatal))!.Flags & FunctionFlags.NoReturn));
        Assert.NotEqual(0, (int)(index.FunctionByStart(rva(fastfail))!.Flags & FunctionFlags.NoReturn));
        var m = index.FunctionByStart(rva(main))!;
        Assert.NotEqual(0, (int)(m.Flags & FunctionFlags.NoReturn));
        Assert.Equal(0, (int)(m.Flags & FunctionFlags.InvalidCode));
        var graph = index.GetGraph(m);
        Assert.Equal(2, graph.Blocks.Count(b => b.EndKind == BlockEnd.NoReturnCall));
        Assert.Equal(BlockEnd.Trap, index.GetGraph(index.FunctionByStart(rva(fastfail))!).Blocks.Single().EndKind);
    }

    [Fact]
    public void Invalid_and_overlapping_bytes_are_bounded()
    {
        // nop; eb ff: jmp to its own second byte; ff c0: inc eax; then c3: ret
        byte[] overlap = [0x90, 0xEB, 0xFF, 0xC0, 0xC3];
        var index = NativeCodeIndex.Build(CodeTestImage.Synthetic(NativeArch.X64, overlap, entry: Code));
        var f = Assert.Single(index.Functions);
        Assert.NotEqual(0, (int)(f.Flags & FunctionFlags.OverlappingCode));
        var graph = index.GetGraph(f);
        Assert.Contains(graph.Blocks, b => b.Start == Code + 2);

        // valid code running into an opcode that is invalid in 64-bit mode
        byte[] invalid = [0x31, 0xC0, 0x40, 0xD6, 0xC3];
        index = NativeCodeIndex.Build(CodeTestImage.Synthetic(NativeArch.X64, invalid, entry: Code));
        f = index.FunctionByStart(Code)!;
        Assert.NotEqual(0, (int)(f.Flags & FunctionFlags.InvalidCode));
        Assert.Equal(BlockEnd.Invalid, index.GetGraph(f).Blocks.Single().EndKind);
        Assert.Equal("(bad)", index.Disassemble(Code + 3, 1).Single().Text);

        // code that runs off the end of the section
        byte[] cut = [0x90, 0x90, 0x48];
        index = NativeCodeIndex.Build(CodeTestImage.Synthetic(NativeArch.X64, cut, entry: Code));
        Assert.Equal(2, index.FunctionByStart(Code)!.InstructionCount);
    }

    [Fact]
    public void Chained_pdata_fragment_is_part_of_its_function_and_not_decoded_from_its_begin()
    {
        // primary [0x1000, 0x1010): test ecx, ecx; jne cold; ret.  fragment [0x1100, 0x1110): 4 bytes of data, then
        // cold code at 0x1104: xor eax, eax; ret.
        var code = new byte[0x110];
        code.AsSpan().Fill(0xCC);
        byte[] primary = [0x85, 0xC9, 0x0F, 0x85, 0, 0, 0, 0, 0xC3];
        BinaryPrimitives.WriteInt32LittleEndian(primary.AsSpan(4), 0x104 - 8);
        primary.CopyTo(code, 0);
        byte[] fragment = [0xFF, 0xFF, 0xFF, 0xFF, 0x31, 0xC0, 0xC3];
        fragment.CopyTo(code, 0x100);
        var data = new byte[0x100];
        // UNWIND_INFO of the primary: version 1, no codes; of the fragment: UNW_FLAG_CHAININFO + chained RUNTIME_FUNCTION
        data[0] = 0x01;
        data[0x10] = 0x01 | (4 << 3);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(0x14), Code);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(0x18), Code + 0x10);
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(0x1C), Data);
        var pdata = new[] { new RuntimeFunction(Code, Code + 0x10, Data), new RuntimeFunction(Code + 0x100, Code + 0x110, Data + 0x10) };
        var image = CodeTestImage.Synthetic(NativeArch.X64, code, data, pdata: pdata);
        var index = NativeCodeIndex.Build(image);
        var f = Assert.Single(index.Functions);
        Assert.Equal(FunctionSource.Pdata, f.Sources);
        var graph = index.GetGraph(f);
        Assert.Contains(graph.Blocks, b => b.Start == Code + 0x104);
        Assert.DoesNotContain(graph.Blocks, b => b.Start == Code + 0x100);
        Assert.Empty(graph.TailCalls);
        Assert.Equal(f, index.FunctionAt(Code + 0x105));
        Assert.Contains(index.RefsTo(Code + 0x104), x => x.Kind == XrefKind.ConditionalJump);
        Assert.Empty(NativeCodeSweepTests.PdataStartsMissing(image, index).Missing);
    }

    [Fact]
    public void Building_honors_cancellation()
    {
        var (image, _, _) = MsvcSwitch(bounded: true);
        using var cts = new CancellationTokenSource();
        cts.Cancel();
        Assert.ThrowsAny<OperationCanceledException>(() => NativeCodeIndex.Build(image, ct: cts.Token));
    }

    [Fact]
    public async Task Progress_ends_with_done_and_build_runs_in_the_background()
    {
        var (image, _, _) = MsvcSwitch(bounded: true);
        var updates = new List<CodeIndexProgress>();
        var index = await NativeCodeIndex.BuildAsync(image, progress: p => { lock (updates) updates.Add(p); });
        Assert.Single(index.Functions);
        Assert.Equal("done", updates[^1].Phase);
        Assert.Contains(updates, u => u.Phase == "analyzing functions");
    }

    [Fact]
    public void Arm_reports_declared_functions_only()
    {
        var code = new byte[0x40];
        var pdata = new[] { new RuntimeFunction(Code, Code + 0x20, 0), new RuntimeFunction(Code + 0x20, Code + 0x40, 0) };
        var index = NativeCodeIndex.Build(CodeTestImage.Synthetic(NativeArch.Arm, code, pdata: pdata));
        Assert.Equal(CodeSupport.DeclaredFunctionsOnly, index.Support);
        Assert.Contains("ARM", index.SupportNote);
        Assert.Equal([Code, Code + 0x20], index.Functions.Select(f => f.Start));
        Assert.Equal(index.Functions[1], index.FunctionAt(Code + 0x24));
        Assert.Throws<NotSupportedException>(() => index.GetGraph(index.Functions[0]));
        Assert.Empty(index.RefsTo(Code));
    }

    public static TheoryData<string> SmallSystemDlls()
    {
        var data = new TheoryData<string>();
        if (!OperatingSystem.IsWindows()) return data;
        var windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        foreach (var path in new[] { Path.Combine(Environment.SystemDirectory, "version.dll"), Path.Combine(windows, "SysWOW64", "version.dll") })
            if (File.Exists(path)) data.Add(path);
        return data;
    }

    [WindowsTheory]
    [MemberData(nameof(SmallSystemDlls))]
    public void Small_system_dll(string path)
    {
        var image = NetDecompilerMcp.Native.Pe.PeFile.Open(path);
        var index = NativeCodeIndex.Build(image);
        Assert.Equal(CodeSupport.Full, index.Support);
        Assert.Empty(index.Truncations);
        Assert.Empty(NativeCodeSweepTests.PdataStartsMissing(image, index).Missing);
        foreach (var e in image.Exports.Where(e => e.ForwardedTo == null && image.SectionAt(e.Rva) is { IsExecutable: true }))
            Assert.NotNull(index.FunctionByStart(e.Rva));
        Assert.Contains(index.Functions, f => f.KnownName == "GetFileVersionInfoW");
        Assert.Contains(index.Functions, f => (f.Sources & FunctionSource.GuardCf) != 0);
        Assert.True(index.Stats.Xrefs > 100);
        Assert.NotEmpty(index.Strings);

        // callers and callees agree
        foreach (var f in index.Functions.Take(200))
            foreach (var callee in index.Callees(f).Where(c => c.Kind == XrefKind.Call && c.Function != null))
                Assert.Contains(index.Callers(callee.Function!), c => c.From == callee.From && c.Caller == f);

        // every function disassembles and its graph is consistent with the index
        foreach (var f in index.Functions)
        {
            var graph = index.GetGraph(f);
            Assert.Equal(f.InstructionCount, graph.Blocks.Sum(b => b.InstructionCount));
            Assert.All(graph.Blocks, b => Assert.All(b.Predecessors, p => Assert.Contains(graph.Blocks, x => x.Start == p.From)));
        }
        var lines = index.DisassembleFunction(index.Functions.First(f => f.KnownName == "GetFileVersionInfoW"), 500, out _);
        Assert.Contains(lines, l => l.Line?.Text.Contains('!') == true || l.Line?.Text.Contains("sub_") == true);
    }
}
