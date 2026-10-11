using System.Buffers.Binary;
using System.Text;
using Iced.Intel;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Native;
using NetDecompilerMcp.Native.Code;
using NetDecompilerMcp.Tools;
using static Iced.Intel.AssemblerRegisters;

namespace NetDecompilerMcp.Tests;

/// <summary>inspect_instruction and the address classifier on synthetic x64 images (assembled with Iced).</summary>
public class InstructionInspectTests
{
    private const uint Code = CodeTestImage.SyntheticCodeRva;
    private const uint Data = CodeTestImage.SyntheticDataRva;
    private const ulong Base = 0x140000000UL;

    private sealed record Sample(NativeCodeIndex Index, Dictionary<string, uint> At);

    private static (byte[] Bytes, Func<Label, uint> Rva) Assemble(Action<Assembler> build)
    {
        var a = new Assembler(64);
        build(a);
        var stream = new MemoryStream();
        var result = a.Assemble(new StreamCodeWriter(stream), Base + Code, BlockEncoderOptions.ReturnNewInstructionOffsets);
        return (stream.ToArray(), label => (uint)(result.GetLabelRIP(label) - Base));
    }

    private static Instruction Rip(Iced.Intel.Code code, Register reg, uint rva) => Instruction.Create(code, reg, new MemoryOperand(Register.RIP, (long)(Base + rva), 8));

    /// <summary>
    /// One function using an indexed load, lock cmpxchg, a RIP-relative global, a string address, a conditional jump and an import call;
    /// after its ret an unowned nop and bytes that do not decode. .data: IAT slot at +0, global at +0x20, string at +0x100, bss from +0x200.
    /// </summary>
    private static Sample Build()
    {
        var names = new[] { "main", "indexed", "locked", "global", "lea", "jz", "call", "skip", "ret", "unowned", "bad" };
        var labels = new Dictionary<string, Label>();
        var (code, rva) = Assemble(a =>
        {
            foreach (var n in names) labels[n] = a.CreateLabel(n);
            void Here(string n) { var l = labels[n]; a.Label(ref l); labels[n] = l; }
            Here("main");
            a.sub(rsp, 0x28);
            Here("indexed");
            a.mov(rax, __qword_ptr[rcx + rdx * 8 + 0x10]);
            Here("locked");
            a.@lock.cmpxchg(__dword_ptr[rcx], edx);
            Here("global");
            a.AddInstruction(Rip(Iced.Intel.Code.Mov_r32_rm32, Register.EAX, Data + 0x20));
            Here("lea");
            a.AddInstruction(Rip(Iced.Intel.Code.Lea_r64_m, Register.RCX, Data + 0x100));
            a.test(eax, eax);
            Here("jz");
            a.jz(labels["skip"]);
            a.mov(ecx, 0x10);
            Here("call");
            a.AddInstruction(Instruction.Create(Iced.Intel.Code.Call_rm64, new MemoryOperand(Register.RIP, (long)(Base + Data), 8)));
            Here("skip");
            a.add(rsp, 0x28);
            Here("ret");
            a.ret();
            Here("unowned");
            a.nop();
            Here("bad");
            a.db(0xFF, 0xFF);
        });
        var data = new byte[0x200];
        Encoding.ASCII.GetBytes("Hello, world\0").CopyTo(data, 0x100);
        var image = CodeTestImage.Synthetic(NativeArch.X64, code, data, [new NativeImport("KERNEL32.dll", "Sleep", null, 0, Data, false)], entry: Code,
            dataVirtualSize: 0x2000);
        return new Sample(NativeCodeIndex.Build(image), names.ToDictionary(n => n, n => rva(labels[n])));
    }

    private static (string Text, InstructionReport Report) Inspect(NativeCodeIndex index, uint rva, int count = 1) =>
        NativeCodeTools.Inspect("sample", index, rva, count, new EngineChoice(false, "test"), CancellationToken.None);

    private static InstructionItem One(NativeCodeIndex index, uint rva) => Assert.Single(Inspect(index, rva).Report.Items);

    [Fact]
    public void Memory_operand_is_decomposed_into_base_index_scale_and_displacement()
    {
        var s = Build();
        var item = One(s.Index, s.At["indexed"]);
        Assert.Equal("decoded", item.Status);
        Assert.Equal("sub_1000+0x4", item.Function);
        var insn = item.Instruction!;
        Assert.Equal("mov", insn.Mnemonic);
        Assert.Equal("legacy", insn.Encoding);
        var dest = insn.Operands[0];
        Assert.Equal(("register", "rax", "rax", 8, "write"), (dest.Kind, dest.Register, dest.FullRegister, dest.Size!.Value, dest.Access));
        var mem = insn.Operands[1];
        Assert.Equal(("memory", "rcx", "rdx", 8, "0x10", 8, "read"), (mem.Kind, mem.Base, mem.IndexRegister, mem.Scale!.Value, mem.Displacement, mem.Size!.Value, mem.Access));
        Assert.False(mem.RipRelative);
        Assert.Null(mem.Target);
        Assert.Equal(["rcx", "rdx"], insn.RegistersRead);
        Assert.Equal(["rax"], insn.RegistersWritten);
        Assert.Equal("next", insn.Flow.Kind);
        Assert.Equal($"0x{Base + s.At["locked"]:X}", insn.Flow.Fallthrough);
    }

    [Fact]
    public void Rip_relative_operands_name_their_effective_address_and_data_item()
    {
        var s = Build();
        var global = One(s.Index, s.At["global"]).Instruction!.Operands[1];
        Assert.True(global.RipRelative);
        Assert.Null(global.Base);
        Assert.Equal($"0x{Base + Data + 0x20:X}", global.Target);
        Assert.Contains("1 read", global.TargetItem);
        var (text, report) = Inspect(s.Index, s.At["lea"]);
        var lea = report.Items[0].Instruction!.Operands[1];
        Assert.Equal($"0x{Base + Data + 0x100:X}", lea.Target);
        Assert.StartsWith("string: \"Hello, world\"", lea.TargetItem);
        Assert.Contains("-> 0x140080100 [string: \"Hello, world\"", text);
    }

    [Fact]
    public void Lock_prefix_and_flags_are_reported()
    {
        var s = Build();
        var insn = One(s.Index, s.At["locked"]).Instruction!;
        Assert.Equal("cmpxchg", insn.Mnemonic);
        Assert.Equal(["lock"], insn.Prefixes);
        Assert.Equal("read_cond_write", insn.Operands[0].Access);
        Assert.Contains("zf", insn.FlagsWritten!);
        Assert.Contains("eax", insn.RegistersRead!);
        Assert.Contains(insn.MemoryAccesses!, m => m is { Base: "rcx", Size: 4 });
    }

    [Fact]
    public void Conditional_jump_has_target_condition_and_fallthrough()
    {
        var s = Build();
        var flow = One(s.Index, s.At["jz"]).Instruction!.Flow;
        Assert.Equal("conditional_jump", flow.Kind);
        Assert.Equal("e", flow.Condition);
        Assert.Equal($"0x{Base + s.At["skip"]:X}", flow.Target);
        Assert.NotNull(flow.Fallthrough);
        Assert.Null(One(s.Index, s.At["ret"]).Instruction!.Flow.Fallthrough);
    }

    [Fact]
    public void Call_site_carries_the_callee_and_its_arguments()
    {
        var s = Build();
        var insn = One(s.Index, s.At["call"]).Instruction!;
        Assert.Equal("indirect_call", insn.Flow.Kind);
        Assert.StartsWith("Sleep(", insn.Call);
        Assert.Contains(insn.ReferencesFrom, r => r is { Kind: "ImportCall", Name: "KERNEL32!Sleep" });
        Assert.Contains("iat_slot: KERNEL32!Sleep", insn.Operands[0].TargetItem);
        Assert.Equal(-8, insn.StackPointerDelta);
    }

    [Fact]
    public void Mid_instruction_reports_the_covering_instruction_and_a_walk_starts_there()
    {
        var s = Build();
        var item = One(s.Index, s.At["indexed"] + 2);
        Assert.Equal("mid_instruction", item.Status);
        Assert.Equal($"0x{Base + s.At["indexed"]:X}", item.ContainingInstruction);
        Assert.Null(item.Instruction);

        var (text, report) = Inspect(s.Index, s.At["indexed"] + 2, count: 3);
        Assert.Equal(["mid_instruction", "decoded", "decoded", "decoded"], report.Items.Select(i => i.Status));
        Assert.Equal([s.At["indexed"], s.At["locked"], s.At["global"]], report.Items.Skip(1).Select(i => Convert.ToUInt32(i.Rva, 16)));
        Assert.Contains("the walk starts there", text);
    }

    [Fact]
    public void Data_items_bss_unowned_code_and_invalid_bytes_are_classified()
    {
        var s = Build();
        var str = One(s.Index, Data + 0x104);
        Assert.Equal("data", str.Status);
        Assert.Equal(("string", $"0x{Base + Data + 0x100:X}", $"0x{Base + Data + 0x10D:X}"), (str.DataItem!.Kind, str.DataItem.Start, str.DataItem.End));
        var slot = One(s.Index, Data + 3);
        Assert.Equal(("iat_slot", "KERNEL32!Sleep"), (slot.DataItem!.Kind, slot.DataItem.Text));
        var plain = One(s.Index, Data + 0x80);
        Assert.Equal(("data", "section", ".data"), (plain.Status, plain.DataItem!.Kind, plain.DataItem.Text));
        var bss = One(s.Index, Data + 0x1000);
        Assert.Equal("unmapped", bss.Status);
        Assert.Contains("zero-filled at load", bss.Note);
        var unowned = One(s.Index, s.At["unowned"]);
        Assert.Equal("not_in_function", unowned.Status);
        Assert.Equal("nop", unowned.Instruction!.Mnemonic);
        Assert.Equal("invalid", One(s.Index, s.At["bad"]).Status);

        // a walk skips a data item and stops at the end of the decodable bytes
        var (_, walk) = Inspect(s.Index, s.At["ret"], count: 5);
        Assert.Equal(["decoded", "not_in_function", "invalid"], walk.Items.Select(i => i.Status));
        Assert.Contains(walk.Notes, n => n.Contains("the walk stops at"));
    }

    [Fact]
    public void Switch_tables_are_data_items_and_the_dispatch_names_its_table()
    {
        Label start = default, dflt = default, jump = default;
        var cases = new Label[3];
        var (code, rva) = Assemble(a =>
        {
            start = a.CreateLabel(); dflt = a.CreateLabel(); jump = a.CreateLabel();
            for (int i = 0; i < cases.Length; i++) cases[i] = a.CreateLabel();
            a.Label(ref start);
            a.AddInstruction(Rip(Iced.Intel.Code.Lea_r64_m, Register.RDX, 0));
            a.cmp(ecx, cases.Length - 1);
            a.ja(dflt);
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
        var index = NativeCodeIndex.Build(CodeTestImage.Synthetic(NativeArch.X64, code, data, entry: Code));

        var table = One(index, Data + 0x44);
        Assert.Equal(("data", "jump_table", $"0x{Base + Data + 0x40:X}", $"0x{Base + Data + 0x4C:X}"),
            (table.Status, table.DataItem!.Kind, table.DataItem.Start, table.DataItem.End));
        var dispatch = One(index, rva(jump)).Instruction!;
        Assert.Equal("indirect_jump", dispatch.Flow.Kind);
        Assert.Equal(3, dispatch.Switch!.Entries);
        Assert.Equal(cases.Select(c => $"0x{Base + rva(c):X}"), dispatch.Switch.Targets);
    }

    [Fact]
    public void A_name_on_two_addresses_is_an_ambiguous_error()
    {
        var s = Build();
        s.Index.SetUserName(s.At["indexed"], "dup");
        s.Index.SetUserName(s.At["locked"], "dup");
        var error = Assert.Throws<ToolError>(() => NativeCodeTools.Address(s.Index, "dup"));
        Assert.Equal(ErrorCode.Ambiguous, error.Code);
        Assert.Equal(s.At["indexed"], NativeCodeTools.Address(s.Index, $"rva:0x{s.At["indexed"]:X}"));
    }
}
