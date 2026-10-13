using System.Buffers.Binary;
using System.Text;
using Corvus.Native;
using Corvus.Native.Code;
using Corvus.Tests.NativeFormats;
using Corvus.Tools;

namespace Corvus.Tests;

/// <summary>inspect_instruction on ARM64: operands, writeback, ADRP pairs, flags, literal pools and 4-byte boundaries.</summary>
public class Arm64InspectTests
{
    private const uint Code = CodeTestImage.SyntheticCodeRva;
    private const uint Data = CodeTestImage.SyntheticDataRva;
    private const ulong Base = 0x10000000UL;
    private const uint Hi = 8;

    private sealed record Sample(NativeCodeIndex Index, Dictionary<string, uint> At);

    /// <summary>
    /// main: stp (pre-index), mov x29, sp, adrp+add (a string), adrp+ldr from a GOT slot, blr, an indexed load with uxtw,
    /// cmp, b.hi, a literal load, ldp (post-index), ret; then the 8-byte literal.
    /// </summary>
    private static Sample Build()
    {
        uint slot = Data + 0x10;
        var at = new Dictionary<string, uint>();
        var a = new A64(Code);
        void Here(string name) => at[name] = a.Here;
        Here("stp"); a.Word(A64.StpFpLrPre);
        a.Word(A64.MovFpSp);
        Here("adrp"); a.Word(A64.Adrp(a.Here, Data + 0x100, 0, Base));
        Here("add"); a.Word(A64.AddImm(0, 0, (Data + 0x100) & 0xFFF));
        a.Word(A64.Adrp(a.Here, slot, 16, Base));
        Here("got"); a.Word(A64.LdrX(17, 16, slot & 0xFFF));
        Here("blr"); a.Word(A64.Blr(17));
        Here("indexed"); a.Word(0xB8625801); // ldr w1, [x0, w2, uxtw #2]
        Here("cmp"); a.Word(0x71000C3F); // cmp w1, #3
        Here("bhi"); a.Later(x => A64.BCond(x, at["skip"], Hi));
        Here("literal"); a.Later(x => 0x58000000 | ((at["pool"] - x) / 4 & 0x7FFFF) << 5 | 2); // ldr x2, pool
        Here("skip"); a.Word(A64.LdpFpLrPost);
        Here("ret"); a.Word(A64.Ret);
        Here("pool"); a.Word(0x55667788).Word(0x11223344);
        var data = new byte[0x200];
        Encoding.ASCII.GetBytes("Hello, arm\0").CopyTo(data, 0x100);
        var image = CodeTestImage.Synthetic(NativeArch.Arm64, a.Bytes(), data, [new NativeImport("libc.so", "free", null, 0, slot, false)], entry: Code);
        return new Sample(NativeCodeIndex.Build(image), at);
    }

    private static (string Text, InstructionReport Report) Inspect(NativeCodeIndex index, uint rva, int count = 1) =>
        NativeCodeTools.Inspect("sample", index, rva, count, new EngineChoice("ours", "test"), CancellationToken.None);

    private static InstructionItem One(NativeCodeIndex index, uint rva) => Assert.Single(Inspect(index, rva).Report.Items);

    private static string Va(uint rva) => $"0x{Base + rva:X}";

    [Fact]
    public void Pre_index_store_pair_reports_writeback_and_the_stack_change()
    {
        var s = Build();
        var insn = One(s.Index, s.At["stp"]).Instruction!;
        Assert.Equal(("stp", "a64"), (insn.Mnemonic, insn.Encoding));
        Assert.Equal(("register", "x29", 8, "read"), (insn.Operands[0].Kind, insn.Operands[0].Register, insn.Operands[0].Size!.Value, insn.Operands[0].Access));
        var mem = insn.Operands[2];
        Assert.Equal(("memory", "sp", "-0x10", "pre", 16, "write"), (mem.Kind, mem.Base, mem.Displacement, mem.Writeback, mem.Size!.Value, mem.Access));
        Assert.Equal(-16, insn.StackPointerDelta);
        Assert.Contains("sp", insn.RegistersWritten!);
        Assert.Equal(["x29", "x30", "sp"], insn.RegistersRead);
        Assert.Contains(insn.MemoryAccesses!, m => m is { Base: "sp", Size: 16, Access: "write" });

        var ldp = One(s.Index, s.At["skip"]).Instruction!;
        Assert.Equal(("post", 16), (ldp.Operands[2].Writeback, ldp.StackPointerDelta!.Value));
        Assert.Equal(["x29", "x30", "sp"], ldp.RegistersWritten);
    }

    [Fact]
    public void Adrp_pairs_name_each_other_and_the_address_they_form()
    {
        var s = Build();
        var (text, report) = Inspect(s.Index, s.At["add"]);
        var add = report.Items[0].Instruction!;
        Assert.Equal(Va(s.At["adrp"]), add.Pair);
        Assert.Equal(Va(Data + 0x100), add.FormedAddress);
        Assert.Contains(add.ReferencesFrom, r => r.Kind == "Address" && r.To == Va(Data + 0x100));
        Assert.Contains("\"Hello, arm\"", add.Comment);
        Assert.Contains("(adrp pair)", text);

        var adrp = One(s.Index, s.At["adrp"]).Instruction!;
        Assert.Equal((Va(s.At["add"]), Va(Data + 0x100)), (adrp.Pair, adrp.FormedAddress));
        Assert.Equal(("pc_relative", Va(Data)), (adrp.Operands[1].Kind, adrp.Operands[1].Target));
    }

    [Fact]
    public void Loads_through_a_got_slot_make_the_branch_an_import_call()
    {
        var s = Build();
        var load = One(s.Index, s.At["got"]).Instruction!;
        Assert.Equal(Va(Data + 0x10), load.Operands[1].Target);
        Assert.Contains("iat_slot: libc.so!free", load.Operands[1].TargetItem);
        var blr = One(s.Index, s.At["blr"]).Instruction!;
        Assert.Equal("indirect_call", blr.Flow.Kind);
        Assert.Equal(("register", "x17", "read"), (blr.Operands[0].Kind, blr.Operands[0].Register, blr.Operands[0].Access));
        Assert.Contains("x30", blr.RegistersWritten!);
        Assert.Contains(blr.ReferencesFrom, r => r.Kind == "ImportCall");
        Assert.StartsWith("free(", blr.Call);
    }

    [Fact]
    public void Indexed_loads_carry_the_extend_and_scale()
    {
        var s = Build();
        var insn = One(s.Index, s.At["indexed"]).Instruction!;
        var mem = insn.Operands[1];
        Assert.Equal(("x0", "w2", "uxtw #2", 4, 4, "read"), (mem.Base, mem.IndexRegister, mem.Extend, mem.Scale!.Value, mem.Size!.Value, mem.Access));
        Assert.Equal(("w1", "x1", 4), (insn.Operands[0].Register, insn.Operands[0].FullRegister, insn.Operands[0].Size!.Value));
        Assert.Equal(["x0", "x2"], insn.RegistersRead);
        Assert.Equal(["x1"], insn.RegistersWritten);
    }

    [Fact]
    public void Compares_write_and_conditional_branches_read_the_flags()
    {
        var s = Build();
        var cmp = One(s.Index, s.At["cmp"]).Instruction!;
        Assert.Equal(["n", "z", "c", "v"], cmp.FlagsWritten);
        Assert.Empty(cmp.FlagsRead!);
        Assert.Equal(("immediate", "0x3"), (cmp.Operands[1].Kind, cmp.Operands[1].Value));
        var b = One(s.Index, s.At["bhi"]).Instruction!;
        Assert.Equal(("conditional_jump", "hi", Va(s.At["skip"]), Va(s.At["literal"])), (b.Flow.Kind, b.Flow.Condition, b.Flow.Target, b.Flow.Fallthrough));
        Assert.Equal(["n", "z", "c", "v"], b.FlagsRead);
        Assert.Contains(b.Operands, o => o.Kind == "condition");
        Assert.Contains(b.Operands, o => o.Kind == "near_branch" && o.Target == Va(s.At["skip"]));
        Assert.Null(One(s.Index, s.At["ret"]).Instruction!.Flow.Fallthrough);
    }

    [Fact]
    public void Literal_loads_name_the_pool_entry_which_is_data()
    {
        var s = Build();
        var insn = One(s.Index, s.At["literal"]).Instruction!;
        var op = insn.Operands[1];
        Assert.Equal(("pc_relative", Va(s.At["pool"]), 8, "read"), (op.Kind, op.Target, op.Size!.Value, op.Access));
        Assert.Equal(Va(s.At["pool"]), insn.FormedAddress);
        Assert.Contains(insn.MemoryAccesses!, m => m is { Base: "pc", Size: 8 });

        var pool = One(s.Index, s.At["pool"] + 4);
        Assert.Equal(("data", "literal", Va(s.At["pool"]), Va(s.At["pool"] + 8)), (pool.Status, pool.DataItem!.Kind, pool.DataItem.Start, pool.DataItem.End));
    }

    [Fact]
    public void Addresses_between_4_byte_boundaries_are_mid_instruction()
    {
        var s = Build();
        var item = One(s.Index, s.At["cmp"] + 2);
        Assert.Equal(("mid_instruction", Va(s.At["cmp"])), (item.Status, item.ContainingInstruction));
        var (_, walk) = Inspect(s.Index, s.At["cmp"] + 1, count: 3);
        Assert.Equal(["mid_instruction", "decoded", "decoded", "decoded"], walk.Items.Select(i => i.Status));
        Assert.Equal([s.At["cmp"], s.At["bhi"], s.At["literal"]], walk.Items.Skip(1).Select(i => Convert.ToUInt32(i.Rva, 16)));
    }

    [Fact]
    public async Task Real_arm64_elf_is_inspected_by_the_built_in_engine()
    {
        using var h = new NativeToolHarness(backgroundIndexing: false);
        var path = NativeFixtures.LinuxArm64DbgShim;
        var text = await h.CodeTools.InspectInstruction(path, "RegisterForRuntimeStartup", limit: 64);
        Assert.Contains("Engine: ours", text);
        Assert.Contains("a64 encoding", text);
        Assert.Equal(64, text.Split('\n').Count(l => l.Contains("  decoded  in RegisterForRuntimeStartup", StringComparison.Ordinal)));
        Assert.Contains("forms 0x", text);
    }
}
