using Corvus.Core;
using System.Text;
using Iced.Intel;
using Corvus.Native;
using Corvus.Native.Code;
using Corvus.Tools;
using static Iced.Intel.AssemblerRegisters;

namespace Corvus.Tests;

/// <summary>collapse=runtime shapes, matched on self-built x86 instruction lists.</summary>
public class RuntimeCollapseTests
{
    private static DisasmLine L(uint rva, string text, FlowKind flow = FlowKind.Next, uint? target = null, bool rip = false, uint? mem = null, int len = 4)
        => new(rva, 0x140000000UL + rva, "", text, null, new InstructionFacts(rva, len, flow, target, mem, rip, OperandAccess.None, null));

    private static string Va(uint r) => $"0x{0x140000000UL + r:X}";

    [Fact]
    public void A_shift_by_12_with_a_bit_set_and_a_backward_branch_is_one_write_barrier()
    {
        var lines = new[]
        {
            L(0x10, "mov rax,rcx"),
            L(0x14, "shr rax,0Ch"),
            L(0x18, "bts dword ptr [rdx],eax"),
            L(0x1C, "lock cmpxchg [rdx],rcx"),
            L(0x20, "jne 0000000140000014h", FlowKind.ConditionalJump, 0x14),
            L(0x24, "ret", FlowKind.Return),
        };
        var runs = RuntimeCollapse.Find(lines, Va);
        var run = Assert.Single(runs.Values);
        Assert.Equal(0x14u, run.Start);
        Assert.Equal(0x24u, run.End);
        Assert.Equal(4, run.Count);
        Assert.StartsWith("collapsed: write barrier (4 instructions", run.Note);
    }

    [Fact]
    public void A_shift_by_12_without_a_bit_set_or_locked_exchange_is_kept()
    {
        var lines = new[] { L(0, "shr rax,0Ch"), L(4, "add rax,rcx"), L(8, "ret", FlowKind.Return) };
        Assert.Empty(RuntimeCollapse.Find(lines, Va));
    }

    [Fact]
    public void A_zero_check_that_skips_one_initializer_call_is_one_lazy_initialization()
    {
        var lines = new[]
        {
            L(0, "cmp qword ptr [140003000h],0", rip: true, mem: 0x3000),
            L(4, "jne 0000000140000010h", FlowKind.ConditionalJump, 0x10),
            L(8, "lea rcx,[140004000h]"),
            L(12, "call 0000000140001000h", FlowKind.Call, 0x1000, len: 4),
            L(16, "mov rax,rcx"),
        };
        var run = Assert.Single(RuntimeCollapse.Find(lines, Va).Values);
        Assert.Equal(4, run.Count);
        Assert.Contains("lazy initialization of 0x140003000", run.Note);
    }

    private static DisasmLine[] Scheduled(string[] between, string? fence, string? store, uint skip, uint storeTarget = 0x3000, string? storeText = null)
    {
        var l = new List<DisasmLine> { L(0, "cmp byte ptr [140003000h],0", rip: true, mem: 0x3000) };
        uint at = 4;
        foreach (var m in between) { l.Add(L(at, m, rip: m.Contains("[rip") , mem: m.Contains("[rip") ? 0x5000u : null)); at += 4; }
        l.Add(L(at, $"jne 00000001400000{skip:X2}h", FlowKind.ConditionalJump, skip));
        l.Add(L(at + 4, "lea rcx,[140004000h]"));
        l.Add(L(at + 8, "call 0000000140001000h", FlowKind.Call, 0x1000, len: 4));
        at += 12;
        if (fence != null) { l.Add(L(at, fence)); at += 4; }
        if (store != null) l.Add(L(at, store, rip: true, mem: storeTarget));
        return [.. l];
    }

    private static string[] Moves(int n) => [.. Enumerable.Range(0, n).Select(_ => "mov rbx,rcx")];

    private const string Fence = "lock or dword ptr [rsp],0";
    private const string Flag = "mov byte ptr [140003000h],1";

    // FT-298 N2: a register move scheduled between the check and the branch.
    [Fact]
    public void A_register_move_between_the_check_and_the_branch_stays_listed_outside_the_run()
    {
        var lines = Scheduled(Moves(1), null, null, 20);
        var run = Assert.Single(RuntimeCollapse.Find(lines, Va).Values);
        Assert.Equal(8u, run.Start);
        Assert.Equal(3, run.Count);
    }

    // FT-298 N2: four moves are the most the window allows.
    [Fact]
    public void Four_register_moves_between_the_check_and_the_branch_collapse()
    {
        var lines = Scheduled(Moves(4), null, null, 32);
        Assert.Single(RuntimeCollapse.Find(lines, Va).Values);
    }

    // FT-298 N2: five moves exceed the window.
    [Fact]
    public void Five_register_moves_between_the_check_and_the_branch_are_kept()
    {
        var lines = Scheduled(Moves(5), null, null, 36);
        Assert.Empty(RuntimeCollapse.Find(lines, Va));
    }

    // FT-298 N2: a fence and a store of 1 to the compared flag end the block.
    [Fact]
    public void A_fence_and_flag_store_after_the_call_collapse_with_the_block()
    {
        var lines = Scheduled(Moves(1), Fence, Flag, 28);
        var run = Assert.Single(RuntimeCollapse.Find(lines, Va).Values);
        Assert.Equal(5, run.Count);
        Assert.Equal(28u, run.End);
    }

    // FT-298 N2: the fence alone may end the block.
    [Fact]
    public void A_fence_without_a_flag_store_collapses_when_it_ends_at_the_skip_target()
    {
        var lines = Scheduled(Moves(1), Fence, null, 24);
        Assert.Equal(4, Assert.Single(RuntimeCollapse.Find(lines, Va).Values).Count);
    }

    // FT-298 N2: the flag store alone may end the block.
    [Fact]
    public void A_flag_store_without_a_fence_collapses_when_it_ends_at_the_skip_target()
    {
        var lines = Scheduled(Moves(1), null, Flag, 24);
        Assert.Equal(4, Assert.Single(RuntimeCollapse.Find(lines, Va).Values).Count);
    }

    // FT-298 N2: the store must target the flag the guard compared.
    [Fact]
    public void A_store_to_another_flag_does_not_end_the_block()
    {
        var lines = Scheduled(Moves(1), Fence, "mov byte ptr [140003008h],1", 28, storeTarget: 0x3008);
        Assert.Empty(RuntimeCollapse.Find(lines, Va));
    }

    // FT-298 N2: only a store of 1 marks the flag initialized.
    [Fact]
    public void A_store_of_another_value_does_not_end_the_block()
    {
        var lines = Scheduled(Moves(1), Fence, "mov byte ptr [140003000h],2", 28);
        Assert.Empty(RuntimeCollapse.Find(lines, Va));
    }

    // FT-298 N2: a register move first, then a move that writes memory, then the branch.
    [Fact]
    public void An_instruction_between_the_check_and_the_branch_that_writes_memory_is_kept()
    {
        var lines = Scheduled(["mov rbx,rcx", "mov [rsp+8],rcx"], null, null, 24);
        Assert.Empty(RuntimeCollapse.Find(lines, Va));
    }

    [Fact]
    public void A_zero_check_whose_branch_skips_other_code_is_kept()
    {
        var lines = new[]
        {
            L(0, "cmp qword ptr [140003000h],0", rip: true, mem: 0x3000),
            L(4, "jne 0000000140000020h", FlowKind.ConditionalJump, 0x20),
            L(8, "call 0000000140001000h", FlowKind.Call, 0x1000, len: 4),
            L(12, "mov rax,rcx"),
        };
        Assert.Empty(RuntimeCollapse.Find(lines, Va));
    }

    [Fact]
    public void A_static_base_call_is_one_metadata_initialization_line()
    {
        var lines = new[] { L(0, "call __GetGCStaticBase_Thing", FlowKind.Call, 0x100), L(4, "ret", FlowKind.Return) };
        var run = Assert.Single(RuntimeCollapse.Find(lines, Va).Values);
        Assert.Equal(1, run.Count);
        Assert.Contains("metadata initialization __GetGCStaticBase_Thing", run.Note);
    }

    [Fact]
    public void An_unknown_collapse_mode_is_rejected_and_none_is_off()
    {
        Assert.False(RuntimeCollapse.Parse(null));
        Assert.False(RuntimeCollapse.Parse("none"));
        Assert.True(RuntimeCollapse.Parse("runtime"));
        Assert.Throws<ToolError>(() => RuntimeCollapse.Parse("all"));
    }

    [Fact]
    public void Collapse_modes_ignore_case_and_blank_is_off()
    {
        Assert.True(RuntimeCollapse.Parse("Runtime"));
        Assert.False(RuntimeCollapse.Parse("NONE"));
        Assert.False(RuntimeCollapse.Parse(""));
    }

    [Fact]
    public void Engine_architecture_and_range_requests_are_refused()
    {
        RuntimeCollapse.RequireEngine(false, false, NativeArch.X64);
        RuntimeCollapse.RequireFunction(true);
        Assert.Throws<ToolError>(() => RuntimeCollapse.RequireEngine(true, false, NativeArch.X64));
        Assert.Throws<ToolError>(() => RuntimeCollapse.RequireEngine(false, true, NativeArch.X64));
        Assert.Throws<ToolError>(() => RuntimeCollapse.RequireEngine(false, false, NativeArch.Arm64));
        Assert.Throws<ToolError>(() => RuntimeCollapse.RequireFunction(false));
    }

    [Fact]
    public void Operand_spacing_and_number_forms_do_not_change_a_match()
    {
        var lines = new[]
        {
            L(0, "CMP  qword ptr [140003000h] , 0x0", rip: true, mem: 0x3000),
            L(4, "jne 0000000140000010h", FlowKind.ConditionalJump, 0x10),
            L(8, "lea rcx,[140004000h]"),
            L(12, "call 0000000140001000h", FlowKind.Call, 0x1000, len: 4),
            L(16, "ret", FlowKind.Return),
            L(20, "shr rax, 12"),
            L(24, "bts [rdx], rax"),
            L(28, "jne 0000000140000014h", FlowKind.ConditionalJump, 20),
        };
        Assert.Equal(2, RuntimeCollapse.Find(lines, Va).Count);
    }

    [Fact]
    public void Four_setup_instructions_before_the_initializer_call_collapse_and_five_do_not()
    {
        static List<DisasmLine> Guard(int setup)
        {
            var list = new List<DisasmLine> { L(0, "cmp qword ptr [140003000h],0", rip: true, mem: 0x3000) };
            uint after = 8 + (uint)setup * 4 + 4;
            list.Add(L(4, "jne 0000000140000100h", FlowKind.ConditionalJump, after));
            uint at = 8;
            for (int i = 0; i < setup; i++, at += 4) list.Add(L(at, "mov rcx,rdx"));
            list.Add(L(at, "call 0000000140001000h", FlowKind.Call, 0x1000));
            list.Add(L(at + 4, "ret", FlowKind.Return));
            return list;
        }
        Assert.Single(RuntimeCollapse.Find(Guard(4), Va));
        Assert.Empty(RuntimeCollapse.Find(Guard(5), Va));
    }

    [Fact]
    public void A_shift_and_bit_set_without_a_closing_loop_is_kept()
    {
        var lines = new[] { L(0, "shr rax,0Ch"), L(4, "bts dword ptr [rdx],eax"), L(8, "ret", FlowKind.Return) };
        Assert.Empty(RuntimeCollapse.Find(lines, Va));
    }

    [Fact]
    public void A_barrier_whose_branch_leaves_the_run_or_loops_elsewhere_is_kept()
    {
        var exits = new[]
        {
            L(0x10, "shr rax,0Ch"), L(0x14, "je 0000000140000100h", FlowKind.ConditionalJump, 0x100),
            L(0x18, "bts [rdx],rax"), L(0x1C, "jne 0000000140000010h", FlowKind.ConditionalJump, 0x10),
        };
        Assert.Empty(RuntimeCollapse.Find(exits, Va));
        var before = new[]
        {
            L(0x10, "shr rax,0Ch"), L(0x14, "bts [rdx],rax"), L(0x18, "jne 0000000140000004h", FlowKind.ConditionalJump, 4),
        };
        Assert.Empty(RuntimeCollapse.Find(before, Va));
    }

    private const uint Code = CodeTestImage.SyntheticCodeRva;
    private const uint Data = CodeTestImage.SyntheticDataRva;
    private const ulong Base = 0x140000000UL;

    // A zero-checked initializer call, a static-base call and a loop whose
    // bit-set is also a branch target.
    private static (NativeCodeIndex Index, NativeFunction Fn) Fixture()
    {
        var a = new Assembler(64);
        var after = a.CreateLabel();
        var top = a.CreateLabel();
        var mid = a.CreateLabel();
        var init = a.CreateLabel();
        var staticBase = a.CreateLabel();
        a.sub(rsp, 0x28);
        a.AddInstruction(Instruction.Create(Iced.Intel.Code.Cmp_rm64_imm8, new MemoryOperand(Register.RIP, (long)(Base + Data + 0x10), 8), 0));
        a.jne(after);
        a.AddInstruction(Instruction.Create(Iced.Intel.Code.Lea_r64_m, Register.RCX, new MemoryOperand(Register.RIP, (long)(Base + Data + 0x20), 8)));
        a.call(init);
        a.Label(ref after);
        a.call(staticBase);
        a.mov(rax, rcx);
        a.test(rdx, rdx);
        a.je(mid);
        a.Label(ref top);
        a.shr(rax, 12);
        a.Label(ref mid);
        a.bts(__qword_ptr[rdx], rax);
        a.jne(top);
        a.add(rsp, 0x28);
        a.ret();
        a.int3();
        a.Label(ref init);
        a.ret();
        a.int3();
        a.Label(ref staticBase);
        a.ret();
        var stream = new MemoryStream();
        var result = a.Assemble(new StreamCodeWriter(stream), Base + Code, BlockEncoderOptions.ReturnNewInstructionOffsets);
        var exports = new[] { new NativeExport("GetGCStaticBase_Thing", 1, (uint)(result.GetLabelRIP(staticBase) - Base), null) };
        var image = CodeTestImage.Synthetic(NativeArch.X64, stream.ToArray(), new byte[0x200], exports: exports, entry: Code);
        var index = NativeCodeIndex.Build(image);
        return (index, index.FunctionAt(Code)!);
    }

    private static string Listing(NativeCodeIndex index, NativeFunction fn, bool? collapse, int max = 2000)
    {
        var sb = new StringBuilder();
        var calls = new Dictionary<uint, string>();
        var classifier = new AddressClassifier(index);
        if (collapse == null) NativeCodeTools.AppendFunction(sb, index, classifier, fn, max, calls, [], default);
        else NativeCodeTools.AppendFunction(sb, index, classifier, fn, max, calls, [], default, collapse.Value);
        return sb.ToString().Replace("\r", "");
    }

    [Fact]
    public void A_function_listing_names_each_run_and_counts_instructions_before_and_after()
    {
        var (index, fn) = Fixture();
        var text = Listing(index, fn, true);
        Assert.Contains("; collapsed: lazy initialization of", text);
        Assert.Contains("; collapsed: write barrier", text);
        Assert.Contains("; collapsed: metadata initialization", text);
        int all = index.DisassembleFunction(fn, 2000, out _).Count(e => e.Line != null);
        var notes = text.Split('\n').Where(l => l.StartsWith("; collapsed:")).ToList();
        int folded = notes.Sum(l => int.Parse(l.Split('(')[1].Split(' ')[0]));
        Assert.Contains($"; collapse=runtime: {all} instructions listed as {all - folded + notes.Count} lines", text);
        Assert.True(folded > notes.Count);
    }

    [Fact]
    public void Collapse_off_leaves_the_listing_byte_identical_to_the_default()
    {
        var (index, fn) = Fixture();
        var plain = Listing(index, fn, false);
        Assert.Equal(Listing(index, fn, null), plain);
        Assert.DoesNotContain("collapse", plain);
    }

    [Fact]
    public void A_label_inside_a_collapsed_run_is_kept_after_the_run_note()
    {
        var (index, fn) = Fixture();
        var lines = Listing(index, fn, true).Split('\n');
        int barrier = Array.FindIndex(lines, l => l.StartsWith("; collapsed: write barrier"));
        Assert.True(barrier >= 0);
        Assert.Matches("^loc_[0-9A-F]+:$", lines[barrier + 1]);
    }

    [Fact]
    public void A_listing_cut_inside_a_barrier_loop_keeps_its_instructions()
    {
        var (index, fn) = Fixture();
        var all = index.DisassembleFunction(fn, 2000, out _).Where(e => e.Line != null).Select(e => e.Line!).ToList();
        int shift = all.FindIndex(l => l.Text.StartsWith("shr", StringComparison.OrdinalIgnoreCase));
        var text = Listing(index, fn, true, shift + 2);
        Assert.DoesNotContain("write barrier", text);
        Assert.Contains("; truncated at", text);
    }

    [Fact]
    public void The_built_in_decoder_text_matches_each_shape()
    {
        var (index, fn) = Fixture();
        var all = index.DisassembleFunction(fn, 2000, out _).Where(e => e.Line != null).Select(e => e.Line!).ToList();
        Assert.Equal(3, RuntimeCollapse.Find(all, Va).Count);
    }

    [Fact]
    public void A_lazy_block_and_a_barrier_in_one_function_collapse_without_hiding_other_code()
    {
        var lines = new[]
        {
            L(0x00, "push rbx"),
            L(0x04, "cmp byte ptr [140003000h],0", rip: true, mem: 0x3000),
            L(0x08, "jne 0000000140000014h", FlowKind.ConditionalJump, 0x14),
            L(0x0C, "lea rcx,[140004000h]"),
            L(0x10, "call 0000000140001000h", FlowKind.Call, 0x1000, len: 4),
            L(0x14, "mov rax,rcx"),
            L(0x18, "shr rax,0Ch"),
            L(0x1C, "bts dword ptr [rdx],eax"),
            L(0x20, "lock cmpxchg [rdx],rcx"),
            L(0x24, "jne 0000000140000018h", FlowKind.ConditionalJump, 0x18),
            L(0x28, "pop rbx"),
            L(0x2C, "ret", FlowKind.Return),
        };
        var runs = RuntimeCollapse.Find(lines, Va);
        Assert.Equal(2, runs.Count);
        Assert.Equal(4, runs[0x04].Count);
        Assert.Equal(4, runs[0x18].Count);
        int kept = lines.Length - runs.Values.Sum(r => r.Count);
        Assert.Equal(4, kept);
        Assert.Contains("lazy initialization of " + Va(0x3000), runs[0x04].Note);
        Assert.Contains("write barrier", runs[0x18].Note);
        Assert.Equal(0x14u, runs[0x04].End);
        Assert.Equal(0x28u, runs[0x18].End);
        Assert.False(runs.ContainsKey(0x00) || runs.ContainsKey(0x14) || runs.ContainsKey(0x28));
    }

    [Fact]
    public void A_function_listing_keeps_code_outside_both_runs_and_drops_their_instructions()
    {
        var (index, fn) = Fixture();
        var plain = Listing(index, fn, false);
        var text = Listing(index, fn, true);
        Assert.Contains("4883EC28", text);
        Assert.Contains("4883C428", text);
        Assert.Contains("48C1E80C", plain);
        Assert.DoesNotContain("48C1E80C", text);
    }

    [Fact]
    public void A_call_named_only_by_the_call_map_is_one_metadata_initialization_line()
    {
        var lines = new[] { L(0, "call 0000000140001000h", FlowKind.Call, 0x1000), L(4, "ret", FlowKind.Return) };
        var calls = new Dictionary<uint, string> { [0] = "GetNonGCStaticBase_Thing" };
        var run = Assert.Single(RuntimeCollapse.Find(lines, Va, calls).Values);
        Assert.Contains("metadata initialization GetNonGCStaticBase_Thing", run.Note);
        Assert.Empty(RuntimeCollapse.Find(lines, Va));
    }

    [Fact]
    public void A_run_split_by_a_gap_between_blocks_is_kept()
    {
        var lines = new[]
        {
            L(0x14, "shr rax,0Ch"),
            L(0x18, "bts dword ptr [rdx],eax"),
            L(0x40, "lock cmpxchg [rdx],rcx"),
            L(0x44, "jne 0000000140000014h", FlowKind.ConditionalJump, 0x14),
            L(0x48, "ret", FlowKind.Return),
        };
        Assert.Empty(RuntimeCollapse.Find(lines, Va));
    }
}
