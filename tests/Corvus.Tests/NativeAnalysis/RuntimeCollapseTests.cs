using Corvus.Core;
using System.Text;
using Iced.Intel;
using Corvus.Native;
using Corvus.Native.Code;
using Corvus.Tools;
using static Iced.Intel.AssemblerRegisters;

namespace Corvus.Tests;

/// <summary>collapse=runtime shapes, found on self-assembled x64 functions.</summary>
public class RuntimeCollapseTests
{
    private const uint CodeRva = CodeTestImage.SyntheticCodeRva;
    private const uint Data = CodeTestImage.SyntheticDataRva;
    private const ulong Base = 0x140000000UL;
    private const uint Flag = 0x10;
    private const uint OtherFlag = 0x18;

    private static string Va(uint r) => $"0x{Base + r:X}";

    private static MemoryOperand Static(uint offset, int size) => new(Register.RIP, (long)(Base + Data + offset), size);

    private static void CompareByte(Assembler a, uint offset = Flag, bool wide = false) =>
        a.AddInstruction(Instruction.Create(wide ? Iced.Intel.Code.Cmp_rm64_imm8 : Iced.Intel.Code.Cmp_rm8_imm8, Static(offset, wide ? 8 : 1), 0));

    private static void StoreByte(Assembler a, int value, uint offset = Flag) =>
        a.AddInstruction(Instruction.Create(Iced.Intel.Code.Mov_rm8_imm8, Static(offset, 1), value));

    private static void LoadByte(Assembler a, bool zeroExtend = true) =>
        a.AddInstruction(zeroExtend
            ? Instruction.Create(Iced.Intel.Code.Movzx_r32_rm8, Register.EAX, Static(Flag, 1))
            : Instruction.Create(Iced.Intel.Code.Mov_r8_rm8, Register.AL, Static(Flag, 1)));

    private static void LeaStatic(Assembler a, Register r, uint offset) =>
        a.AddInstruction(Instruction.Create(Iced.Intel.Code.Lea_r64_m, r, Static(offset, 8)));

    // A function assembled from the body, followed by one stub per helper
    // the body called; the stubs are exported under their names.
    private sealed record Built(NativeCodeIndex Index, NativeFunction Fn)
    {
        public List<DisasmLine> Lines => [.. Index.DisassembleFunction(Fn, 2000, out _).Where(e => e.Line != null).Select(e => e.Line!)];

        public Dictionary<uint, RuntimeCollapse.Run> Runs(IReadOnlyDictionary<uint, string>? calls = null) =>
            RuntimeCollapse.Find(Index, Fn, Lines, Va, calls);

        public uint Rva(string mnemonic, int nth = 0) =>
            Lines.Where(l => l.Text.StartsWith(mnemonic, StringComparison.OrdinalIgnoreCase)).ElementAt(nth).Rva;

        public RuntimeCollapse.Run Single() => Assert.Single(Runs().Values);
    }

    private static Built Build(Action<Assembler, Func<string, Label>> body, byte[]? data = null)
    {
        var a = new Assembler(64);
        var helpers = new Dictionary<string, Label>();
        Label Helper(string name) => helpers.TryGetValue(name, out var l) ? l : helpers[name] = a.CreateLabel();
        body(a, Helper);
        var stubs = new List<(string Name, Label Label)>();
        foreach (var (name, label) in helpers)
        {
            var l = label;
            a.int3();
            a.Label(ref l);
            a.ret();
            stubs.Add((name, l));
        }
        var stream = new MemoryStream();
        var result = a.Assemble(new StreamCodeWriter(stream), Base + CodeRva, BlockEncoderOptions.ReturnNewInstructionOffsets);
        var exports = stubs.Where(s => s.Name.Length > 0).Select((s, k) => new NativeExport(s.Name, (uint)k + 1, (uint)(result.GetLabelRIP(s.Label) - Base), null)).ToList();
        var image = CodeTestImage.Synthetic(NativeArch.X64, stream.ToArray(), data ?? new byte[0x200], exports: exports, entry: CodeRva);
        var index = NativeCodeIndex.Build(image);
        return new Built(index, index.FunctionAt(CodeRva)!);
    }

    private static Built Unnamed(Action<Assembler, Label> body) => Build((a, helper) => body(a, helper("")));

    [Fact]
    public void A_shift_by_12_then_a_bit_set_of_memory_and_a_backward_branch_is_one_write_barrier()
    {
        var b = Build((a, _) =>
        {
            var top = a.CreateLabel();
            a.mov(rax, rcx);
            a.shr(rax, 12);
            a.Label(ref top);
            a.bts(__qword_ptr[rdx], rax);
            a.jne(top);
            a.ret();
        });
        var run = b.Single();
        Assert.Equal(b.Rva("shr"), run.Start);
        Assert.Equal(3, run.Count);
        Assert.StartsWith("collapsed: write barrier (3 instructions", run.Note);
    }

    // Regression 0bf3610b2: the shifted value reaches the update through
    // unrelated code.
    [Fact]
    public void Instructions_between_the_shift_and_the_update_stay_inside_the_write_barrier()
    {
        var b = Build((a, _) =>
        {
            var top = a.CreateLabel();
            a.mov(rax, rcx);
            a.shr(rax, 12);
            a.mov(r10, rdx);
            a.add(r10, 8);
            a.mov(r11, rcx);
            a.Label(ref top);
            a.bts(__qword_ptr[r10], rax);
            a.jne(top);
            a.ret();
        });
        Assert.Equal(6, b.Single().Count);
    }

    // Regression 0bf3610b2: the shifted value is spilled to the stack and
    // reloaded.
    [Fact]
    public void A_shifted_value_spilled_to_the_stack_and_reloaded_is_one_write_barrier()
    {
        var b = Build((a, _) =>
        {
            var top = a.CreateLabel();
            a.sub(rsp, 0x28);
            a.mov(rax, rcx);
            a.shr(rax, 12);
            a.mov(__qword_ptr[rsp + 0x20], rax);
            a.xor(eax, eax);
            a.mov(r8, __qword_ptr[rsp + 0x20]);
            a.Label(ref top);
            a.bts(__qword_ptr[rdx], r8);
            a.jne(top);
            a.add(rsp, 0x28);
            a.ret();
        });
        var run = b.Single();
        Assert.Equal(b.Rva("shr"), run.Start);
        Assert.Equal(6, run.Count);
    }

    // Regression 0bf3610b2: a bit mask made from the shifted value, stored by a
    // locked exchange.
    [Fact]
    public void A_locked_exchange_of_a_value_made_from_the_shifted_one_is_one_write_barrier()
    {
        var b = Build((a, _) =>
        {
            var retry = a.CreateLabel();
            a.mov(r10, rcx);
            a.shr(r10, 12);
            a.mov(r11d, 1);
            a.mov(ecx, r10d);
            a.shl(r11, cl);
            a.Label(ref retry);
            a.mov(rax, __qword_ptr[rdx]);
            a.mov(r9, rax);
            a.or(r9, r11);
            a.@lock.cmpxchg(__qword_ptr[rdx], r9);
            a.jne(retry);
            a.ret();
        });
        var run = b.Single();
        Assert.Equal(b.Rva("shr"), run.Start);
        Assert.Equal(9, run.Count);
    }

    [Fact]
    public void A_shift_by_12_with_a_bit_set_of_an_unrelated_value_is_kept()
    {
        var b = Build((a, _) =>
        {
            var top = a.CreateLabel();
            a.shr(rax, 12);
            a.Label(ref top);
            a.bts(__qword_ptr[rdx], rcx);
            a.jne(top);
            a.ret();
        });
        Assert.Empty(b.Runs());
    }

    [Fact]
    public void A_shift_by_12_without_a_bit_set_or_locked_exchange_is_kept()
    {
        var b = Build((a, _) => { a.shr(rax, 12); a.add(rax, rcx); a.ret(); });
        Assert.Empty(b.Runs());
    }

    [Fact]
    public void A_shift_and_register_bit_set_in_a_loop_is_kept()
    {
        var b = Build((a, _) =>
        {
            var top = a.CreateLabel();
            a.Label(ref top);
            a.shr(rax, 12);
            a.bts(rdx, rax);
            a.jne(top);
            a.ret();
        });
        Assert.Empty(b.Runs());
    }

    [Fact]
    public void A_shift_and_bit_set_without_a_closing_loop_is_kept()
    {
        var b = Build((a, _) => { a.shr(rax, 12); a.bts(__qword_ptr[rdx], rax); a.ret(); });
        Assert.Empty(b.Runs());
    }

    [Fact]
    public void A_barrier_whose_branch_leaves_the_run_is_kept()
    {
        var b = Build((a, _) =>
        {
            var top = a.CreateLabel();
            var far = a.CreateLabel();
            a.shr(rax, 12);
            a.je(far);
            a.Label(ref top);
            a.bts(__qword_ptr[rdx], rax);
            a.jne(top);
            a.nop();
            a.Label(ref far);
            a.ret();
        });
        Assert.Empty(b.Runs());
    }

    [Fact]
    public void A_barrier_whose_loop_head_is_before_the_shift_is_kept()
    {
        var b = Build((a, _) =>
        {
            var head = a.CreateLabel();
            a.Label(ref head);
            a.nop();
            a.shr(rax, 12);
            a.bts(__qword_ptr[rdx], rax);
            a.jne(head);
            a.ret();
        });
        Assert.Empty(b.Runs());
    }

    [Fact]
    public void A_run_split_by_a_gap_between_blocks_is_kept()
    {
        var b = Build((a, _) =>
        {
            var top = a.CreateLabel();
            var closing = a.CreateLabel();
            a.shr(rax, 12);
            a.Label(ref top);
            a.bts(__qword_ptr[rdx], rax);
            a.jmp(closing);
            for (int i = 0; i < 8; i++) a.int3();
            a.Label(ref closing);
            a.jne(top);
            a.ret();
        });
        Assert.Empty(b.Runs());
    }

    // One zero check of a static flag, `calls` initializer calls and the
    // optional fence and flag store.
    private static Built Lazy(Func<Assembler, Label, Label> check, int calls = 1, string helper = "Runtime_InitMetadata", bool fence = false, bool store = false, int setup = 1)
        => Build((a, h) =>
        {
            var skip = a.CreateLabel();
            check(a, skip);
            for (int i = 0; i < setup; i++) LeaStatic(a, rcx, 0x20);
            for (int i = 0; i < calls; i++) a.call(h(helper));
            if (fence) a.@lock.or(__dword_ptr[rsp], 0);
            if (store) StoreByte(a, 1);
            a.Label(ref skip);
            a.mov(rax, rcx);
            a.ret();
        });

    private static Label Compare(Assembler a, Label skip, int moves = 0, bool wide = false)
    {
        CompareByte(a, wide: wide);
        for (int i = 0; i < moves; i++) a.mov(rbx, rcx);
        a.jne(skip);
        return skip;
    }

    [Fact]
    public void A_zero_check_that_skips_one_initializer_call_is_one_lazy_initialization()
    {
        var b = Lazy((a, skip) => Compare(a, skip, wide: true), helper: "Init");
        var run = b.Single();
        Assert.Equal(4, run.Count);
        Assert.Equal(b.Rva("cmp"), run.Start);
        Assert.Contains($"lazy initialization of {Va(Data + Flag)}", run.Note);
    }

    // Regression 0bf3610b2: a register move scheduled between the check and the
    // branch stays listed.
    [Fact]
    public void A_register_move_between_the_check_and_the_branch_stays_listed_outside_the_run()
    {
        var b = Lazy((a, skip) => Compare(a, skip, 1));
        var run = b.Single();
        Assert.Equal(b.Rva("jne"), run.Start);
        Assert.Equal(3, run.Count);
    }

    [Fact]
    public void Four_register_moves_between_the_check_and_the_branch_collapse_and_five_do_not()
    {
        Assert.Single(Lazy((a, skip) => Compare(a, skip, 4)).Runs());
        Assert.Empty(Lazy((a, skip) => Compare(a, skip, 5)).Runs());
    }

    [Fact]
    public void A_fence_and_flag_store_after_the_call_collapse_with_the_block()
    {
        var b = Lazy((a, skip) => Compare(a, skip), fence: true, store: true);
        Assert.Equal(6, b.Single().Count);
    }

    [Fact]
    public void A_fence_alone_or_a_flag_store_alone_ends_the_block_at_the_skip_target()
    {
        Assert.Equal(5, Lazy((a, skip) => Compare(a, skip), fence: true).Single().Count);
        Assert.Equal(5, Lazy((a, skip) => Compare(a, skip), store: true).Single().Count);
    }

    [Fact]
    public void A_store_to_another_flag_does_not_end_the_block()
    {
        var b = Build((a, h) =>
        {
            var skip = a.CreateLabel();
            CompareByte(a);
            a.jne(skip);
            LeaStatic(a, rcx, 0x20);
            a.call(h("Runtime_InitMetadata"));
            a.@lock.or(__dword_ptr[rsp], 0);
            StoreByte(a, 1, OtherFlag);
            a.Label(ref skip);
            a.ret();
        });
        Assert.Empty(b.Runs());
    }

    [Fact]
    public void A_store_of_another_value_does_not_end_the_block()
    {
        var b = Build((a, h) =>
        {
            var skip = a.CreateLabel();
            CompareByte(a);
            a.jne(skip);
            LeaStatic(a, rcx, 0x20);
            a.call(h("Runtime_InitMetadata"));
            StoreByte(a, 2);
            a.Label(ref skip);
            a.ret();
        });
        Assert.Empty(b.Runs());
    }

    [Fact]
    public void An_instruction_between_the_check_and_the_branch_that_writes_memory_is_kept()
    {
        var b = Lazy((a, skip) =>
        {
            CompareByte(a);
            a.mov(rbx, rcx);
            a.mov(__qword_ptr[rsp + 8], rcx);
            a.jne(skip);
            return skip;
        });
        Assert.Empty(b.Runs());
    }

    [Fact]
    public void A_zero_check_whose_branch_skips_other_code_is_kept()
    {
        var b = Build((a, h) =>
        {
            var far = a.CreateLabel();
            CompareByte(a, wide: true);
            a.jne(far);
            a.call(h("Init"));
            a.mov(rax, rcx);
            a.nop();
            a.nop();
            a.Label(ref far);
            a.ret();
        });
        Assert.Empty(b.Runs());
    }

    [Fact]
    public void Four_setup_instructions_before_the_initializer_call_collapse_and_five_do_not()
    {
        Assert.Single(Lazy((a, skip) => Compare(a, skip, wide: true), setup: 4).Runs());
        Assert.Empty(Lazy((a, skip) => Compare(a, skip, wide: true), setup: 5).Runs());
    }

    [Fact]
    public void A_tested_load_of_a_pointer_static_before_one_call_is_kept()
    {
        var b = Build((a, h) =>
        {
            var skip = a.CreateLabel();
            a.AddInstruction(Instruction.Create(Iced.Intel.Code.Mov_r64_rm64, Register.RAX, Static(Flag, 8)));
            a.test(rax, rax);
            a.jne(skip);
            a.call(h("Init"));
            a.Label(ref skip);
            a.nop();
            a.ret();
        });
        Assert.DoesNotContain(b.Runs().Values, r => r.Note.Contains("lazy", StringComparison.Ordinal));
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void A_tested_byte_load_of_a_flag_before_one_call_is_one_lazy_initialization(bool zeroExtend)
    {
        var b = Build((a, h) =>
        {
            var skip = a.CreateLabel();
            LoadByte(a, zeroExtend);
            if (zeroExtend) a.test(eax, eax); else a.test(al, al);
            a.jne(skip);
            a.call(h("Init"));
            a.Label(ref skip);
            a.nop();
            a.ret();
        });
        Assert.Contains("lazy initialization", b.Single().Note);
    }

    // Regression 0bf3610b2: the loaded flag is spilled and reloaded, with code
    // between the load and the test.
    [Fact]
    public void A_flag_loaded_early_and_spilled_before_the_test_is_one_lazy_initialization()
    {
        var b = Build((a, h) =>
        {
            var skip = a.CreateLabel();
            a.sub(rsp, 0x28);
            LoadByte(a);
            a.mov(__qword_ptr[rsp + 0x20], rax);
            a.add(edx, 5);
            a.mov(r8, rdx);
            a.mov(rax, __qword_ptr[rsp + 0x20]);
            a.test(eax, eax);
            a.jne(skip);
            a.call(h("Init"));
            a.Label(ref skip);
            a.add(rsp, 0x28);
            a.ret();
        });
        var run = b.Single();
        Assert.Equal(b.Rva("test"), run.Start);
        Assert.Equal(3, run.Count);
    }

    [Fact]
    public void A_static_base_call_is_one_metadata_initialization_line()
    {
        var b = Build((a, h) => { a.call(h("GetGCStaticBase_Thing")); a.ret(); });
        var run = b.Single();
        Assert.Equal(1, run.Count);
        Assert.Contains("metadata initialization GetGCStaticBase_Thing", run.Note);
    }

    [Fact]
    public void A_call_named_only_by_the_call_map_is_one_metadata_initialization_line()
    {
        var b = Unnamed((a, target) => { a.call(target); a.ret(); });
        var calls = new Dictionary<uint, string> { [CodeRva] = "GetNonGCStaticBase_Thing" };
        Assert.Contains("metadata initialization GetNonGCStaticBase_Thing", Assert.Single(b.Runs(calls).Values).Note);
        Assert.Empty(b.Runs());
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
        Assert.Throws<ToolError>(() => RuntimeCollapse.RequireEngine(false, false, NativeArch.X86));
        Assert.Throws<ToolError>(() => RuntimeCollapse.RequireEngine(false, false, NativeArch.Arm64));
        Assert.Throws<ToolError>(() => RuntimeCollapse.RequireFunction(false));
    }

    // A zero-checked initializer call, a static-base call and a loop whose
    // bit-set is also a branch target.
    private static Built Fixture() => Build((a, h) =>
    {
        var after = a.CreateLabel();
        var mid = a.CreateLabel();
        a.sub(rsp, 0x28);
        CompareByte(a, wide: true);
        a.jne(after);
        LeaStatic(a, rcx, 0x20);
        a.call(h("Init"));
        a.Label(ref after);
        a.call(h("GetGCStaticBase_Thing"));
        a.mov(rax, rcx);
        a.shr(rax, 12);
        a.Label(ref mid);
        a.bts(__qword_ptr[rdx], rax);
        a.jne(mid);
        a.test(rdx, rdx);
        a.je(mid);
        a.add(rsp, 0x28);
        a.ret();
    });

    private static string Listing(Built b, bool? collapse, int max = 2000)
    {
        var sb = new StringBuilder();
        var calls = new Dictionary<uint, string>();
        var classifier = new AddressClassifier(b.Index);
        if (collapse == null) NativeCodeTools.AppendFunction(sb, b.Index, classifier, b.Fn, max, calls, [], default);
        else NativeCodeTools.AppendFunction(sb, b.Index, classifier, b.Fn, max, calls, [], default, collapse.Value);
        return sb.ToString().Replace("\r", "");
    }

    [Fact]
    public void A_function_listing_names_each_run_and_counts_instructions_before_and_after()
    {
        var b = Fixture();
        var text = Listing(b, true);
        Assert.Contains("; collapsed: lazy initialization of", text);
        Assert.Contains("; collapsed: write barrier", text);
        Assert.Contains("; collapsed: metadata initialization", text);
        int all = b.Lines.Count;
        var notes = text.Split('\n').Where(l => l.StartsWith("; collapsed:")).ToList();
        int folded = notes.Sum(l => int.Parse(l.Split('(')[1].Split(' ')[0]));
        Assert.Contains($"; collapse=runtime: {all} instructions listed as {all - folded + notes.Count} lines", text);
        Assert.True(folded > notes.Count);
    }

    [Fact]
    public void Collapse_off_leaves_the_listing_byte_identical_to_the_default()
    {
        var b = Fixture();
        var plain = Listing(b, false);
        Assert.Equal(Listing(b, null), plain);
        Assert.DoesNotContain("collapse", plain);
    }

    [Fact]
    public void A_label_inside_a_collapsed_run_is_kept_after_the_run_note_when_a_listed_line_branches_to_it()
    {
        var lines = Listing(Fixture(), true).Split('\n');
        int barrier = Array.FindIndex(lines, l => l.StartsWith("; collapsed: write barrier"));
        Assert.True(barrier >= 0);
        Assert.Matches("^loc_[0-9A-F]+:$", lines[barrier + 1]);
    }

    [Fact]
    public void A_listing_cut_inside_a_barrier_loop_keeps_its_instructions()
    {
        var b = Fixture();
        int shift = b.Lines.FindIndex(l => l.Text.StartsWith("shr", StringComparison.OrdinalIgnoreCase));
        var text = Listing(b, true, shift + 2);
        Assert.DoesNotContain("write barrier", text);
        Assert.Contains("; truncated at", text);
    }

    [Fact]
    public void The_built_in_decoder_text_matches_each_shape()
    {
        Assert.Equal(3, Fixture().Runs().Count);
    }

    [Fact]
    public void A_function_listing_keeps_code_outside_the_runs_and_drops_their_instructions()
    {
        var b = Fixture();
        var plain = Listing(b, false);
        var text = Listing(b, true);
        Assert.Contains("4883EC28", text);
        Assert.Contains("4883C428", text);
        Assert.Contains("48C1E80C", plain);
        Assert.DoesNotContain("48C1E80C", text);
    }

    [Fact]
    public void A_lazy_block_and_a_barrier_in_one_function_collapse_without_hiding_other_code()
    {
        var b = Build((a, h) =>
        {
            var after = a.CreateLabel();
            var top = a.CreateLabel();
            a.push(rbx);
            CompareByte(a);
            a.jne(after);
            LeaStatic(a, rcx, 0x20);
            a.call(h("Init"));
            a.Label(ref after);
            a.mov(rax, rcx);
            a.shr(rax, 12);
            a.Label(ref top);
            a.bts(__qword_ptr[rdx], rax);
            a.jne(top);
            a.pop(rbx);
            a.ret();
        });
        var runs = b.Runs();
        Assert.Equal(2, runs.Count);
        uint lazy = b.Rva("cmp"), barrier = b.Rva("shr");
        Assert.Equal(4, runs[lazy].Count);
        Assert.Equal(3, runs[barrier].Count);
        Assert.Equal(4, b.Lines.Count - runs.Values.Sum(r => r.Count));
        Assert.Contains("lazy initialization of " + Va(Data + Flag), runs[lazy].Note);
        Assert.Contains("write barrier", runs[barrier].Note);
        Assert.Equal(b.Rva("mov"), runs[lazy].End);
        Assert.Equal(b.Rva("pop"), runs[barrier].End);
    }

    private static Built ClassInitBlock(string helper, Action<Assembler>? before = null, Action<Assembler>? between = null, Action<Assembler>? check = null) =>
        Build((a, h) =>
        {
            var skip = a.CreateLabel();
            before?.Invoke(a);
            if (check != null) check(a);
            else a.cmp(__dword_ptr[rcx + 0xE0], 0);
            between?.Invoke(a);
            a.jne(skip);
            a.call(h(helper));
            a.Label(ref skip);
            a.mov(rax, rcx);
            a.ret();
        });

    // Regression 0bf3610b2: the class-init check is folded.
    [Fact]
    public void A_flag_check_that_skips_the_class_init_helper_is_one_class_initialization()
    {
        var run = ClassInitBlock("Runtime_ClassInit").Single();
        Assert.Equal(3, run.Count);
        Assert.StartsWith("collapsed: class initialization", run.Note);
    }

    [Fact]
    public void A_byte_flag_of_the_class_is_checked_the_same_way()
    {
        var b = ClassInitBlock("Runtime_ClassInit", check: a => a.cmp(__byte_ptr[rcx + 0x18], 0));
        Assert.Equal(3, b.Single().Count);
    }

    // Regression 0bf3610b2: the field is loaded, then tested.
    [Fact]
    public void A_loaded_class_flag_that_is_tested_is_one_class_initialization()
    {
        var b = ClassInitBlock("Runtime_ClassInit", check: a => { a.mov(eax, __dword_ptr[rcx + 0xE0]); a.test(eax, eax); });
        var run = b.Single();
        Assert.Equal(b.Rva("test"), run.Start);
        Assert.Equal(3, run.Count);
    }

    // Regression 0bf3610b2: a register move scheduled between the check and the
    // branch.
    [Fact]
    public void A_register_move_between_the_class_check_and_the_branch_stays_listed()
    {
        var b = ClassInitBlock("Runtime_ClassInit", between: a => a.mov(rbx, rcx));
        var run = b.Single();
        Assert.Equal(b.Rva("jne"), run.Start);
        Assert.Equal(2, run.Count);
    }

    // Regression 0bf3610b2: the class pointer is kept in a stack slot and
    // reloaded for the check and the call.
    [Fact]
    public void A_class_pointer_reloaded_from_a_stack_slot_binds_the_check_and_the_call()
    {
        var b = Build((a, h) =>
        {
            var skip = a.CreateLabel();
            a.sub(rsp, 0x28);
            a.mov(__qword_ptr[rsp + 0x20], rcx);
            a.xor(ecx, ecx);
            a.mov(rdx, __qword_ptr[rsp + 0x20]);
            a.cmp(__dword_ptr[rdx + 0xE0], 0);
            a.jne(skip);
            a.mov(rcx, __qword_ptr[rsp + 0x20]);
            a.call(h("Runtime_ClassInit"));
            a.Label(ref skip);
            a.add(rsp, 0x28);
            a.ret();
        });
        Assert.StartsWith("collapsed: class initialization", b.Single().Note);
    }

    // Regression 0bf3610b2: the setup register is restored after the call,
    // before the skip target.
    [Fact]
    public void A_register_restored_after_the_class_init_call_stays_inside_the_run()
    {
        var b = Build((a, h) =>
        {
            var skip = a.CreateLabel();
            a.mov(rsi, __qword_ptr[rcx]);
            a.cmp(__byte_ptr[rsi + 0xE4], 0);
            a.jne(skip);
            a.mov(rbx, rcx);
            a.mov(rcx, rsi);
            a.call(h("Runtime_ClassInit"));
            a.mov(rcx, rbx);
            a.Label(ref skip);
            a.call(__qword_ptr[rsi + 0x168]);
            a.ret();
        });
        Assert.Equal(6, b.Single().Count);
    }

    [Fact]
    public void A_class_init_call_made_with_another_pointer_is_kept()
    {
        var other = Build((a, h) =>
        {
            var skip = a.CreateLabel();
            a.cmp(__dword_ptr[rcx + 0xE0], 0);
            a.jne(skip);
            a.mov(rcx, rdx);
            a.call(h("Runtime_ClassInit"));
            a.Label(ref skip);
            a.ret();
        });
        Assert.Empty(other.Runs());
    }

    [Theory]
    [InlineData("Runtime_ObjectNew")]
    [InlineData("Runtime_ClassInitFoo")]
    [InlineData("NotRuntime_ClassInit2")]
    public void A_flag_check_that_skips_a_call_to_another_function_is_kept(string name)
    {
        Assert.Single(ClassInitBlock("Runtime_ClassInit").Runs());
        Assert.Empty(ClassInitBlock(name).Runs());
    }

    [Fact]
    public void A_class_init_helper_named_only_by_the_call_map_is_folded()
    {
        var b = ClassInitBlock("");
        uint call = b.Lines.Single(l => l.Text.StartsWith("call", StringComparison.Ordinal)).Rva;
        Assert.Single(b.Runs(new Dictionary<uint, string> { [call] = "Runtime_ClassInit" }));
        Assert.Empty(b.Runs(new Dictionary<uint, string> { [call] = "Runtime_ObjectNew" }));
        Assert.Empty(b.Runs());
    }

    private static Built TwoInit(string second, bool fence, bool fenceBetween = false, bool saved = false) => Build((a, h) =>
    {
        var skip = a.CreateLabel();
        CompareByte(a);
        if (saved) a.mov(rdi, rax);
        a.jne(skip);
        LeaStatic(a, rcx, 0x20);
        a.call(h("Runtime_InitMetadata"));
        if (fenceBetween) a.@lock.or(__dword_ptr[rsp], 0);
        LeaStatic(a, rcx, 0x28);
        a.call(h(second));
        if (fence || fenceBetween) a.@lock.or(__dword_ptr[rsp], 0);
        StoreByte(a, 1);
        a.Label(ref skip);
        if (saved) a.test(rdi, rdi);
        a.nop();
        a.ret();
    });

    // Regression 0bf3610b2: a lazy block with two metadata-init calls is
    // folded.
    [Theory]
    [InlineData(true, 8)]
    [InlineData(false, 7)]
    public void A_lazy_block_with_two_metadata_init_calls_is_one_lazy_initialization(bool fence, int count)
    {
        var b = TwoInit("Runtime_InitMetadata", fence);
        var run = b.Single();
        Assert.Equal(count, run.Count);
    }

    // Regression 0bf3610b2: several calls fold only when every one is a
    // metadata-init helper.
    [Theory]
    [InlineData("Runtime_ObjectNew")]
    [InlineData("Runtime_InitMetadataFoo")]
    public void A_lazy_block_with_a_second_call_to_another_function_is_kept(string second)
    {
        Assert.Empty(TwoInit(second, true).Runs());
    }

    [Fact]
    public void A_lazy_block_with_one_call_to_any_target_and_no_fence_is_folded()
    {
        var b = Lazy((a, skip) => Compare(a, skip), helper: "Runtime_ObjectNew");
        Assert.Equal(4, b.Single().Count);
    }

    [Fact]
    public void A_lazy_scan_does_not_continue_past_the_skip_target()
    {
        var b = Build((a, h) =>
        {
            var skip = a.CreateLabel();
            CompareByte(a);
            a.jne(skip);
            LeaStatic(a, rcx, 0x20);
            a.mov(rax, rcx);
            a.Label(ref skip);
            for (int i = 0; i < 8; i++) { a.mov(rax, rcx); a.call(h("Init")); }
            a.ret();
        });
        Assert.Empty(b.Runs());
    }

    [Fact]
    public void A_lazy_block_with_a_fence_after_each_of_two_initializer_calls_is_one_run()
    {
        // The retest on 106651bf: the fence after the first call ended the scan.
        var b = TwoInit("Runtime_InitMetadata", false, fenceBetween: true, saved: true);
        var run = b.Single();
        Assert.Equal(b.Rva("jne"), run.Start);
        Assert.Equal(b.Rva("test"), run.End);
    }

    private static (NativeCodeIndex Index, NativeFunction Fn, uint Case0) BarrierCase(bool table)
    {
        var a = new Assembler(64);
        var dflt = a.CreateLabel();
        var cases = new[] { a.CreateLabel(), a.CreateLabel(), a.CreateLabel(), a.CreateLabel() };
        if (table)
        {
            a.AddInstruction(Instruction.Create(Iced.Intel.Code.Lea_r64_m, Register.RDX, new MemoryOperand(Register.RIP, (long)Base, 8)));
            a.cmp(ecx, 3);
            a.ja(dflt);
            a.movsxd(rax, ecx);
            a.mov(ecx, __dword_ptr[rdx + rax * 4 + (int)(Data + 0x40)]);
            a.add(rcx, rdx);
            a.jmp(rcx);
        }
        else a.sub(rsp, 0x28);
        a.Label(ref cases[0]);
        a.shr(rax, 12);
        a.bts(__qword_ptr[rdx], rax);
        a.jne(cases[0]);
        a.mov(eax, 10);
        a.ret();
        for (int i = 1; i < cases.Length; i++)
        {
            a.Label(ref cases[i]);
            a.mov(eax, i + 10);
            a.ret();
        }
        a.Label(ref dflt);
        a.xor(eax, eax);
        a.ret();
        var stream = new MemoryStream();
        var result = a.Assemble(new StreamCodeWriter(stream), Base + CodeRva, BlockEncoderOptions.ReturnNewInstructionOffsets);
        var data = new byte[0x100];
        for (int i = 0; i < cases.Length; i++)
            System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(0x40 + i * 4), (uint)(result.GetLabelRIP(cases[i]) - Base));
        var image = CodeTestImage.Synthetic(NativeArch.X64, stream.ToArray(), data, entry: CodeRva);
        var index = NativeCodeIndex.Build(image);
        return (index, index.FunctionAt(CodeRva)!, (uint)(result.GetLabelRIP(cases[0]) - Base));
    }

    // Regression 0bf3610b2: a label that only the collapsed run jumps to is
    // dropped.
    [Fact]
    public void A_label_used_only_inside_a_collapsed_run_is_dropped()
    {
        var (index, fn, case0) = BarrierCase(table: false);
        var b = new Built(index, fn);
        var text = Listing(b, true);
        Assert.Contains("; collapsed: write barrier", text);
        Assert.DoesNotContain($"loc_{case0:X}:", text);
        Assert.Contains($"loc_{case0:X}:", Listing(b, false));
    }

    // Regression 0bf3610b2: a switch-table target in front of a collapsed run
    // keeps its label.
    [Fact]
    public void A_switch_table_target_in_front_of_a_collapsed_run_keeps_its_label()
    {
        var (index, fn, case0) = BarrierCase(table: true);
        Assert.Contains(index.GetGraph(fn).Switches, s => s.Targets.Contains(case0));
        var text = Listing(new Built(index, fn), true).Split('\n');
        int note = Array.FindIndex(text, l => l.StartsWith("; collapsed: write barrier"));
        Assert.True(note > 0);
        Assert.Equal($"loc_{case0:X}:", text[note - 1]);
    }
}
