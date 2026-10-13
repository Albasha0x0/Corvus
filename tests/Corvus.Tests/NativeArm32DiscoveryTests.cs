using Corvus.Native.Code;
using Corvus.Native.Elf;
using Corvus.Tests.NativeFormats;

namespace Corvus.Tests;

/// <summary>
/// Thumb discovery without unwind tables: code right after a function's literal pool, literal pools that end flow, tail
/// jumps to PLT stubs while a candidate is verified, no start inside an IT block, the state of code next to decoded code.
/// </summary>
public class NativeArm32DiscoveryTests
{
    private const uint Text = ElfWriter.TextRva;
    private const uint Data = ElfWriter.DataRva;
    private const uint Got = ElfWriter.GotRva;
    // a literal that reads as Thumb code: movs r0, #1; movs r0, #1
    private const uint CodeLikeLiteral = 0x20012001;

    private static NativeCodeIndex Build(A32Code a, Action<ElfWriter>? configure = null)
    {
        var w = new ElfWriter { Is64 = false, Machine = ElfWriter.EmArm, UseRel = true, Text = a.Bytes() };
        w.Symbols.Add(new ElfWriter.Symbol("main", Text | 1, Type: 2));
        configure?.Invoke(w);
        return NativeCodeIndex.Build(ElfFile.FromBytes(w.Build(), "thumb.so"));
    }

    /// <summary>main: push; ldr r0, =literal; pop; the literal; then a function nothing references and without a prologue.</summary>
    [Fact]
    public void Code_after_a_literal_pool_is_a_function()
    {
        var a = new A32Code(Text);
        uint lit = 0;
        a.H(A32Code.PushLr(0x10)).Later(2, at => A32Code.LdrLit(0, at, lit)).H(A32Code.PopPc(0x10));
        a.Align4();
        lit = a.Here;
        a.W(CodeLikeLiteral);
        uint dead = a.Here;
        a.H(A32Code.LdrImm(0, 0, 8)).H(A32Code.BxLr);
        var index = Build(a);

        Assert.Equal([Text, dead], index.Functions.Select(f => f.Start));
        Assert.True((index.FunctionByStart(dead)!.Sources & FunctionSource.CodeGap) != 0);
        Assert.Null(index.FunctionAt(lit));
    }

    /// <summary>main: ldr r0, =literal; blx r3 (returns, then runs into its literal); the next function stays separate.</summary>
    [Fact]
    public void A_literal_pool_ends_the_flow_into_it()
    {
        var a = new A32Code(Text);
        uint lit = Text + 4;
        a.H(A32Code.LdrLit(0, Text, lit)).H(A32Code.BlxReg(3));
        a.W(CodeLikeLiteral);
        uint next = a.Here;
        a.H(A32Code.PushLr(0x10)).H(A32Code.MovImm(0, 2)).H(A32Code.PopPc(0x10));
        var index = Build(a);

        Assert.Equal([Text, next], index.Functions.Select(f => f.Start));
        // main's extent keeps its pool, as symbol sizes do, and stops at the next function
        Assert.Equal([(Text, next)], index.Ranges(index.FunctionByStart(Text)!));
    }

    /// <summary>A function reached only through a pointer ends in b.w to a PLT entry (Thumb bx pc; nop, then A32): a tail call, not code to verify.</summary>
    [Fact]
    public void A_tail_jump_to_a_plt_stub_verifies()
    {
        var a = new A32Code(Text);
        uint stub = 0;
        a.H(A32Code.BxLr);
        uint f = a.Here;
        a.H(A32Code.PushLr(0x10)).T(0xE8BD4010).Later(-4, at => A32Code.Bl(at, stub) & 0xFFFFBFFF | 0x1000);   // pop.w {r4, lr}; b.w stub
        a.Align4();
        stub = a.Here;
        a.H(0x4778).H(0x46C0).PltEntry(Got);
        var index = Build(a, w =>
        {
            w.Symbols.Add(new ElfWriter.Symbol("puts", Defined: false));
            w.Relocations.Add(new ElfWriter.Reloc(Got, 22, "puts"));
            w.Relocations.Add(new ElfWriter.Reloc(Data + 0x40, 23, Addend: f | 1));
        });

        var fn = index.FunctionByStart(f);
        Assert.NotNull(fn);
        Assert.True((fn.Sources & FunctionSource.DataPointer) != 0);
        Assert.Contains(index.RefsFrom(fn), x => x.Kind == XrefKind.TailCall && x.To == stub);
    }

    /// <summary>A pointer to the instruction after an IT (cmp r0, #0; it eq; movs r0, #1; bx lr) starts no function.</summary>
    [Fact]
    public void No_function_starts_inside_an_it_block()
    {
        var a = new A32Code(Text);
        a.H(A32Code.BxLr);
        uint cmp = a.Here;
        a.H(A32Code.CmpImm(0, 0)).H(A32Code.It(0));
        uint inside = a.Here;
        a.H(A32Code.MovImm(0, 1)).H(A32Code.BxLr);
        var index = Build(a, w => w.Relocations.Add(new ElfWriter.Reloc(Data + 0x40, 23, Addend: inside | 1)));

        Assert.Null(index.FunctionByStart(inside));
        Assert.DoesNotContain(index.Functions, f => f.Start > Text && f.Start < cmp);
    }

    /// <summary>
    /// In an image of Thumb functions, an A32 function forms the address of another (ldr r0, =handler - pc; add r0, pc, r0):
    /// the handler (cmp r0, #0; bxeq lr; bx r0, crtbegin's atexit wrapper) is an A32 function with a reference from the add.
    /// </summary>
    [Fact]
    public void An_a32_pic_pair_seeds_an_a32_function_in_a_thumb_image()
    {
        var a = new A32Code(Text);
        var w = new ElfWriter { Is64 = false, Machine = ElfWriter.EmArm, UseRel = true };
        for (int k = 0; k < 16; k++)
        {
            w.Symbols.Add(new ElfWriter.Symbol($"t{k}", a.Here | 1, Type: 2));
            a.H(A32Code.BxLr).H(A32Code.Nop);
        }
        uint main = a.Here, lit = 0, handler = 0;
        a.Later(4, at => 0xE59F0000 | (lit - (at + 8)));     // ldr r0, [pc, #x]
        uint add = a.Here;
        a.W(0xE08F0000).W(A32Code.ArmBxLr);                   // add r0, pc, r0; bx lr
        lit = a.Here;
        a.Later(4, _ => handler - (add + 8));
        handler = a.Here;
        a.W(0xE3500000).W(0x012FFF1E).W(0xE12FFF10);          // cmp r0, #0; bxeq lr; bx r0
        w.Text = a.Bytes();
        w.Symbols.Add(new ElfWriter.Symbol("main", main, Type: 2));
        var index = NativeCodeIndex.Build(ElfFile.FromBytes(w.Build(), "pic.so"));

        Assert.NotNull(index.FunctionByStart(handler));
        Assert.False(index.CreateDisassembler().ThumbAt(handler));
        Assert.Contains(index.RefsTo(handler), x => x.From == add);
    }

    /// <summary>A start whose bytes read in both states takes the state of the code decoded right before it.</summary>
    [Fact]
    public void A_start_next_to_decoded_code_takes_its_state()
    {
        var a = new A32Code(Text);
        a.W(A32Code.ArmCmp(0, 0)).W(A32Code.ArmBxLr);
        var image = ElfFile.FromBytes(new ElfWriter { Is64 = false, Machine = ElfWriter.EmArm, UseRel = true, Text = a.Bytes() }.Build(), "state.so");
        var modes = new Arm32Modes(image);
        modes.HintNeighbor(Text, thumb: false);
        Assert.False(modes.StartMode(Text));
        Assert.False(modes.IsUnsure(Text));
        // a halfword-aligned start is Thumb whatever the neighbour
        modes.HintNeighbor(Text + 2, thumb: false);
        Assert.True(modes.StartMode(Text + 2));
    }

    // b.w (T4) from Thumb: BL with bit 14 of the second halfword clear
    private static uint BW(uint from, uint to) => A32Code.Bl(from, to) & 0xFFFFBFFF | 0x1000;

    /// <summary>
    /// main: push {r4, lr}; cmp r0, #0; bne 1f; b.w cold; 1: pop.w {r4, lr}; b.w helper. helper, before main, runs on its
    /// own frame (push; a tbb switch; pop {r4, pc}): a tail-called function. cold pops main's frame: a block of main.
    /// </summary>
    [Fact]
    public void A_tail_jump_target_before_its_function_is_a_function_when_its_frame_balances()
    {
        var a = new A32Code(Text);
        uint helper = 0, cold, main, after = 0, dflt = 0, tb;
        var cases = new uint[2];
        a.H(A32Code.BxLr);
        cold = a.Here;
        a.H(A32Code.MovImm(0, 3)).H(A32Code.PopPc(0x10));
        helper = a.Here;
        a.H(A32Code.PushLr(0x10)).H(A32Code.CmpImm(0, 1)).Later(2, at => A32Code.BCond(at, dflt, 8));   // bhi default
        tb = a.Here;
        a.T(A32Code.Tbb(0)).Later(2, _ => (cases[0] - (tb + 4)) / 2 | (cases[1] - (tb + 4)) / 2 << 8);
        for (int k = 0; k < 2; k++) { cases[k] = a.Here; a.H(A32Code.MovImm(0, k + 10)).H(A32Code.PopPc(0x10)); }
        dflt = a.Here;
        a.H(A32Code.MovImm(0, 0)).H(A32Code.PopPc(0x10));
        main = a.Here;
        a.H(A32Code.PushLr(0x10)).H(A32Code.CmpImm(0, 0)).Later(2, at => A32Code.BCond(at, after, 1));      // bne
        a.Later(-4, at => BW(at, cold));
        after = a.Here;
        a.T(0xE8BD4010).Later(-4, at => BW(at, helper));                                                       // pop.w {r4, lr}
        var w = new ElfWriter { Is64 = false, Machine = ElfWriter.EmArm, UseRel = true, Text = a.Bytes() };
        w.Symbols.Add(new ElfWriter.Symbol("main", main | 1, Type: 2));
        var index = NativeCodeIndex.Build(ElfFile.FromBytes(w.Build(), "tail.so"));

        Assert.True(index.FunctionByStart(helper) is { } h && (h.Sources & FunctionSource.TailJump) != 0);
        Assert.Null(index.FunctionByStart(cold));
        Assert.Equal(main, index.FunctionAt(cold)?.Start);
    }

    /// <summary>main: b.w over a speculation barrier (dsb sy; isb sy) to the code right after it: a tail call to the next function.</summary>
    [Fact]
    public void A_jump_over_a_speculation_barrier_is_a_tail_call()
    {
        var a = new A32Code(Text);
        uint next = 0;
        a.H(0x460B).Later(-4, at => BW(at, next)).T(0xF3BF8F4F).T(0xF3BF8F6F);   // mov r3, r1; b.w next; dsb sy; isb sy
        next = a.Here;
        a.H(A32Code.PushLr(0x10)).H(A32Code.MovImm(0, 1)).H(A32Code.PopPc(0x10));
        var index = Build(a);

        Assert.True(index.FunctionByStart(next) is { } f && (f.Sources & FunctionSource.TailJump) != 0);
        Assert.Equal([(Text, Text + 6)], index.Ranges(index.FunctionByStart(Text)!));
    }
}
