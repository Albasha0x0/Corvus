using Corvus.Native.Code;
using Corvus.Native.Elf;
using Corvus.Tests.NativeFormats;

namespace Corvus.Tests;

/// <summary>ARM32 jump tables: TBB / TBH, LDR PC tables (absolute), ADD PC of a base and a table entry, ADD PC, PC, index runs of branches.</summary>
public class NativeArm32SwitchTests
{
    private const uint Text = ElfWriter.TextRva;
    private const int Hi = 8;

    private static (FunctionGraph Graph, NativeCodeIndex Index) Build(A32Code a, bool thumb)
    {
        var w = new ElfWriter { Is64 = false, Machine = ElfWriter.EmArm, UseRel = true, Text = a.Bytes() };
        w.Symbols.Add(new ElfWriter.Symbol("dispatch", thumb ? Text | 1 : Text, Type: 2));
        var index = NativeCodeIndex.Build(ElfFile.FromBytes(w.Build(), "switch.so"));
        return (index.GetGraph(index.FunctionByStart(Text)!), index);
    }

    /// <summary>Thumb: cmp r0, #n-1; bhi default; tbb / tbh [pc, r0]; table; cases (movs r0, #k; bx lr); default.</summary>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Thumb_table_branch(bool halfword)
    {
        const int n = 4;
        var a = new A32Code(Text);
        var cases = new uint[n];
        uint dflt = 0, tb = 0;
        a.H(A32Code.CmpImm(0, n - 1)).Later(2, at => A32Code.BCond(at, dflt, Hi));
        tb = a.Here;
        a.T(halfword ? A32Code.Tbh(0) : A32Code.Tbb(0));
        for (int k = 0; k < n; k++)
        {
            int c = k;
            if (halfword) a.Later(2, _ => (cases[c] - (tb + 4)) / 2);
            else if (k % 2 == 0) a.Later(2, _ => (cases[c] - (tb + 4)) / 2 | (cases[c + 1] - (tb + 4)) / 2 << 8);
        }
        for (int k = 0; k < n; k++)
        {
            cases[k] = a.Here;
            a.H(A32Code.MovImm(0, k + 10)).H(A32Code.BxLr);
        }
        dflt = a.Here;
        a.H(A32Code.MovImm(0, 0)).H(A32Code.BxLr);
        var (g, _) = Build(a, thumb: true);

        var s = Assert.Single(g.Switches);
        Assert.Equal((tb, tb + 4, halfword ? 2 : 1, SwitchTableKind.BaseRelative, 1), (s.JumpRva, s.TableRva, s.EntrySize, s.Kind, s.Shift));
        Assert.Equal(cases, s.Cases.Select(c => c.Target));
        Assert.Equal(dflt, s.Default);
        Assert.Empty(g.UnresolvedJumps);
        Assert.Contains(g.Blocks, b => b.Start == cases[3] && b.EndKind == BlockEnd.Return);
    }

    /// <summary>ARM: cmp r0, #2; ldrls pc, [pc, r0, lsl #2]; b default; three absolute entries (an image without relocations).</summary>
    [Fact]
    public void Arm_conditional_load_into_pc()
    {
        var a = new A32Code(Text);
        var cases = new uint[3];
        uint dflt = 0;
        a.W(A32Code.ArmCmp(0, 2)).W(0x979FF100).Later(4, at => A32Code.ArmB(at, dflt));
        uint table = a.Here;
        for (int k = 0; k < 3; k++) { int c = k; a.Later(4, _ => cases[c]); }
        for (int k = 0; k < 3; k++) { cases[k] = a.Here; a.W(0xE3A00000 | (uint)k + 10).W(A32Code.ArmBxLr); }
        dflt = a.Here;
        a.W(0xE3A00000).W(A32Code.ArmBxLr);
        var (g, _) = Build(a, thumb: false);

        var s = Assert.Single(g.Switches);
        Assert.Equal((Text + 4, table, SwitchTableKind.Absolute, 3), (s.JumpRva, s.TableRva, s.Kind, s.EntryCount));
        Assert.Equal(cases, s.Cases.Select(c => c.Target));
        Assert.Equal(Text + 8, s.Default);
        // the conditional dispatch falls through to the branch to the default
        Assert.Contains(g.Blocks, b => b.Start == Text + 8 && b.EndKind == BlockEnd.Jump);
        Assert.Contains(g.Blocks, b => b.Start == dflt);
    }

    /// <summary>ARM: cmp r0, #2; addls pc, pc, r0, lsl #2; b default; b case0; b case1; b case2.</summary>
    [Fact]
    public void Arm_add_pc_into_a_run_of_branches()
    {
        var a = new A32Code(Text);
        var cases = new uint[3];
        uint dflt = 0;
        a.W(A32Code.ArmCmp(0, 2)).W(0x908FF100).Later(4, at => A32Code.ArmB(at, dflt));
        uint run = a.Here;
        for (int k = 0; k < 3; k++) { int c = k; a.Later(4, at => A32Code.ArmB(at, cases[c])); }
        for (int k = 0; k < 3; k++) { cases[k] = a.Here; a.W(0xE3A00000 | (uint)k + 10).W(A32Code.ArmBxLr); }
        dflt = a.Here;
        a.W(0xE3A00000).W(A32Code.ArmBxLr);
        var (g, _) = Build(a, thumb: false);

        var s = Assert.Single(g.Switches);
        Assert.Equal((SwitchTableKind.Indexed, 3), (s.Kind, s.EntryCount));
        Assert.Equal([run, run + 4, run + 8], s.Cases.Select(c => c.Target));
        foreach (var (slot, target) in new[] { (run, cases[0]), (run + 4, cases[1]), (run + 8, cases[2]) })
            Assert.Contains(g.Blocks, b => b.Start == slot && b.Successors.Any(e => e.To == target));
    }

    /// <summary>Thumb: cmp r1, #2; bhi default; adr.w r0, run; add.w r0, r0, r1, lsl #2; mov pc, r0; b.w case0..2.</summary>
    [Fact]
    public void Thumb_mov_pc_into_a_run_of_branches()
    {
        var a = new A32Code(Text);
        var cases = new uint[3];
        uint dflt = 0, run = 0;
        a.H(A32Code.CmpImm(1, 2)).Later(2, at => A32Code.BCond(at, dflt, Hi));
        a.Later(-4, at => 0xF20F0000 | (run - ((at + 4) & ~3u)));   // adr.w r0, run
        a.T(0xEB000081).H(0x4687).H(A32Code.Nop);                     // add.w r0, r0, r1, lsl #2; mov pc, r0
        run = a.Here;
        for (int k = 0; k < 3; k++) { int c = k; a.Later(-4, at => A32Code.Bl(at, cases[c]) & 0xFFFFBFFF | 0x1000); }
        for (int k = 0; k < 3; k++) { cases[k] = a.Here; a.H(A32Code.MovImm(0, k + 10)).H(A32Code.BxLr); }
        dflt = a.Here;
        a.H(A32Code.MovImm(0, 0)).H(A32Code.BxLr);
        var (g, index) = Build(a, thumb: true);

        var s = Assert.Single(g.Switches);
        Assert.Equal((SwitchTableKind.Indexed, 3, dflt), (s.Kind, s.EntryCount, s.Default));
        Assert.Equal([run, run + 4, run + 8], s.Cases.Select(c => c.Target));
        Assert.Equal([Text], index.Functions.Select(f => f.Start));
        Assert.Contains(g.Blocks, b => b.Start == run + 4 && b.Successors.Any(e => e.To == cases[1]));
    }

    /// <summary>
    /// Thumb runs of branches the compiler dispatches through lr (adr.w lr, run; add.w lr, lr, r1, lsl #2; mov pc, lr: not a
    /// return), or bounds by a shifted index (lsrs r3, r1, #1; cmp r3, #1; bhi: four entries).
    /// </summary>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void Thumb_run_of_branches_through_lr_or_a_shifted_bound(bool shifted)
    {
        var a = new A32Code(Text);
        int n = shifted ? 4 : 3;
        var cases = new uint[n];
        uint dflt = 0, run = 0;
        if (shifted) a.H(0x084B).H(A32Code.CmpImm(3, 1));             // lsrs r3, r1, #1; cmp r3, #1
        else a.H(A32Code.CmpImm(1, 2));
        a.Later(2, at => A32Code.BCond(at, dflt, Hi));
        a.Later(-4, at => 0xF20F0E00 | (run - ((at + 4) & ~3u)));   // adr.w lr, run
        a.T(0xEB0E0E81).H(0x46F7).H(A32Code.Nop);                     // add.w lr, lr, r1, lsl #2; mov pc, lr
        run = a.Here;
        for (int k = 0; k < n; k++) { int c = k; a.Later(-4, at => A32Code.Bl(at, cases[c]) & 0xFFFFBFFF | 0x1000); }
        for (int k = 0; k < n; k++) { cases[k] = a.Here; a.H(A32Code.MovImm(0, k + 10)).H(A32Code.BxLr); }
        dflt = a.Here;
        a.H(A32Code.MovImm(0, 0)).H(A32Code.BxLr);
        var (g, index) = Build(a, thumb: true);

        var s = Assert.Single(g.Switches);
        Assert.Equal((SwitchTableKind.Indexed, n, dflt), (s.Kind, s.EntryCount, s.Default));
        Assert.Equal(Enumerable.Range(0, n).Select(k => run + 4 * (uint)k), s.Cases.Select(c => c.Target));
        Assert.Equal([Text], index.Functions.Select(f => f.Start));
        Assert.Empty(g.UnresolvedJumps);
    }

    /// <summary>Thumb, position independent, biased: subs r3, r0, #1; cmp r3, #2; bhi; adr r2, table; ldr.w r3, [r2, r3, lsl #2]; add r2, r3; bx r2.</summary>
    [Fact]
    public void Thumb_base_relative_entries_added_before_bx()
    {
        var a = new A32Code(Text);
        var cases = new uint[3];
        uint dflt = 0, table = 0;
        a.H(0x1E43).H(A32Code.CmpImm(3, 2)).Later(2, at => A32Code.BCond(at, dflt, Hi));
        a.Later(2, at => (0xA200 | (table - ((at + 4) & ~3u)) / 4));
        a.T(0xF8523023).H(0x441A).H(0x4710);
        a.Align4();
        table = a.Here;
        for (int k = 0; k < 3; k++) { int c = k; a.Later(4, _ => (cases[c] | 1) - table); }
        for (int k = 0; k < 3; k++) { cases[k] = a.Here; a.H(A32Code.MovImm(0, k + 10)).H(A32Code.BxLr); }
        dflt = a.Here;
        a.H(A32Code.MovImm(0, 0)).H(A32Code.BxLr);
        var (g, index) = Build(a, thumb: true);

        var s = Assert.Single(g.Switches);
        Assert.Equal((table, SwitchTableKind.BaseRelative, table, 1L), (s.TableRva, s.Kind, s.Base, s.Bias));
        Assert.Equal(cases, s.Cases.Select(c => c.Target));
        Assert.Equal(dflt, s.Default);
        Assert.Equal([Text], index.Functions.Select(f => f.Start));
    }

    /// <summary>ARM, position independent: cmp; bhi default; adr r1, table; ldr r0, [r1, r0, lsl #2]; add pc, r0, r1.</summary>
    [Fact]
    public void Arm_table_relative_entries()
    {
        var a = new A32Code(Text);
        var cases = new uint[3];
        uint dflt = 0, table = 0;
        a.W(A32Code.ArmCmp(0, 2)).Later(4, at => A32Code.ArmB(at, dflt, Hi));
        a.Later(4, at => 0xE28F1000 | (table - (at + 8)));
        a.W(0xE7910100).W(0xE080F001);
        table = a.Here;
        for (int k = 0; k < 3; k++) { int c = k; a.Later(4, _ => cases[c] - table); }
        for (int k = 0; k < 3; k++) { cases[k] = a.Here; a.W(0xE3A00000 | (uint)k + 10).W(A32Code.ArmBxLr); }
        dflt = a.Here;
        a.W(0xE3A00000).W(A32Code.ArmBxLr);
        var (g, index) = Build(a, thumb: false);

        var s = Assert.Single(g.Switches);
        Assert.Equal((table, SwitchTableKind.BaseRelative, table), (s.TableRva, s.Kind, s.Base));
        Assert.Equal(cases, s.Cases.Select(c => c.Target));
        Assert.Equal(dflt, s.Default);
        Assert.Contains(index.RefsTo(table), x => x.Kind == XrefKind.JumpTable);
    }
}
