using System.Buffers.Binary;
using Corvus.Native;
using Corvus.Native.Calls;
using Corvus.Native.Code;

namespace Corvus.Tests;

/// <summary>ARM64 jump tables: entry sizes and signedness, ADR / table bases, absolute tables, bias, sparse defaults, bounds across blocks.</summary>
public class NativeArm64SwitchTests
{
    private const uint Code = CodeTestImage.SyntheticCodeRva;
    private const uint Data = CodeTestImage.SyntheticDataRva;
    private const uint Table = Data + 0x40;
    private const ulong Base = 0x10000000UL;

    private static uint CmpImm(int n, uint imm) => 0x7100001F | imm << 10 | (uint)n << 5;
    private static uint SubImm(int d, int n, uint imm) => 0x51000000 | imm << 10 | (uint)n << 5 | (uint)d;
    private static uint Ldrb(int t, int n, int m) => 0x38606800 | (uint)m << 16 | (uint)n << 5 | (uint)t;
    private static uint LdrbUxtw(int t, int n, int m) => 0x38604800 | (uint)m << 16 | (uint)n << 5 | (uint)t;
    private static uint Ldrh(int t, int n, int m) => 0x78607800 | (uint)m << 16 | (uint)n << 5 | (uint)t;
    private static uint Ldrsw(int t, int n, int m) => 0xB8A07800 | (uint)m << 16 | (uint)n << 5 | (uint)t;
    private static uint LdrX(int t, int n, int m) => 0xF8607800 | (uint)m << 16 | (uint)n << 5 | (uint)t;
    private static uint AddShift(int d, int n, int m, int shift) => 0x8B000000 | (uint)m << 16 | (uint)shift << 10 | (uint)n << 5 | (uint)d;
    private static uint AddSxtb(int d, int n, int m, int shift) => 0x8B208000 | (uint)m << 16 | (uint)shift << 10 | (uint)n << 5 | (uint)d;
    private static uint MovX(int d, int m) => 0xAA0003E0 | (uint)m << 16 | (uint)d;
    private const uint Hs = 2, Ne = 1, Hi = 8;

    /// <summary>A function with a switch on w0; <paramref name="dispatch"/> emits the table load and the br (case and anchor labels given).</summary>
    private static (FunctionGraph Graph, uint[] Cases, uint Default) Build(int cases, Action<A64, Func<uint>> dispatch, Func<uint[], uint, uint, byte[]> table,
        uint bias = 0, uint branch = Hi, IEnumerable<uint>? relocations = null, bool hoisted = false, bool flagsInOtherBlock = false)
    {
        var a = new A64(Code);
        var caseAt = new uint[cases];
        uint anchor = 0, dflt = 0, dispatchBlock = 0;
        if (hoisted) a.Word(A64.Adrp(a.Here, Table, 19, Base)).Word(A64.AddImm(19, 19, Table & 0xFFF));
        a.Word(bias != 0 ? SubImm(8, 0, bias) : MovX(8, 0));
        int count = cases + 1;
        if (flagsInOtherBlock)
        {
            // the compare is in this block; the bounding b.hi is in the block the b.ne reaches
            a.Word(CmpImm(8, (uint)count - 1)).Later(at => A64.BCond(at, dispatchBlock, Ne)).Word(A64.MovW(0, 9)).Word(A64.Ret);
            dispatchBlock = a.Here;
            a.Later(at => A64.BCond(at, dflt, Hi));
        }
        else
        {
            a.Word(CmpImm(8, branch == Hs ? (uint)count : (uint)count - 1)).Later(at => A64.BCond(at, dflt, branch));
        }
        if (!hoisted) a.Word(A64.Adrp(a.Here, Table, 9, Base)).Word(A64.AddImm(9, 9, Table & 0xFFF));
        dispatch(a, () => anchor);
        anchor = a.Here;
        for (int i = 0; i < cases; i++) { caseAt[i] = a.Here; a.Word(A64.MovW(0, (uint)i + 1)).Word(A64.Ret); }
        dflt = a.Here;
        a.Word(A64.MovW(0, 0)).Word(A64.Ret);
        var code = a.Bytes();
        var data = new byte[0x200];
        table(caseAt, anchor, dflt).CopyTo(data, Table - Data);
        var index = NativeCodeIndex.Build(CodeTestImage.Synthetic(NativeArch.Arm64, code, data, relocations: relocations, entry: Code));
        return (index.GetGraph(index.FunctionByStart(Code)!), caseAt, dflt);
    }

    /// <summary>Case i of value i, then one entry that goes to the default.</summary>
    private static uint[] Targets(uint[] cases, uint dflt) => [.. cases, dflt];

    [Fact]
    public void Forward_constant_selects_its_case_through_the_bias()
    {
        var a = new A64(Code);
        uint anchor = 0, dflt = 0;
        var caseAt = new uint[3];
        a.Word(A64.MovW(0, 7)).Word(SubImm(8, 0, 5)).Word(CmpImm(8, 3)).Later(at => A64.BCond(at, dflt, Hi));
        a.Word(A64.Adrp(a.Here, Table, 9, Base)).Word(A64.AddImm(9, 9, Table & 0xFFF));
        a.Later(at => A64.Adr(at, anchor, 10)).Word(Ldrb(11, 9, 8)).Word(AddShift(10, 10, 11, 2)).Word(A64.Br(10));
        anchor = a.Here;
        for (int i = 0; i < 3; i++) { caseAt[i] = a.Here; a.Word(A64.MovW(0, (uint)i + 1)).Word(A64.Ret); }
        dflt = a.Here;
        a.Word(A64.MovW(0, 0)).Word(A64.Ret);
        var code = a.Bytes();
        var data = new byte[0x200];
        Targets(caseAt, dflt).Select(t => (byte)((t - anchor) / 4)).ToArray().CopyTo(data, Table - Data);
        var host = Arm64Trace.For(NativeCodeIndex.Build(CodeTestImage.Synthetic(NativeArch.Arm64, code, data, entry: Code)));
        var seed = Corvus.Tools.NativeTraceTools.Arm64Seed(host, $"0x{Base + Code:X}", "x0", null, default);
        var g = ValueTrace.Build(host, seed, new ValueTraceOptions(TraceDirection.Forward));
        Assert.Equal($"selects case 7 -> 0x{Base + caseAt[2]:X}", Assert.Single(g.Nodes, n => n.Kind == TraceNodeKind.Switch).Decoded);
    }

    /// <summary>A table at the start of a page: add x9, x9, #0 after the adrp decodes as mov x9, x9 (MSVC, biased by 100).</summary>
    [Fact]
    public void A_table_at_a_page_start_through_the_mov_alias()
    {
        var a = new A64(Code);
        uint anchor = 0, dflt = 0;
        var caseAt = new uint[3];
        a.Word(SubImm(8, 0, 100)).Word(CmpImm(8, 2)).Later(at => A64.BCond(at, dflt, Hi));
        a.Word(A64.Adrp(a.Here, Data, 9, Base)).Word(A64.AddImm(9, 9, 0));
        a.Later(at => A64.Adr(at, anchor, 10)).Word(Ldrb(11, 9, 8)).Word(AddShift(10, 10, 11, 2)).Word(A64.Br(10));
        anchor = a.Here;
        for (int i = 0; i < 3; i++) { caseAt[i] = a.Here; a.Word(A64.MovW(0, (uint)i + 1)).Word(A64.Ret); }
        dflt = a.Here;
        a.Word(A64.MovW(0, 0)).Word(A64.Ret);
        var data = new byte[0x200];
        caseAt.Select(t => (byte)((t - anchor) / 4)).ToArray().CopyTo(data, 0);
        var index = NativeCodeIndex.Build(CodeTestImage.Synthetic(NativeArch.Arm64, a.Bytes(), data, entry: Code));
        var graph = index.GetGraph(index.FunctionByStart(Code)!);

        var sw = Assert.Single(graph.Switches);
        Assert.Equal((Data, 3, 100L, dflt), (sw.TableRva, sw.EntryCount, sw.Bias, sw.Default));
        Assert.Equal(caseAt, sw.Cases.Select(c => c.Target));
        Assert.Empty(graph.UnresolvedJumps);
    }

    [Fact]
    public void Byte_offsets_from_an_adr_anchor_with_bias_and_a_sparse_default()
    {
        var (graph, cases, dflt) = Build(3, (a, anchor) => a.Later(at => A64.Adr(at, anchor(), 10)).Word(Ldrb(11, 9, 8)).Word(AddShift(10, 10, 11, 2)).Word(A64.Br(10)),
            (c, anchor, d) => [.. Targets(c, d).Select(t => (byte)((t - anchor) / 4))], bias: 5);
        var sw = Assert.Single(graph.Switches);
        Assert.Equal(SwitchTableKind.BaseRelative, sw.Kind);
        Assert.Equal(1, sw.EntrySize);
        Assert.Equal(4, sw.EntryCount);
        Assert.Equal(5, sw.Bias);
        Assert.Equal(dflt, sw.Default);
        Assert.Equal([5L], sw.Cases.Single(x => x.Target == cases[0]).Values);
        Assert.Equal([7L], sw.Cases.Single(x => x.Target == cases[2]).Values);
        Assert.Equal([8L], sw.DefaultValues);
        Assert.Empty(graph.UnresolvedJumps);
    }

    [Fact]
    public void Signed_byte_offsets_and_halfwords_with_b_hs()
    {
        // gcc: ldrb w11, [x9, w8, uxtw]; add x10, x10, w11, sxtb #2 with the cases before the anchor
        var (graph, cases, _) = Build(3, (a, anchor) => a.Word(LdrbUxtw(11, 9, 8)).Later(at => A64.Adr(at, anchor() + 3 * 8 + 8, 10)).Word(AddSxtb(10, 10, 11, 2)).Word(A64.Br(10)),
            (c, anchor, d) => [.. Targets(c, d).Select(t => (byte)(sbyte)(((long)t - (anchor + 3 * 8 + 8)) / 4))]);
        var sw = Assert.Single(graph.Switches);
        Assert.Equal(cases, sw.Cases.Select(x => x.Target));

        var (half, halfCases, halfDefault) = Build(3, (a, anchor) => a.Later(at => A64.Adr(at, anchor(), 10)).Word(Ldrh(11, 9, 8)).Word(MovX(12, 13)).Word(AddShift(10, 10, 11, 2)).Word(A64.Br(10)),
            (c, anchor, d) => [.. Targets(c, d).SelectMany(t => BitConverter.GetBytes((ushort)((t - anchor) / 4)))], branch: Hs);
        var h = Assert.Single(half.Switches);
        Assert.Equal(2, h.EntrySize);
        Assert.Equal(4, h.EntryCount);
        Assert.Equal(halfDefault, h.Default);
        Assert.Equal(halfCases, h.Cases.Select(x => x.Target));
    }

    [Fact]
    public void Word_offsets_from_the_table_and_absolute_entries()
    {
        var (graph, cases, _) = Build(3, (a, _) => a.Word(Ldrsw(11, 9, 8)).Word(AddShift(10, 9, 11, 0)).Word(A64.Br(10)),
            (c, _, d) => [.. Targets(c, d).SelectMany(t => BitConverter.GetBytes((int)((long)t - Table)))]);
        var sw = Assert.Single(graph.Switches);
        Assert.Equal(4, sw.EntrySize);
        Assert.Equal(Table, sw.Base);
        Assert.Equal(cases, sw.Cases.Select(x => x.Target));

        var (abs, absCases, _) = Build(3, (a, _) => a.Word(LdrX(10, 9, 8)).Word(A64.Br(10)),
            (c, _, d) => [.. Targets(c, d).SelectMany(t => BitConverter.GetBytes(Base + t))], relocations: Enumerable.Range(0, 4).Select(i => Table + (uint)i * 8));
        var s = Assert.Single(abs.Switches);
        Assert.Equal(SwitchTableKind.Absolute, s.Kind);
        Assert.Equal(8, s.EntrySize);
        Assert.Equal(absCases, s.Cases.Select(x => x.Target));
    }

    [Fact]
    public void Bound_in_another_block_and_a_hoisted_table_register()
    {
        var (graph, cases, dflt) = Build(3, (a, anchor) => a.Later(at => A64.Adr(at, anchor(), 10)).Word(Ldrb(11, 19, 8)).Word(AddShift(10, 10, 11, 2)).Word(A64.Br(10)),
            (c, anchor, d) => [.. Targets(c, d).Select(t => (byte)((t - anchor) / 4))], hoisted: true, flagsInOtherBlock: true);
        var sw = Assert.Single(graph.Switches);
        Assert.Equal(4, sw.EntryCount);
        Assert.Equal(dflt, sw.Default);
        Assert.Equal(cases, sw.Cases.Select(x => x.Target));
    }

    [Fact]
    public void A_table_entry_outside_code_leaves_the_jump_unresolved_with_the_reason()
    {
        var (graph, _, _) = Build(3, (a, anchor) => a.Later(at => A64.Adr(at, anchor(), 10)).Word(Ldrb(11, 9, 8)).Word(AddShift(10, 10, 11, 2)).Word(A64.Br(10)),
            (c, anchor, d) => [.. Targets(c, d).Select(t => (byte)((t - anchor) / 4)).Take(3), 0xF0]);
        Assert.Empty(graph.Switches);
        Assert.Contains("entry 3", Assert.Single(graph.UnresolvedJumps).Reason);
    }

    /// <summary>
    /// The table register is written twice in the function (no single function-wide value), and its table value reaches
    /// the dispatch block through the branch to it; or the table address is spilled to the stack across a call and reloaded.
    /// </summary>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void A_table_base_from_the_branch_state_or_a_stack_slot(bool spilled)
    {
        var a = new A64(Code);
        uint anchor = 0, dflt = 0, dispatchBlock = 0, ext = 0;
        var caseAt = new uint[3];
        int tableReg = spilled ? 9 : 19, index = spilled ? 20 : 8;
        a.Word(MovX(19, 1)).Word(A64.Adrp(a.Here, Table, tableReg, Base)).Word(A64.AddImm(tableReg, tableReg, Table & 0xFFF)).Word(MovX(index, 0));
        if (spilled)
        {
            a.Word(0xF9000BE9).Later(at => A64.Bl(at, ext)).Word(A64.LdrX(9, 31, 16));      // str x9, [sp, #16]; bl ext; ldr x9, [sp, #16]
            a.Word(CmpImm(index, 2)).Later(at => A64.BCond(at, dflt, Hi));
        }
        else
        {
            a.Word(CmpImm(index, 2)).Later(at => A64.BCond(at, dispatchBlock, Ne)).Word(A64.MovW(0, 9)).Word(A64.Ret);
            dispatchBlock = a.Here;
            a.Later(at => A64.BCond(at, dflt, Hi));
        }
        a.Later(at => A64.Adr(at, anchor, 10)).Word(Ldrb(11, tableReg, index)).Word(AddShift(10, 10, 11, 2)).Word(A64.Br(10));
        anchor = a.Here;
        for (int i = 0; i < 3; i++) { caseAt[i] = a.Here; a.Word(A64.MovW(0, (uint)i + 1)).Word(A64.Ret); }
        dflt = a.Here;
        a.Word(A64.MovW(0, 0)).Word(A64.Ret);
        ext = a.Here;
        a.Word(A64.MovW(9, 0)).Word(A64.Ret);
        var data = new byte[0x200];
        caseAt.Select(t => (byte)((t - anchor) / 4)).ToArray().CopyTo(data, Table - Data);
        var index2 = NativeCodeIndex.Build(CodeTestImage.Synthetic(NativeArch.Arm64, a.Bytes(), data, entry: Code));
        var graph = index2.GetGraph(index2.FunctionByStart(Code)!);

        var sw = Assert.Single(graph.Switches);
        Assert.Equal(Table, sw.TableRva);
        Assert.Equal(caseAt, sw.Cases.Select(c => c.Target));
    }
}
