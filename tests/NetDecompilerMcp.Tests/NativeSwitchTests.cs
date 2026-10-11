using System.Buffers.Binary;
using Iced.Intel;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Mcp;
using NetDecompilerMcp.Native;
using NetDecompilerMcp.Native.Code;
using NetDecompilerMcp.Services;
using NetDecompilerMcp.Tools;
using static Iced.Intel.AssemblerRegisters;

namespace NetDecompilerMcp.Tests;

/// <summary>Switch cases: values per target, default from the bound check, bias, index tables, unresolved reasons.</summary>
public class NativeSwitchTests
{
    private const uint Code = CodeTestImage.SyntheticCodeRva;
    private const uint Data = CodeTestImage.SyntheticDataRva;
    private const ulong Base64 = 0x140000000UL;
    private const ulong Base32 = 0x10000000UL;

    private static (byte[] Bytes, Func<Label, uint> Rva) Assemble(int bitness, ulong codeVa, Action<Assembler> build)
    {
        var a = new Assembler(bitness);
        build(a);
        var stream = new MemoryStream();
        var result = a.Assemble(new StreamCodeWriter(stream), codeVa, BlockEncoderOptions.ReturnNewInstructionOffsets);
        ulong imageBase = bitness == 64 ? Base64 : Base32;
        return (stream.ToArray(), label => (uint)(result.GetLabelRIP(label) - imageBase));
    }

    private static Instruction LeaImageBase(Register reg) =>
        Instruction.Create(Iced.Intel.Code.Lea_r64_m, reg, new MemoryOperand(Register.RIP, (long)Base64, 8));

    /// <summary>
    /// x64 MSVC switch on rcx: an optional bias (lea eax, [rcx-bias]), the bound check, an optional byte index table, the
    /// RVA table, and a case per target; <paramref name="table"/> entries name cases by number, -1 for the default.
    /// </summary>
    private static (FunctionGraph Graph, NativeCodeIndex Index, uint Jump, uint[] Cases, uint Default) Msvc(int bias, int[] table, byte[]? index = null,
        bool mask = false, bool jbe = false)
    {
        int cases = table.Max() + 1;
        Label dflt = default, jump = default, dispatch = default;
        var labels = new Label[cases];
        uint tableRva = Data + 0x40, indexRva = Data + 0x100;
        var (code, rva) = Assemble(64, Base64 + Code, a =>
        {
            dflt = a.CreateLabel(); jump = a.CreateLabel(); dispatch = a.CreateLabel();
            for (int i = 0; i < cases; i++) labels[i] = a.CreateLabel();
            if (bias != 0) a.lea(eax, __[rcx - bias]); else a.mov(eax, ecx);
            int bound = (index?.Length ?? table.Length) - 1;
            if (mask) a.and(eax, bound);
            else
            {
                a.cmp(eax, bound);
                if (jbe) a.jbe(dispatch); else a.ja(dflt);
            }
            if (jbe) { a.xor(eax, eax); a.ret(); }
            a.Label(ref dispatch);
            a.AddInstruction(LeaImageBase(Register.RDX));
            a.movsxd(rax, eax);
            if (index != null) a.movzx(eax, __byte_ptr[rdx + rax + (int)indexRva]);
            a.mov(ecx, __dword_ptr[rdx + rax * 4 + (int)tableRva]);
            a.add(rcx, rdx);
            a.Label(ref jump);
            a.jmp(rcx);
            for (int i = 0; i < cases; i++)
            {
                a.Label(ref labels[i]);
                a.mov(eax, i + 100);
                a.ret();
            }
            a.Label(ref dflt);
            a.xor(eax, eax);
            a.ret();
        });
        var data = new byte[0x200];
        uint dfltRva = jbe ? 0 : rva(dflt);
        for (int i = 0; i < table.Length; i++)
            BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan((int)(tableRva - Data) + i * 4), table[i] < 0 ? rva(dflt) : rva(labels[table[i]]));
        index?.CopyTo(data, (int)(indexRva - Data));
        var built = NativeCodeIndex.Build(CodeTestImage.Synthetic(NativeArch.X64, code, data, entry: Code));
        var graph = built.GetGraph(built.FunctionByStart(Code)!);
        if (jbe) dfltRva = graph.Switches.Count > 0 ? graph.Switches[0].Default ?? 0 : 0;
        return (graph, built, rva(jump), labels.Select(rva).ToArray(), dfltRva);
    }

    [Fact]
    public void Biased_table_gives_values_per_target_and_the_default_from_the_bound()
    {
        var (graph, _, jump, cases, dflt) = Msvc(bias: 3, table: [0, 1, -1, 2]);
        var sw = Assert.Single(graph.Switches);
        Assert.Equal(jump, sw.JumpRva);
        Assert.Equal(3, sw.Bias);
        Assert.Equal(dflt, sw.Default);
        Assert.Equal(SwitchTableKind.Rva, sw.Kind);
        Assert.True(sw.ValuesExact);
        Assert.Equal([(cases[0], new long[] { 3 }), (cases[1], [4]), (cases[2], [6])], sw.Cases.Select(c => (c.Target, c.Values.ToArray())));
        Assert.Equal([5L], sw.DefaultValues);
    }

    [Fact]
    public void Byte_index_table_maps_values_to_targets_with_default_holes()
    {
        var (graph, _, _, cases, dflt) = Msvc(bias: 0, table: [0, 1, -1], index: [0, 0, 1, 2, 1, 2, 2, 0]);
        var sw = Assert.Single(graph.Switches);
        Assert.Equal(dflt, sw.Default);
        Assert.Equal(8, sw.IndexEntryCount);
        Assert.Equal([0L, 1, 7], sw.Cases.Single(c => c.Target == cases[0]).Values);
        Assert.Equal([2L, 4], sw.Cases.Single(c => c.Target == cases[1]).Values);
        Assert.Equal([3L, 5, 6], sw.DefaultValues);
    }

    [Fact]
    public void Masked_index_has_no_default_and_inexact_values()
    {
        var (graph, _, _, cases, _) = Msvc(bias: 0, table: [0, 1, 2, 3], mask: true);
        var sw = Assert.Single(graph.Switches);
        Assert.Null(sw.Default);
        Assert.False(sw.ValuesExact);
        Assert.Equal(cases, sw.Cases.Select(c => c.Target));
    }

    [Fact]
    public void Bound_carried_into_the_dispatch_block_keeps_default_and_bias()
    {
        var (graph, index, _, cases, _) = Msvc(bias: 2, table: [0, 1, 2], jbe: true);
        var sw = Assert.Single(graph.Switches);
        Assert.Equal(2, sw.Bias);
        // jbe: out-of-range values fall through to the code after the branch
        var fallThrough = index.Disassemble(Code, 4)[3].Rva;
        Assert.Equal(fallThrough, sw.Default);
        Assert.Equal([2L], sw.Cases.Single(c => c.Target == cases[0]).Values);
    }

    [Fact]
    public void Unbounded_dispatch_reports_its_reason()
    {
        Label jump = default;
        var (code, rva) = Assemble(64, Base64 + Code, a =>
        {
            jump = a.CreateLabel();
            a.AddInstruction(LeaImageBase(Register.RDX));
            a.movsxd(rax, ecx);
            a.mov(ecx, __dword_ptr[rdx + rax * 4 + (int)(Data + 0x40)]);
            a.add(rcx, rdx);
            a.Label(ref jump);
            a.jmp(rcx);
        });
        var index = NativeCodeIndex.Build(CodeTestImage.Synthetic(NativeArch.X64, code, entry: Code));
        var unresolved = Assert.Single(index.GetGraph(index.FunctionByStart(Code)!).UnresolvedJumps);
        Assert.Equal(rva(jump), unresolved.Rva);
        Assert.Equal("switch index bound not found", unresolved.Reason);
    }

    [Theory]
    [InlineData(0)] // lea rcx, [rip+table]; jmp [rcx + rdx*8]
    [InlineData(1)] // lea rcx, [rip+table]; mov rcx, [rcx + rdx*8]; jmp rcx
    [InlineData(2)] // jmp [table + rdx*8] (fixed address)
    public void X64_absolute_eight_byte_tables(int form)
    {
        // a fixed-address ELF executable: no relocations, addresses fit a 32-bit displacement
        const ulong Base = 0x400000;
        Label dflt = default;
        var labels = new Label[3];
        uint tableRva = NativeFormats.ElfWriter.DataRva + 0x20;
        var a = new Assembler(64);
        dflt = a.CreateLabel();
        for (int i = 0; i < 3; i++) labels[i] = a.CreateLabel();
        a.lea(rdx, __[rcx - 2]);
        a.cmp(rdx, 2);
        a.ja(dflt);
        var lea = Instruction.Create(Iced.Intel.Code.Lea_r64_m, Register.RCX, new MemoryOperand(Register.RIP, (long)(Base + tableRva), 8));
        switch (form)
        {
            case 0: a.AddInstruction(lea); a.jmp(__qword_ptr[rcx + rdx * 8]); break;
            case 1: a.AddInstruction(lea); a.mov(rcx, __qword_ptr[rcx + rdx * 8]); a.jmp(rcx); break;
            default: a.jmp(__qword_ptr[rdx * 8 + (int)(Base + tableRva)]); break;
        }
        for (int i = 0; i < 3; i++) { a.Label(ref labels[i]); a.mov(eax, i); a.ret(); }
        a.Label(ref dflt);
        a.xor(eax, eax);
        a.ret();
        var stream = new MemoryStream();
        var result = a.Assemble(new StreamCodeWriter(stream), Base + NativeFormats.ElfWriter.TextRva, BlockEncoderOptions.ReturnNewInstructionOffsets);
        uint Rva(Label l) => (uint)(result.GetLabelRIP(l) - Base);
        var data = new byte[0x100];
        for (int i = 0; i < 3; i++) BinaryPrimitives.WriteUInt64LittleEndian(data.AsSpan(0x20 + i * 8), Base + Rva(labels[i]));
        var w = new NativeFormats.ElfWriter
        {
            Machine = NativeFormats.ElfWriter.EmX64, Type = 2, Base = Base, Entry = NativeFormats.ElfWriter.TextRva, Text = stream.ToArray(), Data = data,
            Hash = NativeFormats.ElfWriter.HashKind.None,
        };
        var index = NativeCodeIndex.Build(Native.Elf.ElfFile.FromBytes(w.Build(), "fixed"));
        var sw = Assert.Single(index.GetGraph(index.FunctionByStart(NativeFormats.ElfWriter.TextRva)!).Switches);
        Assert.Equal(SwitchTableKind.Absolute, sw.Kind);
        Assert.Equal(8, sw.EntrySize);
        Assert.Equal(Rva(dflt), sw.Default);
        Assert.Equal([2L, 3, 4], sw.Cases.SelectMany(c => c.Values));
    }

    [Fact]
    public void X86_absolute_and_x64_table_relative_kinds()
    {
        Label dflt = default;
        var labels = new Label[3];
        uint tableRva = Data + 0x20;
        var (code, rva) = Assemble(32, Base32 + Code, a =>
        {
            dflt = a.CreateLabel();
            for (int i = 0; i < 3; i++) labels[i] = a.CreateLabel();
            a.mov(eax, __dword_ptr[esp + 4]);
            a.sub(eax, 10);
            a.cmp(eax, 2);
            a.ja(dflt);
            a.jmp(__dword_ptr[eax * 4 + (int)(Base32 + tableRva)]);
            for (int i = 0; i < 3; i++) { a.Label(ref labels[i]); a.mov(eax, i); a.ret(); }
            a.Label(ref dflt);
            a.xor(eax, eax);
            a.ret();
        });
        var data = new byte[0x100];
        var relocs = new List<uint>();
        for (int i = 0; i < 3; i++)
        {
            BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(0x20 + i * 4), (uint)Base32 + rva(labels[i]));
            relocs.Add(tableRva + (uint)i * 4);
        }
        int jmp = code.AsSpan().IndexOf((ReadOnlySpan<byte>)[0xFF, 0x24, 0x85]);
        relocs.Add(Code + (uint)jmp + 3);
        var index = NativeCodeIndex.Build(CodeTestImage.Synthetic(NativeArch.X86, code, data, relocations: relocs, entry: Code));
        var sw = Assert.Single(index.GetGraph(index.FunctionByStart(Code)!).Switches);
        Assert.Equal(SwitchTableKind.Absolute, sw.Kind);
        Assert.Equal(10, sw.Bias);
        Assert.Equal(rva(dflt), sw.Default);
        Assert.Equal([10L, 11, 12], sw.Cases.SelectMany(c => c.Values));

        var relative = new Label[2];
        Label d64 = default;
        var (code64, rva64) = Assemble(64, Base64 + Code, a =>
        {
            d64 = a.CreateLabel();
            for (int i = 0; i < 2; i++) relative[i] = a.CreateLabel();
            a.cmp(ecx, 1);
            a.ja(d64);
            a.AddInstruction(Instruction.Create(Iced.Intel.Code.Lea_r64_m, Register.RDX, new MemoryOperand(Register.RIP, (long)(Base64 + Data), 8)));
            a.movsxd(rax, __dword_ptr[rdx + rcx * 4]);
            a.add(rax, rdx);
            a.jmp(rax);
            for (int i = 0; i < 2; i++) { a.Label(ref relative[i]); a.mov(eax, i); a.ret(); }
            a.Label(ref d64);
            a.xor(eax, eax);
            a.ret();
        });
        var data64 = new byte[0x100];
        for (int i = 0; i < 2; i++) BinaryPrimitives.WriteInt32LittleEndian(data64.AsSpan(i * 4), (int)(rva64(relative[i]) - Data));
        var index64 = NativeCodeIndex.Build(CodeTestImage.Synthetic(NativeArch.X64, code64, data64, entry: Code));
        var sw64 = Assert.Single(index64.GetGraph(index64.FunctionByStart(Code)!).Switches);
        Assert.Equal(SwitchTableKind.TableRelative, sw64.Kind);
        Assert.Equal(rva64(d64), sw64.Default);
    }

    [Fact]
    public async Task GetCfg_lists_cases_and_find_xrefs_names_the_case_values()
    {
        // the biased switch of Msvc() as a PE file: .text at 0x1000, the table in .rdata at 0x2000
        Label dflt = default, jump = default;
        var labels = new Label[3];
        const uint TableRva = 0x2000;
        var (code, rva) = Assemble(64, Base64 + 0x1000, a =>
        {
            dflt = a.CreateLabel(); jump = a.CreateLabel();
            for (int i = 0; i < 3; i++) labels[i] = a.CreateLabel();
            a.lea(eax, __[rcx - 5]);
            a.cmp(eax, 3);
            a.ja(dflt);
            a.AddInstruction(LeaImageBase(Register.RDX));
            a.movsxd(rax, eax);
            a.mov(ecx, __dword_ptr[rdx + rax * 4 + (int)TableRva]);
            a.add(rcx, rdx);
            a.Label(ref jump);
            a.jmp(rcx);
            for (int i = 0; i < 3; i++) { a.Label(ref labels[i]); a.mov(eax, i); a.ret(); }
            a.Label(ref dflt);
            a.xor(eax, eax);
            a.ret();
        });
        var table = new byte[16];
        int[] entries = [0, 1, 0, -1];
        for (int i = 0; i < 4; i++) BinaryPrimitives.WriteUInt32LittleEndian(table.AsSpan(i * 4), entries[i] < 0 ? rva(dflt) : rva(labels[entries[i]]));
        var pe = new PeBuilder { EntryPoint = 0x1000 };
        pe.Add(".text", code, 0x60000020);
        pe.Add(".rdata", table);
        using var dir = new TempDir();
        var path = dir.File("switch.dll");
        File.WriteAllBytes(path, pe.Build());

        var options = new ServerOptions { BackgroundIndexing = false };
        using var workspace = new AssemblyWorkspace(options);
        var tools = new NativeCodeTools(workspace, new NativeCodeService(workspace, options), new OutputPager(options));
        var collector = StructuredOutput.Begin();
        var text = await tools.GetCfg(path, "0x140001000");
        string Va(uint r) => $"0x{Base64 + r:X}";
        Assert.Contains($"switch at {Va(rva(jump))} (jmp rcx): rva table {Va(TableRva)} (4-byte entries, 4); value = index + 5; default {Va(rva(dflt))}", text);
        Assert.Contains($"    case 5, 7: {Va(rva(labels[0]))}", text);
        Assert.Contains($"    default (also 8): {Va(rva(dflt))}", text);
        var report = Assert.IsType<CfgReport>(collector.Value);
        var sw = Assert.Single(report.Switches);
        Assert.Equal(["5", "7"], sw.Cases[0].Values);
        Assert.Equal(5, sw.Bias);

        var xrefs = await tools.FindXrefs(path, Va(rva(labels[0])));
        Assert.Matches($@"{Va(rva(jump))}\s+SwitchCase\s+\S+\s+case 5, 7", xrefs);
    }

    [Fact]
    public void Engine_block_rows_carry_switch_details_when_present()
    {
        var reply = System.Text.Json.JsonDocument.Parse("""
            {"start": 4096, "name": "f", "tail_calls": [], "blocks": [
              [4096, 4110, 4, "normal", [4110, 4200], false],
              [4110, 4120, 3, "indjump", [4130, 4140, 4200], true,
               {"jump": 4116, "cases": [[4130, [3, 4]], [4140, [5]], [4200, [6]]], "default": 4200, "table": 8192, "entry_size": 4, "entries": 4,
                "index_table": null, "index_entries": null, "bias": 3}]]}
            """).RootElement;
        var graph = Native.Providers.WorkerRows.Blocks(reply);
        Assert.Null(graph.Blocks[0].SwitchInfo);
        var si = graph.Blocks[1].SwitchInfo!;
        Assert.Equal(4116u, si.Jump);
        Assert.Equal(4200u, si.Default);
        Assert.Equal(3, si.Bias);
        Assert.Equal([3L, 4], si.Cases[0].Values);
        Assert.Equal(8192u, si.Table);
    }

    [Fact]
    public void Value_ranges_join_runs_of_three()
    {
        Assert.Equal(["1", "2", "4..6", "9", "-3..-1"], NativeCodeTools.ValueRanges([9, 6, 5, 4, 2, 1, -1, -2, -3]).OrderBy(s => s.StartsWith('-')).ToList());
    }
}
