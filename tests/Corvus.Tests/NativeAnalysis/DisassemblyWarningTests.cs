using System.Buffers.Binary;
using System.Text;
using Iced.Intel;
using Corvus.Native;
using Corvus.Native.Code;
using Corvus.Tools;
using static Iced.Intel.AssemblerRegisters;

namespace Corvus.Tests;

/// <summary>disassemble: start warnings, data-aware linear listings with resynchronization, and gaps between a function's blocks.</summary>
public class DisassemblyWarningTests
{
    private const uint Code = CodeTestImage.SyntheticCodeRva;
    private const ulong Base = 0x140000000UL;

    private static (byte[] Bytes, Func<Label, uint> Rva) Assemble(Action<Assembler> build)
    {
        var a = new Assembler(64);
        build(a);
        var stream = new MemoryStream();
        var result = a.Assemble(new StreamCodeWriter(stream), Base + Code, BlockEncoderOptions.ReturnNewInstructionOffsets);
        return (stream.ToArray(), label => (uint)(result.GetLabelRIP(label) - Base));
    }

    private static string Linear(NativeCodeIndex index, uint rva, int max, List<string> warnings)
    {
        var sb = new StringBuilder();
        var classifier = new AddressClassifier(index);
        if (NativeCodeTools.StartWarning(classifier, rva, CancellationToken.None) is { } w) sb.AppendLine("; " + w);
        NativeCodeTools.AppendLinear(sb, index, classifier, rva, max, warnings, CancellationToken.None);
        return sb.ToString();
    }

    /// <summary>main: mov rax, [rcx+8]; lea rcx, text; ret; then the string in .text and an unowned nop; ret.</summary>
    private static (NativeCodeIndex Index, uint Mov, uint Ret, uint Text, uint After) StringInCode()
    {
        Label main = default, ret = default, text = default, after = default;
        var (code, rva) = Assemble(a =>
        {
            main = a.CreateLabel(); ret = a.CreateLabel(); text = a.CreateLabel(); after = a.CreateLabel();
            a.Label(ref main);
            a.mov(rax, __qword_ptr[rcx + 8]);
            a.lea(rcx, __[text]);
            a.Label(ref ret);
            a.ret();
            a.Label(ref text);
            a.db(Encoding.ASCII.GetBytes("Hello, text\0"));
            a.Label(ref after);
            a.nop();
            a.ret();
        });
        var index = NativeCodeIndex.Build(CodeTestImage.Synthetic(NativeArch.X64, code, entry: Code));
        return (index, rva(main), rva(ret), rva(text), rva(after));
    }

    [Fact]
    public void A_listing_that_starts_mid_instruction_warns_and_resynchronizes()
    {
        var (index, mov, _, _, _) = StringInCode();
        var warnings = new List<string>();
        var text = Linear(index, mov + 2, 3, warnings);
        Assert.Contains($"; warning: 0x{Base + mov + 2:X} is inside the instruction at 0x{Base + mov:X} (mov    rax, [rcx+8]); decoding from here desynchronizes - use address=0x{Base + mov:X}", text);
        Assert.Contains($"resynchronized to 0x{Base + mov:X}", text);
        var lines = text.Split('\n').Where(l => l.StartsWith("  ", StringComparison.Ordinal)).ToList();
        Assert.StartsWith($"  {Base + mov:X}  488B4108", lines[0]);
        Assert.Equal(3, lines.Count);
    }

    [Fact]
    public void A_linear_run_renders_a_string_as_data_and_continues_after_it()
    {
        var (index, _, ret, str, after) = StringInCode();
        var warnings = new List<string>();
        var text = Linear(index, ret, 10, warnings);
        Assert.Contains($"  {Base + str:X}  48656C6C6F2C2074...      db \"Hello, text\",0", text);
        Assert.Contains($"  {Base + after:X}  90", text);
        Assert.DoesNotContain("(bad)", text);

        var inside = Linear(index, str + 3, 2, warnings);
        Assert.StartsWith($"; warning: 0x{Base + str + 3:X} is in a string \"Hello, text\" (0x{Base + str:X}-0x{Base + str + 12:X})", inside);
        Assert.Contains("tail of the string at", inside);
    }

    [Fact]
    public void Function_listing_names_the_gap_holding_its_switch_table()
    {
        Label start = default, dflt = default, jump = default, table = default;
        var cases = new Label[3];
        var (code, rva) = Assemble(a =>
        {
            start = a.CreateLabel(); dflt = a.CreateLabel(); jump = a.CreateLabel(); table = a.CreateLabel();
            for (int i = 0; i < cases.Length; i++) cases[i] = a.CreateLabel();
            a.Label(ref start);
            a.AddInstruction(Instruction.Create(Iced.Intel.Code.Lea_r64_m, Register.RDX, new MemoryOperand(Register.RIP, (long)Base, 8)));
            a.cmp(ecx, cases.Length - 1);
            a.ja(dflt);
            a.movsxd(rax, ecx);
            a.mov(ecx, __dword_ptr[rdx + rax * 4 + 0x7FFF0000]); // displacement patched to the table RVA below
            a.add(rcx, rdx);
            a.Label(ref jump);
            a.jmp(rcx);
            a.Label(ref table);
            for (int i = 0; i < cases.Length; i++) a.dd(0);
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
        uint tableRva = rva(table);
        int disp = code.AsSpan().IndexOf(new byte[] { 0x00, 0x00, 0xFF, 0x7F });
        BinaryPrimitives.WriteUInt32LittleEndian(code.AsSpan(disp), tableRva);
        for (int i = 0; i < cases.Length; i++) BinaryPrimitives.WriteUInt32LittleEndian(code.AsSpan((int)(tableRva - Code) + i * 4), rva(cases[i]));
        var index = NativeCodeIndex.Build(CodeTestImage.Synthetic(NativeArch.X64, code, entry: Code));
        var fn = Assert.Single(index.Functions);
        Assert.Single(index.GetGraph(fn).Switches);

        var sb = new StringBuilder();
        var warnings = new List<string>();
        NativeCodeTools.AppendFunction(sb, index, new AddressClassifier(index), fn, 100, new Dictionary<uint, string>(), warnings, CancellationToken.None);
        var text = sb.ToString();
        Assert.Contains($"; gap 0x{Base + tableRva:X}-0x{Base + tableRva + 12:X} (12 bytes): jump table: switch table of sub_1000 (jump at 0x{Base + rva(jump):X}): 3 entries of 4 bytes", text);
        Assert.Single(warnings);
        // the gap line comes before the label of the block after it
        Assert.True(text.IndexOf("; gap", StringComparison.Ordinal) < text.IndexOf($"loc_{rva(cases[0]):X}:", StringComparison.Ordinal));

        var linear = Linear(index, rva(jump), 5, warnings);
        Assert.Contains($"dd rva loc_{rva(cases[1]):X}", linear);
    }
}
