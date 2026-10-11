using NetDecompilerMcp.Native.Code;
using NetDecompilerMcp.Native.Diff;
using NetDecompilerMcp.Native.Elf;
using NetDecompilerMcp.Tests.NativeFormats;
using NetDecompilerMcp.Tools;

namespace NetDecompilerMcp.Tests;

/// <summary>
/// The native tools on 32-bit ARM: inspect_instruction (operands, register lists, stack change, PC-relative pairs, IT
/// conditions, literal pools, Thumb pointers), code patterns, and disassemble / get_cfg / find_xrefs / native_call_tree /
/// list_functions end to end; real Android, Linux and Windows ARM libraries in the slow set.
/// </summary>
public class Arm32ToolTests
{
    private const uint Text = ElfWriter.TextRva;

    private static (string Text, InstructionReport Report) Inspect(NativeCodeIndex index, uint rva, int count = 1) =>
        NativeCodeTools.Inspect("sample", index, rva, count, new EngineChoice("ours", "test"), CancellationToken.None);

    private static InstructionItem One(NativeCodeIndex index, uint rva) => Assert.Single(Inspect(index, rva).Report.Items);

    private static string Va(uint rva) => $"0x{rva:X}";

    [Fact]
    public void Inspect_reports_operands_pairs_conditions_and_literals()
    {
        var (image, helper, armFn, _) = NativeArm32Tests.Sample();
        var index = NativeCodeIndex.Build(image);

        var push = One(index, Text).Instruction!;
        Assert.Equal(("push", "t16"), (push.Mnemonic, push.Encoding));
        Assert.Equal("register_list", push.Operands[0].Kind);
        Assert.Equal(-8, push.StackPointerDelta);
        Assert.Contains("lr", push.RegistersRead!);
        Assert.Equal(["sp"], push.RegistersWritten);

        // ldr r0, [pc, #x]; add r0, pc forms the string's address
        var (text, report) = Inspect(index, Text + 4);
        var add = report.Items[0].Instruction!;
        Assert.Equal(Va(ElfWriter.DataRva), add.FormedAddress);
        Assert.Equal(Va(Text + 2), add.Pair);
        Assert.Contains("Hello, thumb", add.Comment);
        Assert.Contains("(address-forming pair)", text);
        var literal = One(index, Text + 2).Instruction!;
        Assert.Equal(("pc_relative", 4), (literal.Operands[1].Kind, literal.Operands[1].Size));

        // bxeq lr inside an IT block: a conditional return that falls through
        var bxeq = One(index, helper + 4).Instruction!;
        Assert.Equal(("eq", "return"), (bxeq.Flow.Condition, bxeq.Flow.Kind));
        Assert.Equal(Va(helper + 6), bxeq.Flow.Fallthrough);
        Assert.StartsWith("bxeq", bxeq.Text);

        var arm = One(index, armFn + 4).Instruction!;
        Assert.Equal(("a32", "ne"), (arm.Encoding, arm.Flow.Condition));

        // an odd address is a Thumb pointer: the instruction one byte lower covers it
        var odd = One(index, Text + 5);
        Assert.Equal(("mid_instruction", Va(Text + 4)), (odd.Status, odd.ContainingInstruction));

        // the literal pool after main is data
        var pool = One(index, index.RefsFrom(Text + 2, Text + 4).Single(x => x.Kind == XrefKind.Read).To);
        Assert.Equal(("data", "literal"), (pool.Status, pool.DataItem?.Kind));
    }

    [Fact]
    public void Code_patterns_mask_branch_and_literal_offsets()
    {
        var (image, helper, _, _) = NativeArm32Tests.Sample();
        var index = NativeCodeIndex.Build(image);
        var decoder = new MaskedDecoder(image, index);
        var code = FunctionCode.Instructions(index, decoder, index.FunctionByStart(Text)!, CancellationToken.None, out _);
        Assert.Equal(Text, code[0].Rva);
        var bl = code.Single(i => i.Rva == Text + 6);
        Assert.Equal(helper, bl.Target);
        Assert.Equal(0b1111, bl.Wild);
        var ldr = code.Single(i => i.Rva == Text + 2);
        Assert.Equal(0b01, ldr.Wild);
        Assert.Equal(0, code[0].Wild);

        var made = CodePatterns.Make(index, helper, 64, allowReference: true, referenceOnly: false, CancellationToken.None);
        Assert.True(made.Unique, made.Note);
    }

    [Fact]
    public async Task Native_tools_work_end_to_end()
    {
        using var dir = new TempDir();
        var path = dir.File("thumb.so");
        var (bytes, helper, armFn, _) = NativeArm32Tests.SampleFile();
        File.WriteAllBytes(path, bytes);
        using var h = new NativeToolHarness(backgroundIndexing: false);

        var functions = await h.CodeTools.ListFunctions(path);
        Assert.Contains("main", functions);
        Assert.Contains("[arm]", functions);
        var asm = await h.CodeTools.Disassemble(path, "main");
        Assert.Contains("Engine: ours", asm);
        Assert.Contains($"blx    sub_{armFn:X}", asm);
        var cfg = await h.CodeTools.GetCfg(path, $"rva:0x{helper:X}");
        Assert.Contains("ConditionalFallThrough", cfg);
        var xrefs = await h.CodeTools.FindXrefs(path, $"rva:0x{helper:X}");
        Assert.Contains("main", xrefs);
        var tree = await h.CodeTools.NativeCallTree(path, "main");
        Assert.Contains($"sub_{armFn:X}", tree);
        Assert.Contains("abort", tree);
        // a Thumb pointer (odd) disassembles as Thumb at the address below it
        var odd = await h.CodeTools.Disassemble(path, $"rva:0x{Text + 1:X}");
        Assert.Contains("push", odd);
    }

    [Trait("Speed", "Slow")]
    [Theory]
    [InlineData("android-arm")]
    [InlineData("linux-arm")]
    [InlineData("win-arm")]
    public async Task Real_arm_libraries_are_decoded_end_to_end(string rid)
    {
        string path = rid switch
        {
            "android-arm" => RealPackages.File("Microsoft.Android.Runtime.35.android-arm", "35.0.105", "runtimes/android-arm/native/libmono-android.release.so"),
            "linux-arm" => NativeFixtures.LinuxArmDbgShim,
            _ => RealPackages.File("Microsoft.Diagnostics.DbgShim.win-arm", "9.0.553101", "runtimes/win-arm/native/dbgshim.dll"),
        };
        var image = Native.NativeImageLoader.Open(path);
        var index = NativeCodeIndex.Build(image);
        Assert.Equal(CodeSupport.Full, index.Support);
        Assert.Empty(index.Functions.Where(f => (f.Flags & FunctionFlags.InvalidCode) != 0).Select(f => f.Name));
        Assert.True(index.Stats.ResolvedSwitches > 0);
        Assert.Contains(index.Functions, f => (f.Flags & FunctionFlags.Thunk) != 0);
        Assert.True(index.Stats.Instructions > 9_000, $"{index.Stats.Instructions} instructions");
        var dis = index.CreateDisassembler();
        if (image is ElfFile elf)
        {
            // every function symbol is found, in the state bit 0 of its value names (and its mapping symbol, when there is one)
            var starts = index.Functions.Select(f => f.Start).ToHashSet();
            foreach (var s in elf.DynamicSymbols.Concat(elf.StaticSymbols).Where(s => s.IsDefined && s.IsFunction && s.Value != 0))
            {
                Assert.True(elf.TryVaToRva(s.Value & ~1UL, out uint rva));
                Assert.Contains(rva, starts);
                Assert.Equal((s.Value & 1) != 0, dis.ThumbAt(rva));
            }
        }
        else
            Assert.All(image.RuntimeFunctions, rf => Assert.Contains(index.Functions, f => f.Start == rf.BeginRva));

        using var h = new NativeToolHarness(backgroundIndexing: false);
        await h.Exercise(path);
        var failed = h.Calls.Where(c => c.Failed).ToList();
        Assert.True(failed.Count == 0, string.Join("\n", failed.Take(10)));
    }
}
