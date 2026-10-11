using Iced.Intel;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Mcp;
using NetDecompilerMcp.Native.Annotations;
using NetDecompilerMcp.Services;
using NetDecompilerMcp.Tools;
using static Iced.Intel.AssemblerRegisters;

namespace NetDecompilerMcp.Tests;

/// <summary>analyze_native_function: sections with totals, the sections filter, failure isolation, exclusive ends.</summary>
public sealed class FunctionDossierTests : IDisposable
{
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    private const ulong Base = 0x180000000;

    /// <summary>
    /// dossier.dll: Main (entry, export) passes L"config.ini" to Helper and ignores its result; Helper (export) saves rbx,
    /// counts in a loop, then calls CreateFileW(name, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL).
    /// </summary>
    internal static string Sample(TempDir dir)
    {
        uint? text = null;
        Dictionary<string, uint>? at = null;
        byte[] Code(Dictionary<string, uint> slots)
        {
            Instruction Rip(Iced.Intel.Code c, Register r, uint rva) => Instruction.Create(c, r, new MemoryOperand(Register.RIP, (long)(Base + rva), 8));
            var a = new Assembler(64);
            var helper = a.CreateLabel();
            var loop = a.CreateLabel();
            var main = a.CreateLabel();
            a.Label(ref main);
            a.sub(rsp, 0x28);
            a.AddInstruction(Rip(Iced.Intel.Code.Lea_r64_m, Register.RCX, slots["name"]));
            a.call(helper);
            a.add(rsp, 0x28);
            a.ret();
            for (int i = 0; i < 6; i++) a.int3();
            a.Label(ref helper);
            a.push(rbx);
            a.mov(r10d, 0x5A17); // a magic number for the constants section
            a.sub(rsp, 0x40);
            a.mov(rbx, rcx);
            a.xor(eax, eax);
            a.Label(ref loop);
            a.inc(eax);
            a.cmp(eax, 10);
            a.jl(loop);
            a.mov(rcx, rbx);
            a.mov(edx, 0x80000000);
            a.xor(r8d, r8d);
            a.xor(r9d, r9d);
            a.mov(__dword_ptr[rsp + 0x20], 3);
            a.mov(__dword_ptr[rsp + 0x28], 0x80);
            a.mov(__qword_ptr[rsp + 0x30], 0);
            a.AddInstruction(Instruction.Create(Iced.Intel.Code.Call_rm64, new MemoryOperand(Register.RIP, (long)(Base + slots["KERNEL32.dll!CreateFileW"]), 8)));
            a.add(rsp, 0x40);
            a.pop(rbx);
            a.ret();
            var stream = new MemoryStream();
            var result = a.Assemble(new StreamCodeWriter(stream), Base + LinkedImages.Text, BlockEncoderOptions.ReturnNewInstructionOffsets);
            at = new() { ["Main"] = (uint)(result.GetLabelRIP(main) - Base), ["Helper"] = (uint)(result.GetLabelRIP(helper) - Base) };
            text = LinkedImages.Text;
            return stream.ToArray();
        }
        // a first pass learns the function offsets for the export table
        LinkedImages.Build("dossier.dll", [], [("KERNEL32.dll", ["CreateFileW"])], Code, Strings);
        var path = dir.File("dossier.dll");
        File.WriteAllBytes(path, LinkedImages.Build("dossier.dll", [("Main", (int)(at!["Main"] - text!.Value)), ("Helper", (int)(at["Helper"] - text.Value))],
            [("KERNEL32.dll", ["CreateFileW"])], Code, Strings));
        return path;

        static Dictionary<string, uint> Strings(PeBlob blob, List<uint> relocations)
        {
            blob.Align(2);
            uint name = blob.Utf16("config.ini\0");
            return new() { ["name"] = name };
        }
    }

    /// <summary>component.dll: Outer (export) and Inner (called by Outer only) both load L"shared" and read the dword g_count; Outer calls Inner twice.</summary>
    private static (string Path, string Inner) ComponentSample(TempDir dir)
    {
        uint? text = null;
        Dictionary<string, uint>? at = null;
        byte[] Code(Dictionary<string, uint> slots)
        {
            Instruction Rip(Iced.Intel.Code c, Register r, uint rva) => Instruction.Create(c, r, new MemoryOperand(Register.RIP, (long)(Base + rva), 8));
            var a = new Assembler(64);
            var outer = a.CreateLabel();
            var inner = a.CreateLabel();
            a.Label(ref outer);
            a.sub(rsp, 0x28);
            a.AddInstruction(Rip(Iced.Intel.Code.Lea_r64_m, Register.RCX, slots["text"]));
            a.AddInstruction(Rip(Iced.Intel.Code.Mov_r32_rm32, Register.EAX, slots["count"]));
            a.call(inner);
            a.call(inner);
            a.add(rsp, 0x28);
            a.ret();
            for (int i = 0; i < 6; i++) a.int3();
            a.Label(ref inner);
            a.AddInstruction(Rip(Iced.Intel.Code.Lea_r64_m, Register.RDX, slots["text"]));
            a.AddInstruction(Rip(Iced.Intel.Code.Mov_r32_rm32, Register.EAX, slots["count"]));
            a.ret();
            var stream = new MemoryStream();
            var result = a.Assemble(new StreamCodeWriter(stream), Base + LinkedImages.Text, BlockEncoderOptions.ReturnNewInstructionOffsets);
            at = new() { ["Outer"] = (uint)(result.GetLabelRIP(outer) - Base), ["Inner"] = (uint)(result.GetLabelRIP(inner) - Base) };
            text = LinkedImages.Text;
            return stream.ToArray();
        }
        LinkedImages.Build("component.dll", [], [("KERNEL32.dll", ["ExitProcess"])], Code, Strings);
        var path = dir.File("component.dll");
        File.WriteAllBytes(path, LinkedImages.Build("component.dll", [("Outer", (int)(at!["Outer"] - text!.Value))], [("KERNEL32.dll", ["ExitProcess"])], Code, Strings));
        return (path, $"rva:0x{at["Inner"]:X}");

        static Dictionary<string, uint> Strings(PeBlob blob, List<uint> relocations)
        {
            blob.Align(4);
            uint count = blob.U32(7);
            uint shared = blob.Utf16("shared\0");
            return new() { ["text"] = shared, ["count"] = count };
        }
    }

    [Fact]
    public async Task Component_view_of_several_functions()
    {
        var (ws, tools) = Rig();
        using var _ = ws;
        var (path, inner) = ComponentSample(_dir);
        var record = StructuredOutput.Begin();
        var text = await tools.AnalyzeNativeFunction(path, $"Outer,{inner}", component: true);
        NativeLinkTests.Has(text, "Component of 2 functions [component.dll]");
        Assert.Matches(@"Outer -> sub_[0-9A-F]+ \(2 sites\)", text);
        Assert.Matches(@"L""shared"": Outer, sub_[0-9A-F]+", text);
        Assert.Matches(@"^  0x[0-9A-F]+  [^\r\n]+: Outer, sub_[0-9A-F]+", text.Split("== shared globals")[1].Split("== shared strings")[0].Split('\n')[1]); // the dword both read
        NativeLinkTests.Has(text, $"== internal only (reached from the set alone) (1) ==");
        Assert.DoesNotContain("== identity", text); // per-function sections only when asked
        var view = Assert.IsType<NativeFunctionTools.FunctionDossier>(record.Value).Component!;
        Assert.Equal([true, false], view.Functions.Select(f => f.Interface));
        Assert.Single(view.SharedGlobals);
        Assert.Single(view.SharedStrings);
        Assert.Contains("== identity", await tools.AnalyzeNativeFunction(path, $"Outer,{inner}", sections: "identity", component: true));
        Assert.Equal(ErrorCode.InvalidArgument, (await Assert.ThrowsAsync<ToolError>(() => tools.AnalyzeNativeFunction(path, "Outer", component: true))).Code);
    }

    private (AssemblyWorkspace Workspace, NativeFunctionTools Tools) Rig()
    {
        var options = new ServerOptions { BackgroundIndexing = false };
        var ws = new AssemblyWorkspace(options);
        var code = new NativeCodeService(ws, options, null, new AnnotationStore(_dir.File("ann")));
        return (ws, new NativeFunctionTools(ws, code, new OutputPager(options), new NativeLinkService(ws, code)));
    }

    [Fact]
    public async Task Every_section_reports_its_facts_with_totals()
    {
        var (ws, tools) = Rig();
        using var _ = ws;
        var path = Sample(_dir);
        var helper = await tools.AnalyzeNativeFunction(path, "Helper");
        NativeLinkTests.Has(helper, "(ends are exclusive throughout)");
        NativeLinkTests.Has(helper, "== identity (");
        NativeLinkTests.Has(helper, "name Helper (");
        NativeLinkTests.Has(helper, "argument registers read before written: rcx");
        NativeLinkTests.Has(helper, "1 of 1 call site checked use the returned value"); // Main returns it
        NativeLinkTests.Has(helper, "saved registers: rbx");
        NativeLinkTests.Has(helper, "allocates 0x40 bytes of stack");
        NativeLinkTests.Has(helper, "call from Main+0x");
        NativeLinkTests.Has(helper, "exported as Helper");
        NativeLinkTests.Has(helper, "CreateFileW(");
        NativeLinkTests.Has(helper, "GENERIC_READ");
        NativeLinkTests.Has(helper, "loop: back edge");
        NativeLinkTests.Has(helper, $"== annotations =={Environment.NewLine}  (none)");
        NativeLinkTests.Has(helper, "Next:");
        NativeLinkTests.Has(helper, "trace_native_values image=dossier.dll address=0x");

        var main = await tools.AnalyzeNativeFunction("dossier.dll", "Main");
        NativeLinkTests.Has(main, "the image entry point");
        NativeLinkTests.Has(main, "address string L\"config.ini\"");
        NativeLinkTests.Has(main, "Helper");
    }

    [Fact]
    public async Task Sections_filter_and_a_failing_section_keeps_the_others()
    {
        var (ws, tools) = Rig();
        using var _ = ws;
        var path = Sample(_dir);
        var flow = await tools.AnalyzeNativeFunction(path, "Helper", sections: "flow");
        Assert.Contains("== flow", flow);
        Assert.DoesNotContain("== identity", flow);
        // no engine in this server: pseudocode reports why, the rest is there
        var both = await tools.AnalyzeNativeFunction(path, "Helper", sections: "identity,callers", pseudocode: true);
        NativeLinkTests.Has(both, $"== pseudocode =={Environment.NewLine}  error: no decompiler engine is set up in this server");
        NativeLinkTests.Has(both, "== callers (");
        var params_ = await tools.AnalyzeNativeFunction(path, "Helper", sections: "params");
        NativeLinkTests.Has(params_, "parameter 1 (rcx): L\"config.ini\"");
        var e = await Assert.ThrowsAsync<ToolError>(() => tools.AnalyzeNativeFunction(path, "Helper", sections: "identity,nonsense"));
        Assert.Equal(ErrorCode.InvalidArgument, e.Code);
        // a second call (a later page) is served from the cache, text and record alike
        var first = StructuredOutput.Begin();
        await tools.AnalyzeNativeFunction(path, "Helper", sections: "flow,callers");
        var second = StructuredOutput.Begin();
        await tools.AnalyzeNativeFunction(path, "Helper", sections: "flow,callers", offset: 10);
        Assert.Same(first.Value, second.Value);
        var capped = await tools.AnalyzeNativeFunction(path, "Helper", sections: "callees,data", maxItems: 1);
        Assert.DoesNotContain("; first", capped.Split("== data")[0]); // one call: under the cap
    }

    [Fact]
    public async Task Constants_complexity_xref_counts_and_a_batch_of_addresses()
    {
        var (ws, tools) = Rig();
        using var _ = ws;
        var path = Sample(_dir);
        var helper = await tools.AnalyzeNativeFunction(path, "Helper", sections: "identity,flow,constants");
        NativeLinkTests.Has(helper, "(1 call site in 1 caller), 1 call out");
        NativeLinkTests.Has(helper, "3 blocks, cyclomatic complexity 2");
        NativeLinkTests.Has(helper, "0x5A17 (23063) (1 site)");
        Assert.DoesNotContain("0x80000000 (", helper); // GENERIC_READ: an all-ones-style mask, not a magic number
        Assert.DoesNotContain("== constants", await tools.AnalyzeNativeFunction(path, "Helper")); // opt-in

        var record = StructuredOutput.Begin();
        var both = await tools.AnalyzeNativeFunction(path, "Main, Helper, Main, 0x1", sections: "identity");
        Assert.Equal(2, both.Split("== identity").Length - 1);
        NativeLinkTests.Has(both, "0x1: ");
        var report = Assert.IsType<NativeFunctionTools.FunctionDossier>(record.Value);
        Assert.Equal("Main", report.Name);
        Assert.Equal(["Helper", null], report.Batch!.Select(b => b.Name));
        Assert.NotNull(report.Batch![1].Error);
        Assert.Equal(ErrorCode.LimitExceeded, (await Assert.ThrowsAsync<ToolError>(() =>
            tools.AnalyzeNativeFunction(path, string.Join(",", Enumerable.Range(1, 17).Select(i => $"rva:0x{i:X}"))))).Code);
    }
}
