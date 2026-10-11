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
}
