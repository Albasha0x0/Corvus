using Iced.Intel;
using System.Buffers.Binary;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Native;
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

    /// <summary>
    /// stack.dll: Main (entry) starts a thread on Worker (only its address is taken), then calls Five(0, 0, 0, 0, 5); Five returns
    /// its fifth argument, read from [rsp+28h] at entry.
    /// </summary>
    private (string Path, NativeFunctionTools Tools, AssemblyWorkspace Workspace, uint Worker) Stack()
    {
        Dictionary<string, uint>? at = null;
        byte[] Code(Dictionary<string, uint> slots)
        {
            var a = new Assembler(64);
            Label five = a.CreateLabel(), worker = a.CreateLabel(), main = a.CreateLabel();
            a.Label(ref main);
            a.sub(rsp, 0x48);
            a.xor(ecx, ecx);
            a.xor(edx, edx);
            a.lea(r8, __[worker]);
            a.xor(r9d, r9d);
            a.mov(__qword_ptr[rsp + 0x20], 0);
            a.mov(__qword_ptr[rsp + 0x28], 0);
            a.AddInstruction(Instruction.Create(Iced.Intel.Code.Call_rm64, new MemoryOperand(Register.RIP, (long)(Base + slots["KERNEL32.dll!CreateThread"]), 8)));
            a.mov(__dword_ptr[rsp + 0x20], 5);
            a.call(five);
            a.add(rsp, 0x48);
            a.ret();
            for (int i = 0; i < 4; i++) a.int3();
            a.Label(ref five);
            a.mov(eax, __dword_ptr[rsp + 0x28]);
            a.ret();
            for (int i = 0; i < 4; i++) a.int3();
            a.Label(ref worker);
            a.xor(eax, eax);
            a.ret();
            var stream = new MemoryStream();
            var r = a.Assemble(new StreamCodeWriter(stream), Base + LinkedImages.Text, BlockEncoderOptions.ReturnNewInstructionOffsets);
            at = new() { ["Main"] = (uint)(r.GetLabelRIP(main) - Base), ["Five"] = (uint)(r.GetLabelRIP(five) - Base), ["Worker"] = (uint)(r.GetLabelRIP(worker) - Base) };
            return stream.ToArray();
        }
        (string, string[])[] imports = [("KERNEL32.dll", ["CreateThread"])];
        LinkedImages.Build("stack.dll", [], imports, Code);
        var path = _dir.File("stack.dll");
        File.WriteAllBytes(path, LinkedImages.Build("stack.dll", [("Main", (int)(at!["Main"] - LinkedImages.Text)), ("Five", (int)(at["Five"] - LinkedImages.Text))], imports, Code));
        var options = new ServerOptions { BackgroundIndexing = false };
        var ws = new AssemblyWorkspace(options);
        var native = ws.LoadAny(path).Native!;
        var code = new NativeCodeService(ws, options, null, new AnnotationStore(_dir.File("ann")));
        code.Annotations(native).ChangeUserTypes(l => l.WithType(at["Five"], "int Five(int a, int b, int c, int d, int e)"));
        return (path, new NativeFunctionTools(ws, code, new OutputPager(options)), ws, at["Worker"]);
    }

    [Fact]
    public async Task Stack_parameters_callbacks_and_the_users_prototype()
    {
        var (path, tools, ws, workerRva) = Stack();
        using var _ = ws;
        var five = await tools.AnalyzeNativeFunction(path, "Five", sections: "identity,signature,callers,params");
        NativeLinkTests.Has(five, "prototype (user): int Five(int a, int b, int c, int d, int e)");
        NativeLinkTests.Has(five, "parameters read at entry: 5 ([rsp+28h]): at least 5 arguments");
        NativeLinkTests.Has(five, "parameter 5 ([rsp+28h]): 5");
        var worker = await tools.AnalyzeNativeFunction(path, $"rva:0x{workerRva:X}", sections: "callers");
        NativeLinkTests.Has(worker, "reachable only through its address: a callback or a stored pointer (passed to CreateThread as lpStartAddress at 0x");
    }

    [Fact]
    public async Task The_pdb_prototype_is_part_of_the_identity()
    {
        var options = new ServerOptions { BackgroundIndexing = false };
        using var ws = new AssemblyWorkspace(options);
        var code = new NativeCodeService(ws, options, null, new AnnotationStore(_dir.File("ann")));
        _ = new PdbService(code);
        var tools = new NativeFunctionTools(ws, code, new OutputPager(options));
        var text = await tools.AnalyzeNativeFunction(PdbTypeFixture.Image(_dir), "rva:0x1040", sections: "identity");
        NativeLinkTests.Has(text, "prototype (pdb): int __cdecl helper(Player *, int)");
    }

    [Fact]
    public void Unwind_data_gives_the_frame()
    {
        // x64: push rbx (offset 1), sub rsp, 28h (offset 8)
        var data = new byte[0x40];
        new byte[] { 0x01, 0x08, 0x02, 0x00, 0x08, 0x42, 0x01, 0x30 }.CopyTo(data, 0);
        var x64 = CodeTestImage.Synthetic(NativeArch.X64, new byte[0x40], data, pdata: [new RuntimeFunction(0x1000, 0x1040, CodeTestImage.SyntheticDataRva)]);
        var u = NetDecompilerMcp.Native.Calls.UnwindFrames.Of(x64, 0x1010)!;
        Assert.Equal(("x64 UNWIND_INFO", 0x28L, 8, "rbx"), (u.Format, u.Allocation, u.PrologBytes, string.Join(",", u.Saved)));

        // ARM64 .xdata: one code word, set_fp then save_fplr_x (stp fp, lr, [sp, #-16]!), end
        var xdata = new byte[0x40];
        BinaryPrimitives.WriteUInt32LittleEndian(xdata, 0x10u | 1u << 21 | 1u << 27);
        new byte[] { 0xE1, 0x81, 0xE4, 0xE3 }.CopyTo(xdata, 4);
        var arm = CodeTestImage.Synthetic(NativeArch.Arm64, new byte[0x40], xdata, pdata: [new RuntimeFunction(0x1000, 0x1040, CodeTestImage.SyntheticDataRva)]);
        var a = NetDecompilerMcp.Native.Calls.UnwindFrames.Of(arm, 0x1004)!;
        Assert.Equal(("ARM64 xdata", 16L, "fp, lr", "x29 = sp"), (a.Format, a.Allocation, string.Join(",", a.Saved), a.FramePointer));

        // ARM64 packed: x19-x20 saved, chained frame record, 32-byte frame
        var b = new PeBuilder { Machine = 0xAA64, ImageBase = 0x140000000 };
        var text = b.Add(".text", Enumerable.Repeat(new byte[] { 0x1F, 0x20, 0x03, 0xD5 }, 4).SelectMany(x => x).ToArray(), 0x60000020);
        uint packed = 1u | 4u << 2 | 2u << 16 | 3u << 21 | 2u << 23;
        var pdata = b.Add(".pdata", [.. BitConverter.GetBytes(text.Rva), .. BitConverter.GetBytes(packed)]);
        b.Directories[NetDecompilerMcp.Native.Pe.PeDirectory.Exception] = (pdata.Rva, 8);
        var file = _dir.File("packed.dll");
        File.WriteAllBytes(file, b.Build());
        var p = NetDecompilerMcp.Native.Calls.UnwindFrames.Of(NetDecompilerMcp.Native.Pe.PeFile.Open(file), text.Rva + 4)!;
        Assert.Equal(("ARM64 packed", 32L, "x19-x20,fp, lr"), (p.Format, p.Allocation, string.Join(",", p.Saved)));
        Assert.NotNull(p.FramePointer);
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
