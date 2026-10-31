using Iced.Intel;
using System.Buffers.Binary;
using Corvus.Core;
using Corvus.Native;
using Corvus.Native.Code;
using Corvus.Mcp;
using Corvus.Native.Annotations;
using Corvus.Services;
using Corvus.Services.Analysis;
using Corvus.Tools;
using static Iced.Intel.AssemblerRegisters;

namespace Corvus.Tests;

/// <summary>analyze_native_function: sections with totals, the sections filter, failure isolation, exclusive ends.</summary>
[Collection(ExternalToolEnvironmentCollection.Name)]
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
        // A first pass learns the function offsets for the export table.
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
        var record = ToolOutput.Collect();
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

    [Fact]
    public async Task A_no_return_call_followed_by_orphan_code_warns_that_the_body_may_be_cut()
    {
        var (ws, tools) = Rig();
        using var _ = ws;
        byte[] Code(Dictionary<string, uint> slots)
        {
            var a = new Assembler(64);
            var exit = slots["KERNEL32.dll!ExitProcess"];
            a.sub(rsp, 0x28);
            a.xor(ecx, ecx);
            a.AddInstruction(Instruction.Create(Iced.Intel.Code.Call_rm64, new MemoryOperand(Register.RIP, (long)(Base + exit), 8)));
            // The body goes on: a no-return guess would cut it here.
            a.mov(eax, 1);
            a.add(rsp, 0x28);
            a.ret();
            var stream = new MemoryStream();
            a.Assemble(new StreamCodeWriter(stream), Base + LinkedImages.Text);
            return stream.ToArray();
        }
        var path = _dir.File("cut.dll");
        File.WriteAllBytes(path, LinkedImages.Build("cut.dll", [("Main", 0)], [("KERNEL32.dll", ["ExitProcess"])], Code));
        var first = await Answer(() => tools.AnalyzeNativeFunction(path, "Main", sections: "flow"));
        NativeLinkTests.Has(first, "the body may be cut at 0x");
        NativeLinkTests.Has(first, "by the call to KERNEL32!ExitProcess");
        Assert.Contains("warning: the body may be cut", first);
        // A repeat answered from the cache carries the same warning (G2-B1).
        Assert.Equal(first, await Answer(() => tools.AnalyzeNativeFunction(path, "Main", sections: "flow")));
    }

    /// <summary>
    /// cipher.dll: Block reads the AES S-box; Wrapper calls Block in a loop that steps 16 bytes and names a storage
    /// operation; Open and Save call Wrapper.
    /// </summary>
    private static (string Path, Dictionary<string, uint> At) CipherSample(
        TempDir dir, int step = 0x10, bool loop = true, bool chain = false, bool zero = false,
        bool mask = false, int rounds = 0, int extraCallers = 0, bool registerChain = false, bool interior = false)
    {
        Dictionary<string, uint>? at = null;
        byte[] Code(Dictionary<string, uint> slots)
        {
            Instruction Rip(Iced.Intel.Code c, Register r, uint rva) => Instruction.Create(c, r, new MemoryOperand(Register.RIP, (long)(Base + rva), 8));
            var a = new Assembler(64);
            var block = a.CreateLabel();
            var wrapper = a.CreateLabel();
            var open = a.CreateLabel();
            var save = a.CreateLabel();
            var again = a.CreateLabel();
            a.Label(ref open);
            a.sub(rsp, 0x28);
            a.call(wrapper);
            a.add(rsp, 0x28);
            a.ret();
            for (int i = 0; i < 6; i++) a.int3();
            a.Label(ref save);
            a.sub(rsp, 0x28);
            a.call(wrapper);
            a.add(rsp, 0x28);
            a.ret();
            for (int i = 0; i < 6; i++) a.int3();
            for (int c = 0; c < extraCallers; c++)
            {
                a.sub(rsp, 0x28);
                a.call(wrapper);
                a.add(rsp, 0x28);
                a.ret();
                for (int i = 0; i < 6; i++) a.int3();
            }
            a.Label(ref wrapper);
            a.sub(rsp, 0x28);
            a.AddInstruction(Rip(Iced.Intel.Code.Lea_r64_m, Register.RDX, slots["name"]));
            a.mov(ecx, 0);
            if (loop)
            {
                a.Label(ref again);
                if (zero) a.xor(eax, eax);
                if (chain) a.xor(__[rdx], eax);
                if (registerChain) a.xor(edx, eax);
                a.call(block);
                a.add(ecx, step);
                a.cmp(ecx, 0x40);
                a.jl(again);
            }
            else a.call(block);
            if (mask) a.and(ecx, 0xF);
            if (rounds != 0) a.cmp(edx, rounds);
            a.add(rsp, 0x28);
            a.ret();
            for (int i = 0; i < 6; i++) a.int3();
            a.Label(ref block);
            a.AddInstruction(Rip(Iced.Intel.Code.Mov_r32_rm32, Register.EAX, slots["sbox"] + (interior ? 100u : 0u)));
            a.ret();
            var stream = new MemoryStream();
            var result = a.Assemble(new StreamCodeWriter(stream), Base + LinkedImages.Text, BlockEncoderOptions.ReturnNewInstructionOffsets);
            at = new()
            {
                ["Open"] = (uint)(result.GetLabelRIP(open) - Base), ["Save"] = (uint)(result.GetLabelRIP(save) - Base),
                ["Wrapper"] = (uint)(result.GetLabelRIP(wrapper) - Base), ["Block"] = (uint)(result.GetLabelRIP(block) - Base),
            };
            return stream.ToArray();
        }
        static Dictionary<string, uint> Data(PeBlob blob, List<uint> relocations)
        {
            blob.Align(16);
            var table = new byte[256];
            byte[] head = [0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76];
            head.CopyTo(table, 0);
            uint sbox = blob.Bytes(table);
            return new() { ["sbox"] = sbox, ["name"] = blob.Ascii("localStorageGetItem") };
        }
        LinkedImages.Build("cipher.dll", [], [("KERNEL32.dll", ["ExitProcess"])], Code, Data);
        var path = dir.File("cipher.dll");
        File.WriteAllBytes(path, LinkedImages.Build("cipher.dll", [("Open", (int)(at!["Open"] - LinkedImages.Text))], [("KERNEL32.dll", ["ExitProcess"])], Code, Data));
        return (path, at);
    }

    [Fact]
    public async Task A_cipher_wrapper_names_its_algorithm_mode_and_local_record_path()
    {
        var (ws, tools) = Rig();
        using var _ = ws;
        var (path, at) = CipherSample(_dir);
        var text = await Answer(() => tools.AnalyzeNativeFunction(path, $"rva:0x{at["Wrapper"]:X}", sections: "annotations"));
        NativeLinkTests.Has(text, "crypto: calls ");
        NativeLinkTests.Has(text, "(AES)");
        NativeLinkTests.Has(text, "mode ECB");
        NativeLinkTests.Has(text, "local record path (localStorageGetItem)");
        NativeLinkTests.Has(text, "not network traffic");
        Assert.DoesNotContain("network request", text);
    }

    private async Task<string> Wrapper(
        int step = 0x10, bool loop = true, bool chain = false, bool zero = false,
        bool mask = false, int rounds = 0, int extraCallers = 0, int maxItems = 40)
    {
        var (ws, tools) = Rig();
        using var _ = ws;
        var (path, at) = CipherSample(_dir, step, loop, chain, zero, mask, rounds, extraCallers);
        return await Answer(() => tools.AnalyzeNativeFunction(
            path, $"rva:0x{at["Wrapper"]:X}", sections: "annotations", maxItems: maxItems));
    }

    [Fact]
    public async Task A_zeroing_xor_in_the_block_loop_keeps_mode_ecb()
    {
        NativeLinkTests.Has(await Wrapper(zero: true), "mode ECB");
    }

    [Fact]
    public async Task An_xor_between_blocks_is_reported_as_not_ecb()
    {
        var text = await Wrapper(chain: true);
        NativeLinkTests.Has(text, "mode CBC");
        NativeLinkTests.Has(text, "confidence=medium");
        Assert.DoesNotContain("mode ECB", text);
    }

    private static NativeCodeIndex Index(string path) =>
        NativeCodeIndex.Build(NativeImageLoader.FromBytes(File.ReadAllBytes(path), path));

    private InspectionService Inspection()
    {
        var options = new ServerOptions { BackgroundIndexing = false };
        var ws = new AssemblyWorkspace(options);
        return new InspectionService(ws, new NativeCodeService(ws, options, null, new AnnotationStore(_dir.File("ann"))));
    }

    [Fact]
    public async Task An_8_byte_block_loop_gets_the_mode_and_confidence_of_the_survey_rule()
    {
        var (ws, tools) = Rig();
        using var _ = ws;
        var (path, at) = CipherSample(_dir, 8);
        var text = await Answer(() => tools.AnalyzeNativeFunction(path, $"rva:0x{at["Wrapper"]:X}", sections: "annotations"));
        NativeLinkTests.Has(text, "crypto: mode ECB (block=8 bytes, confidence=low");
        var rule = Inspection().SurveyFeatures(null, path, null, CancellationToken.None).Features
            .SelectMany(f => f.Evidence).Single(e => e.Feature == "const:ecb-loop");
        var location = Assert.Single(rule.Locations);
        Assert.Contains("mode=ECB confidence=low", location);
        Assert.Contains("block=8 bytes", location);
    }

    // A register xor is not chaining evidence for the loop shape.
    [Fact]
    public async Task A_register_xor_in_the_block_loop_is_not_read_as_chaining()
    {
        var (ws, tools) = Rig();
        using var _ = ws;
        var (path, at) = CipherSample(_dir, registerChain: true);
        var text = await Answer(() => tools.AnalyzeNativeFunction(path, $"rva:0x{at["Wrapper"]:X}", sections: "annotations"));
        NativeLinkTests.Has(text, "crypto: mode ECB (block=16 bytes, confidence=low");
    }

    [Fact]
    public async Task A_reference_into_the_middle_of_a_table_is_named()
    {
        var (ws, tools) = Rig();
        using var _ = ws;
        var (path, at) = CipherSample(_dir, interior: true);
        var text = await Answer(() => tools.AnalyzeNativeFunction(path, $"rva:0x{at["Block"]:X}", sections: "data"));
        NativeLinkTests.Has(text, "constant data");
        NativeLinkTests.Has(text, "(AES)");
    }

    [Fact]
    public async Task A_capped_scan_reports_partial_not_absent()
    {
        var (ws, tools) = Rig();
        using var _ = ws;
        var (path, at) = CipherSample(_dir);
        var index = Index(path);
        var report = InspectionService.NativeReport(index, "cipher.dll", null, CancellationToken.None, scanLimit: 16);
        Assert.Contains(report.Notes, n => n.StartsWith("partial: scanned 16 of ", StringComparison.Ordinal)
                                           && n.Contains("unknown, not absent", StringComparison.Ordinal));
        Assert.DoesNotContain(InspectionService.NativeReport(index, "cipher.dll", null, CancellationToken.None, "imports", 16).Notes,
            n => n.StartsWith("partial:", StringComparison.Ordinal));
        Assert.DoesNotContain(InspectionService.NativeReport(index, "cipher.dll", null, CancellationToken.None).Notes,
            n => n.StartsWith("partial:", StringComparison.Ordinal));
        var lines = new List<string>();
        CryptoAttribution.Notes(index, Assert.Single(index.Functions, f => f.Start == at["Wrapper"]),
            (_, text, _) => lines.Add(text), CancellationToken.None, scanLimit: 16);
        Assert.Contains(lines, l => l.StartsWith("crypto: tables unknown (partial: scanned 16 of ", StringComparison.Ordinal));
    }

    [Fact]
    public async Task A_call_outside_a_loop_leaves_the_mode_undetermined()
    {
        NativeLinkTests.Has(await Wrapper(loop: false), "mode not determined (no loop calls the block routine)");
    }

    [Fact]
    public async Task An_aes_round_count_compare_names_the_key_size()
    {
        NativeLinkTests.Has(await Wrapper(rounds: 0xC), "AES key size 192 bits");
        var plain = await Wrapper();
        NativeLinkTests.Has(plain, "AES key size not determined");
    }

    [Fact]
    public async Task A_16_byte_mask_reports_the_padding_block_size_only_when_seen()
    {
        NativeLinkTests.Has(await Wrapper(mask: true), "padding to 16-byte blocks");
        Assert.DoesNotContain("padding", await Wrapper());
    }

    [Fact]
    public async Task A_wrapper_lists_every_caller_and_the_count_survives_a_section_limit()
    {
        var all = await Wrapper(extraCallers: 10);
        NativeLinkTests.Has(all, "crypto: 12 callers");
        Assert.True(System.Text.RegularExpressions.Regex.Count(all, "crypto caller: ") >= 12);
        NativeLinkTests.Has(await Wrapper(extraCallers: 10, maxItems: 5), "crypto: 12 callers");
    }

    [Fact]
    public async Task A_caller_of_a_wrapper_reaches_the_cipher_routine_two_calls_deep()
    {
        var (ws, tools) = Rig();
        using var _ = ws;
        var (path, at) = CipherSample(_dir);
        var text = await Answer(() => tools.AnalyzeNativeFunction(path, $"rva:0x{at["Open"]:X}", sections: "annotations"));
        NativeLinkTests.Has(text, "crypto: reaches ");
    }

    [Fact]
    public async Task A_cipher_routine_names_its_references_and_callers()
    {
        var (ws, tools) = Rig();
        using var _ = ws;
        var (path, at) = CipherSample(_dir);
        var block = await Answer(() => tools.AnalyzeNativeFunction(path, $"rva:0x{at["Block"]:X}", sections: "annotations"));
        NativeLinkTests.Has(block, "crypto: reads AES tables");
        NativeLinkTests.Has(block, "crypto: 1 caller");
        NativeLinkTests.Has(block, "crypto caller: ");
    }

    /// <summary>A call's text, record, warnings and coverage as one string, to compare repeats.</summary>
    internal static async Task<string> Answer(Func<Task<string>> call)
    {
        var collector = ToolOutput.Collect();
        var text = await call();
        return $"{text}\nrecord: {System.Text.Json.JsonSerializer.Serialize(collector.Record)}\n" +
               string.Concat(collector.Warnings.Select(w => $"warning: {w}\n")) + $"coverage: {collector.Coverage}";
    }

    private (AssemblyWorkspace Workspace, NativeFunctionTools Tools) Rig()
    {
        var options = new ServerOptions { BackgroundIndexing = false };
        var ws = new AssemblyWorkspace(options);
        var code = new NativeCodeService(ws, options, null, new AnnotationStore(_dir.File("ann")));
        return (ws, new NativeFunctionTools(ws, code, new OutputPager(options), new NativeLinkService(ws, code)));
    }

    [Fact]
    public async Task A_repeated_call_answers_the_same_record_with_its_facets()
    {
        var path = Sample(_dir);
        await using var server = await InProcessServer.StartAsync();
        await server.Client.CallToolAsync("load_assembly", new Dictionary<string, object?> { ["path"] = path });
        var args = new Dictionary<string, object?> { ["image"] = path, ["address"] = "Helper" };
        var first = (await server.Client.CallToolAsync("analyze_native_function", args)).StructuredContent!.Value.GetRawText();
        var again = (await server.Client.CallToolAsync("analyze_native_function", args)).StructuredContent!.Value.GetRawText();
        Assert.Contains("\"facets\"", first);
        Assert.Equal(first, again);
    }

    [Fact]
    public async Task Every_section_reports_its_facts_with_totals()
    {
        // The annotations section is read as on a machine without capa.
        using var env = new EnvironmentScope().Set("CORVUS_CAPA", null);
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
        NativeLinkTests.Has(helper, "== annotations ==\n  (none)");
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
        // No engine in this server: pseudocode reports why, the rest is there.
        var both = await tools.AnalyzeNativeFunction(path, "Helper", sections: "identity,callers", pseudocode: true);
        NativeLinkTests.Has(both, "== pseudocode ==\n  error: no decompiler engine is set up in this server");
        NativeLinkTests.Has(both, "== callers (");
        var params_ = await tools.AnalyzeNativeFunction(path, "Helper", sections: "params");
        NativeLinkTests.Has(params_, "parameter 1 (rcx): L\"config.ini\"");
        var e = await Assert.ThrowsAsync<ToolError>(() => tools.AnalyzeNativeFunction(path, "Helper", sections: "identity,nonsense"));
        Assert.Equal(ErrorCode.InvalidArgument, e.Code);
        // A second call (a later page) is served from the cache, text and record alike.
        var first = ToolOutput.Collect();
        await tools.AnalyzeNativeFunction(path, "Helper", sections: "flow,callers");
        var second = ToolOutput.Collect();
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
        NativeLinkTests.Has(text, "prototype (pdb): int __cdecl helper(Sensor *, int)");
    }

    [Fact]
    public void Unwind_data_gives_the_frame()
    {
        // x64: push rbx (offset 1), sub rsp, 28h (offset 8)
        var data = new byte[0x40];
        new byte[] { 0x01, 0x08, 0x02, 0x00, 0x08, 0x42, 0x01, 0x30 }.CopyTo(data, 0);
        var x64 = CodeTestImage.Synthetic(NativeArch.X64, new byte[0x40], data, pdata: [new RuntimeFunction(0x1000, 0x1040, CodeTestImage.SyntheticDataRva)]);
        var u = Corvus.Native.Calls.UnwindFrames.Of(x64, 0x1010)!;
        Assert.Equal(("x64 UNWIND_INFO", 0x28L, 8, "rbx"), (u.Format, u.Allocation, u.PrologBytes, string.Join(",", u.Saved)));

        // ARM64 .xdata: one code word, set_fp then save_fplr_x (stp fp, lr, [sp, #-16]!), end
        var xdata = new byte[0x40];
        BinaryPrimitives.WriteUInt32LittleEndian(xdata, 0x10u | 1u << 21 | 1u << 27);
        new byte[] { 0xE1, 0x81, 0xE4, 0xE3 }.CopyTo(xdata, 4);
        var arm = CodeTestImage.Synthetic(NativeArch.Arm64, new byte[0x40], xdata, pdata: [new RuntimeFunction(0x1000, 0x1040, CodeTestImage.SyntheticDataRva)]);
        var a = Corvus.Native.Calls.UnwindFrames.Of(arm, 0x1004)!;
        Assert.Equal(("ARM64 xdata", 16L, "fp, lr", "x29 = sp"), (a.Format, a.Allocation, string.Join(",", a.Saved), a.FramePointer));

        // ARM64 packed: x19-x20 saved, chained frame record, 32-byte frame
        var b = new PeBuilder { Machine = 0xAA64, ImageBase = 0x140000000 };
        var text = b.Add(".text", Enumerable.Repeat(new byte[] { 0x1F, 0x20, 0x03, 0xD5 }, 4).SelectMany(x => x).ToArray(), 0x60000020);
        uint packed = 1u | 4u << 2 | 2u << 16 | 3u << 21 | 2u << 23;
        var pdata = b.Add(".pdata", [.. BitConverter.GetBytes(text.Rva), .. BitConverter.GetBytes(packed)]);
        b.Directories[Corvus.Native.Pe.PeDirectory.Exception] = (pdata.Rva, 8);
        var file = _dir.File("packed.dll");
        File.WriteAllBytes(file, b.Build());
        var p = Corvus.Native.Calls.UnwindFrames.Of(Corvus.Native.Pe.PeFile.Open(file), text.Rva + 4)!;
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

        var record = ToolOutput.Collect();
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

    [Fact]
    public async Task X86_push_of_a_volatile_register_in_the_prologue_allocates_stack()
    {
        var (ws, tools) = Rig();
        using var _ = ws;
        var path = _dir.File("frame32.dll");
        File.WriteAllBytes(path, SyntheticCrashX86.Pe32("frame32.dll", 0x10000000, _ =>
        {
            var text = new byte[0x40];
            // Local: push ebp; mov ebp, esp; push ecx; mov dword [ebp-4], 5; mov eax, [ebp-4]; mov esp, ebp; pop ebp; ret.
            new byte[] { 0x55, 0x8B, 0xEC, 0x51, 0xC7, 0x45, 0xFC, 5, 0, 0, 0, 0x8B, 0x45, 0xFC, 0x8B, 0xE5, 0x5D, 0xC3 }.CopyTo(text, 0);
            // Method: push ebp; mov ebp, esp; push ecx; mov [ebp-4], ecx; mov eax, [ebp-4]; mov eax, [eax]; mov esp, ebp; pop ebp; ret.
            new byte[] { 0x55, 0x8B, 0xEC, 0x51, 0x89, 0x4D, 0xFC, 0x8B, 0x45, 0xFC, 0x8B, 0x00, 0x8B, 0xE5, 0x5D, 0xC3 }.CopyTo(text, 0x20);
            return text;
        }, [("Local", 0x1000), ("Method", 0x1020)], null));
        var local = await tools.AnalyzeNativeFunction(path, "Local", sections: "signature,frame");
        NativeLinkTests.Has(local, "ecx / edx not read before written");
        NativeLinkTests.Has(local, "saved registers: ebp");
        NativeLinkTests.Has(local, "allocates 4 bytes of stack (push ecx)");
        var method = await tools.AnalyzeNativeFunction("frame32.dll", "Method", sections: "signature,frame");
        NativeLinkTests.Has(method, "argument registers read before written: ecx");
        NativeLinkTests.Has(method, "saved registers: ebp");
    }

    [Fact]
    public void A_guessed_engine_prototype_is_summarized()
    {
        var parameters = Enumerable.Range(0, 32).Select(i => new Corvus.Native.Providers.EngineParameter($"a{i + 1}", "int", $"stack[0x{4 * i:X}]")).ToList();
        var record = new Corvus.Native.Providers.EngineFunctionRecord(0x1000, "Load", null, "int __cdecl Load(" + string.Join(", ", parameters.Select(p => $"int {p.Name}")) + ")",
            "cdecl", "guessed", [(0x1000u, 0x1100u)], null, null, false, false, false, null, parameters, "int", "eax", false);
        var lines = NativeEngineCode.RecordLines(record, r => $"0x{r:X}", compact: true);
        Assert.DoesNotContain(lines, l => l.StartsWith("param ", StringComparison.Ordinal));
        Assert.Contains("32 guessed parameter(s): 0 in registers, 32 on the stack", lines);
        Assert.True(lines[0].Length < 200, lines[0]);
        Assert.Equal(32, NativeEngineCode.RecordLines(record with { SignatureSource = "user" }, r => $"0x{r:X}", compact: true).Count(l => l.StartsWith("param ", StringComparison.Ordinal)));
    }
}
