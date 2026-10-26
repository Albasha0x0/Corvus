using System.Text;
using System.Text.Json;
using Iced.Intel;
using Corvus.Core;
using Corvus.Native.Providers;
using Corvus.Native.Providers.Ghidra;
using Corvus.Native.Providers.Ida;
using Corvus.Services;
using Corvus.Tools;
using Xunit.Abstractions;
using static Iced.Intel.AssemblerRegisters;

namespace Corvus.Tests;

/// <summary>emulate_native arguments and report text without Ghidra.</summary>
public sealed class NativeEmulationTests
{
    [Fact]
    public async Task Arguments_are_checked_before_any_engine_starts()
    {
        var tools = new NativeEmulationTools(null!, null!);
        var unknown = await Assert.ThrowsAsync<ToolError>(() => tools.EmulateNative("x.dll", "f", engine: "qemu"));
        Assert.Equal(ErrorCode.Unsupported, unknown.Code);
        Assert.Contains("engine=ours", unknown.Remediation);
        Assert.Equal(ErrorCode.InvalidArgument, (await Assert.ThrowsAsync<ToolError>(() => tools.EmulateNative("x.dll", "f", maxInstructions: 0))).Code);
        Assert.Equal(ErrorCode.InvalidArgument, (await Assert.ThrowsAsync<ToolError>(() => tools.EmulateNative("x.dll", "f", timeoutSeconds: 301))).Code);
        Assert.Equal(ErrorCode.InvalidArgument, (await Assert.ThrowsAsync<ToolError>(() => tools.EmulateNative("x.dll", "f", trace: 2001))).Code);
    }

    [Fact]
    public void Candidate_sets_split_on_semicolons_outside_quotes()
    {
        Assert.Equal(["1, 2", "\"a;b\", 3"], NativeEmulationTools.Split("1, 2; \"a;b\", 3", ';'));
    }

    [Fact]
    public void Lists_split_on_commas_outside_quotes_and_literals_unescape()
    {
        Assert.Equal(["\"a, b\"", "u'x\\'y,'", "buf:16", "-1"], NativeEmulationTools.Split(" \"a, b\" , u'x\\'y,',buf:16,, -1 "));
        Assert.Equal("x'y,", NativeEmulationTools.Literal("'x\\'y,'"));
        Assert.Equal("a, \"b\"\n", NativeEmulationTools.Literal("\"a, \\\"b\\\"\\n\""));
        Assert.Null(NativeEmulationTools.Literal("buf:4"));
        Assert.Equal(ulong.MaxValue, NativeEmulationTools.Integer("-1"));
        Assert.Equal(0x10UL, NativeEmulationTools.Integer("0x10"));
        Assert.Null(NativeEmulationTools.Integer("rcx"));
        Assert.Throws<ToolError>(() => NativeEmulationTools.Split("\"open"));
    }

    [Fact]
    public void Written_bytes_show_as_text_when_they_read_as_text()
    {
        Assert.StartsWith("\"Hi\\n\" | 48 69 0A 00", NativeEmulationTools.Show([0x48, 0x69, 0x0A, 0]));
        Assert.StartsWith("u\"ok\" | 6F 00 6B 00", NativeEmulationTools.Show(Encoding.Unicode.GetBytes("ok\0")));
        Assert.Equal("01 02 FF", NativeEmulationTools.Show([1, 2, 0xFF]));
        Assert.EndsWith(" ...", NativeEmulationTools.Show(new byte[100]));
    }

    [Fact]
    public void Report_names_the_stop_return_value_calls_and_memory()
    {
        const string json = """
            {"language":"x86:LE:64:default","stop":"returned","detail":null,"pc":"0x7ffe00200000","where":null,"instructions":1234,"seconds":0.05,
             "return_register":"RAX","return_value":"0x2a","registers":[["RAX","0x2a",true],["RBX","0x0",false]],
             "calls":[{"site":"0x180001010","target":"0x0","name":"KERNEL32.dll!GetTickCount","action":"stub","value":"0x41"}],"call_count":1,
             "scratch":[{"label":"arg1","va":"0x7ffe00101000","length":4}],"stack":"0x7ffe00000000-0x7ffe00100000","stack_bytes_written":16,
             "written":[{"va":"0x7ffe00101000","length":4,"bytes":"48690000","where":null}],"written_ranges":1,
             "reads":[{"label":"rcx","va":"0x7ffe00101000","bytes":"4869"}],"trace":[["0x180001000","RET"]]}
            """;
        var text = NativeEmulationTools.Format("t.dll", JsonDocument.Parse(json).RootElement, 100);
        Assert.Contains("1,234 instructions\n", text); // the time taken is in _meta: the text is the same in every run
        var report = NativeEmulationTools.Report("t.dll", JsonDocument.Parse(json).RootElement);
        Assert.Equal(("returned", "RAX", "0x2a", 1234L), (report.Stop, report.ReturnRegister, report.ReturnValue, report.Instructions));
        Assert.Equal([new NativeEmulationTools.EmulatedRegister("RAX", "0x2a")], report.Registers);
        Assert.Equal("\"Hi\"", report.Written[0].Text);
        Assert.Equal("stub", report.Calls[0].Action);
        Assert.Null(report.StoppedAt);
        Assert.Equal(0.05, report.ElapsedSeconds);
        Assert.Contains("Stopped: returned to the caller\n", text);
        Assert.Contains("Return value: RAX = 0x2a (42)", text);
        Assert.Contains("Registers changed: RAX=0x2a\n", text);
        Assert.Contains("0x180001010 -> KERNEL32.dll!GetTickCount: stubbed, returned 0x41", text);
        Assert.Contains("Scratch: arg1 0x7ffe00101000 (4 bytes)", text);
        Assert.Contains("Written memory: 1 range, 16 stack bytes", text);
        Assert.Contains("0x7ffe00101000 4 bytes: \"Hi\"", text);
        Assert.Contains("rcx -> 0x7ffe00101000: \"Hi\"", text);
        Assert.Contains("Trace (last 1):\n  0x180001000  RET", text);
    }
}

/// <summary>emulate_native through a real Ghidra on a small x64 DLL: a XOR decoder, a hash, calls into the image, stubs, faults and budgets.</summary>
[Trait("Speed", "Slow")]
public sealed class NativeEmulationGhidraTests(ITestOutputHelper output, NativeEmulationGhidraTests.Rig rig) : IClassFixture<NativeEmulationGhidraTests.Rig>
{
    internal const ulong Base = 0x180000000;
    private const byte Key = 0x5A;
    internal const string Secret = "Hello, emulator!";
    internal const string HashInput = "kernel32.dll";

    /// <summary>emu.dll and a workspace with the Ghidra engine, built once for the class.</summary>
    public sealed class Rig : IDisposable
    {
        private readonly TempDir _dir = new();
        private readonly Lazy<(AssemblyWorkspace Workspace, NativeEngineService Engines, NativeEmulationTools Tools)> _rig;
        public Dictionary<string, uint> At { get; } = [];

        public Rig()
        {
            _rig = new(() =>
            {
                var path = Build(_dir, At);
                var options = new ServerOptions { TimeoutSeconds = 600, BackgroundIndexing = false };
                var workspace = new AssemblyWorkspace(options);
                var engines = new NativeEngineService(new IdaProviderOptions { CacheRoot = _dir.File("cache") }, null, workspace, options);
                workspace.LoadAny(path);
                return (workspace, engines, new NativeEmulationTools(workspace, engines));
            });
        }

        public NativeEmulationTools Tools => _rig.Value.Tools;

        /// <summary>Requests sent to the image's Ghidra worker so far.</summary>
        public long WorkerRequests => ((WorkerSessionBase)_rig.Value.Engines.OpenSession(_rig.Value.Workspace.Read(() => _rig.Value.Workspace.Natives[0]), "ghidra")!).Worker!.Requests;

        public void Dispose()
        {
            if (_rig.IsValueCreated)
            {
                _rig.Value.Engines.Dispose();
                _rig.Value.Workspace.Dispose();
            }
            _dir.Dispose();
        }
    }

    /// <summary>
    /// emu.dll exports: XorDecode(dst, src, n) writes src[i] ^ 0x5A; Fnv1a(s) returns the 32-bit FNV-1a of a NUL-terminated string;
    /// HashName() returns Fnv1a("kernel32.dll") + 1 through a call; Ticks() returns GetTickCount() + 1; Deref(p) returns *(int*)p; Spin() loops.
    /// </summary>
    internal static string Build(TempDir dir, Dictionary<string, uint> at)
    {
        byte[] Code(Dictionary<string, uint> slots)
        {
            var a = new Assembler(64);
            Label xorDecode = a.CreateLabel(), xorLoop = a.CreateLabel(), xorDone = a.CreateLabel();
            Label fnv = a.CreateLabel(), fnvLoop = a.CreateLabel(), fnvEnd = a.CreateLabel();
            Label hashName = a.CreateLabel(), ticks = a.CreateLabel(), deref = a.CreateLabel(), spin = a.CreateLabel();
            a.Label(ref xorDecode);
            a.test(r8d, r8d);
            a.jz(xorDone);
            a.xor(eax, eax);
            a.Label(ref xorLoop);
            a.movzx(r9d, __byte_ptr[rdx + rax]);
            a.xor(r9b, Key);
            a.mov(__byte_ptr[rcx + rax], r9b);
            a.inc(eax);
            a.cmp(eax, r8d);
            a.jl(xorLoop);
            a.Label(ref xorDone);
            a.ret();
            Pad(a);
            a.Label(ref fnv);
            a.mov(eax, 0x811C9DC5);
            a.Label(ref fnvLoop);
            a.movzx(edx, __byte_ptr[rcx]);
            a.test(dl, dl);
            a.jz(fnvEnd);
            a.xor(eax, edx);
            a.imul(eax, eax, 0x01000193);
            a.inc(rcx);
            a.jmp(fnvLoop);
            a.Label(ref fnvEnd);
            a.ret();
            Pad(a);
            a.Label(ref hashName);
            a.sub(rsp, 0x28);
            a.AddInstruction(Instruction.Create(Iced.Intel.Code.Lea_r64_m, Register.RCX, new MemoryOperand(Register.RIP, (long)(Base + slots["input"]))));
            a.call(fnv);
            a.inc(eax);
            a.add(rsp, 0x28);
            a.ret();
            Pad(a);
            a.Label(ref ticks);
            a.sub(rsp, 0x28);
            a.AddInstruction(Instruction.Create(Iced.Intel.Code.Call_rm64, new MemoryOperand(Register.RIP, (long)(Base + slots["KERNEL32.dll!GetTickCount"]), 8)));
            a.inc(eax);
            a.add(rsp, 0x28);
            a.ret();
            Pad(a);
            a.Label(ref deref);
            a.mov(eax, __dword_ptr[rcx]);
            a.ret();
            Pad(a);
            a.Label(ref spin);
            a.jmp(spin);
            var stream = new MemoryStream();
            var result = a.Assemble(new StreamCodeWriter(stream), Base + LinkedImages.Text, BlockEncoderOptions.ReturnNewInstructionOffsets);
            uint Rva(Label l) => (uint)(result.GetLabelRIP(l) - Base);
            at["XorDecode"] = Rva(xorDecode);
            at["Fnv1a"] = Rva(fnv);
            at["Fnv1aEnd"] = Rva(fnvEnd);
            at["HashName"] = Rva(hashName);
            at["Ticks"] = Rva(ticks);
            at["Deref"] = Rva(deref);
            at["Spin"] = Rva(spin);
            at["encoded"] = slots["encoded"];
            return stream.ToArray();
        }
        static Dictionary<string, uint> Data(PeBlob blob, List<uint> relocations)
        {
            blob.Align(16);
            uint encoded = blob.Bytes([.. Encoding.ASCII.GetBytes(Secret).Select(b => (byte)(b ^ Key))]);
            blob.Align(16);
            uint input = blob.Ascii(HashInput);
            return new() { ["encoded"] = encoded, ["input"] = input };
        }
        (string, string[])[] imports = [("KERNEL32.dll", ["GetTickCount"])];
        LinkedImages.Build("emu.dll", [], imports, Code, Data);
        string[] exported = ["XorDecode", "Fnv1a", "HashName", "Ticks", "Deref", "Spin"];
        var path = dir.File("emu.dll");
        File.WriteAllBytes(path, LinkedImages.Build("emu.dll", [.. exported.Select(n => (n, (object)(int)(at[n] - LinkedImages.Text)))], imports, Code, Data));
        return path;
    }

    private static void Pad(Assembler a)
    {
        for (int i = 0; i < 8; i++) a.int3();
    }

    internal static uint Fnv1a(string s)
    {
        uint h = 0x811C9DC5;
        foreach (var b in Encoding.ASCII.GetBytes(s)) h = (h ^ b) * 0x01000193;
        return h;
    }

    private async Task<string> Run(string address, string? args = null, string? registers = null, string? memory = null, string? stopAt = null,
        string? stubs = null, string? read = null, int maxInstructions = 1_000_000, int trace = 0)
    {
        var text = await rig.Tools.EmulateNative("emu.dll", address, args, registers, memory, stopAt, stubs, read, maxInstructions, trace: trace);
        output.WriteLine(text);
        return text;
    }

    [GhidraFact]
    public async Task A_xor_decoder_decodes_into_a_scratch_buffer()
    {
        var text = await Run("XorDecode", args: $"buf:32, rva:0x{rig.At["encoded"]:X}, {Secret.Length}", read: "rcx 16", trace: 4);
        Assert.Contains("Stopped: returned to the caller", text);
        Assert.Contains($"\"{Secret}\"", text[text.IndexOf("Written memory", StringComparison.Ordinal)..]);
        Assert.Contains("Scratch: arg1 ", text);
        Assert.Contains("Trace (last 4):", text);
        Assert.Contains("RET", text);
    }

    [GhidraFact]
    public async Task A_hash_of_a_string_argument_is_the_return_value()
    {
        var text = await Run("Fnv1a", args: $"\"{HashInput}\"");
        Assert.Contains($"Return value: RAX = 0x{Fnv1a(HashInput):x}", text);
    }

    [GhidraFact]
    [Trait(PerfBudget.Trait, PerfBudget.Timing)]
    public async Task A_hundred_argument_sets_run_in_one_request_faster_than_a_hundred_calls()
    {
        await Run("Fnv1a", args: "\"warm\"");
        var one = System.Diagnostics.Stopwatch.StartNew();
        await Run("Fnv1a", args: $"\"{HashInput}\"");
        one.Stop();
        var inputs = Enumerable.Range(0, 100).Select(i => $"name{i}.dll").ToList();
        long requests = rig.WorkerRequests;
        var all = System.Diagnostics.Stopwatch.StartNew();
        var text = await rig.Tools.EmulateNative("emu.dll", "Fnv1a", candidates: string.Join("; ", inputs.Select(i => $"\"{i}\"")));
        all.Stop();
        Assert.Equal(requests + 1, rig.WorkerRequests);
        output.WriteLine($"one call {one.ElapsedMilliseconds} ms, 100 sets {all.ElapsedMilliseconds} ms\n{text[..Math.Min(text.Length, 400)]}");
        Assert.Contains("100 argument sets, 100 returned", text);
        for (int i = 0; i < inputs.Count; i++) Assert.Contains($"#{i + 1} (\"{inputs[i]}\"): returned 0x{Fnv1a(inputs[i]):x},", text);
        // One emulator for the batch, reset between sets: about 6 ms a set against about 10-20 ms for a call of its own.
        PerfBudget.AtMost("engines/emulation-batch-in-calls", all.Elapsed / one.Elapsed, 100, "calls", output, $"100 sets {all.ElapsedMilliseconds} ms, one call {one.ElapsedMilliseconds} ms");
    }

    [GhidraFact]
    public async Task Calls_step_into_the_image_or_return_the_value_of_the_any_call_stub()
    {
        Assert.Contains($"Return value: RAX = 0x{Fnv1a(HashInput) + 1:x}", await Run("HashName"));
        var skipped = await Run("HashName", stubs: "*=7");
        Assert.Contains("Return value: RAX = 0x8", skipped);
        Assert.Contains("Fnv1a: skipped, returned 0x7", skipped);
    }

    [GhidraFact]
    public async Task An_import_call_needs_a_stub_and_names_the_call_otherwise()
    {
        var stubbed = await Run("Ticks", stubs: "kernel32!GetTickCount=0x41");
        Assert.Contains("Return value: RAX = 0x42", stubbed);
        Assert.Contains("GetTickCount: stubbed, returned 0x41", stubbed);
        var e = await Assert.ThrowsAsync<ToolError>(() => Run("Ticks"));
        output.WriteLine(e.Message + "\n" + e.Remediation);
        Assert.Equal(ErrorCode.Unsupported, e.Code);
        Assert.Contains("GetTickCount", e.Message);
        Assert.Contains($"0x{Base + rig.At["Ticks"] + 4:x}", e.Message); // the call after sub rsp, 0x28
        Assert.Contains("stubs=", e.Remediation);
        Assert.Contains("Stopped:", Assert.IsType<string>(e.Partial));
    }

    [GhidraFact]
    public async Task An_unmapped_read_is_an_error_naming_the_address_and_mapped_memory_reads_back()
    {
        // Ghidra 12.0's emulator does not say why it reads, so a data read cannot be told from the decoder's read-ahead
        if (Version.Parse(GhidraInstallation.Locate(null, out _, out _)!.Version) >= new Version(12, 1))
        {
            var e = await Assert.ThrowsAsync<ToolError>(() => Run("Deref", registers: "rcx=0x1234"));
            output.WriteLine(e.Message);
            Assert.Equal(ErrorCode.Failed, e.Code);
            Assert.Contains("0x1234", e.Message);
            Assert.Contains("Deref", e.Message);
        }
        var mapped = await Run("Deref", registers: "rcx=0x10000000", memory: "va:0x10000000=u32:0x1234567");
        Assert.Contains("Return value: RAX = 0x1234567", mapped);
    }

    [GhidraFact]
    public async Task Budgets_and_stop_addresses_end_the_run_with_the_state_so_far()
    {
        var spin = await Run("Spin", maxInstructions: 1000);
        Assert.Contains("1,000 instructions", spin);
        Assert.Contains("instruction budget (1,000) reached at ", spin);
        Assert.Contains("(Spin); raise maxInstructions", spin);
        var timed = await rig.Tools.EmulateNative("emu.dll", "Spin", maxInstructions: 50_000_000, timeoutSeconds: 1);
        output.WriteLine(timed);
        Assert.Contains("Stopped: time budget reached at ", timed);
        var stopped = await Run("Fnv1a", args: "\"a\"", stopAt: $"rva:0x{rig.At["Fnv1aEnd"]:X}");
        Assert.Contains("Stopped: reached a stop address", stopped);
        Assert.Contains($"RAX=0x{Fnv1a("a"):x}", stopped);
    }
}
