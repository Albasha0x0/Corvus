using Corvus.Core;
using Corvus.Native.Providers;
using Corvus.Services;
using Corvus.Tools;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>emulate_native engine=ours on the emu.dll of the Ghidra tests: the same scenarios without an engine installed.</summary>
public sealed class IntegerEmulationTests(ITestOutputHelper output, IntegerEmulationTests.Rig rig) : IClassFixture<IntegerEmulationTests.Rig>
{
    private const ulong Base = NativeEmulationGhidraTests.Base;

    /// <summary>emu.dll in a workspace whose engine service has no engines, so auto falls back to the built-in emulator.</summary>
    public sealed class Rig : IDisposable
    {
        private readonly TempDir _dir = new();
        public Dictionary<string, uint> At { get; } = [];
        public AssemblyWorkspace Workspace { get; }
        public NativeEngineService Engines { get; }
        public NativeEmulationTools Tools { get; }

        public Rig()
        {
            var path = NativeEmulationGhidraTests.Build(_dir, At);
            var options = new ServerOptions { TimeoutSeconds = 600, BackgroundIndexing = false };
            Workspace = new AssemblyWorkspace(options);
            Engines = new NativeEngineService(Array.Empty<INativeDecompilerProvider>(), _dir.File("cache"));
            Workspace.LoadAny(path);
            Tools = new NativeEmulationTools(Workspace, Engines, new NativeCodeService(Workspace, options));
        }

        public void Dispose()
        {
            Engines.Dispose();
            Workspace.Dispose();
            _dir.Dispose();
        }
    }

    private async Task<string> Run(string address, string? args = null, string? registers = null, string? memory = null, string? stopAt = null,
        string? stubs = null, string? read = null, int maxInstructions = 1_000_000, int trace = 0, string? engine = "ours")
    {
        var text = await rig.Tools.EmulateNative("emu.dll", address, args, registers, memory, stopAt, stubs, read, maxInstructions, trace: trace, engine: engine);
        output.WriteLine(text);
        return text;
    }

    [Fact]
    public async Task A_xor_decoder_decodes_into_a_scratch_buffer()
    {
        var text = await Run("XorDecode", args: $"buf:32, rva:0x{rig.At["encoded"]:X}, {NativeEmulationGhidraTests.Secret.Length}", read: "rcx 16", trace: 4);
        Assert.Contains("emu.dll: built-in emulation (x86-64)", text);
        Assert.Contains("Stopped: returned to the caller", text);
        Assert.Contains($"\"{NativeEmulationGhidraTests.Secret}\"", text[text.IndexOf("Written memory", StringComparison.Ordinal)..]);
        Assert.Contains("Scratch: arg1 ", text);
        Assert.Contains("Trace (last 4):", text);
        Assert.Contains("ret", text, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Auto_runs_the_built_in_emulator_when_ghidra_is_not_available()
    {
        var text = await Run("Fnv1a", args: $"\"{NativeEmulationGhidraTests.HashInput}\"", engine: null);
        Assert.Contains($"Return value: RAX = 0x{NativeEmulationGhidraTests.Fnv1a(NativeEmulationGhidraTests.HashInput):x}", text);
        Assert.Contains("built-in emulation", text);
    }

    [Fact]
    public async Task A_hundred_argument_sets_run_in_one_request()
    {
        var inputs = Enumerable.Range(0, 100).Select(i => $"name{i}.dll").ToList();
        var text = await rig.Tools.EmulateNative("emu.dll", "Fnv1a", candidates: string.Join("; ", inputs.Select(i => $"\"{i}\"")), engine: "ours");
        Assert.Contains("built-in emulation of 100 argument sets, 100 returned", text);
        for (int i = 0; i < inputs.Count; i++) Assert.Contains($"#{i + 1} (\"{inputs[i]}\"): returned 0x{NativeEmulationGhidraTests.Fnv1a(inputs[i]):x},", text);
    }

    [Fact]
    public async Task Calls_step_into_the_image_or_return_the_value_of_the_any_call_stub()
    {
        var into = await Run("HashName");
        Assert.Contains($"Return value: RAX = 0x{NativeEmulationGhidraTests.Fnv1a(NativeEmulationGhidraTests.HashInput) + 1:x}", into);
        Assert.Contains("Fnv1a: stepped in", into);
        var skipped = await Run("HashName", stubs: "*=7");
        Assert.Contains("Return value: RAX = 0x8", skipped);
        Assert.Contains("Fnv1a: skipped, returned 0x7", skipped);
    }

    [Fact]
    public async Task An_import_call_needs_a_stub_and_names_the_call_otherwise()
    {
        var stubbed = await Run("Ticks", stubs: "kernel32!GetTickCount=0x41");
        Assert.Contains("Return value: RAX = 0x42", stubbed);
        Assert.Contains("GetTickCount: stubbed, returned 0x41", stubbed);
        var e = await Assert.ThrowsAsync<ToolError>(() => Run("Ticks"));
        output.WriteLine(e.Message + "\n" + e.Remediation);
        Assert.Equal(ErrorCode.Unsupported, e.Code);
        Assert.Contains("KERNEL32!GetTickCount", e.Message);
        // The call after sub rsp, 0x28.
        Assert.Contains($"0x{Base + rig.At["Ticks"] + 4:x}", e.Message);
        Assert.Contains("stubs=", e.Remediation);
        Assert.Contains("Stopped:", Assert.IsType<string>(e.Partial));
    }

    [Fact]
    public async Task An_unmapped_read_is_an_error_naming_the_address_and_mapped_memory_reads_back()
    {
        var e = await Assert.ThrowsAsync<ToolError>(() => Run("Deref", registers: "rcx=0x1234"));
        output.WriteLine(e.Message);
        Assert.Equal(ErrorCode.Failed, e.Code);
        Assert.Contains("0x1234", e.Message);
        Assert.Contains("Deref", e.Message);
        var mapped = await Run("Deref", registers: "rcx=0x10000000", memory: "va:0x10000000=u32:0x1234567");
        Assert.Contains("Return value: RAX = 0x1234567", mapped);
    }

    [Fact]
    public async Task Budgets_and_stop_addresses_end_the_run_with_the_state_so_far()
    {
        var spin = await Run("Spin", maxInstructions: 1000);
        Assert.Contains("1,000 instructions", spin);
        Assert.Contains("instruction budget (1,000) reached at ", spin);
        Assert.Contains("(Spin); raise maxInstructions", spin);
        var timed = await rig.Tools.EmulateNative("emu.dll", "Spin", maxInstructions: 50_000_000, timeoutSeconds: 1, engine: "ours");
        output.WriteLine(timed);
        Assert.Contains("Stopped: time budget reached at ", timed);
        var stopped = await Run("Fnv1a", args: "\"a\"", stopAt: $"rva:0x{rig.At["Fnv1aEnd"]:X}");
        Assert.Contains("Stopped: reached a stop address", stopped);
        Assert.Contains($"RAX=0x{NativeEmulationGhidraTests.Fnv1a("a"):x}", stopped);
    }
}
