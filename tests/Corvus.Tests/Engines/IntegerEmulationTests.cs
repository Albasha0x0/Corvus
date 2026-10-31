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

    [Fact]
    public async Task Allocation_calls_run_against_a_heap_that_keeps_resized_bytes()
    {
        var text = await Run("HeapRoundTrip");
        Assert.Contains("Return value: RAX = 0x1234", text);
        Assert.Contains("malloc: modelled, returned 0x", text);
        Assert.Contains("realloc: modelled, returned 0x", text);
        Assert.Contains("free: modelled, returned 0x0", text);
    }

    [Fact]
    public async Task A_released_block_is_reused_and_comes_back_zeroed_from_calloc()
    {
        var text = await Run("HeapReuse");
        Assert.Matches(@"Return value: RAX = 0x1(?!\w)", text);
    }

    [Fact]
    public async Task Equal_allocation_calls_return_equal_addresses()
    {
        var first = await Run("Alloc", args: "32");
        var second = await Run("Alloc", args: "32");
        var line = first.Split((char)10).First(l => l.StartsWith("Return value:", StringComparison.Ordinal));
        Assert.DoesNotContain("RAX = 0x0", line);
        Assert.Contains(line, second);
    }

    [Fact]
    public async Task An_allocation_larger_than_the_heap_returns_null()
    {
        var text = await Run("Alloc", args: "0x40000000");
        Assert.Contains("Return value: RAX = 0x0", text);
    }

    [Fact]
    public async Task A_second_release_of_a_block_stops_the_run_naming_the_call()
    {
        var e = await Assert.ThrowsAsync<ToolError>(() => Run("DoubleFree"));
        output.WriteLine(e.Message);
        Assert.Equal(ErrorCode.Failed, e.Code);
        Assert.Contains("already released", e.Message);
    }

    [Fact]
    public async Task A_stub_for_an_allocation_call_wins_over_the_heap_model()
    {
        var text = await Run("Alloc", args: "32", stubs: "malloc=0x77");
        Assert.Contains("Return value: RAX = 0x77", text);
        Assert.Contains("malloc: stubbed, returned 0x77", text);
    }

    [Fact]
    public async Task An_allocation_through_a_jump_stub_is_modelled()
    {
        var text = await Run("ThunkAlloc", args: "32");
        Assert.Contains("malloc: modelled, returned 0x", text);
        Assert.DoesNotContain("Return value: RAX = 0x0", text);
    }

    [Fact]
    public async Task A_read_after_the_block_is_released_is_a_memory_fault()
    {
        var e = await Assert.ThrowsAsync<ToolError>(() => Run("UseAfterFree"));
        output.WriteLine(e.Message);
        Assert.Contains("memory=", e.Remediation);
    }

    [Fact]
    public async Task A_read_past_the_end_of_a_block_is_a_memory_fault()
    {
        var e = await Assert.ThrowsAsync<ToolError>(() => Run("PastEnd"));
        output.WriteLine(e.Message);
        Assert.Contains("memory=", e.Remediation);
    }

    [Fact]
    public async Task Releasing_a_null_pointer_is_a_no_op()
    {
        var text = await Run("Free", args: "0");
        Assert.Contains("free: modelled, returned 0x0", text);
    }

    [Fact]
    public async Task A_resize_of_a_null_pointer_allocates()
    {
        var text = await Run("Realloc", args: "0,16");
        Assert.Contains("realloc: modelled, returned 0x", text);
        Assert.DoesNotContain("Return value: RAX = 0x0", text);
    }

    [Fact]
    public async Task A_resize_to_zero_releases_the_block()
    {
        var e = await Assert.ThrowsAsync<ToolError>(() => Run("ReallocZero"));
        Assert.Contains("already released", e.Message);
    }

    [Fact]
    public async Task A_zeroed_array_whose_product_overflows_returns_null()
    {
        var text = await Run("Calloc", args: "0x100000000,0x100000000");
        Assert.Contains("Return value: RAX = 0x0", text);
    }

    [Fact]
    public async Task A_resize_of_an_unknown_address_stops_the_run_naming_the_call()
    {
        var e = await Assert.ThrowsAsync<ToolError>(() => Run("Realloc", args: "0x12345,8"));
        Assert.Equal(ErrorCode.Failed, e.Code);
        Assert.Contains("no live allocation", e.Message);
    }

    [Fact]
    public async Task A_failed_resize_keeps_the_old_block_live()
    {
        var text = await Run("GrowFail");
        Assert.Contains("Return value: RAX = 0x77", text);
    }
}
