using System.Text.Json;
using Corvus.Core;
using Corvus.Native;
using Corvus.Native.Providers;
using Corvus.Native.Providers.Ida;
using Corvus.Services;
using Corvus.Tools;

namespace Corvus.Tests;

/// <summary>decompile_native functions=[...]: one engine request, per-item outcomes, dedup by function, budgets, the text cache shared with single calls.</summary>
public sealed class DecompileBatchTests : IDisposable
{
    private readonly TempDir _dir = new();
    private readonly List<IDisposable> _owned = [];

    public void Dispose()
    {
        foreach (var d in _owned) d.Dispose();
        _dir.Dispose();
    }

    private async Task<(NativeAnalysisTools Tools, BatchProvider Provider, LoadedNative Native, uint First, uint Second)> Setup(BatchProvider? other = null)
    {
        var options = new ServerOptions { BackgroundIndexing = false };
        var workspace = new AssemblyWorkspace(options);
        var code = new NativeCodeService(workspace, options, null, new Native.Annotations.AnnotationStore(_dir.File("annotations")));
        var provider = new BatchProvider();
        var engines = new NativeEngineService(other == null ? [provider] : [provider, other], _dir.File("cache"), code, workspace, options);
        _owned.Add(engines);
        _owned.Add(workspace);
        var tools = new NativeAnalysisTools(workspace, engines, new OutputPager(options), null, code);
        var native = workspace.LoadAny(McpProtocolTests.NativeSample(_dir)).Native!;
        var index = await code.Index(native, null, default);
        uint first = index.AddressOfName("First")!.Value, second = index.AddressOfName("Second")!.Value;
        provider.Functions = [(first, second, "First"), (second, second + 0x10, "Second")];
        if (other != null) other.Functions = provider.Functions;
        return (tools, provider, native, first, second);
    }

    [Fact]
    public async Task Items_keep_their_order_and_outcomes_and_duplicates_are_marked()
    {
        var (tools, provider, native, first, second) = await Setup();
        provider.Failing.Add(second);
        var text = await tools.DecompileNative(native.Id, functions: ["Second", "First", "no_such_name", $"rva:0x{first:X}"]);
        Assert.Contains("// 4 inputs: 1 decompiled, 2 failed, 0 not reached, 1 duplicate (ida)", text);
        Assert.Matches(@"// \[1/4\] Second at 0x[0-9A-F]+ \(input ""Second""\): error failed: decompilation failed at", text);
        Assert.Contains("// [2/4] First at", text);
        Assert.Contains("int First(void)", text);
        Assert.Matches(@"// \[3/4\] no_such_name \(input ""no_such_name""\): error not_found", text);
        Assert.Contains($"(input \"rva:0x{first:X}\"): the same function as [2]", text);
        Assert.True(text.IndexOf("[1/4]", StringComparison.Ordinal) < text.IndexOf("[2/4]", StringComparison.Ordinal));
    }

    [Fact]
    public async Task MaxFunctions_skips_the_rest_with_the_follow_up_call()
    {
        var (tools, provider, native, _, _) = await Setup();
        var text = await tools.DecompileNative(native.Id, functions: ["First", "Second"], maxFunctions: 1);
        Assert.Contains("// 1 input not reached (maxFunctions=1) [More: offset=1]", text);
        Assert.DoesNotContain("(input \"Second\")", text);
        Assert.Equal(1, provider.Decompiles);
        // the next call starts at that input
        var next = await tools.DecompileNative(native.Id, functions: ["First", "Second"], maxFunctions: 1, offset: 1);
        Assert.Contains("// 2 inputs from offset 1: 1 decompiled", next);
        Assert.Contains("(input \"Second\")", next);
        Assert.Equal(2, provider.Decompiles);
    }

    [Fact]
    public async Task Batch_items_share_the_text_cache_with_single_calls()
    {
        var (tools, provider, native, _, _) = await Setup();
        var single = await tools.DecompileNative(native.Id, "First");
        Assert.Contains("int First(void)", single);
        Assert.Equal(1, provider.Decompiles);
        var batch = await tools.DecompileNative(native.Id, functions: ["First", "Second"]);
        Assert.Contains("int First(void)", batch);
        Assert.Contains("int Second(void)", batch);
        Assert.Equal(2, provider.Decompiles); // First came from the cache
        await tools.DecompileNative(native.Id, "Second");
        Assert.Equal(2, provider.Decompiles);
    }

    [Fact]
    public async Task Each_engine_decompiles_for_itself_when_both_have_the_same_names()
    {
        var ghidra = new BatchProvider("ghidra");
        var (tools, ida, native, _, _) = await Setup(ghidra);
        Assert.Contains("/* ida */", await tools.DecompileNative(native.Id, "First", engine: "ida"));
        var text = await tools.DecompileNative(native.Id, "First", engine: "ghidra");
        Assert.Contains("/* ghidra */", text);
        Assert.Equal((1, 1), (ida.Decompiles, ghidra.Decompiles));
        Assert.Contains("/* ghidra */", await tools.DecompileNative(native.Id, functions: ["First"], engine: "ghidra"));
        Assert.Equal(1, ghidra.Decompiles);
    }

    [Fact]
    public async Task Engine_all_decompiles_with_each_engine_in_turn_and_keeps_a_failure_as_its_item()
    {
        var ghidra = new BatchProvider("ghidra");
        var (tools, ida, native, _, second) = await Setup(ghidra);
        var text = await tools.DecompileNative(native.Id, "First", engine: "all");
        int idaAt = text.IndexOf("/* ida */", StringComparison.Ordinal), ghidraAt = text.IndexOf("/* ghidra */", StringComparison.Ordinal);
        Assert.True(idaAt >= 0 && ghidraAt > idaAt, text);
        Assert.Equal((1, 1), (ida.Decompiles, ghidra.Decompiles));

        ghidra.Failing.Add(second);
        text = await tools.DecompileNative(native.Id, "Second", engine: "all");
        Assert.Contains("/* ida */", text);
        Assert.Contains($"// ghidra: failed: decompilation failed at 0x{second:X}", text);

        var e = await Assert.ThrowsAsync<ToolError>(() => tools.DecompileNative(native.Id, functions: ["First"], engine: "all"));
        Assert.Equal(ErrorCode.InvalidArgument, e.Code);
    }

    [Fact]
    public async Task Address_and_functions_are_exclusive()
    {
        var (tools, _, native, _, _) = await Setup();
        var e = await Assert.ThrowsAsync<ToolError>(() => tools.DecompileNative(native.Id, "First", functions: ["Second"]));
        Assert.Equal(ErrorCode.InvalidArgument, e.Code);
        e = await Assert.ThrowsAsync<ToolError>(() => tools.DecompileNative(native.Id));
        Assert.Equal(ErrorCode.InvalidArgument, e.Code);
    }

    [Fact]
    public async Task TimeoutSeconds_reaches_the_engine_and_is_range_checked()
    {
        var (tools, provider, native, _, _) = await Setup();
        await tools.DecompileNative(native.Id, "First", timeoutSeconds: 120);
        Assert.Equal(TimeSpan.FromSeconds(120), provider.LastTimeout);
        await tools.DecompileNative(native.Id, "Second");
        Assert.Null(provider.LastTimeout);
        var e = await Assert.ThrowsAsync<ToolError>(() => tools.DecompileNative(native.Id, "First", timeoutSeconds: 0));
        Assert.Equal(ErrorCode.InvalidArgument, e.Code);
    }

    [Fact]
    public async Task The_default_batch_gives_each_item_its_own_deadline_and_skips_past_the_budget()
    {
        var provider = new BatchProvider { Functions = [(0x1000, 0x1010, "a"), (0x1010, 0x1020, "slow"), (0x1020, 0x1030, "c")] };
        provider.Slow.Add(0x1010);
        INativeDecompilerSession session = new BatchSession(provider);
        var results = await session.DecompileManyAsync([0x1000, 0x1010, 0x1020], 0.2, 30);
        Assert.Equal([DecompileStatus.Ok, DecompileStatus.Error, DecompileStatus.Ok], results.Select(r => r.Status));
        Assert.Equal("timeout", results[1].ErrorCode);
        var budget = await session.DecompileManyAsync([0x1010, 0x1000], 0.3, 0.2); // the slow first item outlasts the whole budget
        Assert.Equal(DecompileStatus.Skipped, budget[1].Status);
    }

    [Fact]
    public void Worker_reply_items_parse()
    {
        using var doc = JsonDocument.Parse("""
            {"items":[{"rva":4096,"status":"ok","start":4096,"name":"f","text":"int f(void)","lines":[[0,4096]]},
                      {"rva":8192,"status":"error","code":"timeout","message":"not decompiled within 60 s"},
                      {"rva":12288,"status":"skipped"}]}
            """);
        var items = WorkerRows.DecompiledMany(doc.RootElement);
        Assert.Equal("f", items[0].Function!.Name);
        Assert.Equal(("timeout", "not decompiled within 60 s"), (items[1].ErrorCode, items[1].Error));
        Assert.Equal(DecompileStatus.Skipped, items[2].Status);
    }

    internal sealed class BatchProvider(string id = IdaProvider.ProviderId) : INativeDecompilerProvider
    {
        public List<(uint Start, uint End, string Name)> Functions { get; set; } = [];
        public HashSet<uint> Failing { get; } = [];
        public HashSet<uint> Slow { get; } = [];
        public int Decompiles;
        public TimeSpan? LastTimeout;
        public string Id => id;
        public string DisplayName => "fake engine";
        public ProviderAvailability CheckAvailability() => ProviderAvailability.Ok(Id, new Dictionary<string, string>());
        public Task<ProviderAvailability> ProbeAsync(CancellationToken cancellationToken = default) => Task.FromResult(CheckAvailability());

        public Task<INativeDecompilerSession> OpenAsync(string imagePath, string? sha256 = null, NativeOpenOptions? options = null, CancellationToken cancellationToken = default) =>
            Task.FromResult<INativeDecompilerSession>(new BatchSession(this));

        public void Dispose() { }
    }

    /// <summary>A session whose batch is the interface's default loop over DecompileAsync.</summary>
    private sealed class BatchSession(BatchProvider provider) : INativeDecompilerSession
    {
        public string ProviderId => provider.Id;
        public string ImagePath => "";
        public string Sha256 => "";
        public NativeArch Arch => NativeArch.X64;
        public ulong ImageBase => 0;
        public bool ReusedDatabase => true;
        public TimeSpan OpenTime => TimeSpan.Zero;
        public bool DecompilerAvailable => true;
        public bool IsOpen => true;

        public async Task<DecompiledFunction> DecompileAsync(uint rva, CancellationToken cancellationToken = default)
        {
            var f = provider.Functions.FirstOrDefault(x => rva >= x.Start && rva < x.End);
            if (f.Name == null) throw new ToolError(ErrorCode.NotFound, $"no function contains rva 0x{rva:X}");
            if (provider.Slow.Contains(f.Start)) await Task.Delay(10_000, cancellationToken);
            if (provider.Failing.Contains(f.Start)) throw new ToolError(ErrorCode.Failed, $"decompilation failed at 0x{f.Start:X}: fake");
            Interlocked.Increment(ref provider.Decompiles);
            return new DecompiledFunction(f.Start, f.Name, $"int {f.Name}(void) {{ return 0; }} /* {provider.Id} */", []);
        }

        public Task<DecompiledFunction> DecompileWithinAsync(uint rva, TimeSpan? timeout, CancellationToken cancellationToken = default)
        {
            provider.LastTimeout = timeout;
            return DecompileAsync(rva, cancellationToken);
        }

        public Task<IReadOnlyList<NativeFunctionInfo>> ListFunctionsAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<NativeFunctionInfo>>(provider.Functions.Select(f => new NativeFunctionInfo(f.Start, f.End, f.Name, NativeFunctionFlags.None)).ToList());

        public Task<FunctionDisassembly> DisassembleAsync(uint rva, CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public Task<PatchSyncResult> SyncPatchesAsync(IReadOnlyList<NativeByteRange> wanted, CancellationToken cancellationToken = default) =>
            Task.FromResult(new PatchSyncResult(wanted.Count, 0, 0, 0, 0, 0, [], TimeSpan.Zero));
        public Task<IReadOnlyList<NativeXref>> GetXrefsToAsync(uint rva, CancellationToken cancellationToken = default) => Task.FromResult<IReadOnlyList<NativeXref>>([]);
        public Task<IReadOnlyList<NativeXref>> GetXrefsFromAsync(uint rva, bool wholeFunction = false, CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<NativeXref>>([]);
        public Task<string> SetNameAsync(uint rva, string name, CancellationToken cancellationToken = default) => Task.FromResult(name);
        public Task<string> SetCommentAsync(uint rva, string text, bool repeatable = false, CancellationToken cancellationToken = default) => Task.FromResult(text);

        public Task<NameBatchResult> ApplyNamesAsync(IReadOnlyList<NativeNameItem> items, string? stampKey = null, string? stamp = null, bool save = false,
            CancellationToken cancellationToken = default) => Task.FromResult(new NameBatchResult(items.Count, 0, 0, 0, TimeSpan.Zero, []));

        public Task<string?> GetStampAsync(string key, CancellationToken cancellationToken = default) => Task.FromResult<string?>(null);
        public Task SaveAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task CloseAsync(bool save = true, CancellationToken cancellationToken = default) => Task.CompletedTask;
        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
        public void Dispose() { }
    }
}
