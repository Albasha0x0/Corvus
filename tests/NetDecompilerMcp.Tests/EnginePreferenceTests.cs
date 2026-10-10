using System.Diagnostics;
using System.Text.RegularExpressions;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Native;
using NetDecompilerMcp.Native.Providers;
using NetDecompilerMcp.Native.Providers.Ida;
using NetDecompilerMcp.Services;
using NetDecompilerMcp.Tools;
using Xunit.Abstractions;

namespace NetDecompilerMcp.Tests;

/// <summary>
/// engine=auto|ours|ida on the native code tools: ours never asks the provider, auto asks it nothing until an analysis
/// is complete in the session and then uses it without a new one, ida opens it or fails with provider_unavailable.
/// </summary>
public sealed class EnginePreferenceTests(ITestOutputHelper output) : IDisposable
{
    private readonly TempDir _dir = new();
    private readonly List<IDisposable> _owned = [];

    public void Dispose()
    {
        foreach (var d in _owned) d.Dispose();
        _dir.Dispose();
    }

    private sealed record Rig(AssemblyWorkspace Workspace, NativeCodeService Code, NativeCodeTools Tools, NativeEngineService Engines, string Image);

    private Rig Setup(INativeDecompilerProvider provider, EngineMode mode = EngineMode.Auto)
    {
        var options = new ServerOptions { BackgroundIndexing = false, Engine = mode };
        var workspace = new AssemblyWorkspace(options);
        var code = new NativeCodeService(workspace, options, null, new Native.Annotations.AnnotationStore(_dir.File("annotations")));
        var engines = new NativeEngineService(provider, _dir.File("cache"), code, workspace, options);
        _owned.Add(engines);
        _owned.Add(workspace);
        return new Rig(workspace, code, new NativeCodeTools(workspace, code, new OutputPager(options), null, engines), engines, McpProtocolTests.NativeSample(_dir));
    }

    private static async Task<(LoadedNative Native, uint First)> Loaded(Rig rig)
    {
        await rig.Tools.ListFunctions(rig.Image, engine: "ours");
        var native = rig.Workspace.Read(() => rig.Workspace.Natives[0]);
        var index = await rig.Code.Index(native, null, default);
        return (native, index.AddressOfName("First") ?? throw new InvalidOperationException("no First"));
    }

    /// <summary>Every engine-aware tool once, on the sample's First function.</summary>
    private static async Task<List<string>> CallAll(Rig rig, string? engine) =>
    [
        await rig.Tools.ListFunctions(rig.Image, engine: engine),
        await rig.Tools.Disassemble(rig.Image, "First", engine: engine),
        await rig.Tools.GetCfg(rig.Image, "First", engine: engine),
        await rig.Tools.FindXrefs(rig.Image, "First", engine: engine),
        await rig.Tools.NativeCallTree(rig.Image, "First", engine: engine),
    ];

    [Fact]
    public async Task Ours_never_asks_the_provider()
    {
        var provider = new FakeProvider(available: true);
        var rig = Setup(provider, EngineMode.Ida); // even with ida as the server default
        await Loaded(rig);
        foreach (var result in await CallAll(rig, "ours"))
            Assert.Contains("Engine: ours (engine=ours: the built-in index; IDA not consulted)", result);
        Assert.Equal(0, provider.Calls);
    }

    [Fact]
    public async Task Auto_without_a_completed_analysis_asks_nothing_and_with_one_uses_it_without_a_new_analysis()
    {
        var provider = new FakeProvider(available: true);
        var rig = Setup(provider);
        var (native, first) = await Loaded(rig);
        foreach (var result in await CallAll(rig, null))
            Assert.Contains("Engine: ours (server default auto: no completed IDA analysis of this image in this session)", result);
        // a saved database is reported, not opened
        var saved = Path.Combine(_dir.File("cache"), IdaProvider.ProviderId, native.OriginalSha256);
        Directory.CreateDirectory(saved);
        File.WriteAllBytes(Path.Combine(saved, "ida-default.i64"), [0]);
        rig.Engines.SavedCheckInterval = 0;
        Assert.Contains("engine=ida loads it without analyzing again", await rig.Tools.ListFunctions(rig.Image, engine: "auto"));
        Assert.Equal(0, provider.Calls);

        // the auto check costs two table lookups (the saved database is looked up again every 5 s), no request
        rig.Engines.SavedCheckInterval = 5_000;
        var index = rig.Code.Ready(native)!;
        NativeEngineCode.Choose(EngineMode.Auto, false, rig.Engines, native, index);
        var clock = Stopwatch.StartNew();
        const int n = 5_000;
        for (int i = 0; i < n; i++) NativeEngineCode.Choose(EngineMode.Auto, false, rig.Engines, native, index);
        output.WriteLine($"auto engine check without a completed analysis: {clock.Elapsed.TotalMicroseconds / n:0.000} us per call");
        Assert.Equal(0, provider.Calls);

        // an analysis completed in the session (prewarm, decompile_native, engine=ida): auto uses it
        provider.Functions = [new(first, first + 0x20, "ida_First", NativeFunctionFlags.None, 3), new(first + 0x40, first + 0x60, "ida_only", NativeFunctionFlags.Library, 1)];
        await rig.Engines.Session(native, null, null, default);
        Assert.Equal(1, provider.Opens);
        var results = await CallAll(rig, null);
        foreach (var result in results)
            Assert.Contains("Engine: ida (server default auto: IDA's analysis of this image is complete in this session)", result);
        Assert.Contains("ida_only", results[0]);     // IDA's function list
        Assert.Contains("First", results[0]);        // our name wins at a function both know
        Assert.Contains("fake_insn", results[1]);    // IDA's disassembly
        Assert.Contains("1 block", results[2]);      // IDA's blocks
        Assert.Contains("Call", results[3]);         // IDA's reference
        Assert.Contains("ida_only", results[4]);     // IDA's call edge
        Assert.Equal(1, provider.Opens);             // no new analysis

        // a patch the database has not taken: back to ours until a call syncs it
        native.Patches.Add(new Native.Patching.NativePatch(first, 0, [0xCC], [0x90], "test"));
        Assert.Contains("Engine: ours", await rig.Tools.GetCfg(rig.Image, "First"));
    }

    [Fact]
    public async Task Ida_opens_the_analysis_or_is_provider_unavailable()
    {
        var provider = new FakeProvider(available: true);
        var rig = Setup(provider);
        var (_, first) = await Loaded(rig);
        provider.Functions = [new(first, first + 0x20, "ida_First", NativeFunctionFlags.None, 0)];
        var list = await rig.Tools.ListFunctions(rig.Image, engine: "ida");
        Assert.Contains("Engine: ida (engine=ida: IDA's analysis)", list);
        Assert.Equal(1, provider.Opens);

        var missing = new FakeProvider(available: false);
        var absent = Setup(missing);
        await Loaded(absent);
        var e = await Assert.ThrowsAsync<ToolError>(() => absent.Tools.FindXrefs(absent.Image, "First", engine: "ida"));
        Assert.Equal(ErrorCode.ProviderUnavailable, e.Code);
        Assert.Contains("not installed here", e.Message);
        Assert.Equal(0, missing.Opens);
        // the server default works the same way
        var byDefault = Setup(missing, EngineMode.Ida);
        Assert.Equal(ErrorCode.ProviderUnavailable, (await Assert.ThrowsAsync<ToolError>(() => byDefault.Tools.GetCfg(byDefault.Image, "First"))).Code);
        // no engine service at all
        var bare = new NativeCodeTools(absent.Workspace, absent.Code, new OutputPager(new ServerOptions()));
        Assert.Equal(ErrorCode.ProviderUnavailable, (await Assert.ThrowsAsync<ToolError>(() => bare.ListFunctions(absent.Image, engine: "ida"))).Code);
        Assert.Equal(ErrorCode.InvalidArgument, (await Assert.ThrowsAsync<ToolError>(() => bare.ListFunctions(absent.Image, engine: "ghidra"))).Code);
    }

    [Fact]
    public void Server_option_and_variable()
    {
        Assert.Equal(EngineMode.Auto, new ServerOptions().Engine);
        Assert.Equal(EngineMode.Ours, ServerOptions.Parse(["--engine", "ours"]).Engine);
        Assert.Equal(EngineMode.Ida, ServerOptions.Parse(["--engine", "IDA"]).Engine);
        Assert.Throws<ArgumentException>(() => ServerOptions.Parse(["--engine", "ghidra"]));
    }

    /// <summary>Real IDA on a small System32 DLL: function and reference counts by engine, and auto switching once the analysis is done.</summary>
    [Trait("Speed", "Slow")]
    [IdaFact]
    public async Task Real_IDA_counts_by_engine()
    {
        var path = new[] { "cabinet.dll", "version.dll" }
            .Select(n => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), n)).FirstOrDefault(File.Exists);
        if (path == null) { output.WriteLine("no System32 sample found"); return; }
        var options = new ServerOptions { BackgroundIndexing = false };
        var workspace = new AssemblyWorkspace(options);
        _owned.Add(workspace);
        var code = new NativeCodeService(workspace, options, null, new Native.Annotations.AnnotationStore(_dir.File("annotations")));
        var engines = new NativeEngineService(new IdaProviderOptions { CacheRoot = _dir.File("cache") }, code, workspace, options);
        _owned.Add(engines);
        var tools = new NativeCodeTools(workspace, code, new OutputPager(options), null, engines, new NativeNamePush(code));

        var clock = Stopwatch.StartNew();
        var ours = await tools.ListFunctions(path, sort: "callers", limit: 1);
        var oursTime = clock.Elapsed;
        clock.Restart();
        var auto = await tools.ListFunctions(path, sort: "callers", limit: 1);
        var autoTime = clock.Elapsed;
        Assert.Contains("Engine: ours (server default auto: no completed IDA analysis", auto);
        clock.Restart();
        var ida = await tools.ListFunctions(path, sort: "callers", limit: 1, engine: "ida");
        var idaTime = clock.Elapsed;
        Assert.Contains("Engine: ida", ida);
        clock.Restart();
        var autoAfter = await tools.ListFunctions(path, sort: "callers", limit: 1);
        var autoAfterTime = clock.Elapsed;
        Assert.Contains("Engine: ida (server default auto: IDA's analysis of this image is complete", autoAfter);

        int Count(string text) => int.Parse(Regex.Match(text, @": ([\d,]+) functions?").Groups[1].Value.Replace(",", ""));
        int oursCount = Count(ours), idaCount = Count(ida);
        output.WriteLine($"{Path.GetFileName(path)}: ours {oursCount} functions ({oursTime.TotalMilliseconds:0} ms incl. index), " +
                         $"auto before analysis {autoTime.TotalMilliseconds:0} ms, ida {idaCount} functions ({idaTime.TotalSeconds:0.0} s incl. analysis), " +
                         $"auto after {autoAfterTime.TotalMilliseconds:0} ms");
        Assert.True(oursCount > 10 && idaCount > 10);
        Assert.InRange(idaCount, oursCount / 2, oursCount * 2);

        // the most called function (ours): references by engine
        var top = Regex.Match(ours, @"^\s*(0x[0-9A-F]+)\s", RegexOptions.Multiline).Groups[1].Value;
        output.WriteLine(string.Join('\n', ours.Split('\n').Take(4)));
        int Rows(string text) => Regex.Matches(text, @"^\s*0x[0-9A-F]+\s+\S+", RegexOptions.Multiline).Count;
        var xOurs = await tools.FindXrefs(path, top, engine: "ours");
        var xIda = await tools.FindXrefs(path, top, engine: "ida");
        output.WriteLine($"references to {top}: ours {Rows(xOurs)}, ida {Rows(xIda)}");
        Assert.True(Rows(xIda) > 0);
        var cfgIda = await tools.GetCfg(path, top, engine: "ida");
        var cfgOurs = await tools.GetCfg(path, top, engine: "ours");
        output.WriteLine($"{cfgOurs.Split('\n')[1]}\n{cfgIda.Split('\n')[1]}");
        Assert.Contains("(via IDA)", cfgIda);
    }

    /// <summary>A provider whose sessions answer from fixed data and count every request.</summary>
    private sealed class FakeProvider(bool available) : INativeDecompilerProvider
    {
        public int AvailabilityChecks, Opens, Probes, Requests;
        public IReadOnlyList<NativeFunctionInfo> Functions { get; set; } = [];

        public int Calls => AvailabilityChecks + Opens + Probes + Requests;
        public string Id => IdaProvider.ProviderId;
        public string DisplayName => "fake engine";

        public ProviderAvailability CheckAvailability()
        {
            Interlocked.Increment(ref AvailabilityChecks);
            return available ? ProviderAvailability.Ok(Id, new Dictionary<string, string>()) : ProviderAvailability.Missing(Id, "not installed here", "install it");
        }

        public Task<ProviderAvailability> ProbeAsync(CancellationToken cancellationToken = default)
        {
            Interlocked.Increment(ref Probes);
            return Task.FromResult(CheckAvailability());
        }

        public Task<INativeDecompilerSession> OpenAsync(string imagePath, string? sha256 = null, NativeOpenOptions? options = null, CancellationToken cancellationToken = default)
        {
            Interlocked.Increment(ref Opens);
            if (!available) throw new ToolError(ErrorCode.ProviderUnavailable, "not installed here");
            return Task.FromResult<INativeDecompilerSession>(new FakeSession(this, imagePath, sha256 ?? ""));
        }

        public void Dispose() { }

        public int Request() => Interlocked.Increment(ref Requests);
    }

    private sealed class FakeSession(FakeProvider provider, string path, string sha) : INativeDecompilerSession
    {
        public string ProviderId => IdaProvider.ProviderId;
        public string ImagePath => path;
        public string Sha256 => sha;
        public NativeArch Arch => NativeArch.X64;
        public ulong ImageBase => 0;
        public bool ReusedDatabase => false;
        public TimeSpan OpenTime => TimeSpan.Zero;
        public bool DecompilerAvailable => false;
        public bool IsOpen => true;

        private T Answer<T>(T value)
        {
            provider.Request();
            return value;
        }

        private NativeFunctionInfo At(uint rva) => provider.Functions.FirstOrDefault(f => rva >= f.StartRva && rva < f.EndRva)
            ?? throw new ToolError(ErrorCode.NotFound, $"no function at {rva:X}");

        public Task<IReadOnlyList<NativeFunctionInfo>> ListFunctionsAsync(CancellationToken cancellationToken = default) => Task.FromResult(Answer(provider.Functions));

        public Task<FunctionDisassembly> DisassembleAsync(uint rva, CancellationToken cancellationToken = default)
        {
            var f = At(rva);
            return Task.FromResult(Answer(new FunctionDisassembly(f.StartRva, f.EndRva, f.Name, [new DisassembledInstruction(f.StartRva, [0xC3], "fake_insn", null)], false)));
        }

        public Task<NativeBlockGraph> GetBlocksAsync(uint rva, CancellationToken cancellationToken = default)
        {
            var f = At(rva);
            return Task.FromResult(Answer(new NativeBlockGraph(f.StartRva, f.Name, [new NativeBlockInfo(f.StartRva, f.EndRva, 1, "ret", [], false)], [])));
        }

        public Task<IReadOnlyList<NativeXref>> GetXrefsToAsync(uint rva, CancellationToken cancellationToken = default) =>
            Task.FromResult(Answer<IReadOnlyList<NativeXref>>(provider.Functions.Count > 1 && rva == provider.Functions[0].StartRva
                ? [new NativeXref(provider.Functions[1].StartRva + 4, rva, NativeXrefKind.Call, provider.Functions[1].StartRva)] : []));

        public Task<IReadOnlyList<NativeXref>> GetXrefsFromAsync(uint rva, bool wholeFunction = false, CancellationToken cancellationToken = default) =>
            Task.FromResult(Answer<IReadOnlyList<NativeXref>>(provider.Functions.Count > 1 && rva == provider.Functions[0].StartRva
                ? [new NativeXref(rva + 4, provider.Functions[1].StartRva, NativeXrefKind.Call, rva)] : []));

        public Task<PatchSyncResult> SyncPatchesAsync(IReadOnlyList<NativeByteRange> wanted, CancellationToken cancellationToken = default) =>
            Task.FromResult(Answer(new PatchSyncResult(wanted.Count, 0, 0, 0, 0, 0, [], TimeSpan.Zero)));

        public Task<DecompiledFunction> DecompileAsync(uint rva, CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public Task<string> SetNameAsync(uint rva, string name, CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public Task<string> SetCommentAsync(uint rva, string text, bool repeatable = false, CancellationToken cancellationToken = default) => throw new NotSupportedException();

        public Task<NameBatchResult> ApplyNamesAsync(IReadOnlyList<NativeNameItem> items, string? stampKey = null, string? stamp = null, bool save = false,
            CancellationToken cancellationToken = default) => Task.FromResult(Answer(new NameBatchResult(items.Count, 0, 0, 0, TimeSpan.Zero, [])));

        public Task<string?> GetStampAsync(string key, CancellationToken cancellationToken = default) => Task.FromResult(Answer<string?>(null));
        public Task SaveAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task CloseAsync(bool save = true, CancellationToken cancellationToken = default) => Task.CompletedTask;
        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
        public void Dispose() { }
    }
}
