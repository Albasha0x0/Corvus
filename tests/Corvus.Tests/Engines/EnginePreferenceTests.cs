using System.Diagnostics;
using System.Text.RegularExpressions;
using Corvus.Core;
using Corvus.Native;
using Corvus.Native.Providers;
using Corvus.Native.Providers.Ida;
using Corvus.Services;
using Corvus.Tools;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>
/// engine=auto|ours|ida|ghidra on the native code tools: ours never asks a provider, auto asks nothing until an engine has
/// analyzed the bytes (open or saved) and then uses it (IDA before Ghidra), ida and ghidra open that engine's analysis or
/// fail with provider_unavailable.
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

    private Rig Setup(INativeDecompilerProvider provider, EngineMode mode = EngineMode.Auto) => Setup([provider], mode);

    private Rig Setup(IReadOnlyList<INativeDecompilerProvider> providers, EngineMode mode = EngineMode.Auto, EngineMode? prewarm = null)
    {
        var options = new ServerOptions { BackgroundIndexing = false, Engine = mode, Prewarm = prewarm };
        var workspace = new AssemblyWorkspace(options);
        var code = new NativeCodeService(workspace, options, null, new Native.Annotations.AnnotationStore(_dir.File("annotations")));
        var engines = new NativeEngineService(providers, _dir.File("cache"), code, workspace, options);
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
            Assert.Contains("Engine: ours (engine=ours: the built-in index; no engine consulted)", result);
        Assert.Equal(0, provider.Calls);
    }

    [Fact]
    public async Task Auto_without_an_analysis_asks_nothing_and_with_a_saved_or_open_one_uses_it()
    {
        var provider = new FakeProvider(available: true);
        var rig = Setup(provider);
        var (native, first) = await Loaded(rig);
        foreach (var result in await CallAll(rig, null))
            Assert.Contains("Engine: ours (server default auto: no engine has analyzed these bytes)", result);
        Assert.Equal(0, provider.Calls);

        // the auto check costs two table lookups (the saved database is looked up again every 5 s), no request
        var index = rig.Code.Ready(native)!;
        NativeEngineCode.Choose(EngineMode.Auto, false, rig.Engines, native, index);
        var clock = Stopwatch.StartNew();
        const int n = 5_000;
        for (int i = 0; i < n; i++) NativeEngineCode.Choose(EngineMode.Auto, false, rig.Engines, native, index);
        output.WriteLine($"auto engine check without an analysis: {clock.Elapsed.TotalMicroseconds / n:0.000} us per call");
        Assert.Equal(0, provider.Calls);

        // a saved database (another process analyzed these bytes): auto opens it
        provider.Functions = [new(first, first + 0x20, "ida_First", NativeFunctionFlags.None, 3), new(first + 0x40, first + 0x60, "ida_only", NativeFunctionFlags.Library, 1)];
        var saved = Path.Combine(_dir.File("cache"), IdaProvider.ProviderId, native.OriginalSha256);
        Directory.CreateDirectory(saved);
        File.WriteAllBytes(Path.Combine(saved, "ida-default.i64"), [0]);
        rig.Engines.SavedCheckInterval = 0;
        var results = await CallAll(rig, null);
        foreach (var result in results)
            Assert.Contains("Engine: ida (server default auto: IDA has analyzed these bytes)", result);
        Assert.Contains("ida_only", results[0]);     // IDA's function list
        Assert.Contains("First", results[0]);        // our name wins at a function both know
        Assert.Contains("fake_insn", results[1]);    // IDA's disassembly
        Assert.Contains("1 block", results[2]);      // IDA's blocks
        Assert.Contains("Call", results[3]);         // IDA's reference
        Assert.Contains("ida_only", results[4]);     // IDA's call edge
        Assert.Equal(1, provider.Opens);

        // the open analysis keeps the choice without the saved file, also while a patch waits to be synced
        Directory.Delete(saved, true);
        native.Patches.Add(new Native.Patching.NativePatch(first, 0, [0xCC], [0x90], "test"));
        Assert.Contains("Engine: ida (server default auto: IDA has analyzed these bytes)", await rig.Tools.GetCfg(rig.Image, "First"));
        Assert.Equal(1, provider.Opens);             // no new analysis
    }

    [Fact]
    public async Task Auto_on_a_partial_saved_analysis_names_it_partial_and_names_reanalyze_native()
    {
        var provider = new FakeProvider(available: true) { Complete = false };
        var rig = Setup(provider);
        var (native, first) = await Loaded(rig);
        provider.Functions = [new(first, first + 0x20, "ida_First", NativeFunctionFlags.None, 3)];
        var saved = Path.Combine(_dir.File("cache"), IdaProvider.ProviderId, native.OriginalSha256);
        Directory.CreateDirectory(saved);
        File.WriteAllBytes(Path.Combine(saved, "ida-default.i64"), [0]);
        rig.Engines.SavedCheckInterval = 0;
        await rig.Engines.Session(native, "ida", null, default);
        Assert.Contains("Engine: ida (server default auto: IDA's analysis of these bytes is partial (an open's time ran out); reanalyze_native completes it)",
            await rig.Tools.ListFunctions(rig.Image));
        provider.Complete = true;
        Assert.Contains("Engine: ida (server default auto: IDA has analyzed these bytes)", await rig.Tools.ListFunctions(rig.Image));
    }

    /// <summary>
    /// Two servers sharing one analysis cache with different call histories (one opened Ghidra, the other nothing) pick
    /// the same engine for the same call, and an engine another call opened never changes the choice.
    /// </summary>
    [Fact]
    public async Task Auto_picks_the_same_engine_in_two_processes_with_different_histories()
    {
        var ida = new FakeProvider(available: true);
        var ghidra = new FakeProvider(available: true, id: "ghidra");
        var a = Setup([ida, ghidra]);
        var b = Setup([new FakeProvider(available: true), new FakeProvider(available: true, id: "ghidra")]);
        var (nativeA, first) = await Loaded(a);
        var (nativeB, _) = await Loaded(b);
        a.Engines.SavedCheckInterval = b.Engines.SavedCheckInterval = 0;
        ghidra.Functions = [new(first, first + 0x20, "FUN_first", NativeFunctionFlags.None, 1)];

        // nothing analyzed: both answer from ours
        Assert.Equal("ours", Choice(a, nativeA).Engine);
        Assert.Equal(Choice(a, nativeA), Choice(b, nativeB));

        // A opens Ghidra with an analysis that is not complete yet: no engine has analyzed the bytes for either
        ghidra.Complete = false;
        await a.Engines.Session(nativeA, "ghidra", null, default);
        Assert.Equal(Choice(a, nativeA), Choice(b, nativeB));
        Assert.Equal("ours", Choice(a, nativeA).Engine);

        // Ghidra's analysis completes and saves its project in the shared cache: both pick Ghidra
        ghidra.Complete = true;
        var project = Path.Combine(_dir.File("cache"), "ghidra", nativeA.OriginalSha256, "p-0123456789abcdef");
        Directory.CreateDirectory(project);
        File.WriteAllBytes(Path.Combine(project, "corvus.gpr"), [0]);
        Assert.Equal("ghidra", Choice(a, nativeA).Engine);
        Assert.Equal(Choice(a, nativeA), Choice(b, nativeB));
        // and the engine-only rule agrees
        Assert.Equal(EngineChoice.EngineOnly(null, a.Engines, nativeA), EngineChoice.EngineOnly(null, b.Engines, nativeB));
        Assert.Equal("ghidra", a.Engines.Resolve(nativeA, null));
        Assert.Equal("ghidra", b.Engines.Resolve(nativeB, null));
        Assert.Equal(0, ida.Opens);

        static EngineChoice Choice(Rig rig, LoadedNative native) =>
            NativeEngineCode.Choose(EngineMode.Auto, false, rig.Engines, native, rig.Code.Ready(native)!);
    }

    [Fact]
    public async Task Find_xrefs_takes_several_targets_with_one_engine_request()
    {
        var provider = new FakeProvider(available: true);
        var rig = Setup(provider);
        var (_, first) = await Loaded(rig);
        provider.Functions = [new(first, first + 0x20, "ida_First", NativeFunctionFlags.None, 0), new(first + 0x40, first + 0x60, "ida_caller", NativeFunctionFlags.None, 0)];
        var text = await rig.Tools.FindXrefs(rig.Image, addresses: ["First", "no_such_name", $"rva:0x{first + 0x40:X}"], engine: "ida");
        Assert.Contains("[1/3] First: References to", text);
        Assert.Contains("[2/3] no_such_name: error", text);
        Assert.Contains("[3/3] rva:", text);
        Assert.Equal([1, 0], text.Split('\n').Select(l => l.Trim()).Where(l => l.EndsWith(" row") || l.EndsWith(" rows")).Select(l => int.Parse(l.Split(' ')[0])));
        Assert.Equal(1, provider.ManyRequests);
        Assert.Equal(0, provider.SingleRequests);

        var ours = await rig.Tools.FindXrefs(rig.Image, addresses: ["First", "First"], engine: "ours");
        Assert.Contains("[2/2] First: References to", ours);
        Assert.Equal(ErrorCode.InvalidArgument, (await Assert.ThrowsAsync<ToolError>(() => rig.Tools.FindXrefs(rig.Image, "First", addresses: ["First"]))).Code);
    }

    [Fact]
    public async Task Ida_opens_the_analysis_or_is_provider_unavailable()
    {
        var provider = new FakeProvider(available: true);
        var rig = Setup(provider);
        var (_, first) = await Loaded(rig);
        provider.Functions = [new(first, first + 0x20, "ida_First", NativeFunctionFlags.None, 0)];
        var (list, call) = await EngineMeta.Run(() => rig.Tools.ListFunctions(rig.Image, engine: "ida"));
        Assert.Contains("Engine: ida (engine=ida: IDA's analysis)", list);
        Assert.Equal(1, provider.Opens);
        // the engine's provenance is in _meta
        Assert.Equal(("full", "complete"), (call.EngineMeta["engineProfile"], call.EngineMeta["analysis"]));

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
        Assert.Equal(ErrorCode.ProviderUnavailable, (await Assert.ThrowsAsync<ToolError>(() => bare.ListFunctions(absent.Image, engine: "ghidra"))).Code);
        Assert.Equal(ErrorCode.InvalidArgument, (await Assert.ThrowsAsync<ToolError>(() => bare.ListFunctions(absent.Image, engine: "binja"))).Code);
        // an engine this server does not have
        Assert.Equal(ErrorCode.ProviderUnavailable, (await Assert.ThrowsAsync<ToolError>(() => absent.Tools.ListFunctions(absent.Image, engine: "ghidra"))).Code);
    }

    [Fact]
    public void Server_option_and_variable()
    {
        Assert.Equal(EngineMode.Auto, new ServerOptions().Engine);
        Assert.Equal(EngineMode.Ours, ServerOptions.Parse(["--engine", "ours"]).Engine);
        Assert.Equal(EngineMode.Ida, ServerOptions.Parse(["--engine", "IDA"]).Engine);
        Assert.Equal(EngineMode.Ghidra, ServerOptions.Parse(["--engine", "ghidra"]).Engine);
        Assert.Throws<ArgumentException>(() => ServerOptions.Parse(["--engine", "binja"]));

        Assert.Null(new ServerOptions().Prewarm);
        Assert.Equal(EngineMode.Ida, ServerOptions.Parse(["--ida-prewarm"]).Prewarm);
        Assert.Equal(EngineMode.Ghidra, ServerOptions.Parse(["--prewarm", "Ghidra"]).Prewarm);
        Assert.Equal(EngineMode.Auto, ServerOptions.Parse(["--prewarm", "auto"]).Prewarm);
        Assert.Null(ServerOptions.Parse(["--prewarm", "off"]).Prewarm);
        Assert.Throws<ArgumentException>(() => ServerOptions.Parse(["--prewarm", "ours"]));
    }

    [Fact]
    public async Task Ghidra_is_chosen_when_named_or_when_it_alone_has_a_complete_analysis()
    {
        var ida = new FakeProvider(available: true);
        var ghidra = new FakeProvider(available: true, id: "ghidra");
        var rig = Setup([ida, ghidra]);
        var (native, first) = await Loaded(rig);
        ida.Functions = [new(first, first + 0x20, "ida_First", NativeFunctionFlags.None, 1), new(first + 0x40, first + 0x60, "ida_only", NativeFunctionFlags.None, 1)];
        ghidra.Functions = [new(first, first + 0x20, "FUN_first", NativeFunctionFlags.None, 1), new(first + 0x40, first + 0x60, "ghidra_only", NativeFunctionFlags.None, 1)];

        // named: Ghidra's analysis is opened (IDA is not), every result says so and our names win
        var results = await CallAll(rig, "ghidra");
        foreach (var result in results) Assert.Contains("Engine: ghidra (engine=ghidra: Ghidra's analysis)", result);
        Assert.Contains("(via Ghidra)", results[0]);
        Assert.Contains("ghidra_only", results[0]);
        Assert.Contains("First", results[0]);
        Assert.DoesNotContain("FUN_first", results[0]);
        Assert.Contains("ghidra_only", results[4]);
        Assert.Equal((0, 1), (ida.Opens, ghidra.Opens));

        // auto: Ghidra's analysis is the only complete one
        foreach (var result in await CallAll(rig, null))
            Assert.Contains("Engine: ghidra (server default auto: Ghidra has analyzed these bytes)", result);
        Assert.Equal(0, ida.Opens);

        // one image holds both sessions; once IDA's is complete, auto prefers it
        Assert.Equal("ida", (await rig.Engines.Session(native, "ida", null, default)).ProviderId);
        Assert.Equal((1, 1), (ida.Opens, ghidra.Opens));
        Assert.Contains("Engine: ida (server default auto: IDA has analyzed these bytes)", await rig.Tools.GetCfg(rig.Image, "First"));
        Assert.Equal("ghidra", (await rig.Engines.Session(native, "ghidra", null, default)).ProviderId);
        Assert.Equal((1, 1), (ida.Opens, ghidra.Opens));
        // without a named engine, the first engine that has analyzed the bytes
        Assert.Equal("ida", rig.Engines.Resolve(native, null));
    }

    [Fact]
    public async Task Auto_skips_an_incomplete_analysis_and_falls_back_from_IDA_to_Ghidra()
    {
        var ida = new FakeProvider(available: false);
        var ghidra = new FakeProvider(available: true, id: "ghidra") { Complete = false };
        var rig = Setup([ida, ghidra]);
        var (native, first) = await Loaded(rig);
        ghidra.Functions = [new(first, first + 0x20, "FUN_first", NativeFunctionFlags.None, 1)];
        // the only installed engine is Ghidra: an unnamed decompiler session goes there
        Assert.Equal("ghidra", rig.Engines.Resolve(native, null));
        await rig.Engines.Session(native, null, null, default);
        Assert.Equal(1, ghidra.Opens);
        // its analysis ran out of time: auto does not use it
        Assert.Contains("Engine: ours (server default auto: no engine has analyzed these bytes)", await rig.Tools.ListFunctions(rig.Image));
        ghidra.Complete = true;
        Assert.Contains("Engine: ghidra (server default auto: Ghidra has analyzed these bytes)", await rig.Tools.ListFunctions(rig.Image));

        // engine=ida names IDA's remediation and offers the others
        var e = await Assert.ThrowsAsync<ToolError>(() => rig.Tools.GetCfg(rig.Image, "First", engine: "ida"));
        Assert.Equal(ErrorCode.ProviderUnavailable, e.Code);
        Assert.Contains("engine=ida: IDA is not available: not installed here", e.Message);
        Assert.Contains("install it", e.Remediation);

        // neither installed: one message names both
        var none = Setup([new FakeProvider(available: false), new FakeProvider(available: false, id: "ghidra")]);
        Assert.Equal(("IDA: not installed here; Ghidra: not installed here", "install it; or install it"), none.Engines.Unavailability!.Value);
        Assert.Null(none.Engines.FirstAvailable());
    }

    [Fact]
    public async Task Prewarm_opens_the_configured_engine_as_an_image_loads()
    {
        var ida = new FakeProvider(available: true);
        var ghidra = new FakeProvider(available: true, id: "ghidra");
        var rig = Setup([ida, ghidra], prewarm: EngineMode.Ghidra);
        await Loaded(rig);
        var until = DateTime.UtcNow.AddSeconds(10);
        while (rig.Engines.Prewarming.Done == 0 && DateTime.UtcNow < until) await Task.Delay(20);
        Assert.Equal(new NativeEngineService.PrewarmStatus(true, "ghidra", 0, null, 0, 1, 0, 0, null), rig.Engines.Prewarming);
        Assert.Equal((0, 1), (ida.Opens, ghidra.Opens));

        // auto: the first engine installed
        var auto = Setup([new FakeProvider(available: false), ghidra], prewarm: EngineMode.Auto);
        await Loaded(auto);
        until = DateTime.UtcNow.AddSeconds(10);
        while (auto.Engines.Prewarming.Done == 0 && DateTime.UtcNow < until) await Task.Delay(20);
        Assert.Equal(1, auto.Engines.Prewarming.Done);
        Assert.Equal(2, ghidra.Opens);
    }

    [Fact]
    public async Task A_saved_Ghidra_project_is_opened_by_auto()
    {
        var ida = new FakeProvider(available: true);
        var ghidra = new FakeProvider(available: true, id: "ghidra");
        var rig = Setup([ida, ghidra]);
        var (native, _) = await Loaded(rig);
        var project = Path.Combine(_dir.File("cache"), "ghidra", native.OriginalSha256, "p-0123456789abcdef");
        Directory.CreateDirectory(project);
        File.WriteAllBytes(Path.Combine(project, "corvus.gpr"), [0]);
        rig.Engines.SavedCheckInterval = 0;
        Assert.Contains("Engine: ghidra (server default auto: Ghidra has analyzed these bytes)", await rig.Tools.ListFunctions(rig.Image));
        Assert.Equal((0, 1), (ida.Opens, ghidra.Opens));
    }

    [Fact]
    public async Task Auto_answers_from_the_built_in_index_while_another_session_holds_the_saved_database()
    {
        var ida = new FakeProvider(available: false);
        var ghidra = new FakeProvider(available: true, id: "ghidra");
        var rig = Setup([ida, ghidra]);
        var (native, _) = await Loaded(rig);
        var entry = Path.Combine(_dir.File("cache"), "ghidra", native.OriginalSha256);
        Directory.CreateDirectory(Path.Combine(entry, "p-0123456789abcdef"));
        File.WriteAllBytes(Path.Combine(entry, "p-0123456789abcdef", "corvus.gpr"), [0]);
        rig.Engines.SavedCheckInterval = 0;
        using (new FileStream(Path.Combine(entry, ".lock"), FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None, 1, FileOptions.DeleteOnClose))
            Assert.Contains("Engine: ours", await rig.Tools.ListFunctions(rig.Image));
        Assert.Equal(0, ghidra.Opens);
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
        Assert.Contains("Engine: ours (server default auto: no engine has analyzed these bytes)", auto);
        clock.Restart();
        var ida = await tools.ListFunctions(path, sort: "callers", limit: 1, engine: "ida");
        var idaTime = clock.Elapsed;
        Assert.Contains("Engine: ida", ida);
        clock.Restart();
        var autoAfter = await tools.ListFunctions(path, sort: "callers", limit: 1);
        var autoAfterTime = clock.Elapsed;
        Assert.Contains("Engine: ida (server default auto: IDA has analyzed these bytes)", autoAfter);

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
        int Rows(string text) => Regex.Count(text, @"^\s*0x[0-9A-F]+\s+\S+", RegexOptions.Multiline);
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
    private sealed class FakeProvider(bool available, string id = IdaProvider.ProviderId) : INativeDecompilerProvider
    {
        public int AvailabilityChecks, Opens, Probes, Requests, SingleRequests, ManyRequests;
        public IReadOnlyList<NativeFunctionInfo> Functions { get; set; } = [];
        public bool Complete { get; set; } = true;

        public int Calls => AvailabilityChecks + Opens + Probes + Requests;
        public string Id => id;
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
        public string ProviderId => provider.Id;
        public bool AnalysisComplete => provider.Complete;
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

        public Task<IReadOnlyList<NativeXref>> GetXrefsToAsync(uint rva, CancellationToken cancellationToken = default)
        {
            Interlocked.Increment(ref provider.SingleRequests);
            return Task.FromResult(XrefsTo(rva));
        }

        public Task<IReadOnlyList<IReadOnlyList<NativeXref>>> GetXrefsToManyAsync(IReadOnlyList<uint> rvas, CancellationToken cancellationToken = default)
        {
            Interlocked.Increment(ref provider.ManyRequests);
            return Task.FromResult<IReadOnlyList<IReadOnlyList<NativeXref>>>(rvas.Select(XrefsTo).ToList());
        }

        private IReadOnlyList<NativeXref> XrefsTo(uint rva) =>
            Answer<IReadOnlyList<NativeXref>>(provider.Functions.Count > 1 && rva == provider.Functions[0].StartRva
                ? [new NativeXref(provider.Functions[1].StartRva + 4, rva, NativeXrefKind.Call, provider.Functions[1].StartRva)] : []);

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

    /// <summary>Sets the engine time limit and analysis variables, which every server's options read: runs with nothing in parallel.</summary>
    [Collection(ProcessEnvironmentCollection.Name)]
    public sealed class EngineVariables
    {
        [Fact]
        public void Engine_time_limits_come_from_the_environment()
        {
            Assert.Equal((120, 1200), (new ServerOptions().EngineRequestTimeoutSeconds, new ServerOptions().EngineOpenTimeoutSeconds));
            var saved = (Environment.GetEnvironmentVariable(ServerOptions.EngineRequestTimeoutVariable), Environment.GetEnvironmentVariable(ServerOptions.EngineOpenTimeoutVariable));
            try
            {
                Environment.SetEnvironmentVariable(ServerOptions.EngineRequestTimeoutVariable, "45");
                Environment.SetEnvironmentVariable(ServerOptions.EngineOpenTimeoutVariable, "3600");
                var o = ServerOptions.Parse([]);
                Assert.Equal((45, 3600), (o.EngineRequestTimeoutSeconds, o.EngineOpenTimeoutSeconds));
                using var engines = new NativeEngineService(new FakeProvider(available: true), null, options: o);
                Assert.Equal((TimeSpan.FromSeconds(45), TimeSpan.FromSeconds(3600)), (engines.RequestTimeout, engines.OpenTimeout));
                Assert.Equal(EngineAnalysis.Full, o.EngineAnalysis);
                Environment.SetEnvironmentVariable(ServerOptions.EngineAnalysisVariable, "None");
                Assert.Equal(EngineAnalysis.None, ServerOptions.Parse([]).EngineAnalysis);
            }
            finally
            {
                Environment.SetEnvironmentVariable(ServerOptions.EngineAnalysisVariable, null);
                Environment.SetEnvironmentVariable(ServerOptions.EngineRequestTimeoutVariable, saved.Item1);
                Environment.SetEnvironmentVariable(ServerOptions.EngineOpenTimeoutVariable, saved.Item2);
            }
        }
    }
}
