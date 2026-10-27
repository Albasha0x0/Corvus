using System.Diagnostics;
using Corvus.Core;
using Corvus.Native.Providers;
using Corvus.Native.Providers.Ghidra;
using Corvus.Native.Providers.Ida;
using Corvus.Services;
using Corvus.Tools;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>One rig per engine: the tests only read, so they share the workspace, sample and open session.</summary>
public sealed class EngineWorkflowRigs : IDisposable
{
    private readonly TempDir _dir = new();
    private readonly List<IDisposable> _owned = [];
    private readonly Dictionary<string, NativeEngineWorkflowTests.Rig> _rigs = [];

    /// <summary>The rig of <paramref name="engine"/>, made on first use.</summary>
    public NativeEngineWorkflowTests.Rig For(string engine)
    {
        if (!_rigs.TryGetValue(engine, out var rig)) _rigs[engine] = rig = Setup(_dir.File(engine));
        return rig;
    }

    public void Dispose()
    {
        foreach (var d in _owned) d.Dispose();
        _dir.Dispose();
    }

    private NativeEngineWorkflowTests.Rig Setup(string root)
    {
        var options = new ServerOptions { TimeoutSeconds = 600, BackgroundIndexing = false };
        var workspace = new AssemblyWorkspace(options);
        var code = new NativeCodeService(workspace, options, null, new Native.Annotations.AnnotationStore(Path.Combine(root, "annotations")));
        var cache = Path.Combine(root, "cache");
        EngineSeed.Copy(cache, NativeIdaProviderTests.System64);
        var engines = new NativeEngineService(new IdaProviderOptions { CacheRoot = cache }, code, workspace, options, new GhidraProviderOptions { CacheRoot = cache });
        _owned.Add(engines);
        _owned.Add(workspace);
        var pager = new OutputPager(options);
        var names = new NativeNamePush(code);
        var dir = Directory.CreateDirectory(Path.Combine(root, "input")).FullName;
        var sample = Path.Combine(dir, Path.GetFileName(NativeIdaProviderTests.System64));
        File.Copy(NativeIdaProviderTests.System64, sample);
        return new(workspace, code, new NativeCodeTools(workspace, code, pager, null, engines, names), new NativeAnalysisTools(workspace, engines, pager, names, code), engines, sample);
    }
}

/// <summary>The introspection workflows through a real IDA and a real Ghidra: batch decompilation, the dossier's pseudocode.</summary>
[Trait("Speed", "Slow")]
public sealed class NativeEngineWorkflowTests(ITestOutputHelper output, EngineWorkflowRigs rigs) : IClassFixture<EngineWorkflowRigs>
{
    public sealed record Rig(AssemblyWorkspace Workspace, NativeCodeService Code, NativeCodeTools Tools, NativeAnalysisTools Analysis, NativeEngineService Engines, string Sample);

    private async Task BatchDecompiles(string engine)
    {
        var rig = rigs.For(engine);
        var path = rig.Sample;
        var clock = Stopwatch.StartNew();
        var text = await rig.Analysis.DecompileNative(path, functions: ["CheckSumMappedFile", "MapFileAndCheckSumW", "no_such_function", "CheckSumMappedFile"], engine: engine);
        output.WriteLine($"{engine}: batch of 4 in {clock.Elapsed.TotalSeconds:0.0} s (includes the analysis)\n{string.Join('\n', text.Split('\n').Where(l => l.StartsWith("// ", StringComparison.Ordinal)))}");
        Assert.Contains($"// 4 inputs: 2 decompiled, 1 failed, 0 not reached, 1 duplicate ({engine})", text);
        Assert.Contains("(input \"no_such_function\"): error not_found", text);
        Assert.Contains("(input \"CheckSumMappedFile\"): the same function as [1]", text);
        Assert.Contains("MapFileAndCheckSumW(", text);

        // The texts are cached: a single call answers without a worker request.
        var native = rig.Workspace.Read(() => rig.Workspace.Natives[0]);
        var worker = ((WorkerSessionBase)rig.Engines.OpenSession(native, engine)!).Worker!;
        long requests = worker.Requests;
        clock.Restart();
        Assert.Contains("CheckSumMappedFile", await rig.Analysis.DecompileNative(native.Id, "CheckSumMappedFile", engine: engine));
        var single = clock.Elapsed;
        Assert.Equal(requests, worker.Requests);
        PerfBudget.Time($"engines/cached-single-decompile/{engine}", single, TimeSpan.FromSeconds(2), output);
    }

    private async Task DossierPseudocode(string engine)
    {
        var rig = rigs.For(engine);
        var path = rig.Sample;
        var tools = new NativeFunctionTools(rig.Workspace, rig.Code, new OutputPager(new ServerOptions()), null, rig.Engines, new NativeNamePush(rig.Code));
        var text = await tools.AnalyzeNativeFunction(path, "CheckSumMappedFile", sections: "identity,callees", pseudocode: true, engine: engine);
        output.WriteLine(string.Join('\n', text.Split('\n').Take(30)));
        Assert.Contains("== pseudocode (", text);
        Assert.Contains($"// {engine}", text);
        Assert.Contains("CheckSumMappedFile(", text);
        Assert.Contains("== callees (", text);
    }

    private async Task TraceThrough(string engine)
    {
        var rig = rigs.For(engine);
        var path = rig.Sample;
        var trace = new NativeTraceTools(rig.Workspace, rig.Code, rig.Engines, new NativeNamePush(rig.Code));
        var text = await trace.TraceNativeValues(path, "MapFileAndCheckSumW", argument: "1", direction: "forward", maxDepth: 1, engine: engine);
        output.WriteLine(string.Join('\n', text.Split('\n').Take(25)));
        Assert.StartsWith($"Engine: {engine} (engine={engine}: ", text);
        Assert.Contains($"engine {engine}", text);
        Assert.Matches($@"Note: {engine} answered [1-9]\d* slices?; ", text);
        Assert.Contains("argument", text);
    }

    [IdaFact]
    public Task Trace_through_IDA_microcode() => TraceThrough("ida");

    [GhidraFact]
    public Task Trace_through_Ghidra_pcode() => TraceThrough("ghidra");

    [IdaFact]
    [Trait(PerfBudget.Trait, PerfBudget.Timing)]
    public Task Batch_decompile_through_IDA() => BatchDecompiles("ida");

    [IdaFact]
    public Task Dossier_pseudocode_through_IDA() => DossierPseudocode("ida");

    [GhidraFact]
    public Task Dossier_pseudocode_through_Ghidra() => DossierPseudocode("ghidra");

    [GhidraFact]
    [Trait(PerfBudget.Trait, PerfBudget.Timing)]
    public Task Batch_decompile_through_Ghidra() => BatchDecompiles("ghidra");
}
