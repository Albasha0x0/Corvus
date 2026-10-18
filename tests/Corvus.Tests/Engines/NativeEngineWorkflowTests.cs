using System.Diagnostics;
using Corvus.Core;
using Corvus.Native.Providers.Ghidra;
using Corvus.Native.Providers.Ida;
using Corvus.Services;
using Corvus.Tools;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>The introspection workflows through a real IDA and a real Ghidra: batch decompilation, the dossier's pseudocode.</summary>
[Trait("Speed", "Slow")]
public sealed class NativeEngineWorkflowTests(ITestOutputHelper output) : IDisposable
{
    private readonly TempDir _dir = new();
    private readonly List<IDisposable> _owned = [];

    public void Dispose()
    {
        foreach (var d in _owned) d.Dispose();
        _dir.Dispose();
    }

    private sealed record Rig(AssemblyWorkspace Workspace, NativeCodeService Code, NativeCodeTools Tools, NativeAnalysisTools Analysis, NativeEngineService Engines);

    private Rig Setup()
    {
        var options = new ServerOptions { TimeoutSeconds = 600, BackgroundIndexing = false };
        var workspace = new AssemblyWorkspace(options);
        var code = new NativeCodeService(workspace, options, null, new Native.Annotations.AnnotationStore(_dir.File("annotations")));
        var cache = _dir.File("cache");
        EngineSeed.Copy(cache, NativeIdaProviderTests.System64);
        var engines = new NativeEngineService(new IdaProviderOptions { CacheRoot = cache }, code, workspace, options, new GhidraProviderOptions { CacheRoot = cache });
        _owned.Add(engines);
        _owned.Add(workspace);
        var pager = new OutputPager(options);
        var names = new NativeNamePush(code);
        return new Rig(workspace, code, new NativeCodeTools(workspace, code, pager, null, engines, names), new NativeAnalysisTools(workspace, engines, pager, names, code), engines);
    }

    private string Sample()
    {
        var dir = Directory.CreateDirectory(_dir.File("input")).FullName;
        var copy = Path.Combine(dir, Path.GetFileName(NativeIdaProviderTests.System64));
        if (!File.Exists(copy)) File.Copy(NativeIdaProviderTests.System64, copy);
        return copy;
    }

    private async Task BatchDecompiles(string engine)
    {
        var rig = Setup();
        var path = Sample();
        var clock = Stopwatch.StartNew();
        var text = await rig.Analysis.DecompileNative(path, functions: ["CheckSumMappedFile", "MapFileAndCheckSumW", "no_such_function", "CheckSumMappedFile"], engine: engine);
        output.WriteLine($"{engine}: batch of 4 in {clock.Elapsed.TotalSeconds:0.0} s (includes the analysis)\n{string.Join('\n', text.Split('\n').Where(l => l.StartsWith("// ", StringComparison.Ordinal)))}");
        Assert.Contains($"// 4 inputs: 2 decompiled, 1 failed, 0 not reached, 1 duplicate ({engine})", text);
        Assert.Contains("(input \"no_such_function\"): error not_found", text);
        Assert.Contains("(input \"CheckSumMappedFile\"): the same function as [1]", text);
        Assert.Contains("MapFileAndCheckSumW(", text);

        // the texts are cached: a single call answers without the engine
        var native = rig.Workspace.Read(() => rig.Workspace.Natives[0]);
        clock.Restart();
        Assert.Contains("CheckSumMappedFile", await rig.Analysis.DecompileNative(native.Id, "CheckSumMappedFile", engine: engine));
        Assert.True(clock.Elapsed < TimeSpan.FromSeconds(2), $"cached single call took {clock.Elapsed}");
    }

    private async Task DossierPseudocode(string engine)
    {
        var rig = Setup();
        var path = Sample();
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
        var rig = Setup();
        var path = Sample();
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
    public Task Batch_decompile_through_IDA() => BatchDecompiles("ida");

    [IdaFact]
    public Task Dossier_pseudocode_through_IDA() => DossierPseudocode("ida");

    [GhidraFact]
    public Task Dossier_pseudocode_through_Ghidra() => DossierPseudocode("ghidra");

    [GhidraFact]
    public Task Batch_decompile_through_Ghidra() => BatchDecompiles("ghidra");
}
