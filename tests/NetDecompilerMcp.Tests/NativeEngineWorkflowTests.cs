using System.Diagnostics;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Native.Providers.Ghidra;
using NetDecompilerMcp.Native.Providers.Ida;
using NetDecompilerMcp.Services;
using NetDecompilerMcp.Tools;
using Xunit.Abstractions;

namespace NetDecompilerMcp.Tests;

/// <summary>The introspection workflows through a real IDA and a real Ghidra: batch decompilation.</summary>
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
        Assert.Contains($"// 4 inputs: 2 decompiled, 1 failed, 0 skipped, 1 duplicate ({engine})", text);
        Assert.Contains("(input \"no_such_function\"): error not_found", text);
        Assert.Contains("(input \"CheckSumMappedFile\"): the same function as [1]", text);
        Assert.Contains("MapFileAndCheckSumW(", text);

        // the texts are cached: a single call answers without the engine
        var native = rig.Workspace.Read(() => rig.Workspace.Natives[0]);
        clock.Restart();
        Assert.Contains("CheckSumMappedFile", await rig.Analysis.DecompileNative(native.Id, "CheckSumMappedFile", engine: engine));
        Assert.True(clock.Elapsed < TimeSpan.FromSeconds(2), $"cached single call took {clock.Elapsed}");
    }

    [IdaFact]
    public Task Batch_decompile_through_IDA() => BatchDecompiles("ida");

    [GhidraFact]
    public Task Batch_decompile_through_Ghidra() => BatchDecompiles("ghidra");
}
