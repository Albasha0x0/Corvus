using Corvus.Core;
using Corvus.Native.Providers;
using Corvus.Services;
using Corvus.Tools;

namespace Corvus.Tests;

/// <summary>engine=auto keeps one engine per image: the one already opening or open on it.</summary>
public sealed class AutoEngineChoiceTests : IDisposable
{
    private readonly TempDir _dir = new();
    private readonly List<IDisposable> _owned = [];

    public void Dispose()
    {
        foreach (var d in _owned) d.Dispose();
        _dir.Dispose();
    }

    [Fact]
    public async Task Auto_keeps_the_engine_open_on_a_partial_analysis_though_another_engine_saved_one()
    {
        var options = new ServerOptions { BackgroundIndexing = false };
        var workspace = new AssemblyWorkspace(options);
        _owned.Add(workspace);
        var native = workspace.LoadAny(McpProtocolTests.NativeSample(_dir)).Native!;
        var root = _dir.File("cache");
        var cache = new AnalysisCache(root);
        // A project another engine saved earlier.
        using (var entry = cache.Acquire("ghidra", native.FilePath, native.OriginalSha256))
        {
            var project = Path.Combine(entry.Directory, "p-earlier");
            Directory.CreateDirectory(project);
            File.WriteAllText(Path.Combine(project, "corvus.gpr"), "");
        }
        var ida = new ScriptedEngine { PartialAnalysis = true, Cache = cache };
        ida.OpenStages.AddRange([("start", 0), ("analysis", 0), ("ready", 0)]);
        var ghidra = new ScriptedEngine { Id = "ghidra", Cache = cache };
        var engines = new NativeEngineService([ida, ghidra], root, null, workspace, options);
        _owned.Add(engines);

        await engines.Session(native, "ida", null, default);

        Assert.Null(engines.AnalyzedBy(native));
        Assert.Equal("ida", EngineChoice.EngineOnly(null, engines, native).Engine);
        Assert.Equal("ida", engines.Resolve(native, null));
        Assert.Equal(0, ghidra.Opens);
    }

    [Fact]
    public async Task Auto_keeps_the_engine_still_opening_on_the_image()
    {
        var options = new ServerOptions { BackgroundIndexing = false };
        var workspace = new AssemblyWorkspace(options);
        _owned.Add(workspace);
        var native = workspace.LoadAny(McpProtocolTests.NativeSample(_dir)).Native!;
        var ida = new ScriptedEngine();
        ida.OpenStages.AddRange([("start", 0), ("analysis", 0), ("ready", 0)]);
        var gate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        ida.StageGates["analysis"] = gate;
        var ghidra = new ScriptedEngine { Id = "ghidra" };
        var engines = new NativeEngineService([ghidra, ida], _dir.File("cache"), null, workspace, options) { EstimateAfter = TimeSpan.FromMilliseconds(50) };
        _owned.Add(engines);

        await Assert.ThrowsAsync<ToolError>(() => engines.Session(native, "ida", null, default));
        try
        {
            Assert.Null(engines.AnalyzedBy(native));
            Assert.Equal("ida", engines.Resolve(native, null));
        }
        finally { gate.SetResult(); }
        Assert.Equal(0, ghidra.Opens);
    }

    [Fact]
    public async Task Prewarm_on_auto_opens_the_engine_that_analyzed_the_image_not_the_first_installed()
    {
        var options = new ServerOptions { BackgroundIndexing = false };
        var workspace = new AssemblyWorkspace(options);
        _owned.Add(workspace);
        var native = workspace.LoadAny(McpProtocolTests.NativeSample(_dir)).Native!;
        var root = _dir.File("cache");
        var cache = new AnalysisCache(root);
        // A project the second engine saved earlier.
        using (var entry = cache.Acquire("ghidra", native.FilePath, native.OriginalSha256))
        {
            var project = Path.Combine(entry.Directory, "p-earlier");
            Directory.CreateDirectory(project);
            File.WriteAllText(Path.Combine(project, "corvus.gpr"), "");
        }
        var ida = new ScriptedEngine { Cache = cache };
        var ghidra = new ScriptedEngine { Id = "ghidra", Cache = cache };
        ghidra.OpenStages.AddRange([("start", 0), ("ready", 0)]);
        var engines = new NativeEngineService([ida, ghidra], root, null, workspace, options);
        _owned.Add(engines);

        await engines.Prewarm(native);

        Assert.Equal((0, 1), (ida.Opens, ghidra.Opens));
    }
}
