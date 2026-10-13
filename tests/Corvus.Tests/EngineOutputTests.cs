using Corvus.Core;
using Corvus.Mcp;
using Corvus.Native.Providers.Ida;
using Corvus.Services;
using Corvus.Tools;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>
/// Engine output across server processes: the same call answers byte for byte the same in both parts whether the
/// engine analyzed the image in this process or loaded the saved analysis (open times, saved-analysis state and push
/// banners are in _meta only).
/// </summary>
public sealed class EngineOutputTests(ITestOutputHelper output) : IDisposable
{
    private const string Function = "CheckSumMappedFile";
    private static string Image => NativeIdaProviderTests.System64;

    private readonly TempDir _dir = new();
    private readonly List<IDisposable> _owned = [];

    public void Dispose()
    {
        foreach (var d in _owned) d.Dispose();
        _dir.Dispose();
    }

    private sealed record Rig(AssemblyWorkspace Workspace, NativeCodeService Code, NativeAnalysisTools Analysis, NativeEngineService Engines);

    /// <summary>One server process: its own workspace and engine sessions over a shared analysis cache and annotation store.</summary>
    private Rig Server()
    {
        var options = new ServerOptions { TimeoutSeconds = 300, BackgroundIndexing = false };
        var workspace = new AssemblyWorkspace(options);
        var code = new NativeCodeService(workspace, options, null, new Native.Annotations.AnnotationStore(_dir.File("annotations")));
        var engines = new NativeEngineService(new IdaProviderOptions { CacheRoot = _dir.File("cache") }, code, workspace, options);
        _owned.Add(engines);
        _owned.Add(workspace);
        var pager = new OutputPager(options);
        var names = new NativeNamePush(code);
        return new Rig(workspace, code, new NativeAnalysisTools(workspace, engines, pager, names, code, new NativeTypePush(), new NativeUserTypePush(code)), engines);
    }

    private static async Task<(string Text, string Record, OutputCall Call)> Decompile(Rig rig, string image)
    {
        var (text, call) = await EngineMeta.Run(() => rig.Analysis.DecompileNative(image, Function));
        return (text, ToolOutput.Serialize(call.Record!)!.ToJsonString(), call);
    }

    [Trait("Speed", "Slow")]
    [IdaFact]
    public async Task Decompile_is_byte_identical_in_a_second_process()
    {
        var first = Server();
        var a = await Decompile(first, Image);
        output.WriteLine(a.Text);
        Assert.False((bool)first.Engines.ImageSessions(first.Workspace.Read(() => first.Workspace.Natives[0]))[0].Session!.ReusedDatabase);
        foreach (var d in _owned) d.Dispose();
        _owned.Clear();

        var second = Server();
        var b = await Decompile(second, Image);
        Assert.True(second.Engines.ImageSessions(second.Workspace.Read(() => second.Workspace.Natives[0]))[0].Session!.ReusedDatabase);
        Assert.Equal(a.Text, b.Text);
        Assert.Equal(a.Record, b.Record);
        Assert.DoesNotContain("\r", a.Text);
        Assert.DoesNotContain("analyzed in", a.Text);
        // the details that differ are in _meta
        Assert.Equal(false, a.Call.EngineMeta["savedAnalysis"]);
        Assert.Equal(true, b.Call.EngineMeta["savedAnalysis"]);
        Assert.Equal("complete", b.Call.EngineMeta["analysis"]);
        Assert.NotNull(b.Call.EngineMeta["engineBuild"]);
    }
}
