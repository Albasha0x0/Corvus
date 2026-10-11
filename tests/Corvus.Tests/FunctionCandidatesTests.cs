using Corvus.Core;
using Corvus.Mcp;
using Corvus.Native.Providers;
using Corvus.Services;
using Corvus.Tools;

namespace Corvus.Tests;

/// <summary>list_functions view=candidates: the engine's code outside functions, ranked by references, paged, with the define_native step.</summary>
public sealed class FunctionCandidatesTests : IDisposable
{
    private readonly TempDir _dir = new();
    private readonly List<IDisposable> _owned = [];

    public void Dispose()
    {
        foreach (var d in _owned) d.Dispose();
        _dir.Dispose();
    }

    private (NativeCodeTools Tools, string Image) Setup()
    {
        var options = new ServerOptions { BackgroundIndexing = false };
        var workspace = new AssemblyWorkspace(options);
        var code = new NativeCodeService(workspace, options, null, new Native.Annotations.AnnotationStore(_dir.File("annotations")));
        var engine = new ScriptedEngine();
        engine.Candidates.AddRange([new(0x1100, 0x1108, 3, 0, 1, 0), new(0x1200, 0x1220, 9, 2, 0, 1), new(0x1300, 0x1304, 1, 0, 0, 0), new(0x1400, 0x1410, 5, 2, 1, 1)]);
        var engines = new NativeEngineService([engine], _dir.File("cache"), code, workspace, options);
        _owned.Add(engines);
        _owned.Add(workspace);
        var image = workspace.LoadAny(McpProtocolTests.NativeSample(_dir)).Native!.Id;
        return (new NativeCodeTools(workspace, code, new OutputPager(options), null, engines), image);
    }

    [Fact]
    public async Task Candidates_are_ranked_by_calls_then_other_references_and_paged()
    {
        var (tools, image) = Setup();
        var collector = StructuredOutput.Begin();
        var text = await tools.ListFunctions(image, view: "candidates", limit: 3);
        var list = Assert.IsType<FunctionList>(collector.Value);
        Assert.Contains("4 runs of code in no function (ida;", text);
        Assert.Equal(["0x140001400", "0x140001200", "0x140001100"], list.Items.Select(i => i.Address));
        Assert.Equal((4, true, 16, 4), (list.Total, list.Truncated, list.Items[0].Size, list.Items[0].References));
        Assert.Contains("0x140001400       16  5 instructions; refs to start: 2 call, 1 jump, 1 data", text);
        Assert.Contains("[More: call again with offset=3]", text);
        Assert.Contains($"Next: define_native image={image} address=0x140001400 kind=function", text);
    }

    [Fact]
    public async Task The_built_in_index_and_unknown_views_are_rejected()
    {
        var (tools, image) = Setup();
        Assert.Equal(ErrorCode.InvalidArgument, (await Assert.ThrowsAsync<ToolError>(() => tools.ListFunctions(image, view: "candidates", engine: "ours"))).Code);
        Assert.Equal(ErrorCode.InvalidArgument, (await Assert.ThrowsAsync<ToolError>(() => tools.ListFunctions(image, view: "orphans"))).Code);
    }
}
