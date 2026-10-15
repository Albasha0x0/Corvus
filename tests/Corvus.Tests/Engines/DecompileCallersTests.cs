using Corvus.Core;
using Corvus.Native;
using Corvus.Native.Providers;
using Corvus.Services;
using Corvus.Tools;

namespace Corvus.Tests;

/// <summary>decompile_native callersOf: the engine's callers of a function go through the batch path.</summary>
public sealed class DecompileCallersTests : IDisposable
{
    private readonly TempDir _dir = new();
    private readonly List<IDisposable> _owned = [];

    public void Dispose()
    {
        foreach (var d in _owned) d.Dispose();
        _dir.Dispose();
    }

    private (NativeAnalysisTools Tools, ScriptedEngine Engine, LoadedNative Native) Setup()
    {
        var options = new ServerOptions { BackgroundIndexing = false };
        var workspace = new AssemblyWorkspace(options);
        var engine = new ScriptedEngine();
        engine.Add(0x1000, "target", "int target(void)", "{ return 1; }");
        engine.Add(0x1040, "second_caller", "int second_caller(void)", "{ return target(); }");
        engine.Add(0x1020, "first_caller", "int first_caller(void)", "{ return target() + target(); }");
        engine.Add(0x1060, "reader", "int reader(void)", "{ return *(int *)target; }");
        engine.Xrefs.AddRange([
            new NativeXref(0x1044, 0x1000, NativeXrefKind.Call, 0x1040),
            new NativeXref(0x1024, 0x1000, NativeXrefKind.Call, 0x1020),
            new NativeXref(0x1028, 0x1000, NativeXrefKind.Call, 0x1020),
            new NativeXref(0x1064, 0x1000, NativeXrefKind.Read, 0x1060),
            new NativeXref(0x1008, 0x1000, NativeXrefKind.Jump, 0x1000),
        ]);
        var engines = new NativeEngineService([engine], _dir.File("cache"), null, workspace, options);
        _owned.Add(engines);
        _owned.Add(workspace);
        var native = workspace.LoadAny(McpProtocolTests.NativeSample(_dir)).Native!;
        return (new NativeAnalysisTools(workspace, engines, new OutputPager(options)), engine, native);
    }

    [Fact]
    public async Task Callers_are_decompiled_once_each_in_address_order()
    {
        var (tools, engine, native) = Setup();
        var text = await tools.DecompileNative(native.Id, callersOf: "rva:0x1004");
        Assert.Contains("// 2 inputs: 2 decompiled, 0 failed, 0 not reached, 0 duplicate", text);
        Assert.True(text.IndexOf("first_caller", StringComparison.Ordinal) < text.IndexOf("second_caller", StringComparison.Ordinal));
        Assert.Contains("return target() + target();", text);
        Assert.DoesNotContain("reader", text); // a data reference is not a call
        Assert.Equal([2], engine.Batches);
        // a caller's input is its start VA: the row and its header name it once
        Assert.DoesNotContain("(input \"", text);
        var report = await NativeQuerySurfaceTests.Structured<NativeAnalysisTools.DecompileReport>(() => tools.DecompileNative(native.Id, callersOf: "rva:0x1004"));
        Assert.All(report.Items, i => Assert.Equal((null, null), (i.Address, i.Function)));
    }

    [Fact]
    public async Task No_callers_and_mixed_arguments_are_errors()
    {
        var (tools, _, native) = Setup();
        var none = await Assert.ThrowsAsync<ToolError>(() => tools.DecompileNative(native.Id, callersOf: "rva:0x1060"));
        Assert.Equal(ErrorCode.NotFound, none.Code);
        Assert.Contains("find_xrefs", none.Remediation);
        var both = await Assert.ThrowsAsync<ToolError>(() => tools.DecompileNative(native.Id, "rva:0x1000", callersOf: "rva:0x1000"));
        Assert.Equal(ErrorCode.InvalidArgument, both.Code);
    }
}
