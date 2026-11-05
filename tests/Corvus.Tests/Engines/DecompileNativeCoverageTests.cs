using Corvus.Core;

namespace Corvus.Tests;

/// <summary>decompile_native labels its coverage from the engine's analysis state.</summary>
public sealed class DecompileNativeCoverageTests : IDisposable
{
    private readonly DecompileBatchTests _rig = new();

    public void Dispose() => _rig.Dispose();

    [Fact]
    public async Task A_partial_analysis_makes_the_coverage_partial_with_the_reason()
    {
        var (tools, provider, native, _, _) = await _rig.Setup();
        provider.Complete = false;
        var call = OutputCall.Begin(new OutputCall("decompile_native", 0, null));
        await tools.DecompileNative(native.Id, address: "First");
        OutputCall.Begin(null!);

        var (status, reason, _) = call.Coverage!.Value;
        Assert.Equal("partial", status);
        Assert.Contains("analysis is partial", reason);
    }

    [Fact]
    public async Task A_complete_analysis_sets_no_coverage_label()
    {
        var (tools, _, native, _, _) = await _rig.Setup();
        var call = OutputCall.Begin(new OutputCall("decompile_native", 0, null));
        await tools.DecompileNative(native.Id, address: "First");
        OutputCall.Begin(null!);

        Assert.Null(call.Coverage);
    }
}
