using Corvus.Core;
using Corvus.Native;
using Corvus.Native.Annotations;
using Corvus.Native.Providers;
using Corvus.Services;
using Corvus.Tools;

namespace Corvus.Tests;

/// <summary>list_native_types ends its engine waits at the request limit and leaves the open running.</summary>
public sealed class NativeTypeWaitTests : IDisposable
{
    private readonly TempDir _dir = new();
    private readonly List<IDisposable> _owned = [];

    public void Dispose()
    {
        foreach (var d in _owned) d.Dispose();
        _dir.Dispose();
    }

    private (NativeTypeTools Tools, ScriptedEngine Engine, string Id) Setup(string label = "a")
    {
        // The request limit is one second, the shortest the options carry.
        var options = new ServerOptions { BackgroundIndexing = false, EngineRequestTimeoutSeconds = 1 };
        var workspace = new AssemblyWorkspace(options);
        var engine = new ScriptedEngine();
        engine.Types.Add(new NativeTypeEntry("Header", "struct", 8, 2));
        var engines = new NativeEngineService([engine], _dir.File("cache-" + label), null, workspace, options);
        var code = new NativeCodeService(workspace, options, annotations: new AnnotationStore(_dir.File("ann-" + label)));
        _owned.Add(engines);
        _owned.Add(workspace);
        var native = workspace.LoadAny(McpProtocolTests.NativeSample(_dir)).Native!;
        return (new NativeTypeTools(workspace, engines, new NativeUserTypePush(code), code), engine, native.Id);
    }

    [Fact]
    public async Task A_delayed_open_times_out_with_its_stage_and_the_next_call_lists_types()
    {
        var (tools, engine, id) = Setup();
        var gate = new TaskCompletionSource();
        engine.OpenStages.Add(("analysis", 0));
        engine.StageGates["analysis"] = gate;

        var first = await Assert.ThrowsAsync<ToolError>(() => tools.ListNativeTypes(id));
        Assert.Equal(ErrorCode.Timeout, first.Code);
        Assert.Contains("analysis", first.Message);
        Assert.NotNull(first.RetryAfter);
        gate.SetResult();
        var second = await tools.ListNativeTypes(id);
        Assert.Contains("Header", second);
        Assert.Equal(1, engine.Opens);
    }

    [Fact]
    public async Task A_type_listing_that_stalls_after_the_open_times_out_and_a_retry_succeeds()
    {
        var (tools, engine, id) = Setup();
        engine.TypeGate = new TaskCompletionSource();

        var first = await Assert.ThrowsAsync<ToolError>(() => tools.ListNativeTypes(id));
        Assert.Equal(ErrorCode.Timeout, first.Code);
        Assert.Contains("did not finish", first.Message);
        engine.TypeGate.SetResult();
        Assert.Contains("Header", await tools.ListNativeTypes(id));
        Assert.Equal(1, engine.Opens);
    }

    [Fact]
    public async Task A_caller_cancel_surfaces_as_a_cancellation_not_a_timeout()
    {
        var (tools, engine, id) = Setup();
        engine.TypeGate = new TaskCompletionSource();
        using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(100));

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => tools.ListNativeTypes(id, cancellationToken: cts.Token));
    }

    [Fact]
    public async Task A_failed_open_reports_its_error_not_a_timeout()
    {
        var (tools, engine, id) = Setup();
        engine.OpenFailure = new ToolError(ErrorCode.Failed, "scripted open failure");

        var error = await Assert.ThrowsAsync<ToolError>(() => tools.ListNativeTypes(id));
        Assert.NotEqual(ErrorCode.Timeout, error.Code);
    }

    [Fact]
    public async Task A_timed_out_call_leaves_another_image_listing_types()
    {
        var (stalled, engineA, idA) = Setup("a");
        var (other, _, idB) = Setup("b");
        engineA.TypeGate = new TaskCompletionSource();

        await Assert.ThrowsAsync<ToolError>(() => stalled.ListNativeTypes(idA));
        Assert.Contains("Header", await other.ListNativeTypes(idB));
    }
}
