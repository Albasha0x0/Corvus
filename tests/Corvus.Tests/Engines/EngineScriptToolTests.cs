using Corvus.Core;
using Corvus.Native.Providers;
using Corvus.Services;
using Corvus.Tools;

namespace Corvus.Tests;

/// <summary>ida_python arguments without IDA: code or scriptPath, output limit, missing file (NativeIdaTypeTests runs scripts in IDA).</summary>
public sealed class EngineScriptToolTests : IDisposable
{
    private readonly TempDir _dir = new();
    private readonly List<IDisposable> _owned = [];

    public void Dispose()
    {
        foreach (var d in _owned) d.Dispose();
        _dir.Dispose();
    }

    [Fact]
    public async Task Arguments_are_checked_before_any_engine_starts()
    {
        using var dir = new TempDir();
        var options = new ServerOptions { IdaScripting = true };
        using var workspace = new AssemblyWorkspace(options);
        using var engines = new NativeEngineService();
        var tools = new EngineScriptTools(workspace, engines, options);
        Task<string> Run(string? code = null, string? file = null) => tools.IdaPython("x.dll", code, scriptPath: file);
        Assert.Equal("Pass code or scriptPath.", (await Assert.ThrowsAsync<ToolError>(() => Run())).Message);
        Assert.Equal("Pass code or scriptPath, not both.", (await Assert.ThrowsAsync<ToolError>(() => Run("1", "a.py"))).Message);
        Assert.Equal(ErrorCode.NotFound, (await Assert.ThrowsAsync<ToolError>(() => Run(file: dir.File("missing.py")))).Code);
        var off = new EngineScriptTools(workspace, engines, new ServerOptions());
        Assert.Equal(ErrorCode.Unsupported, (await Assert.ThrowsAsync<ToolError>(() => off.IdaPython("x.dll", "1"))).Code);
    }

    private (EngineScriptTools Tools, ScriptedEngine Engine, AssemblyWorkspace Workspace, NativeEngineService Engines, LoadedNative Native) Setup()
    {
        var options = new ServerOptions { IdaScripting = true, BackgroundIndexing = false };
        var workspace = new AssemblyWorkspace(options);
        var engine = new ScriptedEngine();
        var engines = new NativeEngineService([engine], _dir.File("cache"), null, workspace, options);
        _owned.Add(engines);
        _owned.Add(workspace);
        var native = workspace.LoadAny(McpProtocolTests.NativeSample(_dir)).Native!;
        return (new EngineScriptTools(workspace, engines, options), engine, workspace, engines, native);
    }

    [Fact]
    public async Task A_script_longer_than_the_default_limit_succeeds_with_timeoutSeconds()
    {
        var (tools, engine, _, _, native) = Setup();
        engine.ScriptSeconds = 150;
        var timedOut = await Assert.ThrowsAsync<ToolError>(() => tools.IdaPython(native.Id, "1"));
        Assert.Equal(ErrorCode.Timeout, timedOut.Code);
        Assert.Contains("timeoutSeconds=", timedOut.Remediation);
        Assert.Contains("background=true", timedOut.Remediation);
        Assert.Contains("Result: 1", await tools.IdaPython(native.Id, "1", timeoutSeconds: 300));
        Assert.Equal(TimeSpan.FromSeconds(300), engine.ScriptLimits[^1]);
        Assert.Null(EngineRequestLimit.Current);
    }

    [Fact]
    public async Task A_timeout_below_one_second_is_refused_with_the_next_call()
    {
        var (tools, _, _, _, native) = Setup();
        var e = await Assert.ThrowsAsync<ToolError>(() => tools.IdaPython(native.Id, "1", timeoutSeconds: 0));
        Assert.Equal(ErrorCode.InvalidArgument, e.Code);
        Assert.Contains("timeoutSeconds=600", e.Remediation);
    }

    [Fact]
    public async Task A_background_script_returns_at_once_and_its_notice_names_the_outcome()
    {
        var (tools, engine, workspace, engines, native) = Setup();
        engine.ScriptGate = new TaskCompletionSource();
        var started = await tools.IdaPython(native.Id, "1", background: true);
        Assert.Contains($"get_engine_status image={native.Id} waitSeconds=60", started);
        Assert.Contains("no time limit", started);
        var jobs = ((IBackgroundJobs)engines.OpenSession(native)!).Jobs;
        Assert.True(jobs.Running);
        Assert.Contains("already running", await tools.IdaPython(native.Id, "1", background: true));
        // The job reaches the engine on its own thread (macOS CI on c63cc50e).
        for (var i = 0; i < 1000 && engine.ScriptLimits.Count == 0; i++) await Task.Delay(10);
        Assert.Single(engine.ScriptLimits);
        engine.ScriptGate.SetResult();
        await jobs.Job!.Task.WaitAsync(TimeSpan.FromSeconds(10));
        var notices = new List<string>();
        for (var i = 0; i < 200 && notices.Count == 0; i++)
        {
            await Task.Delay(10);
            notices.AddRange(workspace.DrainNotices());
        }
        var notice = Assert.Single(notices);
        Assert.Contains("complete", notice);
        Assert.Contains($"next: get_engine_status image={native.Id} shows the output", notice);
        Assert.Equal("complete", jobs.Kind);
        Assert.Contains("Result: 1", jobs.Result);
        Assert.Equal(Timeout.InfiniteTimeSpan, engine.ScriptLimits[0]);
    }

    [Fact]
    public async Task A_background_script_that_raises_ends_failed_and_names_the_traceback()
    {
        var (tools, engine, workspace, engines, native) = Setup();
        engine.ScriptResult = new NativeScriptResult(null, "", "", "NameError: x");
        await tools.IdaPython(native.Id, "x", background: true);
        var jobs = ((IBackgroundJobs)engines.OpenSession(native)!).Jobs;
        await jobs.Job!.Task.WaitAsync(TimeSpan.FromSeconds(10));
        var notices = new List<string>();
        for (var i = 0; i < 200 && notices.Count == 0; i++)
        {
            await Task.Delay(10);
            notices.AddRange(workspace.DrainNotices());
        }
        Assert.Equal("failed", jobs.Kind);
        Assert.Contains("shows the error", Assert.Single(notices));
    }

    [Fact]
    public async Task A_foreground_script_during_a_running_one_is_a_conflict_naming_background()
    {
        var (tools, engine, _, engines, native) = Setup();
        engine.ScriptGate = new TaskCompletionSource();
        await tools.IdaPython(native.Id, "1", background: true);
        var e = await Assert.ThrowsAsync<ToolError>(() => tools.IdaPython(native.Id, "2"));
        Assert.Equal(ErrorCode.Conflict, e.Code);
        Assert.Contains("background=true", e.Remediation);
        Assert.Contains("not started", await tools.IdaPython(native.Id, "2", background: true));
        engine.ScriptGate.SetResult();
        await ((IBackgroundJobs)engines.OpenSession(native)!).Jobs.Job!.Task.WaitAsync(TimeSpan.FromSeconds(10));
    }

    [Fact]
    public async Task Allowing_an_error_with_background_is_refused()
    {
        var (tools, _, _, _, native) = Setup();
        var e = await Assert.ThrowsAsync<ToolError>(() => tools.IdaPython(native.Id, "1", allowError: true, background: true));
        Assert.Equal(ErrorCode.InvalidArgument, e.Code);
        Assert.Contains("omit allowError", e.Remediation);
    }

    [Fact]
    public async Task A_background_script_past_its_limit_ends_partial_and_names_a_larger_limit()
    {
        var (tools, engine, workspace, engines, native) = Setup();
        engine.ScriptSeconds = 150;
        await tools.IdaPython(native.Id, "1", timeoutSeconds: 100, background: true);
        var jobs = ((IBackgroundJobs)engines.OpenSession(native)!).Jobs;
        await jobs.Job!.Task.WaitAsync(TimeSpan.FromSeconds(10));
        var notices = new List<string>();
        for (var i = 0; i < 200 && notices.Count == 0; i++)
        {
            await Task.Delay(10);
            notices.AddRange(workspace.DrainNotices());
        }
        Assert.Equal("partial", jobs.Kind);
        Assert.Contains("larger timeoutSeconds", Assert.Single(notices));
    }

    [Fact]
    public async Task A_ghidra_script_takes_a_limit_past_an_hour()
    {
        var options = new ServerOptions { GhidraScripting = true, BackgroundIndexing = false };
        var workspace = new AssemblyWorkspace(options);
        var engine = new ScriptedEngine { Id = "ghidra" };
        var engines = new NativeEngineService([engine], _dir.File("cache"), null, workspace, options);
        _owned.Add(engines);
        _owned.Add(workspace);
        var native = workspace.LoadAny(McpProtocolTests.NativeSample(_dir)).Native!;
        var tools = new EngineScriptTools(workspace, engines, options);
        Assert.Contains("Result: 1", await tools.GhidraScript(native.Id, "int x;", timeoutSeconds: 7200));
        var e = await Assert.ThrowsAsync<ToolError>(() => tools.GhidraScript(native.Id, "int x;", timeoutSeconds: 0));
        Assert.Equal(ErrorCode.InvalidArgument, e.Code);
    }
}
