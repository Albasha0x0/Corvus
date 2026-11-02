using System.Text.Json;
using Corvus.Core;
using Corvus.Mcp;
using Corvus.Native.Providers;
using Corvus.Services;
using Corvus.Tools;
using Microsoft.Extensions.Time.Testing;

namespace Corvus.Tests;

/// <summary>The open-time stage profile: stage durations from progress reports, the PDB step after, the ready message, get_engine_status.</summary>
public sealed class EngineOpenProfileTests : IDisposable
{
    private readonly TempDir _dir = new();
    private readonly List<IDisposable> _owned = [];

    public void Dispose()
    {
        foreach (var d in _owned) d.Dispose();
        _dir.Dispose();
    }

    [Fact]
    public void A_progress_event_names_its_stage_or_keeps_the_open_stage()
    {
        using var named = JsonDocument.Parse("{\"stage\":\"analysis: code\"}");
        using var empty = JsonDocument.Parse("{\"stage\":\"\"}");
        using var none = JsonDocument.Parse("{\"elapsed\":2}");
        using var nul = JsonDocument.Parse("null");
        Assert.Equal("analysis: code", WorkerSessionBase.EventStage(named.RootElement, "analysis"));
        Assert.Equal("analysis", WorkerSessionBase.EventStage(empty.RootElement, "analysis"));
        Assert.Equal("analysis", WorkerSessionBase.EventStage(none.RootElement, "analysis"));
        Assert.Equal("analysis", WorkerSessionBase.EventStage(nul.RootElement, "analysis"));
        Assert.Equal("analysis", WorkerSessionBase.EventStage(default, "analysis"));
    }

    [Fact]
    public void A_heartbeat_without_a_stage_reports_the_open_stage_with_its_elapsed_time()
    {
        using var named = JsonDocument.Parse("{\"stage\":\"Decompiler Parameter ID\"}");
        using var empty = JsonDocument.Parse("{\"stage\":\"\"}");
        var named_progress = WorkerSessionBase.HeartbeatProgress(named.RootElement, "analysis", TimeSpan.FromSeconds(4));
        var empty_progress = WorkerSessionBase.HeartbeatProgress(empty.RootElement, "analysis", TimeSpan.FromSeconds(6));
        Assert.Equal(("Decompiler Parameter ID", TimeSpan.FromSeconds(4)), (named_progress.Stage, named_progress.Elapsed));
        Assert.Equal(("analysis", TimeSpan.FromSeconds(6)), (empty_progress.Stage, empty_progress.Elapsed));
        using var unnamed = JsonDocument.Parse("{}");
        using var scalar = JsonDocument.Parse("7");
        Assert.Equal("load", WorkerSessionBase.HeartbeatProgress(unnamed.RootElement, "load", TimeSpan.Zero).Stage);
        Assert.Equal("load", WorkerSessionBase.HeartbeatProgress(scalar.RootElement, "load", TimeSpan.Zero).Stage);
    }

    [Fact]
    public void The_ida_worker_shows_a_named_queue_for_open_heartbeats_only()
    {
        var script = Corvus.Setup.ToolCli.WriteIdaScripts(Path.Combine(_dir.Path, "scripts"));
        var code = """
            import sys, types
            sys.path.insert(0, sys.argv[1])
            import ida_worker as w
            class Auto:
                AU_NONE = 0; AU_CODE = 10; AU_PROC = 20
                def __init__(self, s): self.s = s
                def get_auto_state(self):
                    if self.s == "boom": raise RuntimeError("x")
                    return self.s
            assert w.analysis_stage(Auto(10)) == "analysis: code"
            assert w.analysis_stage(Auto(0)) is None
            assert w.analysis_stage(Auto(57)) is None
            assert w.analysis_stage(Auto("boom")) is None
            assert w.analysis_stage(object()) is None
            r = types.SimpleNamespace(id=1, op="open", start=__import__("time").time())
            assert w.heartbeat_event(r, "analysis: code")["stage"] == "analysis: code"
            assert "stage" not in w.heartbeat_event(r, None)
            r.op = "decompile"
            assert "stage" not in w.heartbeat_event(r, "analysis: code")
            for op in ("analyze", "reanalyze_native"):
                r.op = op
                assert w.heartbeat_event(r, "analysis: code")["stage"] == "analysis: code"
            """;
        var file = _dir.File("worker_stage.py");
        File.WriteAllText(file, code);
        var result = Tools.Run("python", $"\"{file}\" \"{Path.GetDirectoryName(script)}\"");
        Assert.True(result.ExitCode == 0, result.Output);
    }

    [Fact]
    public void Stages_last_until_the_next_one_and_ready_ends_the_open()
    {
        var p = new EngineOpenProfile();
        p.Mark("prepare", 0);
        p.Mark("start", 0.5);
        p.Mark("analysis", 3.5);
        p.Mark("analysis", 5); // repeats fold in
        p.Mark("Decompiler Parameter ID", 9);
        Assert.False(p.Finished);
        Assert.Equal(6.5, p.Stages(10)[^1].Seconds, 3); // the running stage is measured to now
        p.Mark("ready", 12);
        p.Mark("load", 20); // a later restart does not change the open's profile
        p.After("pdb types", 1.234);
        Assert.True(p.Finished);
        Assert.Equal("prepare 0.5 s, start 3.0 s, analysis 8.5 s (Decompiler Parameter ID 3.0 s), pdb types 1.2 s", EngineOpenProfile.Describe(p.Stages(99)));
    }

    /// <summary>The engine's exact analyzer times, when it reports them, replace the parts sampled from its messages.</summary>
    [Fact]
    public void Engine_analyzer_times_replace_the_sampled_parts()
    {
        var p = new EngineOpenProfile();
        double now = 0;
        var progress = p.Recording(() => now, null);
        progress.Report(new NativeProviderProgress("analysis", TimeSpan.Zero));
        now = 4;
        progress.Report(new NativeProviderProgress("Stack f", TimeSpan.Zero));
        now = 10;
        progress.Report(new NativeProviderProgress("analyzers", TimeSpan.Zero) { Analyzers = [new("Stack", 2.5), new("Decompiler Switch Analysis", 6.0)] });
        progress.Report(new NativeProviderProgress("ready", TimeSpan.Zero));
        Assert.Equal("analysis 10.0 s (Decompiler Switch Analysis 6.0 s, Stack 2.5 s)", EngineOpenProfile.Describe(p.Stages(10)));
    }

    [Fact]
    public void Engine_steps_are_parts_of_their_stage_grouped_and_the_longest_kept()
    {
        var p = new EngineOpenProfile();
        p.Mark("start", 0);
        p.Mark("analysis", 1);
        for (int i = 0; i < 40; i++) p.Mark($"Decompiling ?f{i}@@YAXXZ", 2 + i);
        for (int i = 0; i < 10; i++) p.Mark($"Analyzer {i}", 42 + i);
        p.Mark("save", 52);
        p.Mark("ready", 53);
        var stages = p.Stages(300);
        Assert.Equal(["start", "analysis", "save"], stages.Select(s => s.Stage));
        var parts = stages[1].Parts!;
        Assert.Equal(6, parts.Count);
        Assert.Equal(("Decompiling", 40.0), (parts[0].Stage, parts[0].Seconds));
        Assert.Equal(51, stages[1].Seconds, 3);
    }

    [Fact]
    public async Task Engine_status_and_the_ready_progress_carry_the_stages()
    {
        var options = new ServerOptions { BackgroundIndexing = false };
        var workspace = new AssemblyWorkspace(options);
        var engine = new ScriptedEngine();
        engine.OpenStages.AddRange([("start", 30), ("analysis", 120), ("save", 30), ("ready", 0)]);
        var engines = new NativeEngineService([engine], _dir.File("cache"), null, workspace, options);
        _owned.Add(engines);
        _owned.Add(workspace);
        var native = workspace.LoadAny(McpProtocolTests.NativeSample(_dir)).Native!;
        // Regression of 25da743e: a heartbeat came after the ready report.
        engines.OpenHeartbeat = Timeout.InfiniteTimeSpan;
        var reports = new List<string>();
        await engines.Session(native, null, new SyncProgress(p => reports.Add(p.Stage)), default);
        var ready = Assert.Single(reports, r => r.StartsWith("ready (", StringComparison.Ordinal));
        Assert.Matches(@"^ready \(prepare \d+\.\d s, start \d+\.\d s, analysis \d+\.\d s, save \d+\.\d s\)$", ready);

        var status = await new NativeEngineStatusTools(workspace, engines).GetEngineStatus(native.Id);
        Assert.Matches(@"open stages: prepare \d+\.\d s, start \d+\.\d s, analysis \d+\.\d s, save \d+\.\d s, pdb types \d+\.\d s", status);
        var stages = engines.ImageSessions(native)[0].OpenStages;
        Assert.Equal(["prepare", "start", "analysis", "save", "pdb types"], stages.Select(s => s.Stage));
        Assert.True(stages[2].Seconds >= 0.05);
    }

    /// <summary>E3: a call whose deadline passes during a long analysis answers with the stage and seconds; the open goes on and a later call picks it up.</summary>
    [Fact]
    public async Task A_call_that_leaves_a_long_open_names_its_stage_and_the_open_goes_on()
    {
        var options = new ServerOptions { BackgroundIndexing = false };
        var workspace = new AssemblyWorkspace(options);
        var engine = new ScriptedEngine();
        engine.OpenStages.AddRange([("start", 20), ("analysis", 0), ("ready", 0)]);
        var analysis = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        engine.StageGates["analysis"] = analysis;
        var engines = new NativeEngineService([engine], _dir.File("cache"), null, workspace, options);
        _owned.Add(engines);
        _owned.Add(workspace);
        var native = workspace.LoadAny(McpProtocolTests.NativeSample(_dir)).Native!;

        // The deadline passes once the analysis stage is reported and the stage
        // holds until released: a timed stage could end before the deadline
        // fired on a slow runner (regression of e19e716d).
        using var deadline = new CancellationTokenSource();
        var progress = new SyncProgress(p => { if (p.Stage == "analysis") deadline.Cancel(); });
        var error = await Assert.ThrowsAsync<ToolError>(() => engines.Session(native, null, progress, deadline.Token));
        Assert.Equal(ErrorCode.Timeout, error.Code);
        Assert.Matches(@"^opening \(analysis, \d+ s, no estimate \(no earlier open of this image\)\); the engine is still opening ", error.Message);
        var details = System.Text.Json.JsonDocument.Parse(error.ToJson()).RootElement.GetProperty("details");
        Assert.True(details.GetProperty("stillRunning").GetBoolean());
        Assert.Equal("analysis", details.GetProperty("stage").GetString());
        Assert.Equal(native.Id, details.GetProperty("image").GetString());
        Assert.Equal("ours", details.GetProperty("fallbackEngine").GetString());
        Assert.False(details.TryGetProperty("estimatedMinutes", out _));
        Assert.False(details.TryGetProperty("expectedSeconds", out _));

        analysis.SetResult();
        Assert.NotNull(await engines.Session(native, null, null, default));
        Assert.Equal(1, engine.Opens);
    }

    [Fact]
    public async Task A_call_reports_the_estimate_after_a_short_wait_before_its_deadline()
    {
        var options = new ServerOptions { BackgroundIndexing = false };
        var workspace = new AssemblyWorkspace(options);
        var engine = new ScriptedEngine();
        engine.OpenStages.AddRange([("start", 0), ("analysis", 0), ("ready", 0)]);
        var gate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        engine.StageGates["analysis"] = gate;
        var engines = new NativeEngineService([engine], _dir.File("cache"), null, workspace, options);
        _owned.Add(engines);
        _owned.Add(workspace);
        var native = workspace.LoadAny(McpProtocolTests.NativeSample(_dir)).Native!;
        engines.EstimateAfter = TimeSpan.FromMilliseconds(300);
        try
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromMinutes(5));
            var error = await Assert.ThrowsAsync<ToolError>(() => engines.Session(native, null, null, deadline.Token));
            Assert.Equal(ErrorCode.Timeout, error.Code);
            Assert.False(deadline.IsCancellationRequested);
        }
        finally { gate.SetResult(); }
    }

    private async Task<ToolError> EarlyAnswer(string? tool, Microsoft.Extensions.Time.Testing.FakeTimeProvider? clock = null, double? earlierOpenSeconds = null)
    {
        var options = new ServerOptions { BackgroundIndexing = false };
        var workspace = new AssemblyWorkspace(options);
        var engine = new ScriptedEngine();
        engine.OpenStages.AddRange([("start", 0), ("analysis", 0), ("ready", 0)]);
        var gate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        engine.StageGates["analysis"] = gate;
        var engines = new NativeEngineService([engine], _dir.File("cache"), null, workspace, options);
        _owned.Add(engines);
        _owned.Add(workspace);
        var native = workspace.LoadAny(McpProtocolTests.NativeSample(_dir)).Native!;
        NativeEngineService.BuiltInEngineFor = Corvus.Mcp.ParameterDomains.AcceptsBuiltInEngine;
        if (earlierOpenSeconds is { } earlier) new OpenEstimate(_dir.File("cache")).RecordRun(engine.Id, native.OriginalSha256, false, 5, earlier);
        if (tool != null) OutputCall.Begin(new OutputCall(tool, 0, null));
        try
        {
            if (clock == null)
            {
                engines.EstimateAfter = TimeSpan.FromMilliseconds(200);
                return await Assert.ThrowsAsync<ToolError>(() => engines.Session(native, null, null, default));
            }
            engines.Clock = clock;
            var call = Assert.ThrowsAsync<ToolError>(() => engines.Session(native, null, null, default));
            while (!call.IsCompleted)
            {
                clock.Advance(TimeSpan.FromHours(1));
                await Task.WhenAny(call, Task.Delay(20));
            }
            return await call;
        }
        finally { gate.SetResult(); }
    }

    // Reproduces N3: list_native_types offered engine=ours, which it does not accept.
    [Fact]
    public async Task An_engine_wait_offers_engine_ours_only_to_tools_that_accept_it()
    {
        var decompilerOnly = await EarlyAnswer("list_native_types");
        Assert.DoesNotContain("engine=ours", decompilerOnly.Remediation);
        Assert.Contains("waitSeconds=", decompilerOnly.Remediation);
        Assert.False(System.Text.Json.JsonDocument.Parse(decompilerOnly.ToJson()).RootElement.GetProperty("details").TryGetProperty("fallbackEngine", out _));
        var builtIn = await EarlyAnswer("list_functions");
        Assert.Contains("engine=ours", builtIn.Remediation);
    }

    // Reproduces N4: a stale estimate reported remainingSeconds 0.
    [Fact]
    public async Task An_open_past_its_estimate_reports_the_overrun_and_no_remaining_time()
    {
        var error = await EarlyAnswer(null, new Microsoft.Extensions.Time.Testing.FakeTimeProvider(), earlierOpenSeconds: 5);
        Assert.Matches(@"^opening \(analysis, \d+ s, \d+ s past 5 s expected from earlier opens\)", error.Message);
        var details = System.Text.Json.JsonDocument.Parse(error.ToJson()).RootElement.GetProperty("details");
        Assert.False(details.TryGetProperty("remainingSeconds", out _));
        Assert.True(details.GetProperty("overdueSeconds").GetDouble() > 0);
        Assert.True(error.RetryAfter >= TimeSpan.FromSeconds(30));
    }

    [Fact]
    public async Task An_open_that_ends_after_the_early_answer_leaves_a_workspace_notice()
    {
        var options = new ServerOptions { BackgroundIndexing = false };
        var workspace = new AssemblyWorkspace(options);
        var engine = new ScriptedEngine();
        engine.OpenStages.AddRange([("start", 0), ("analysis", 0), ("ready", 0)]);
        var gate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        engine.StageGates["analysis"] = gate;
        var engines = new NativeEngineService([engine], _dir.File("cache"), null, workspace, options);
        _owned.Add(engines);
        _owned.Add(workspace);
        var native = workspace.LoadAny(McpProtocolTests.NativeSample(_dir)).Native!;
        engines.EstimateAfter = TimeSpan.FromMilliseconds(200);
        var error = await Assert.ThrowsAsync<ToolError>(() => engines.Session(native, null, null, default));
        Assert.Contains($"get_engine_status image={native.Id} waitSeconds=", error.Remediation);
        Assert.Contains("engine=ours", error.Remediation);
        Assert.Contains("ends when the engine finishes, is cancelled or exits, or after 1800 s without progress", error.Message);
        Assert.Equal(TimeSpan.FromSeconds(30), error.RetryAfter);
        Assert.Empty(workspace.DrainNotices());
        gate.SetResult();
        var notices = new List<string>();
        for (int i = 0; i < 100 && notices.Count == 0; i++)
        {
            await Task.Delay(50);
            notices.AddRange(workspace.DrainNotices());
        }
        var notice = Assert.Single(notices);
        Assert.Matches($@"^{System.Text.RegularExpressions.Regex.Escape(native.Id)}: \w+ analysis (complete|partial) in \d+ s; next: list_functions image=", notice);
    }

    [Fact]
    public async Task Engine_status_waits_until_the_open_ends_not_for_the_whole_bound()
    {
        var options = new ServerOptions { BackgroundIndexing = false };
        var workspace = new AssemblyWorkspace(options);
        var engine = new ScriptedEngine();
        engine.OpenStages.AddRange([("start", 0), ("analysis", 0), ("ready", 0)]);
        var gate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        engine.StageGates["analysis"] = gate;
        var engines = new NativeEngineService([engine], _dir.File("cache"), null, workspace, options);
        _owned.Add(engines);
        _owned.Add(workspace);
        var native = workspace.LoadAny(McpProtocolTests.NativeSample(_dir)).Native!;
        _ = engines.Session(native, null, null, default);
        for (int i = 0; i < 100 && engines.ImageSessions(native).Count == 0; i++) await Task.Delay(20);
        var tools = new NativeEngineStatusTools(workspace, engines);
        var release = Task.Run(async () => { await Task.Delay(500); gate.SetResult(); });
        var watch = System.Diagnostics.Stopwatch.StartNew();
        var status = await tools.GetEngineStatus(native.Id, waitSeconds: 60);
        await release;
        Assert.True(watch.Elapsed < TimeSpan.FromSeconds(5), $"waited {watch.Elapsed} of a 60 s bound");
        Assert.DoesNotContain("opening (", status);
    }

    private (NativeEngineService Engines, LoadedNative Native, TaskCompletionSource Gate, AssemblyWorkspace Workspace) Rig(Exception? lateFailure = null)
    {
        var (engines, native, gate, workspace, _) = RigWithEngine(lateFailure);
        return (engines, native, gate, workspace);
    }

    private (NativeEngineService Engines, LoadedNative Native, TaskCompletionSource Gate, AssemblyWorkspace Workspace, ScriptedEngine Engine) RigWithEngine(Exception? lateFailure = null)
    {
        var options = new ServerOptions { BackgroundIndexing = false };
        var workspace = new AssemblyWorkspace(options);
        var engine = new ScriptedEngine { LateOpenFailure = lateFailure };
        engine.OpenStages.AddRange([("start", 0), ("analysis", 0), ("ready", 0)]);
        var gate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        engine.StageGates["analysis"] = gate;
        var engines = new NativeEngineService([engine], _dir.File("cache"), null, workspace, options);
        _owned.Add(engines);
        _owned.Add(workspace);
        var native = workspace.LoadAny(McpProtocolTests.NativeSample(_dir)).Native!;
        return (engines, native, gate, workspace, engine);
    }

    private static async Task Settled(NativeEngineService engines, LoadedNative native)
    {
        for (int i = 0; i < 200 && engines.ImageSessions(native).Any(e => e.State == "opening"); i++) await Task.Delay(20);
    }

    // The open is held on a gate that never completes.
    [Fact]
    public async Task Disposing_the_service_cancels_an_open_and_ends_the_engine()
    {
        var (engines, native, _, _, engine) = RigWithEngine();
        _ = engines.Session(native, null, null, default).ContinueWith(t => _ = t.Exception, TaskScheduler.Default);
        for (int i = 0; i < 100 && engines.ImageSessions(native).Count == 0; i++) await Task.Delay(20);
        engines.Dispose();
        await engine.OpenCancelled.Task.WaitAsync(TimeSpan.FromSeconds(30));
        await engine.Disposed.Task.WaitAsync(TimeSpan.FromSeconds(30));
    }

    [Fact]
    public async Task Engine_status_names_an_opening_run_as_a_job_with_its_expected_time()
    {
        var (engines, native, gate, workspace) = Rig();
        _ = engines.Session(native, null, null, default);
        for (int i = 0; i < 100 && engines.ImageSessions(native).Count == 0; i++) await Task.Delay(20);
        var tools = new NativeEngineStatusTools(workspace, engines);
        string text = "";
        var report = await NativeQuerySurfaceTests.Structured<NativeEngineStatusTools.EngineStatusReport>(async () => text = await tools.GetEngineStatus(native.Id));
        gate.SetResult();
        await Settled(engines, native);
        var row = Assert.Single(report.Engines, e => e.State == "opening");
        Assert.Contains("Next: get_engine_status image=", text);
        Assert.Null(row.ExpectedSeconds);
        Assert.Null(row.RemainingSeconds);
        Assert.Contains("no estimate (no earlier open of this image)", text);
        var job = Assert.IsType<NativeEngineStatusTools.EngineJob>(row.Job);
        Assert.Equal(("open", "running"), (job.What, job.State));
        Assert.Null(job.BudgetSeconds);
        Assert.Null(job.Outcome);
        Assert.True(DateTime.Parse(job.StartedAt).ToUniversalTime() > DateTime.UtcNow.AddMinutes(-5));
    }

    [Theory]
    [InlineData(0, 30)]
    [InlineData(400, 100)]
    [InlineData(100000, 300)]
    public void The_retry_is_a_quarter_of_the_remaining_estimate_between_30_s_and_5_min(double remaining, int seconds) =>
        Assert.Equal(TimeSpan.FromSeconds(seconds), Corvus.Native.Providers.BackgroundRunner.RetryFor(remaining));

    [Fact]
    public async Task An_open_that_fails_after_the_early_answer_leaves_a_failed_notice_with_the_next_call()
    {
        var (engines, native, gate, workspace) = Rig(new ToolError(ErrorCode.Failed, "scripted open failure"));
        engines.EstimateAfter = TimeSpan.FromMilliseconds(200);
        await Assert.ThrowsAsync<ToolError>(() => engines.Session(native, null, null, default));
        gate.SetResult();
        var notices = new List<string>();
        for (int i = 0; i < 100 && notices.Count == 0; i++)
        {
            await Task.Delay(50);
            notices.AddRange(workspace.DrainNotices());
        }
        var notice = Assert.Single(notices);
        Assert.Contains("analysis failed (scripted open failure) in", notice);
        Assert.Contains($"next: get_engine_status image={native.Id}", notice);
        var failed = Assert.Single(engines.ImageSessions(native), e => e.State == "failed");
        Assert.Equal("scripted open failure", failed.Error);
    }

    [Fact]
    public async Task Engine_status_wait_ends_before_the_call_deadline_and_says_so()
    {
        var (engines, native, gate, workspace) = Rig();
        _ = engines.Session(native, null, null, default);
        for (int i = 0; i < 100 && engines.ImageSessions(native).Count == 0; i++) await Task.Delay(20);
        var watch = System.Diagnostics.Stopwatch.StartNew();
        string text;
        using (Deadlines.Enter(TimeSpan.FromSeconds(3)))
            text = await new NativeEngineStatusTools(workspace, engines).GetEngineStatus(native.Id, waitSeconds: 600);
        var waited = watch.Elapsed;
        gate.SetResult();
        await Settled(engines, native);
        Assert.True(waited < TimeSpan.FromSeconds(6), $"waited {waited} of a 600 s bound");
        Assert.Contains("the call's deadline ended the wait", text);
        Assert.Contains("opening (", text);
    }

    [Fact]
    public async Task Engine_status_wait_on_a_settled_image_returns_at_once()
    {
        var (engines, native, gate, workspace) = Rig();
        gate.SetResult();
        await engines.Session(native, null, null, default);
        var watch = System.Diagnostics.Stopwatch.StartNew();
        var text = await new NativeEngineStatusTools(workspace, engines).GetEngineStatus(native.Id, waitSeconds: 600);
        Assert.True(watch.Elapsed < TimeSpan.FromSeconds(5), $"waited {watch.Elapsed}");
        Assert.DoesNotContain("no change in", text);
    }

    [Theory]
    [InlineData(-1)]
    [InlineData(601)]
    public async Task Engine_status_refuses_a_wait_outside_0_to_600_seconds(int seconds)
    {
        var (engines, native, gate, workspace) = Rig();
        gate.SetResult();
        var error = await Assert.ThrowsAsync<ToolError>(() => new NativeEngineStatusTools(workspace, engines).GetEngineStatus(native.Id, waitSeconds: seconds));
        Assert.Equal(ErrorCode.InvalidArgument, error.Code);
    }

    private (NativeEngineService Engines, ScriptedEngine Engine, TaskCompletionSource Gate, AssemblyWorkspace Workspace) ClockRig(
        TimeProvider clock, string cache, bool partial = false, EngineMode? prewarm = null, bool refusePatches = false)
    {
        var options = new ServerOptions { BackgroundIndexing = false, Prewarm = prewarm };
        var workspace = new AssemblyWorkspace(options);
        var engine = new ScriptedEngine { PartialAnalysis = partial, RefusePatches = refusePatches };
        engine.OpenStages.AddRange([("start", 0), ("analysis", 0), ("ready", 0)]);
        var gate = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        engine.StageGates["analysis"] = gate;
        var engines = new NativeEngineService([engine], cache, null, workspace, options) { EstimateAfter = TimeSpan.FromSeconds(20), Clock = clock };
        _owned.Add(engines);
        _owned.Add(workspace);
        return (engines, engine, gate, workspace);
    }

    /// <summary>Waits until the open has marked its analysis stage.</summary>
    private static async Task InAnalysis(NativeEngineService engines, LoadedNative native)
    {
        for (int i = 0; i < 500 && !engines.ImageSessions(native).Any(e => e.State == "opening" && e.OpenStages.Any(s => s.Stage == "analysis")); i++)
            await Task.Delay(20);
    }

    [Fact]
    public async Task A_prewarm_open_that_outlives_the_early_answer_ends_done_not_failed()
    {
        var clock = new ArmedClock();
        var (engines, _, gate, workspace) = ClockRig(clock, _dir.File("cache"), prewarm: EngineMode.Ida);
        workspace.LoadAny(McpProtocolTests.NativeSample(_dir));
        await clock.ArmedAsync();
        clock.Advance(engines.EstimateAfter + TimeSpan.FromSeconds(1));
        // The retry asks again and arms a new wait: the early answer was seen and not counted.
        await clock.ArmedAsync();
        var running = engines.Prewarming;
        Assert.Equal((0, 0), (running.Done, running.Failed));
        Assert.NotNull(running.Running);
        gate.SetResult();
        for (int i = 0; i < 500 && engines.Prewarming.Done == 0 && engines.Prewarming.Failed == 0; i++) await Task.Delay(20);
        var ended = engines.Prewarming;
        Assert.True((1, 0) == (ended.Done, ended.Failed), ended.ToString());
        Assert.Null(ended.Running);
        // The completed analysis records its rate; wait for it so the cache folder is not written after the test.
        for (int i = 0; i < 500 && !File.Exists(Path.Combine(_dir.File("cache"), OpenEstimate.FileName)); i++) await Task.Delay(20);
    }

    [Fact]
    public async Task A_patched_copy_that_opens_slowly_shows_its_own_seconds_as_opening()
    {
        var clock = new ArmedClock();
        var (engines, engine, gate, workspace) = ClockRig(clock, _dir.File("cache"), refusePatches: true);
        var native = workspace.LoadAny(McpProtocolTests.NativeSample(_dir)).Native!;
        gate.SetResult();
        await engines.Session(native, null, null, default);
        // The base open lies far in the past when the patched copy starts.
        clock.Advance(TimeSpan.FromSeconds(1000));
        clock.Forget();
        var original = File.ReadAllBytes(native.FilePath)[0x40];
        native.Patches.Add(new Native.Patching.NativePatch(0x1000, 0x40, [original], [(byte)(original ^ 1)], "test"));
        engine.StageGates["analysis"] = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var call = Assert.ThrowsAsync<ToolError>(() => engines.Session(native, null, null, default));
        await InAnalysis(engines, native);
        await clock.ArmedAsync();
        clock.Advance(TimeSpan.FromSeconds(21));
        var error = await call;
        var row = Assert.Single(engines.ImageSessions(native));
        Assert.Contains("analysis, 21 s", error.Message);
        Assert.Equal(("opening", "analysis", 21), (row.State, row.Stage, row.Seconds));
        Assert.Null(row.ExpectedSeconds);
    }

    [Fact]
    public async Task A_partial_saved_database_open_is_kept_apart_from_a_complete_one()
    {
        var cache = _dir.File("cache");
        await OpenAfterThirtySeconds(cache, partial: true);
        await OpenAfterThirtySeconds(cache, partial: false);
        var history = Path.Combine(cache, OpenEstimate.FileName);
        // Each open records after it returns, so wait for both entries.
        for (int i = 0; i < 500 && !(File.Exists(history) && File.ReadAllText(history) is var text && text.Contains("|reused-partial") && text.Contains("|reused\"")); i++) await Task.Delay(20);
        using var doc = JsonDocument.Parse(File.ReadAllText(history));
        var kept = doc.RootElement.EnumerateObject().OrderBy(e => e.Name, StringComparer.Ordinal).ToList();
        Assert.Collection(kept,
            e => { Assert.EndsWith("|reused", e.Name); Assert.Equal(1, e.Value.GetArrayLength()); },
            e => { Assert.EndsWith("|reused-partial", e.Name); Assert.Equal(1, e.Value.GetArrayLength()); });
    }

    [Fact]
    public async Task A_completed_open_records_its_rate_in_the_open_history()
    {
        var cache = _dir.File("cache");
        await OpenAfterThirtySeconds(cache, partial: false);
        var history = Path.Combine(cache, OpenEstimate.FileName);
        for (int i = 0; i < 500 && !File.Exists(history); i++) await Task.Delay(20);
        using var doc = JsonDocument.Parse(File.ReadAllText(history));
        var kept = Assert.Single(doc.RootElement.EnumerateObject());
        Assert.StartsWith("ida|", kept.Name);
        Assert.Equal(30, kept.Value[0][1].GetDouble());
    }

    /// <summary>Opens the image with an analysis stage that lasts 30 s on a fake clock.</summary>
    private async Task OpenAfterThirtySeconds(string cache, bool partial)
    {
        var clock = new FakeTimeProvider();
        var (engines, _, gate, workspace) = ClockRig(clock, cache, partial);
        engines.EstimateAfter = TimeSpan.FromHours(1);
        var native = workspace.LoadAny(McpProtocolTests.NativeSample(_dir)).Native!;
        var call = engines.Session(native, null, null, default);
        await InAnalysis(engines, native);
        clock.Advance(TimeSpan.FromSeconds(30));
        gate.SetResult();
        await call;
    }

    [Fact]
    public async Task An_open_without_an_earlier_open_of_the_image_names_no_estimate_in_every_tool()
    {
        var clock = new ArmedClock();
        var (engines, _, _, workspace) = ClockRig(clock, _dir.File("cache"));
        var native = workspace.LoadAny(McpProtocolTests.NativeSample(_dir)).Native!;
        var call = Assert.ThrowsAsync<ToolError>(() => engines.Session(native, null, null, default));
        await clock.ArmedAsync();
        clock.Advance(TimeSpan.FromSeconds(21));
        var error = await call;
        var row = Assert.Single(engines.ImageSessions(native));
        Assert.Contains("analysis, 21 s, no estimate (no earlier open of this image)", error.Message);
        Assert.Null(row.ExpectedBasis);
        Assert.Contains("analysis, 21 s, no estimate (no earlier open of this image)", await new NativeEngineStatusTools(workspace, engines).GetEngineStatus(native.Id));
    }

    [Fact]
    public async Task A_call_and_the_engine_status_give_one_estimate_from_earlier_opens_of_the_image()
    {
        var clock = new ArmedClock();
        var cache = _dir.File("cache");
        var (engines, engine, _, workspace) = ClockRig(clock, cache);
        var native = workspace.LoadAny(McpProtocolTests.NativeSample(_dir)).Native!;
        new OpenEstimate(cache).RecordRun(engine.Id, native.OriginalSha256, false, 5, 100);
        var call = Assert.ThrowsAsync<ToolError>(() => engines.Session(native, null, null, default));
        await clock.ArmedAsync();
        clock.Advance(TimeSpan.FromSeconds(21));
        var error = await call;
        const string Shared = "analysis, 21 s, about 79 s left of 100 s expected from earlier opens";
        Assert.Contains(Shared, error.Message);
        Assert.Contains(Shared, await new NativeEngineStatusTools(workspace, engines).GetEngineStatus(native.Id));
    }

    private sealed class SyncProgress(Action<NativeProviderProgress> report) : IProgress<NativeProviderProgress>
    {
        public void Report(NativeProviderProgress value) => report(value);
    }
}
