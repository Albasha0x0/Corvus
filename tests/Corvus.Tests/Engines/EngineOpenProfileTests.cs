using System.Text.Json;
using Corvus.Core;
using Corvus.Mcp;
using Corvus.Native.Providers;
using Corvus.Services;
using Corvus.Tools;

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
        Assert.Matches(@"^analysis running, about \d+ min \((from (executable section size|earlier opens))\); the engine is still opening .+ \(analysis, \d+ s\)", error.Message);
        var details = System.Text.Json.JsonDocument.Parse(error.ToJson()).RootElement.GetProperty("details");
        Assert.True(details.GetProperty("stillRunning").GetBoolean());
        Assert.Equal("analysis", details.GetProperty("stage").GetString());
        Assert.Equal(native.Id, details.GetProperty("image").GetString());
        Assert.Equal("ours", details.GetProperty("fallbackEngine").GetString());
        Assert.True(details.GetProperty("estimatedMinutes").GetInt32() >= 1);

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
        var previous = NativeEngineService.EstimateAfter;
        NativeEngineService.EstimateAfter = TimeSpan.FromMilliseconds(300);
        try
        {
            using var deadline = new CancellationTokenSource(TimeSpan.FromMinutes(5));
            var error = await Assert.ThrowsAsync<ToolError>(() => engines.Session(native, null, null, deadline.Token));
            Assert.Equal(ErrorCode.Timeout, error.Code);
            Assert.False(deadline.IsCancellationRequested);
        }
        finally { NativeEngineService.EstimateAfter = previous; gate.SetResult(); }
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
        var previous = NativeEngineService.EstimateAfter;
        NativeEngineService.EstimateAfter = TimeSpan.FromMilliseconds(200);
        try
        {
            var error = await Assert.ThrowsAsync<ToolError>(() => engines.Session(native, null, null, default));
            Assert.Contains($"get_engine_status image={native.Id} waitSeconds=", error.Remediation);
            Assert.Contains("engine=ours", error.Remediation);
            Assert.Contains("ends when the engine finishes, is cancelled or exits, or after 1800 s without progress", error.Message);
            Assert.Equal(TimeSpan.FromSeconds(30), error.RetryAfter);
            Assert.Empty(workspace.DrainNotices());
        }
        finally { NativeEngineService.EstimateAfter = previous; }
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
        return (engines, native, gate, workspace);
    }

    private static async Task Settled(NativeEngineService engines, LoadedNative native)
    {
        for (int i = 0; i < 200 && engines.ImageSessions(native).Any(e => e.State == "opening"); i++) await Task.Delay(20);
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
        Assert.Contains("next: get_engine_status image=", text);
        Assert.True(row.ExpectedSeconds > 0, "the section-size estimate stands in without earlier opens");
        Assert.True(row.RemainingSeconds > 0);
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
        Assert.Equal(TimeSpan.FromSeconds(seconds), NativeEngineService.RetryFor(remaining));

    [Fact]
    public async Task An_open_that_fails_after_the_early_answer_leaves_a_failed_notice_with_the_next_call()
    {
        var (engines, native, gate, workspace) = Rig(new ToolError(ErrorCode.Failed, "scripted open failure"));
        var previous = NativeEngineService.EstimateAfter;
        NativeEngineService.EstimateAfter = TimeSpan.FromMilliseconds(200);
        try { await Assert.ThrowsAsync<ToolError>(() => engines.Session(native, null, null, default)); }
        finally { NativeEngineService.EstimateAfter = previous; }
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
    public void A_background_reanalysis_notice_names_the_engine_result_and_next_call() =>
        Assert.Equal("a.exe: ida reanalysis ended in 4 s: complete; next: list_functions image=img engine=ida",
            NativeEngineControlTools.BackgroundEndNotice("a.exe", "img", "ida", "reanalysis ended in 4 s: complete"));

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

    [Fact]
    public void The_estimate_is_one_minute_per_started_mebibyte_of_executable_sections()
    {
        const long mib = 1 << 20;
        Assert.Equal(1, NativeEngineService.EstimateMinutes([]));
        Assert.Equal(1, NativeEngineService.EstimateMinutes([(true, 0)]));
        Assert.Equal(1, NativeEngineService.EstimateMinutes([(true, mib)]));
        Assert.Equal(2, NativeEngineService.EstimateMinutes([(true, mib + 1)]));
        Assert.Equal(3, NativeEngineService.EstimateMinutes([(true, mib), (true, mib + mib / 2), (false, 40 * mib)]));
        Assert.Equal(1, NativeEngineService.EstimateMinutes([(false, 40 * mib)]));
    }

    private sealed class SyncProgress(Action<NativeProviderProgress> report) : IProgress<NativeProviderProgress>
    {
        public void Report(NativeProviderProgress value) => report(value);
    }
}
