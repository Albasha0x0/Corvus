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
        Assert.Matches(@"still opening .+ \(analysis, \d+ s; a first analysis can take minutes\)", error.Message);
        var details = System.Text.Json.JsonDocument.Parse(error.ToJson()).RootElement.GetProperty("details");
        Assert.True(details.GetProperty("stillRunning").GetBoolean());
        Assert.Equal("analysis", details.GetProperty("stage").GetString());

        analysis.SetResult();
        Assert.NotNull(await engines.Session(native, null, null, default));
        Assert.Equal(1, engine.Opens);
    }

    private sealed class SyncProgress(Action<NativeProviderProgress> report) : IProgress<NativeProviderProgress>
    {
        public void Report(NativeProviderProgress value) => report(value);
    }
}
