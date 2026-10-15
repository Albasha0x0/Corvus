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
        var reports = new List<string>();
        await engines.Session(native, null, new SyncProgress(p => reports.Add(p.Stage)), default);
        Assert.Matches(@"^ready \(prepare \d\.\d s, start \d\.\d s, analysis \d\.\d s, save \d\.\d s\)$", reports[^1]);

        var status = await new NativeEngineStatusTools(workspace, engines).GetEngineStatus(native.Id);
        Assert.Matches(@"open stages: prepare \d\.\d s, start \d\.\d s, analysis \d\.\d s, save \d\.\d s, pdb types \d\.\d s", status);
        var stages = engines.ImageSessions(native)[0].OpenStages;
        Assert.Equal(["prepare", "start", "analysis", "save", "pdb types"], stages.Select(s => s.Stage));
        Assert.InRange(stages[2].Seconds, 0.05, 30);
    }

    /// <summary>E3: a call whose deadline passes during a long analysis answers with the stage and seconds; the open goes on and a later call picks it up.</summary>
    [Fact]
    public async Task A_call_that_leaves_a_long_open_names_its_stage_and_the_open_goes_on()
    {
        var options = new ServerOptions { BackgroundIndexing = false };
        var workspace = new AssemblyWorkspace(options);
        var engine = new ScriptedEngine();
        engine.OpenStages.AddRange([("start", 20), ("analysis", 1_500), ("ready", 0)]);
        var engines = new NativeEngineService([engine], _dir.File("cache"), null, workspace, options);
        _owned.Add(engines);
        _owned.Add(workspace);
        var native = workspace.LoadAny(McpProtocolTests.NativeSample(_dir)).Native!;

        using var deadline = new CancellationTokenSource(TimeSpan.FromMilliseconds(400));
        var error = await Assert.ThrowsAsync<ToolError>(() => engines.Session(native, null, null, deadline.Token));
        Assert.Equal(ErrorCode.Timeout, error.Code);
        Assert.Matches(@"still opening .+: analysis, \d+ s so far", error.Message);
        var details = System.Text.Json.JsonDocument.Parse(error.ToJson()).RootElement.GetProperty("details");
        Assert.True(details.GetProperty("stillRunning").GetBoolean());
        Assert.Equal("analysis", details.GetProperty("stage").GetString());

        Assert.NotNull(await engines.Session(native, null, null, default));
        Assert.Equal(1, engine.Opens);
    }

    private sealed class SyncProgress(Action<NativeProviderProgress> report) : IProgress<NativeProviderProgress>
    {
        public void Report(NativeProviderProgress value) => report(value);
    }
}
