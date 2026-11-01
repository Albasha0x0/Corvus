using System.Text.Json;
using Corvus.Core;
using Corvus.Native;
using Corvus.Native.Providers;
using Corvus.Services;
using Corvus.Tools;

namespace Corvus.Tests;

/// <summary>reanalyze_native over a scripted engine: analyzer listing, background runs with per-run options and ranges, cancel, end notices; worker replies parse.</summary>
public sealed class ReanalyzeNativeTests : IDisposable
{
    private readonly TempDir _dir = new();
    private readonly List<IDisposable> _owned = [];
    private NativeEngineService _engines = null!;
    private AssemblyWorkspace _workspace = null!;

    public void Dispose()
    {
        foreach (var d in _owned) d.Dispose();
        _dir.Dispose();
    }

    private (NativeEngineControlTools Control, NativeSearchDecompiledTools Search, ScriptedEngine Engine, LoadedNative Native) Setup()
    {
        var options = new ServerOptions { BackgroundIndexing = false };
        var workspace = new AssemblyWorkspace(options);
        var engine = new ScriptedEngine();
        engine.Add(0x1000, "f", "int f(void)", "{ return 0; }");
        engine.Analyzers.AddRange([new("AF_FLIRT", "bool", "true", "use flirt signatures"), new("AF_CODE", "bool", "true", "trace execution flow"),
            new("Decompiler Parameter ID", "bool", "false", "Creates parameter and return\ndefinitions")]);
        var engines = new NativeEngineService([engine], _dir.File("cache"), null, workspace, options);
        _owned.Add(engines);
        _owned.Add(workspace);
        (_engines, _workspace) = (engines, workspace);
        var native = workspace.LoadAny(McpProtocolTests.NativeSample(_dir)).Native!;
        var pager = new OutputPager(options);
        return (new NativeEngineControlTools(workspace, engines), new NativeSearchDecompiledTools(workspace, engines, pager), engine, native);
    }

    /// <summary>Waits for the image's background job to end and its notice to be queued; returns the notices.</summary>
    private async Task<List<string>> Ended(LoadedNative native)
    {
        var jobs = ((IBackgroundJobs)_engines.OpenSession(native)!).Jobs;
        await jobs.Job!.Task.WaitAsync(TimeSpan.FromSeconds(10));
        var notices = new List<string>();
        for (var i = 0; i < 200 && notices.Count == 0; i++)
        {
            await Task.Delay(10);
            notices.AddRange(_workspace.DrainNotices());
        }
        return notices;
    }

    [Fact]
    public async Task Analyzers_are_listed_with_values_and_filtered()
    {
        var (control, _, _, native) = Setup();
        var all = await control.ReanalyzeNative(native.Id, analyzers: true);
        Assert.Contains("3 options", all);
        Assert.Contains("AF_FLIRT = true  (bool)  use flirt signatures", all);
        Assert.Contains("Decompiler Parameter ID = false  (bool)  Creates parameter and return definitions", all);
        var some = await control.ReanalyzeNative(native.Id, analyzers: true, filter: "AF_*");
        Assert.Contains("2 options", some);
        Assert.DoesNotContain("Decompiler", some);
        // N10: the listing pages by rows like any list
        var page = await control.ReanalyzeNative(native.Id, analyzers: true, offset: 1, limit: 1);
        Assert.Single(page.Split('\n'), l => l.Contains(" = ", StringComparison.Ordinal));
        Assert.Contains("offset=2", page);
    }

    [Fact]
    public async Task A_reanalysis_returns_before_a_slow_engine_ends_and_names_the_status_call()
    {
        var (control, _, engine, native) = Setup();
        engine.ReanalysisGate = new TaskCompletionSource();
        var started = await control.ReanalyzeNative(native.Id);
        Assert.Contains($"get_engine_status image={native.Id} waitSeconds=60", started);
        Assert.Contains("no time limit", started);
        var jobs = ((IBackgroundJobs)_engines.OpenSession(native)!).Jobs;
        Assert.True(jobs.Running);
        engine.ReanalysisGate.SetResult();
        var notice = Assert.Single(await Ended(native));
        Assert.Contains("complete", notice);
        Assert.Contains($"next: list_functions image={native.Id}", notice);
        Assert.Equal("complete", jobs.Kind);
    }

    [Fact]
    public async Task A_repeated_reanalysis_joins_the_running_one()
    {
        var (control, _, engine, native) = Setup();
        engine.ReanalysisGate = new TaskCompletionSource();
        await control.ReanalyzeNative(native.Id);
        var again = await control.ReanalyzeNative(native.Id);
        Assert.Contains("already running", again);
        Assert.Contains("cancel=true", again);
        Assert.Single(engine.Reanalyses);
        engine.ReanalysisGate.SetResult();
        await Ended(native);
    }

    [Fact]
    public async Task Cancelling_a_reanalysis_through_the_status_call_leaves_the_engine_idle()
    {
        var (control, _, engine, native) = Setup();
        engine.ReanalysisGate = new TaskCompletionSource();
        await control.ReanalyzeNative(native.Id);
        var status = new NativeEngineStatusTools(_workspace, _engines);
        var text = await status.GetEngineStatus(native.Id, cancel: true);
        Assert.Contains("cancelled: IDA reanalysis", text);
        var jobs = ((IBackgroundJobs)_engines.OpenSession(native)!).Jobs;
        Assert.False(jobs.Running);
        Assert.Equal("cancelled", jobs.Kind);
        var notice = Assert.Single(await Ended(native));
        Assert.Contains("cancelled", notice);
        Assert.Contains($"next: get_engine_status image={native.Id}", notice);
        engine.ReanalysisGate = null;
        await control.ReanalyzeNative(native.Id);
        await Ended(native);
        Assert.Equal("complete", jobs.Kind);
    }

    [Fact]
    public async Task Cancelling_with_nothing_running_says_so_and_names_the_next_call()
    {
        var (control, _, _, native) = Setup();
        await control.ReanalyzeNative(native.Id, analyzers: true);
        var text = await new NativeEngineStatusTools(_workspace, _engines).GetEngineStatus(native.Id, cancel: true);
        Assert.Contains("nothing to cancel", text);
        Assert.Contains($"reanalyze_native image={native.Id}", text);
    }

    [Fact]
    public void The_end_notice_names_the_next_call_by_outcome()
    {
        Assert.Equal("a.exe: ida reanalysis ended in 4 s: complete; next: list_functions image=img engine=ida",
            NativeEngineControlTools.BackgroundEndNotice("a.exe", "img", "ida", "complete", "reanalysis ended in 4 s: complete"));
        Assert.Equal("a.exe: ida reanalysis ended in 4 s: partial; next: reanalyze_native image=img engine=ida completes it",
            NativeEngineControlTools.BackgroundEndNotice("a.exe", "img", "ida", "partial", "reanalysis ended in 4 s: partial"));
        Assert.Equal("a.exe: ida reanalysis failed after 4 s: broke; next: get_engine_status image=img shows the state, engine=ours answers now; use engine=ghidra",
            NativeEngineControlTools.BackgroundEndNotice("a.exe", "img", "ida", "failed", "reanalysis failed after 4 s: broke", "use engine=ghidra"));
    }

    [Fact]
    public async Task A_failed_reanalysis_notice_carries_the_error_s_next_call()
    {
        var (control, _, engine, native) = Setup();
        engine.ReanalysisResult = () => throw new ToolError(ErrorCode.Failed, "the engine refused", "use engine=ghidra");
        await control.ReanalyzeNative(native.Id);
        var notice = Assert.Single(await Ended(native));
        Assert.Contains("failed", notice);
        Assert.EndsWith("use engine=ghidra", notice);
    }

    [Fact]
    public async Task A_run_passes_options_and_range_and_drops_cached_pseudocode()
    {
        var (control, search, engine, native) = Setup();
        var first = await search.SearchDecompiled(native.Id, "return");
        Assert.True(engine.Decompiles == 1, $"{engine.Decompiles} decompiles; search answered: {first}");
        engine.ReanalysisResult = () => new NativeReanalysis(false, 10, 14, TimeSpan.FromSeconds(2), ["unknown analysis option 'Bogus'"]);
        var text = await control.ReanalyzeNative(native.Id, options: ["AF_FLIRT=false", "Decompiler Parameter ID = true", "Bogus=1"],
            from: "rva:0x1000", to: "rva:0x1100", timeoutSeconds: 30);
        Assert.Equal(ErrorCode.InvalidArgument, (await Assert.ThrowsAsync<ToolError>(() => control.ReanalyzeNative(native.Id, timeoutSeconds: 0))).Code);
        var notice = Assert.Single(await Ended(native));
        var run = Assert.Single(engine.Reanalyses);
        Assert.Equal([new("AF_FLIRT", "false"), new("Decompiler Parameter ID", "true"), new("Bogus", "1")], run.Options);
        Assert.Equal((0x1000u, 0x1100u, 30.0), (run.Start!.Value, run.End!.Value, run.Seconds));
        Assert.Contains("reanalysis of 0x140001000-0x140001100 started in the background (30 s budget)", text);
        Assert.Contains("Options for this run: AF_FLIRT=false", text);
        Assert.Contains("partial, the budget ran out; functions 10 before, 14 after; 1 warning(s), first: unknown analysis option 'Bogus'", notice);
        Assert.Contains($"next: reanalyze_native image={native.Id}", notice);
        await search.SearchDecompiled(native.Id, "return");
        Assert.Equal(2, engine.Decompiles); // the earlier pseudocode no longer counts
    }

    [Fact]
    public async Task The_whole_image_by_default_and_bad_arguments_are_rejected()
    {
        var (control, _, engine, native) = Setup();
        Assert.Contains("of the whole image", await control.ReanalyzeNative(native.Id, timeoutSeconds: 7200));
        await Ended(native);
        Assert.Null(engine.Reanalyses[0].Start);
        Assert.Equal(7200, engine.Reanalyses[0].Seconds);
        foreach (var call in new Func<Task<string>>[]
                 {
                     () => control.ReanalyzeNative(native.Id, options: ["AF_FLIRT"]),
                     () => control.ReanalyzeNative(native.Id, analyzers: true, options: ["AF_FLIRT=1"]),
                     () => control.ReanalyzeNative(native.Id, to: "rva:0x1000"),
                     () => control.ReanalyzeNative(native.Id, from: "rva:0x1100", to: "rva:0x1000"),
                 })
            Assert.Equal(ErrorCode.InvalidArgument, (await Assert.ThrowsAsync<ToolError>(call)).Code);
        Assert.Single(engine.Reanalyses);
    }

    [Fact]
    public void Worker_replies_parse()
    {
        using var reanalysis = JsonDocument.Parse("""{"complete":true,"analysis_complete":true,"before":5,"after":7,"warnings":["w"],"seconds":1.5}""");
        var r = EngineControl.Reanalysis(reanalysis.RootElement);
        Assert.Equal((true, 5, 7, 1.5, "w"), (r.Complete, r.FunctionsBefore, r.FunctionsAfter, r.Elapsed.TotalSeconds, Assert.Single(r.Warnings)));
        using var analyzers = JsonDocument.Parse("""{"options":[["AF_CODE","bool","true","trace"],["X","int","3",null]]}""");
        Assert.Equal([new("AF_CODE", "bool", "true", "trace"), new("X", "int", "3", null)], EngineControl.Analyzers(analyzers.RootElement));
        using var candidates = JsonDocument.Parse("""{"rows":[[4096,4112,4,2,1,0]],"scanned":900,"truncated":true}""");
        var scan = EngineControl.Candidates(candidates.RootElement);
        Assert.Equal((new NativeFunctionCandidate(0x1000, 0x1010, 4, 2, 1, 0), 900, true), (scan.Items[0], scan.Scanned, scan.Truncated));
        using var marks = JsonDocument.Parse("""{"set":2,"removed":1,"failed":1,"failures":["0xFFFF: not mapped"]}""");
        Assert.Equal((2, 1, 1, "0xFFFF: not mapped"), (EngineControl.Marks(marks.RootElement) is var m ? (m.Set, m.Removed, m.Failed, m.Failures[0]) : default));
    }
}
