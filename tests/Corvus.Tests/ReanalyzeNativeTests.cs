using System.Text.Json;
using Corvus.Core;
using Corvus.Native;
using Corvus.Native.Providers;
using Corvus.Services;
using Corvus.Tools;

namespace Corvus.Tests;

/// <summary>reanalyze_native over a scripted engine: analyzer listing, per-run options and ranges, cached pseudocode dropped; worker replies parse.</summary>
public sealed class ReanalyzeNativeTests : IDisposable
{
    private readonly TempDir _dir = new();
    private readonly List<IDisposable> _owned = [];

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
        var native = workspace.LoadAny(McpProtocolTests.NativeSample(_dir)).Native!;
        var pager = new OutputPager(options);
        return (new NativeEngineControlTools(workspace, engines), new NativeSearchDecompiledTools(workspace, engines, pager), engine, native);
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
    public async Task A_run_passes_options_and_range_and_drops_cached_pseudocode()
    {
        var (control, search, engine, native) = Setup();
        await search.SearchDecompiled(native.Id, "return");
        Assert.Equal(1, engine.Decompiles);
        engine.ReanalysisResult = () => new NativeReanalysis(false, 10, 14, TimeSpan.FromSeconds(2), ["unknown analysis option 'Bogus'"]);
        var (text, call) = await EngineMeta.Run(() => control.ReanalyzeNative(native.Id, options: ["AF_FLIRT=false", "Decompiler Parameter ID = true", "Bogus=1"],
            start: "rva:0x1000", end: "rva:0x1100", timeoutSeconds: 30));
        var report = Assert.IsType<NativeEngineControlTools.ReanalysisReport>(call.Record);
        Assert.Equal((false, 10, 14, "0x140001000-0x140001100"), (report.Complete, report.FunctionsBefore, report.FunctionsAfter, report.Scope));
        Assert.Equal(2.0, report.ElapsedSeconds);
        Assert.DoesNotContain(" s; database saved", text); // the time taken is in _meta
        Assert.Equal(ErrorCode.InvalidArgument, (await Assert.ThrowsAsync<ToolError>(() => control.ReanalyzeNative(native.Id, timeoutSeconds: 3601))).Code);
        var run = Assert.Single(engine.Reanalyses);
        Assert.Equal([new("AF_FLIRT", "false"), new("Decompiler Parameter ID", "true"), new("Bogus", "1")], run.Options);
        Assert.Equal((0x1000u, 0x1100u, 30.0), (run.Start!.Value, run.End!.Value, run.Seconds));
        Assert.Contains("reanalysis of 0x140001000-0x140001100", text);
        Assert.Contains("Partial: the 30 s budget ran out; run again to continue.", text);
        Assert.Contains("Functions: 10 before, 14 after (+4)", text);
        Assert.Contains("Warning: unknown analysis option 'Bogus'", text);
        await search.SearchDecompiled(native.Id, "return");
        Assert.Equal(2, engine.Decompiles); // the earlier pseudocode no longer counts
    }

    [Fact]
    public async Task The_whole_image_by_default_and_bad_arguments_are_rejected()
    {
        var (control, _, engine, native) = Setup();
        Assert.Contains("of the whole image", await control.ReanalyzeNative(native.Id));
        Assert.Null(engine.Reanalyses[0].Start);
        Assert.Equal(600, engine.Reanalyses[0].Seconds);
        foreach (var call in new Func<Task<string>>[]
                 {
                     () => control.ReanalyzeNative(native.Id, options: ["AF_FLIRT"]),
                     () => control.ReanalyzeNative(native.Id, analyzers: true, options: ["AF_FLIRT=1"]),
                     () => control.ReanalyzeNative(native.Id, end: "rva:0x1000"),
                     () => control.ReanalyzeNative(native.Id, start: "rva:0x1100", end: "rva:0x1000"),
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
