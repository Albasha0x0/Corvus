using System.Diagnostics;
using Corvus.Core;
using Corvus.Mcp;
using Corvus.Native;
using Corvus.Native.Providers;
using Corvus.Native.Providers.Ida;
using Corvus.Services;
using Corvus.Tools;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>
/// Pseudocode search, callers decompiled, reanalysis, function candidates and note marks through a real IDA and Ghidra on a
/// scratch copy of a system DLL.
/// </summary>
[Trait("Speed", "Slow")]
public sealed class EngineControlRealTests(ITestOutputHelper output) : IDisposable
{
    private readonly TempDir _dir = new();
    private readonly List<IDisposable> _owned = [];

    public void Dispose()
    {
        foreach (var d in _owned) d.Dispose();
        _dir.Dispose();
    }

    private sealed record Rig(AssemblyWorkspace Workspace, NativeCodeService Code, NativeEngineService Engines, NativeCodeTools CodeTools, NativeAnalysisTools Analysis,
        NativeSearchDecompiledTools Search, NativeEngineControlTools Control, NativeEditTools Edits, NotesService Notes, LoadedNative Native);

    private async Task<Rig> Setup()
    {
        var options = new ServerOptions { TimeoutSeconds = 600, BackgroundIndexing = false };
        var workspace = new AssemblyWorkspace(options);
        var store = new Native.Annotations.AnnotationStore(_dir.File("annotations"));
        var code = new NativeCodeService(workspace, options, null, store);
        var engines = new NativeEngineService(new IdaProviderOptions { CacheRoot = _dir.File("cache") }, code, workspace, options);
        _owned.Add(engines);
        _owned.Add(workspace);
        var pager = new OutputPager(options);
        var names = new NativeNamePush(code);
        var notes = new NotesService(store);
        var dir = Directory.CreateDirectory(_dir.File("input")).FullName;
        var copy = Path.Combine(dir, Path.GetFileName(NativeIdaProviderTests.System64));
        File.Copy(NativeIdaProviderTests.System64, copy, overwrite: true);
        var native = workspace.LoadAny(copy).Native!;
        await code.Index(native, null, default);
        return new Rig(workspace, code, engines, new NativeCodeTools(workspace, code, pager, null, engines, names),
            new NativeAnalysisTools(workspace, engines, pager, names, code, new NativeTypePush(), new NativeUserTypePush(code), notes),
            new NativeSearchDecompiledTools(workspace, engines, pager, code, names), new NativeEngineControlTools(workspace, engines, pager, code),
            new NativeEditTools(workspace, code, new NativeEditService(workspace, code), null, engines, names), notes, native);
    }

    /// <summary>The open's stage profile, cold (a new cache) and warm (the saved database), on notepad.exe and dbghelp.dll copies.</summary>
    [GhidraFact]
    public Task Open_stages_Ghidra() => OpenStages("ghidra");

    [IdaFact]
    public Task Open_stages_Ida() => OpenStages("ida");

    private async Task OpenStages(string engine)
    {
        foreach (var name in new[] { "notepad.exe", "dbghelp.dll" })
        {
            var cache = _dir.File("profile-cache-" + engine);
            foreach (var pass in new[] { "cold", "warm" })
            {
                var options = new ServerOptions { TimeoutSeconds = 1200, BackgroundIndexing = false };
                using var workspace = new AssemblyWorkspace(options);
                using var engines = new NativeEngineService(new IdaProviderOptions { CacheRoot = cache }, null, workspace, options);
                var dir = Directory.CreateDirectory(_dir.File($"profile-{engine}-{pass}")).FullName;
                var copy = Path.Combine(dir, name);
                File.Copy(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32", name), copy, overwrite: true);
                var native = workspace.LoadAny(copy).Native!;
                var clock = Stopwatch.StartNew();
                await engines.Session(native, engine, null, default);
                var stages = engines.ImageSessions(native).Single(s => s.Engine == engine).OpenStages;
                output.WriteLine($"{engine} {name} {pass}: {clock.Elapsed.TotalSeconds:0.0} s: {EngineOpenProfile.Describe(stages)}");
                Assert.Equal(["prepare", "start"], stages.Take(2).Select(s => s.Stage));
                Assert.Equal("pdb types", stages[^1].Stage);
            }
        }
    }

    /// <summary>A Ghidra open whose analysis budget runs out: lookups that fail say so and name reanalyze_native, which completes the analysis.</summary>
    [GhidraFact]
    public async Task A_partial_Ghidra_analysis_points_at_reanalysis_which_completes_it()
    {
        var dir = Directory.CreateDirectory(_dir.File("partial")).FullName;
        var copy = Path.Combine(dir, "dbghelp.dll");
        File.Copy(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32", "dbghelp.dll"), copy, overwrite: true);
        using var provider = new Native.Providers.Ghidra.GhidraProvider(new Native.Providers.Ghidra.GhidraProviderOptions { CacheRoot = _dir.File("partial-cache") });
        await using var session = (Native.Providers.Ghidra.GhidraSession)await provider.OpenAsync(copy, null,
            new NativeOpenOptions { Symbols = SymbolMode.Off, AnalysisBudget = TimeSpan.FromSeconds(1) }); // seconds short of a full analysis, however fast the machine
        Assert.False(session.AnalysisComplete);
        var e = await Assert.ThrowsAsync<ToolError>(() => session.DecompileAsync(0x10)); // the headers: in no function
        Assert.Equal(ErrorCode.NotFound, e.Code);
        Assert.Contains("is partial (the open's budget ran out): reanalyze_native image=dbghelp.dll engine=ghidra completes it", e.Remediation);
        var clock = Stopwatch.StartNew();
        var r = await EngineControl.Of(session)!.ReanalyzeAsync([], null, null, 900);
        output.WriteLine($"resumed in {clock.Elapsed.TotalSeconds:0.0} s: complete {r.Complete}, functions {r.FunctionsBefore} -> {r.FunctionsAfter}");
        Assert.True(r.Complete);
        Assert.True(session.AnalysisComplete);
        Assert.True(r.FunctionsAfter >= r.FunctionsBefore);
        e = await Assert.ThrowsAsync<ToolError>(() => session.DecompileAsync(0x10));
        Assert.DoesNotContain("partial", e.Remediation ?? "");
    }

    [IdaFact]
    public Task Ida() => Run("ida");

    [GhidraFact]
    public Task Ghidra() => Run("ghidra");

    private async Task Run(string engine)
    {
        var rig = await Setup();
        var id = rig.Native.Id;
        var clock = Stopwatch.StartNew();

        // search_decompiled: hits, then the cursor continues where the first call stopped. The engine opens first: the
        // search's time budget would otherwise go to the analysis, all of it on a busy machine.
        await rig.Engines.Session(rig.Native, engine, null, default);
        output.WriteLine($"{engine} opened in {clock.Elapsed.TotalSeconds:0.0} s");
        clock.Restart();
        var collector = ToolOutput.Collect();
        var first = await rig.Search.SearchDecompiled(id, @"\breturn\b", engine: engine, limit: 5);
        var report = Assert.IsType<NativeSearchDecompiledTools.SearchDecompiledReport>(collector.Value);
        output.WriteLine($"{engine} search ({clock.Elapsed.TotalSeconds:0.0} s):\n{string.Join('\n', first.Split('\n').Take(6))}");
        Assert.Equal(engine, report.Engine);
        Assert.InRange(report.Hits.Count, 5, 400);
        Assert.Equal("hits", report.StoppedBy);
        collector = ToolOutput.Collect();
        clock.Restart();
        await rig.Search.SearchDecompiled(id, @"\breturn\b", engine: engine, cursor: report.Cursor!.Value, maxFunctions: 40, limit: 2000);
        var next = Assert.IsType<NativeSearchDecompiledTools.SearchDecompiledReport>(collector.Value);
        output.WriteLine($"{engine} 40 functions from cursor {report.Cursor}: {next.Hits.Count} hits in {clock.Elapsed.TotalSeconds:0.0} s");
        Assert.Equal(report.Cursor, next.From);
        Assert.True(string.CompareOrdinal(next.Hits[0].Function, report.Hits[^1].Function) > 0);

        // callersOf: a function with callers inside the image
        var session = await rig.Engines.Session(rig.Native, engine, null, default);
        uint? callee = null;
        foreach (var f in (await session.ListFunctionsAsync()).Where(f => (f.Flags & NativeFunctionFlags.Thunk) == 0).Take(400))
            if ((await session.GetXrefsToAsync(f.StartRva)).Any(x => x.Kind == NativeXrefKind.Call && x.FromFunctionRva is { } c && c != f.StartRva))
            {
                callee = f.StartRva;
                break;
            }
        Assert.NotNull(callee);
        var callers = await rig.Analysis.DecompileNative(id, engine: engine, callersOf: $"rva:0x{callee:X}");
        output.WriteLine($"{engine} callersOf: {callers.Split('\n')[0]}");
        Assert.Matches(@"// \d+ inputs?: [1-9]\d* decompiled", callers);

        // notes become engine marks (Ghidra bookmarks, IDA marked positions), replaced as the notes change
        rig.Notes.Record("checks the certificate table", "finding", null, new NoteAnchor(NoteAnchor.Native, rig.Native.OriginalSha256.ToLowerInvariant(), Rva: callee), null, null, null);
        var marked = await rig.Analysis.DecompileNative(id, $"rva:0x{callee:X}", engine: engine);
        Assert.Contains($"// notes: 1 mark(s) in {engine}", marked);
        rig.Notes.Record("second note", "question", null, new NoteAnchor(NoteAnchor.Native, rig.Native.OriginalSha256.ToLowerInvariant(), Rva: callee + 1), null, null, null);
        var remarked = await rig.Analysis.DecompileNative(id, $"rva:0x{callee:X}", engine: engine, addresses: true);
        Assert.Contains($"// notes: 2 mark(s) in {engine}", remarked);
        var control = EngineControl.Of(session)!;
        var again = await control.SetMarksAsync([new NativeMark(callee!.Value, "only")], "test");
        Assert.Equal((1, 2, 0), (again.Set, again.Removed, again.Failed)); // the two earlier marks were replaced, not added to

        // list_functions view=candidates: the engine's code outside functions
        clock.Restart();
        collector = ToolOutput.Collect();
        var candidates = await rig.CodeTools.ListFunctions(id, engine: engine, view: "candidates", limit: 5);
        var candidateList = Assert.IsType<FunctionList>(collector.Value);
        output.WriteLine($"{engine} candidates ({clock.Elapsed.TotalSeconds:0.0} s):\n{string.Join('\n', candidates.Split('\n').Take(5))}");
        Assert.Contains("runs of code in no function", candidates);
        Assert.Equal(engine, candidateList.Engine);
        Assert.All(candidateList.Items, c => Assert.Contains("candidate", c.Flags));

        // reanalyze_native: the analyzer list, then a run over one function's range
        var analyzers = await rig.Control.ReanalyzeNative(id, engine: engine, analyzers: true);
        Assert.Contains(engine == "ida" ? "AF_FLIRT = " : "Decompiler Parameter ID = ", analyzers);
        clock.Restart();
        var run = await rig.Control.ReanalyzeNative(id, engine: engine, start: $"rva:0x{callee:X}", end: $"rva:0x{callee + 0x40:X}", seconds: 120,
            options: [engine == "ida" ? "AF_FLIRT=false" : "Decompiler Parameter ID=false"]);
        output.WriteLine($"{engine} reanalysis {clock.Elapsed.TotalSeconds:0.0} s:\n{run}");
        Assert.Contains("Complete: the analysis queue ran empty.", run);
        Assert.DoesNotContain("Warning:", run);
        Assert.Contains(engine == "ida" ? "AF_FLIRT = true" : "Decompiler Parameter ID = ", await rig.Control.ReanalyzeNative(id, engine: engine, analyzers: true));
    }
}
