using System.Diagnostics;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Mcp;
using NetDecompilerMcp.Native;
using NetDecompilerMcp.Native.Providers;
using NetDecompilerMcp.Native.Providers.Ida;
using NetDecompilerMcp.Services;
using NetDecompilerMcp.Tools;
using Xunit.Abstractions;

namespace NetDecompilerMcp.Tests;

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

    [IdaFact]
    public Task Ida() => Run("ida");

    [GhidraFact]
    public Task Ghidra() => Run("ghidra");

    private async Task Run(string engine)
    {
        var rig = await Setup();
        var id = rig.Native.Id;
        var clock = Stopwatch.StartNew();

        // search_decompiled: hits, then the cursor continues where the first call stopped
        var collector = StructuredOutput.Begin();
        var first = await rig.Search.SearchDecompiled(id, @"\breturn\b", engine: engine, limit: 5);
        var report = Assert.IsType<NativeSearchDecompiledTools.SearchDecompiledReport>(collector.Value);
        output.WriteLine($"{engine} search ({clock.Elapsed.TotalSeconds:0.0} s with the analysis):\n{string.Join('\n', first.Split('\n').Take(6))}");
        Assert.Equal(engine, report.Engine);
        Assert.InRange(report.Hits.Count, 5, 400);
        Assert.Equal("hits", report.StoppedBy);
        collector = StructuredOutput.Begin();
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
        collector = StructuredOutput.Begin();
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
