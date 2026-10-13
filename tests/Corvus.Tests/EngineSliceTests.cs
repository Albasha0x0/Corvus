using System.Diagnostics;
using System.Text.Json;
using Corvus.Core;
using Corvus.Native;
using Corvus.Native.Calls;
using Corvus.Native.Code;
using Corvus.Native.Providers;
using Corvus.Native.Providers.Ghidra;
using Corvus.Native.Providers.Ida;
using Corvus.Services;
using Corvus.Tools;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>trace_native_values over engine slices: the reply parsed, nodes completed from the built-in analysis, fallbacks; IDA and Ghidra against ours.</summary>
public sealed class EngineSliceTests(ITestOutputHelper output) : IDisposable
{
    private readonly TempDir _dir = new();
    private readonly List<IDisposable> _owned = [];

    public void Dispose()
    {
        foreach (var d in _owned) d.Dispose();
        _dir.Dispose();
    }

    [Fact]
    public void Worker_reply_parses()
    {
        using var doc = JsonDocument.Parse("""
            {"nodes": [{"kind": "merge", "rva": 4096, "text": "2 values", "why": "v1"},
                       {"kind": "constant", "rva": 4100, "text": "0x80000000", "why": "mov", "value": 2147483648},
                       {"kind": "argument", "rva": 4110, "text": "argument 2", "why": "", "site": 4110, "index": 1, "callee": "CreateFileW", "derived": true}],
             "edges": [[1, 0, "merge"]], "truncated": false, "note": null, "variable": "v1"}
            """);
        var s = WorkerRows.Slice(doc.RootElement);
        Assert.Equal(["merge", "constant", "argument"], s.Nodes.Select(n => n.Kind));
        Assert.Equal(0x80000000UL, s.Nodes[1].Value);
        Assert.Equal((1, "CreateFileW", true, 4110u), (s.Nodes[2].Index, s.Nodes[2].Callee, s.Nodes[2].Derived, s.Nodes[2].Site!.Value));
        Assert.Equal([(1, 0, "merge")], s.Edges);
        Assert.Equal("v1", s.Variable);
    }

    /// <summary>A session answering every slice with one constant, or failing for one function.</summary>
    private sealed class SliceSession(uint failing) : INativeDecompilerSession
    {
        public List<EngineSliceRequest> Requests { get; } = [];
        public string ProviderId => "ida";
        public string ImagePath => "";
        public string Sha256 => "";
        public NativeArch Arch => NativeArch.X64;
        public ulong ImageBase => 0;
        public bool ReusedDatabase => true;
        public TimeSpan OpenTime => TimeSpan.Zero;
        public bool DecompilerAvailable => true;
        public bool IsOpen => true;

        public Task<EngineSlice> ValueSliceAsync(EngineSliceRequest request, CancellationToken cancellationToken = default)
        {
            Requests.Add(request);
            if (request.Function == failing) throw new ToolError(ErrorCode.Failed, "decompilation failed: fake");
            if (request.Seed == "parameter" && !request.Forward)
                return Task.FromResult(new EngineSlice([new EngineSliceNode("parameter", request.Rva, "parameter", "engine") { Index = request.Index }], [], false, null, "a1"));
            return Task.FromResult(new EngineSlice([new EngineSliceNode("constant", request.Rva, "0x2A", "engine") { Value = 42 }], [], false, null, "v7"));
        }

        public Task<IReadOnlyList<NativeFunctionInfo>> ListFunctionsAsync(CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public Task<DecompiledFunction> DecompileAsync(uint rva, CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public Task<FunctionDisassembly> DisassembleAsync(uint rva, CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public Task<IReadOnlyList<NativeXref>> GetXrefsToAsync(uint rva, CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public Task<IReadOnlyList<NativeXref>> GetXrefsFromAsync(uint rva, bool wholeFunction = false, CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public Task<string> SetNameAsync(uint rva, string name, CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public Task<string> SetCommentAsync(uint rva, string text, bool repeatable = false, CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public Task<NameBatchResult> ApplyNamesAsync(IReadOnlyList<NativeNameItem> items, string? stampKey = null, string? stamp = null, bool save = false,
            CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public Task<string?> GetStampAsync(string key, CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public Task SaveAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task CloseAsync(bool save = true, CancellationToken cancellationToken = default) => Task.CompletedTask;
        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
        public void Dispose() { }
    }

    [Fact]
    public async Task Engine_slices_compose_across_functions_and_fall_back_per_function()
    {
        var options = new ServerOptions { BackgroundIndexing = false };
        using var ws = new AssemblyWorkspace(options);
        var code = new NativeCodeService(ws, options, null, new Native.Annotations.AnnotationStore(_dir.File("ann")));
        var native = ws.LoadAny(FunctionDossierTests.Sample(_dir)).Native!;
        var index = await code.Index(native, null, default);
        var a = CallAnalysis.For(index);
        uint helper = index.AddressOfName("Helper")!.Value, main = index.AddressOfName("Main")!.Value;
        var site = a.CallsIn(index.FunctionByStart(helper)!).Single().Rva;

        // the argument slice comes from the engine, as a request by argument index
        var session = new SliceSession(failing: uint.MaxValue);
        var provider = new EngineSliceProvider(a, session);
        var seed = NativeTraceTools.Seed(a, NativeAddress.Va(index.Image, site), null, "2", default);
        var g = ValueTrace.Build(a, seed, new ValueTraceOptions(MaxDepth: 1), provider);
        Assert.Equal("ida", g.Engine);
        Assert.Equal(("argument", 1), (session.Requests[0].Seed, session.Requests[0].Index));
        Assert.Contains(g.Values, v => v.Text.StartsWith("0x2A = FILE_WRITE_DATA", StringComparison.Ordinal)); // decoded through dwDesiredAccess
        Assert.Equal((1, 0), (provider.EngineSlices, provider.Fallbacks));
        // the same trace again reuses the graph and a fresh provider counts nothing: the note still says what built it (E2)
        var note = NativeTraceTools.SliceNote(g, provider);
        var again = new EngineSliceProvider(a, session);
        var g1 = ValueTrace.Build(a, seed, new ValueTraceOptions(MaxDepth: 1), again);
        Assert.Same(g, g1);
        Assert.Equal((0, 0), (again.EngineSlices, again.Fallbacks));
        Assert.Equal("ida answered 1 slice; 0 slices fell back to the built-in analysis", note);
        Assert.Equal(note, NativeTraceTools.SliceNote(g1, again));

        // a stack-slot location is not one the engine names: the built-in slice answers it, and says so
        var stack = NativeTraceTools.Seed(a, NativeAddress.Va(index.Image, site), "[rsp+20h]", null, default);
        var g2 = ValueTrace.Build(a, stack, new ValueTraceOptions(), provider);
        Assert.Contains(g2.Values, v => v.Text.StartsWith('3'));
        Assert.Contains(g2.Notes, n => n.Contains("ida: the seed [rsp+20h] is not a register or argument the engine names; built-in slice", StringComparison.Ordinal));

        // an engine failure on one function falls back for that function only
        var failing = new SliceSession(failing: main);
        var p3 = new EngineSliceProvider(a, failing);
        var param = NativeTraceTools.Seed(a, NativeAddress.Va(index.Image, helper), null, "1", default);
        var g3 = ValueTrace.Build(a, param, new ValueTraceOptions(MaxDepth: 1), p3);
        Assert.Contains(g3.Values, v => v.Text.Contains("config.ini", StringComparison.Ordinal)); // Main's slice: built-in
        Assert.Contains(g3.Notes, n => n.Contains("decompilation failed: fake; built-in slice", StringComparison.Ordinal));
        Assert.Equal(1, p3.Fallbacks);
    }

    private (AssemblyWorkspace Workspace, NativeCodeService Code, NativeEngineService Engines) Rig()
    {
        var options = new ServerOptions { TimeoutSeconds = 600, BackgroundIndexing = false };
        var ws = new AssemblyWorkspace(options);
        var code = new NativeCodeService(ws, options, null, new Native.Annotations.AnnotationStore(_dir.File("ann")));
        var cache = _dir.File("cache");
        var engines = new NativeEngineService(new IdaProviderOptions { CacheRoot = cache }, code, ws, options, new GhidraProviderOptions { CacheRoot = cache });
        _owned.Add(engines);
        _owned.Add(ws);
        return (ws, code, engines);
    }

    /// <summary>
    /// Constant API arguments: for call sites in a system DLL whose argument the built-in slice resolves to constants, the
    /// engine's slice of the same argument (depth 0) gives the same constants. Counts are written to the output.
    /// </summary>
    private async Task ConstantsAgree(string engine)
    {
        var (ws, code, engines) = Rig();
        var path = Path.Combine(Directory.CreateDirectory(_dir.File("input")).FullName, Path.GetFileName(NativeIdaProviderTests.System64));
        File.Copy(NativeIdaProviderTests.System64, path);
        var native = ws.LoadAny(path).Native!;
        var index = await code.Index(native, null, default);
        var a = CallAnalysis.For(index);
        var session = await engines.Session(native, engine, null, default);
        await new NativeNamePush(code).EnsureAsync(native, session, default);
        var provider = new EngineSliceProvider(a, session);
        int compared = 0, agree = 0, partial = 0, engineOnly = 0;
        var clock = Stopwatch.StartNew();
        var sites = index.Functions.Where(f => f.ThunkImport == null).SelectMany(f => a.CallsIn(f))
            .Where(c => c.Kind == CalleeKind.Import && c.Signature != null && c.Arguments.Any(x => x.Kind == ArgKind.Immediate)).Take(30).ToList();
        var misses = new List<string>();
        foreach (var c in sites)
            foreach (var arg in c.Arguments.Where(x => x.Kind == ArgKind.Immediate && x.Index < 4))
            {
                var seed = NativeTraceTools.Seed(a, NativeAddress.Va(index.Image, c.Rva), null, (arg.Index + 1).ToString(System.Globalization.CultureInfo.InvariantCulture), default);
                var options = new ValueTraceOptions(MaxDepth: 0);
                var ours = ValueTrace.Build(a, seed, options).Nodes.Where(n => n.Kind == TraceNodeKind.Const).Select(n => n.Value).ToHashSet();
                var theirs = ValueTrace.Build(a, seed, options, provider).Nodes.Where(n => n.Kind == TraceNodeKind.Const).Select(n => n.Value).ToHashSet();
                compared++;
                if (ours.SetEquals(theirs)) agree++;
                else if (ours.Overlaps(theirs)) partial++;
                else misses.Add($"{c.Display} arg {arg.Index + 1}: ours {string.Join(",", ours)} vs {engine} {string.Join(",", theirs)}");
                if (!ours.IsSupersetOf(theirs)) engineOnly++;
            }
        output.WriteLine($"{engine}: {compared} constant arguments at {sites.Count} API call sites: {agree} agree, {partial} overlap, {misses.Count} differ " +
                         $"({engineOnly} with constants only the engine has); {provider.EngineSlices} engine slices, {provider.Fallbacks} fallbacks, {clock.Elapsed.TotalSeconds:0.0} s");
        foreach (var m in misses.Take(10)) output.WriteLine("  " + m);
        Assert.True(compared >= 15, $"only {compared} arguments compared");
        Assert.True(agree + partial >= compared * 0.8, $"{agree + partial} of {compared} agree");
        Assert.True(provider.EngineSlices >= compared * 0.8, $"{provider.EngineSlices} engine slices for {compared} arguments");

        // forward: a function's first parameter reaches the same API arguments
        var withParam = index.Functions.Where(f => f.ThunkImport == null && a.CallsIn(f).Count(x => x.Kind == CalleeKind.Import) >= 2).Take(10).ToList();
        int forwardCompared = 0, forwardAgree = 0;
        foreach (var f in withParam)
        {
            var seed = NativeTraceTools.Seed(a, NativeAddress.Va(index.Image, f.Start), null, "1", default);
            var options = new ValueTraceOptions(TraceDirection.Forward, MaxDepth: 0);
            var ours = ValueTrace.Build(a, seed, options).Nodes.Where(n => n.Kind is TraceNodeKind.Sink or TraceNodeKind.Argument).Select(n => n.Address).ToHashSet();
            if (ours.Count == 0) continue;
            var theirs = ValueTrace.Build(a, seed, options, provider).Nodes.Where(n => n.Kind is TraceNodeKind.Sink or TraceNodeKind.Argument).Select(n => n.Address).ToHashSet();
            forwardCompared++;
            if (ours.Overlaps(theirs)) forwardAgree++;
        }
        output.WriteLine($"{engine}: forward from parameter 1 in {forwardCompared} functions: {forwardAgree} reach a call site ours reaches");
        Assert.True(forwardAgree >= forwardCompared / 2, $"forward: {forwardAgree} of {forwardCompared}");

        // across functions: parameters bound to callers' arguments, call results to the callee's returned values
        int before = provider.Fallbacks, crossCompared = 0, crossAgree = 0;
        var called = index.Functions.Where(f => f.ThunkImport == null && index.Callers(f, CallEdgeFilter.Direct).Count(c => c.Kind == XrefKind.Call) is >= 1 and <= 4).Take(12).ToList();
        foreach (var f in called)
        {
            var options = new ValueTraceOptions(MaxDepth: 1, MaxFunctions: 8);
            foreach (var seed in new[]
                     {
                         NativeTraceTools.Seed(a, NativeAddress.Va(index.Image, f.Start), null, "1", default),
                         NativeTraceTools.Seed(a, NativeAddress.Va(index.Image, index.Callers(f).First(c => c.Kind == XrefKind.Call).From), "result", null, default),
                     })
            {
                var ours = ValueTrace.Build(a, seed, options).Values.Select(v => v.Text).ToHashSet();
                var graph = ValueTrace.Build(a, seed, options, provider);
                foreach (var note in graph.Notes.Where(n => n.Contains("built-in slice", StringComparison.Ordinal)).Take(2)) output.WriteLine("  fallback: " + note);
                var theirs = graph.Values.Select(v => v.Text).ToHashSet();
                if (ours.Count == 0) continue;
                crossCompared++;
                if (ours.Overlaps(theirs)) crossAgree++;
            }
        }
        output.WriteLine($"{engine}: across one function boundary: {crossCompared} traces with values, {crossAgree} share a value with ours; " +
                         $"{provider.Fallbacks - before} slices fell back");
        Assert.True(crossAgree >= crossCompared / 2, $"cross-function: {crossAgree} of {crossCompared}");

        // a register at an ordinary instruction: the result register read after a call
        int located = 0, placed = 0;
        before = provider.Fallbacks;
        foreach (var c in index.Functions.Where(f => f.ThunkImport == null).SelectMany(f => a.CallsIn(f)).Where(x => x.Kind == CalleeKind.Import && !x.TailCall))
        {
            var fc = a.Code(c.Caller, default);
            var (b, i) = fc.Position(c.Rva);
            if (b < 0) continue;
            var (nb, ni) = fc.Position(c.Rva + (uint)fc.Blocks[b][i].I.Length); // a call may end its block
            if (nb < 0) continue;
            var next = fc.Blocks[nb][ni];
            if (located >= 20 || next.I.OpCount < 2 || next.I.Op1Kind != Iced.Intel.OpKind.Register || Iced.Intel.RegisterExtensions.GetFullRegister(next.I.Op1Register) != Iced.Intel.Register.RAX) continue;
            var seed = NativeTraceTools.Seed(a, NativeAddress.Va(index.Image, next.Rva), "rax", null, default);
            int engineBefore = provider.EngineSlices;
            var graph = ValueTrace.Build(a, seed, new ValueTraceOptions(MaxDepth: 0), provider);
            located++;
            if (provider.EngineSlices > engineBefore && graph.Nodes.Any(n => n.Kind is TraceNodeKind.ApiResult or TraceNodeKind.CallResult)) placed++;
            else output.WriteLine($"  not placed at {NativeAddress.Va(index.Image, next.Rva)} {next.I}: {string.Join("; ", graph.Notes)} | {string.Join(", ", graph.Nodes.Select(n => n.Kind + ":" + n.Text))}");
        }
        output.WriteLine($"{engine}: rax read after {located} API calls: the engine placed {placed} as the call's result; {provider.Fallbacks - before} fell back");
        Assert.True(placed >= located / 2, $"location: {placed} of {located}");
    }

    /// <summary>ARM64 (an ELF from the runtime packages): constant call arguments through the engine against the built-in AAPCS64 slices.</summary>
    private async Task Arm64ConstantsAgree(string engine)
    {
        var (ws, code, engines) = Rig();
        var native = ws.LoadAny(NativeFormats.NativeFixtures.LinuxArm64DbgShim).Native!;
        var index = await code.Index(native, null, default);
        var a = Arm64Trace.For(index);
        var session = await engines.Session(native, engine, null, default);
        var provider = new EngineSliceProvider(a, session);
        var sites = index.Functions.SelectMany(f => a.Calls.CallsIn(f)).Where(c => c.Arguments.Any(x => x.Kind == ArgKind.Immediate && x.Index < 8)).Take(25).ToList();
        int compared = 0, agree = 0;
        foreach (var c in sites)
            foreach (var arg in c.Arguments.Where(x => x.Kind == ArgKind.Immediate && x.Index < 8))
            {
                var seed = NativeTraceTools.Arm64Seed(a, NativeAddress.Va(index.Image, c.Rva), null, (arg.Index + 1).ToString(System.Globalization.CultureInfo.InvariantCulture), default);
                var ours = ValueTrace.Build(a, seed, new ValueTraceOptions(MaxDepth: 0)).Nodes.Where(n => n.Kind == TraceNodeKind.Const).Select(n => n.Value).ToHashSet();
                var theirs = ValueTrace.Build(a, seed, new ValueTraceOptions(MaxDepth: 0), provider).Nodes.Where(n => n.Kind == TraceNodeKind.Const).Select(n => n.Value).ToHashSet();
                compared++;
                if (ours.Overlaps(theirs)) agree++;
                else output.WriteLine($"  {c.Display} arg {arg.Index + 1} [{(c.Signature != null ? "signature" : "guessed")}]: ours {string.Join(",", ours)} vs {string.Join(",", theirs)}");
            }
        output.WriteLine($"{engine} ARM64: {compared} constant arguments at {sites.Count} call sites: {agree} agree; {provider.EngineSlices} engine slices, {provider.Fallbacks} fallbacks");
        Assert.True(compared >= 10, $"only {compared} arguments compared");
        Assert.True(agree >= compared * 0.7, $"{agree} of {compared} agree");
        Assert.True(provider.EngineSlices >= compared / 2, $"{provider.EngineSlices} engine slices");
    }

    [IdaFact]
    [Trait("Speed", "Slow")]
    public Task Ida_microcode_slices_agree_on_arm64() => Arm64ConstantsAgree("ida");

    [GhidraFact]
    [Trait("Speed", "Slow")]
    public Task Ghidra_pcode_slices_agree_on_arm64() => Arm64ConstantsAgree("ghidra");

    [IdaFact]
    [Trait("Speed", "Slow")]
    public Task Ida_microcode_slices_agree_with_ours() => ConstantsAgree("ida");

    [GhidraFact]
    [Trait("Speed", "Slow")]
    public Task Ghidra_pcode_slices_agree_with_ours() => ConstantsAgree("ghidra");
}
