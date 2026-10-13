using Corvus.Core;
using Corvus.Native;
using Corvus.Native.Providers;
using Corvus.Native.Providers.Ghidra;
using Corvus.Services;
using Corvus.Tools;

namespace Corvus.Tests;

/// <summary>The engine read views (status, data, strings, function records, namespaces, call sites) over a fake engine.</summary>
public sealed class EngineViewTests : IDisposable
{
    private readonly TempDir _dir = new();
    private readonly List<IDisposable> _owned = [];

    public void Dispose()
    {
        foreach (var d in _owned) d.Dispose();
        _dir.Dispose();
    }

    internal sealed record Rig(AssemblyWorkspace Workspace, NativeCodeService Code, NativeCodeTools Tools, NativeEngineService Engines, string Image, ViewProvider Provider);

    private Rig Setup()
    {
        var options = new ServerOptions { BackgroundIndexing = false };
        var workspace = new AssemblyWorkspace(options);
        var code = new NativeCodeService(workspace, options, null, new Native.Annotations.AnnotationStore(_dir.File("annotations")));
        var provider = new ViewProvider();
        var engines = new NativeEngineService([provider], _dir.File("cache"), code, workspace, options);
        _owned.Add(engines);
        _owned.Add(workspace);
        return new Rig(workspace, code, new NativeCodeTools(workspace, code, new OutputPager(options), null, engines), engines, McpProtocolTests.NativeSample(_dir), provider);
    }

    private static async Task<LoadedNative> Loaded(Rig rig)
    {
        await rig.Tools.ListFunctions(rig.Image, engine: "ours");
        return rig.Workspace.Read(() => rig.Workspace.Natives[0]);
    }

    /// <summary>A call waiting for an open hears from it every few seconds while a stage lasts (S9.2), not only when the stage changes.</summary>
    [Fact]
    public async Task A_wait_for_an_open_sends_progress_while_a_stage_lasts()
    {
        var rig = Setup();
        var native = await Loaded(rig);
        rig.Engines.OpenHeartbeat = TimeSpan.FromMilliseconds(40);
        rig.Provider.Gate = new TaskCompletionSource();
        var reports = new System.Collections.Concurrent.ConcurrentQueue<NativeProviderProgress>();
        var opening = rig.Engines.Session(native, "ghidra", new SyncProgress(reports.Enqueue), default);
        await rig.Provider.Reported.Task;
        var until = DateTime.UtcNow.AddSeconds(5);
        while (reports.Count(r => r.Stage.Contains("waiting", StringComparison.Ordinal)) < 3 && DateTime.UtcNow < until) await Task.Delay(20);
        Assert.True(reports.Count(r => r.Stage.StartsWith("analysis, waiting", StringComparison.Ordinal)) >= 3, string.Join("; ", reports.Select(r => r.Stage)));
        rig.Provider.Gate.SetResult();
        await opening;
    }

    /// <summary>A call whose deadline comes during an engine's open gets a timeout that says the open goes on; the retry picks the same open up (EL-5).</summary>
    [Fact]
    public async Task A_deadline_during_an_open_is_a_timeout_and_the_retry_joins_the_open()
    {
        var rig = Setup();
        var native = await Loaded(rig);
        rig.Provider.Gate = new TaskCompletionSource();
        using var deadline = new CancellationTokenSource(TimeSpan.FromMilliseconds(300));
        var e = await Assert.ThrowsAsync<ToolError>(() => rig.Engines.Session(native, "ghidra", null, deadline.Token));
        Assert.Equal(ErrorCode.Timeout, e.Code);
        Assert.Contains("goes on in the background", e.Message);
        Assert.Contains("server_status", e.Remediation);
        Assert.Equal(TimeSpan.FromSeconds(30), e.RetryAfter);
        var retry = rig.Engines.Session(native, "ghidra", null, default);
        rig.Provider.Gate.SetResult();
        await retry;
        Assert.Equal(1, rig.Provider.Opens);
    }

    private sealed class SyncProgress(Action<NativeProviderProgress> report) : IProgress<NativeProviderProgress>
    {
        public void Report(NativeProviderProgress value) => report(value);
    }

    [Fact]
    public async Task Engine_status_reports_not_started_opening_with_its_stage_and_open_with_the_engine_view()
    {
        var rig = Setup();
        var native = await Loaded(rig);
        var tool = new NativeEngineStatusTools(rig.Workspace, rig.Engines);
        var before = await tool.GetEngineStatus(rig.Image);
        Assert.Contains("Ghidra: not started", before);
        Assert.Equal(0, rig.Provider.Opens);

        rig.Provider.Gate = new TaskCompletionSource();
        var opening = rig.Engines.Session(native, "ghidra", null, default);
        await rig.Provider.Reported.Task;
        var during = await tool.GetEngineStatus(rig.Image, "ghidra");
        Assert.Contains("Ghidra: opening (analysis, ", during);

        rig.Provider.Gate.SetResult();
        await opening;
        var (open, call) = await EngineMeta.Run(() => tool.GetEngineStatus(rig.Image));
        Assert.Contains("Ghidra 12.1: open, analysis complete", open);
        Assert.Contains("profile full", open);
        var ghidra = Assert.IsType<NativeEngineStatusTools.EngineStatusReport>(call.Record).Engines.Single(e => e.Engine == "ghidra");
        Assert.Equal(("full", null), (ghidra.Profile, ghidra.Limitations));
        Assert.Contains("x86 x86:LE:64:default, compiler windows, PE, 64-bit little", open);
        Assert.Contains("input: sha256 abc, md5 d41d", open);
        Assert.Contains(".text", open);
        Assert.Equal(1, rig.Provider.Opens);
        Assert.Equal(ErrorCode.InvalidArgument, (await Assert.ThrowsAsync<ToolError>(() => tool.GetEngineStatus(rig.Image, "bogus"))).Code);
    }

    [Fact]
    public async Task List_globals_with_an_engine_adds_its_defined_data_with_types_and_values()
    {
        var rig = Setup();
        await Loaded(rig);
        var ours = await rig.Tools.ListGlobals(rig.Image);
        Assert.Contains("Engine: ours", ours);
        Assert.DoesNotContain("g_engine_table", ours);
        var text = await rig.Tools.ListGlobals(rig.Image, engine: "ghidra");
        Assert.Contains("(5 defined by Ghidra, the first 4 read)", text);
        Assert.DoesNotContain("dup(0CCh)", text);
        Assert.DoesNotContain("align 10h", text);
        Assert.Contains("Engine: ghidra", text);
        Assert.Matches(@"0x[0-9A-F]+3000  g_engine_table  pointer  8 bytes  \S+  \(ghidra\)  = 180001000h", text);
        Assert.Matches(@"0x[0-9A-F]+3010  data_3010  string  6 bytes  \S+  \(ghidra\)  = ""hello""", text);
        Assert.Contains("g_engine_table", await rig.Tools.ListGlobals(rig.Image, filter: "engine_t", engine: "ghidra"));
    }

    [Fact]
    public async Task Native_strings_with_an_engine_add_the_strings_only_it_defined()
    {
        var rig = Setup();
        await Loaded(rig);
        Assert.DoesNotContain("only in the engine", await rig.Tools.SearchNativeStrings(rig.Image));
        var text = await rig.Tools.SearchNativeStrings(rig.Image, "engine", engine: "ghidra");
        Assert.Contains("Engine: ghidra", text);
        Assert.Matches(@"0x[0-9A-F]+3020  ghidra:utf8 ""only in the engine""  0 refs", text);
        Assert.DoesNotContain("zzz", text);
    }

    [Fact]
    public async Task An_exact_name_and_the_dossier_show_the_engine_function_record_of_an_open_session()
    {
        var rig = Setup();
        var native = await Loaded(rig);
        var first = (await rig.Code.Index(native, null, default)).AddressOfName("First")!.Value;
        rig.Provider.Functions = [new NativeFunctionInfo(first, first + 0x10, "First", NativeFunctionFlags.None)];
        var dossiers = new NativeFunctionTools(rig.Workspace, rig.Code, new OutputPager(new ServerOptions()), null, rig.Engines);
        Assert.DoesNotContain("record of", await rig.Tools.ListFunctions(rig.Image, filter: "First"));
        Assert.DoesNotContain("ghidra: prototype", await dossiers.AnalyzeNativeFunction(rig.Image, "First"));
        Assert.Equal(0, rig.Provider.Opens);

        var engine = await rig.Tools.ListFunctions(rig.Image, filter: "first", engine: "ghidra");
        Assert.Contains("Ghidra's record of First:\n  prototype: int __fastcall First(int a)\n  convention __fastcall, signature from user, callee pops 0 bytes", engine);
        Assert.Contains("  param int a in ECX:4\n  returns int in EAX:4", engine);
        Assert.DoesNotContain("record of", await rig.Tools.ListFunctions(rig.Image, filter: "Firs", engine: "ghidra"));
        // the session is open now: the built-in listing and the dossier show it too
        Assert.Contains("Ghidra's record of First", await rig.Tools.ListFunctions(rig.Image, filter: "First", engine: "ours"));
        Assert.Contains("ghidra: prototype: int __fastcall First(int a)", await dossiers.AnalyzeNativeFunction(rig.Image, "First"));
    }

    [Fact]
    public async Task Cpp_classes_from_ghidra_list_its_class_namespaces_and_on_request_the_others()
    {
        var rig = Setup();
        await Loaded(rig);
        var tools = new NativeAnalysisTools(rig.Workspace, rig.Engines, new OutputPager(new ServerOptions()));
        Assert.Contains("0 classes with RTTI", await tools.ListCppClasses(rig.Image));
        var classes = await tools.ListCppClasses(rig.Image, engine: "ghidra");
        Assert.Contains("1 class in Ghidra's namespaces", classes);
        Assert.Matches(@"class std::exception  \(3 functions\)  vftable 0x[0-9A-F]+3000", classes);
        Assert.DoesNotContain("KERNEL32", classes);
        var all = await tools.ListCppClasses(rig.Image, engine: "ghidra", namespaces: true, filter: "std");
        Assert.Contains("namespace std  (2 functions)", all);
        Assert.Contains("2 match 'std'", all);
        // engine=ida asks IDA, which this rig does not have
        Assert.Equal(Core.ErrorCode.InvalidArgument, (await Assert.ThrowsAsync<ToolError>(() => tools.ListCppClasses(rig.Image, engine: "ida"))).Code);
    }

    [Fact]
    public async Task Call_tree_both_lists_callers_and_callees_by_call_site_with_flags()
    {
        var rig = Setup();
        var native = await Loaded(rig);
        var ours = await rig.Tools.NativeCallTree(rig.Image, "First", direction: "both");
        Assert.Contains("one level, by call site", ours);
        Assert.Matches(@"callers \(\d+\):", ours);
        Assert.Matches(@"callees \(\d+\):", ours);
        Assert.Equal(0, rig.Provider.Opens);

        var first = (await rig.Code.Index(native, null, default)).AddressOfName("First")!.Value;
        rig.Provider.Functions = [new NativeFunctionInfo(first, first + 0x10, "First", NativeFunctionFlags.None),
            new NativeFunctionInfo(first + 0x100, first + 0x110, "helper", NativeFunctionFlags.None)];
        var engine = await rig.Tools.NativeCallTree(rig.Image, "First", direction: "both", engine: "ghidra");
        Assert.Contains("(via Ghidra)", engine);
        Assert.Matches(@"callers \(1\):\r?\n  0x[0-9A-F]+  \S+\+0x4  \[call, direct\]", engine);
        Assert.Matches(@"callees \(1\):\r?\n  0x[0-9A-F]+  -> \S+  0x[0-9A-F]+  \[call, direct\]", engine);
    }

    [Fact]
    public void Ghidra_scripting_is_off_unless_the_option_allows_it()
    {
        Assert.False(ServerOptions.Parse([]).GhidraScripting);
        Assert.True(ServerOptions.Parse(["--ghidra-scripting"]).GhidraScripting);
        var ghidra = ProviderAvailability.Ok("ghidra", new Dictionary<string, string>());
        var registered = new HashSet<string> { "ghidra_script" };
        var off = Assert.Single(Mcp.ToolAvailability.Of(registered, [ghidra], idaScripting: false, isWindows: true));
        Assert.Equal("ghidra_script", off.Tool);
        Assert.Contains("--ghidra-scripting", off.Remediation);
        Assert.Empty(Mcp.ToolAvailability.Of(registered, [ghidra], idaScripting: false, isWindows: true, ghidraScripting: true));
    }

    /// <summary>A Ghidra-like engine whose sessions answer the read views from fixed data.</summary>
    internal sealed class ViewProvider : INativeDecompilerProvider
    {
        public int Opens;
        public TaskCompletionSource? Gate;
        public readonly TaskCompletionSource Reported = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public IReadOnlyList<NativeFunctionInfo> Functions { get; set; } = [];

        public string Id => GhidraProvider.ProviderId;
        public string DisplayName => "fake Ghidra";
        public ProviderAvailability CheckAvailability() => ProviderAvailability.Ok(Id, new Dictionary<string, string>());
        public Task<ProviderAvailability> ProbeAsync(CancellationToken cancellationToken = default) => Task.FromResult(CheckAvailability());

        public async Task<INativeDecompilerSession> OpenAsync(string imagePath, string? sha256 = null, NativeOpenOptions? options = null, CancellationToken cancellationToken = default)
        {
            Interlocked.Increment(ref Opens);
            options?.Progress?.Report(new NativeProviderProgress("analysis", TimeSpan.FromSeconds(1)));
            await Task.Yield();
            Reported.TrySetResult();
            if (Gate != null) await Gate.Task.WaitAsync(cancellationToken);
            return new ViewSession(this, imagePath, sha256 ?? "");
        }

        public void Dispose() { }
    }

    internal sealed class ViewSession(ViewProvider provider, string path, string sha) : INativeDecompilerSession
    {
        public string ProviderId => provider.Id;
        public string ImagePath => path;
        public string Sha256 => sha;
        public NativeArch Arch => NativeArch.X64;
        public ulong ImageBase => 0x180000000;
        public bool ReusedDatabase => true;
        public TimeSpan OpenTime => TimeSpan.FromSeconds(2);
        public bool DecompilerAvailable => true;
        public bool IsOpen => true;

        public Task<EngineDataList> ListDataAsync(int max, CancellationToken cancellationToken = default) =>
            Task.FromResult(new EngineDataList(5, [new EngineDataItem(0x3000, 8, "pointer", "g_engine_table", "180001000h", false),
                new EngineDataItem(0x3010, 6, "string", null, "\"hello\"", true),
                // padding in the code section: no globals
                new EngineDataItem(0x1001, 5, "byte[5]", null, "db 5 dup(0CCh)", false), new EngineDataItem(0x1006, 10, "align", null, "align 10h", false)]));

        public Task<EngineFunctionRecord> GetFunctionRecordAsync(uint rva, CancellationToken cancellationToken = default) =>
            Task.FromResult(new EngineFunctionRecord(rva, "First", "Ns", "int __fastcall First(int a)", "__fastcall", "user", [(rva, rva + 0x10)], null, null,
                false, false, false, 0, [new EngineParameter("a", "int", "ECX:4")], "int", "EAX:4", false));

        public Task<IReadOnlyList<EngineNamespace>> ListNamespacesAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<EngineNamespace>>([new EngineNamespace("KERNEL32.DLL", "library", 0, null), new EngineNamespace("std", "namespace", 2, null),
                new EngineNamespace("std::exception", "class", 3, 0x3000)]);

        public Task<IReadOnlyList<EngineString>> ListStringsAsync(int max, CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<EngineString>>([new EngineString(0x3020, 12, "utf8", "only in the engine"), new EngineString(0x3040, 8, "unicode", "zzz")]);

        public Task<EngineImageInfo> GetEngineInfoAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult(new EngineImageInfo("12.1", "x86", "x86:LE:64:default", "windows", "PE", 8, "little", 3, 2, [0x1000], "d41d", "abc",
                [new EngineMemoryBlock(".text", 0x180001000, 0x2000, "r-x", true)], false, "complete"));

        public Task<IReadOnlyList<NativeFunctionInfo>> ListFunctionsAsync(CancellationToken cancellationToken = default) => Task.FromResult(provider.Functions);
        public Task<PatchSyncResult> SyncPatchesAsync(IReadOnlyList<NativeByteRange> wanted, CancellationToken cancellationToken = default) =>
            Task.FromResult(new PatchSyncResult(wanted.Count, 0, 0, 0, 0, 0, [], TimeSpan.Zero));
        public Task<DecompiledFunction> DecompileAsync(uint rva, CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public Task<FunctionDisassembly> DisassembleAsync(uint rva, CancellationToken cancellationToken = default) => throw new NotSupportedException();
        // with two functions: the second calls the first at +4, the first calls the second at +4
        public Task<IReadOnlyList<NativeXref>> GetXrefsToAsync(uint rva, CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<NativeXref>>(provider.Functions.Count > 1 && rva == provider.Functions[0].StartRva
                ? [new NativeXref(provider.Functions[1].StartRva + 4, rva, NativeXrefKind.Call, provider.Functions[1].StartRva)] : []);

        public Task<IReadOnlyList<NativeXref>> GetXrefsFromAsync(uint rva, bool wholeFunction = false, CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<NativeXref>>(provider.Functions.Count > 1 && rva == provider.Functions[0].StartRva
                ? [new NativeXref(rva + 4, provider.Functions[1].StartRva, NativeXrefKind.Call, rva)] : []);
        public Task<string> SetNameAsync(uint rva, string name, CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public Task<string> SetCommentAsync(uint rva, string text, bool repeatable = false, CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public Task<NameBatchResult> ApplyNamesAsync(IReadOnlyList<NativeNameItem> items, string? stampKey = null, string? stamp = null, bool save = false,
            CancellationToken cancellationToken = default) => Task.FromResult(new NameBatchResult(items.Count, 0, 0, 0, TimeSpan.Zero, []));
        public Task<string?> GetStampAsync(string key, CancellationToken cancellationToken = default) => Task.FromResult<string?>(null);
        public Task SaveAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task CloseAsync(bool save = true, CancellationToken cancellationToken = default) => Task.CompletedTask;
        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
        public void Dispose() { }
    }
}
