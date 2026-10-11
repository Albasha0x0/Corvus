using NetDecompilerMcp.Core;
using NetDecompilerMcp.Native;
using NetDecompilerMcp.Native.Providers;
using NetDecompilerMcp.Native.Providers.Ghidra;
using NetDecompilerMcp.Services;
using NetDecompilerMcp.Tools;

namespace NetDecompilerMcp.Tests;

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
        var open = await tool.GetEngineStatus(rig.Image);
        Assert.Contains("Ghidra 12.1: open, analysis complete", open);
        Assert.Contains("x86 x86:LE:64:default, compiler windows, PE, 64-bit little", open);
        Assert.Contains("input: sha256 abc, md5 d41d", open);
        Assert.Contains(".text", open);
        Assert.Equal(1, rig.Provider.Opens);
        Assert.Equal(ErrorCode.InvalidArgument, (await Assert.ThrowsAsync<ToolError>(() => tool.GetEngineStatus(rig.Image, "bogus"))).Code);
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

        public Task<EngineImageInfo> GetEngineInfoAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult(new EngineImageInfo("12.1", "x86", "x86:LE:64:default", "windows", "PE", 8, "little", 3, 2, [0x1000], "d41d", "abc",
                [new EngineMemoryBlock(".text", 0x180001000, 0x2000, "r-x", true)], false, "complete"));

        public Task<IReadOnlyList<NativeFunctionInfo>> ListFunctionsAsync(CancellationToken cancellationToken = default) => Task.FromResult(provider.Functions);
        public Task<PatchSyncResult> SyncPatchesAsync(IReadOnlyList<NativeByteRange> wanted, CancellationToken cancellationToken = default) =>
            Task.FromResult(new PatchSyncResult(wanted.Count, 0, 0, 0, 0, 0, [], TimeSpan.Zero));
        public Task<DecompiledFunction> DecompileAsync(uint rva, CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public Task<FunctionDisassembly> DisassembleAsync(uint rva, CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public Task<IReadOnlyList<NativeXref>> GetXrefsToAsync(uint rva, CancellationToken cancellationToken = default) => Task.FromResult<IReadOnlyList<NativeXref>>([]);
        public Task<IReadOnlyList<NativeXref>> GetXrefsFromAsync(uint rva, bool wholeFunction = false, CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<NativeXref>>([]);
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
