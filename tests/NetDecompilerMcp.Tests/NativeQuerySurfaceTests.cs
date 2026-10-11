using NetDecompilerMcp.Core;
using NetDecompilerMcp.Native;
using NetDecompilerMcp.Native.Providers;
using NetDecompilerMcp.Native.Providers.Ida;
using NetDecompilerMcp.Services;
using NetDecompilerMcp.Tools;

namespace NetDecompilerMcp.Tests;

/// <summary>The native query surface over a scripted engine: headers, cross-reference directions, function filters, decompiler references, types.</summary>
public sealed class NativeQuerySurfaceTests : IDisposable
{
    private readonly TempDir _dir = new();
    private readonly List<IDisposable> _owned = [];

    public void Dispose()
    {
        foreach (var d in _owned) d.Dispose();
        _dir.Dispose();
    }

    private sealed record Rig(AssemblyWorkspace Workspace, NativeCodeService Code, NativeEngineService Engines, FakeProvider Provider, LoadedNative Native,
        NativeAnalysisTools Analysis, NativeTypeTools Types, NativeCodeTools CodeTools, uint First, uint Second);

    private async Task<Rig> Setup()
    {
        var options = new ServerOptions { BackgroundIndexing = false };
        var workspace = new AssemblyWorkspace(options);
        var code = new NativeCodeService(workspace, options, null, new Native.Annotations.AnnotationStore(_dir.File("annotations")));
        var provider = new FakeProvider();
        var engines = new NativeEngineService([provider], _dir.File("cache"), code, workspace, options);
        _owned.Add(engines);
        _owned.Add(workspace);
        var pager = new OutputPager(options);
        var native = workspace.LoadAny(McpProtocolTests.NativeSample(_dir)).Native!;
        var index = await code.Index(native, null, default);
        uint first = index.AddressOfName("First")!.Value, second = index.AddressOfName("Second")!.Value;
        provider.Functions = [(first, second, "First"), (second, second + 0x10, "Second")];
        return new Rig(workspace, code, engines, provider, native, new NativeAnalysisTools(workspace, engines, pager, null, code),
            new NativeTypeTools(workspace, engines, new NativeUserTypePush(code), code), new NativeCodeTools(workspace, code, pager, null, engines), first, second);
    }

    [Theory]
    [InlineData("?Run@Widget@@QEAAXXZ", "Widget::Run")]
    [InlineData("_ZN6Widget3RunEv", "Widget::Run()")]
    [InlineData("plain_name", "plain_name")]
    public void Display_names_demangle_msvc_and_itanium(string symbol, string display)
    {
        Assert.Equal(display, NativeTools.DisplayName(symbol));
        Assert.Equal(symbol == display ? "" : $"; symbol {symbol}", NativeTools.Named(symbol, ImageFormat.Pe).Symbol);
    }

    [Fact]
    public async Task Decompile_and_frame_headers_show_the_demangled_name_and_keep_the_symbol()
    {
        var rig = await Setup();
        rig.Provider.Functions = [(rig.First, rig.Second, "?Run@Widget@@QEAAXXZ"), (rig.Second, rig.Second + 0x10, "Second")];
        var batch = await rig.Analysis.DecompileNative(rig.Native.Id, functions: ["First", "Second"]);
        Assert.Contains("// [1/2] Widget::Run at", batch);
        var text = await rig.Analysis.DecompileNative(rig.Native.Id, "First");
        Assert.Matches(@"// Widget::Run at 0x[0-9A-F]+ \(ida, saved analysis; symbol \?Run@Widget@@QEAAXXZ\)", text);
        var frame = await rig.Types.GetNativeFrame(rig.Native.Id, "First");
        Assert.StartsWith("Frame of Widget::Run at ", frame);
        Assert.Contains("(symbol ?Run@Widget@@QEAAXXZ)", frame);
        Assert.StartsWith("Frame of Second at ", await rig.Types.GetNativeFrame(rig.Native.Id, "Second"));
    }

    internal sealed class FakeProvider : INativeDecompilerProvider
    {
        public List<(uint Start, uint End, string Name)> Functions { get; set; } = [];
        public string Id => IdaProvider.ProviderId;
        public string DisplayName => "fake engine";
        public ProviderAvailability CheckAvailability() => ProviderAvailability.Ok(Id, new Dictionary<string, string>());
        public Task<ProviderAvailability> ProbeAsync(CancellationToken cancellationToken = default) => Task.FromResult(CheckAvailability());

        public Task<INativeDecompilerSession> OpenAsync(string imagePath, string? sha256 = null, NativeOpenOptions? options = null, CancellationToken cancellationToken = default) =>
            Task.FromResult<INativeDecompilerSession>(new FakeSession(this));

        public void Dispose() { }

        public (uint Start, uint End, string Name) At(uint rva) =>
            Functions.FirstOrDefault(x => rva >= x.Start && rva < x.End) is { Name: not null } f ? f : throw new ToolError(ErrorCode.NotFound, $"no function contains rva 0x{rva:X}");
    }

    private sealed class FakeSession(FakeProvider provider) : INativeDecompilerSession
    {
        public string ProviderId => provider.Id;
        public string ImagePath => "";
        public string Sha256 => "";
        public NativeArch Arch => NativeArch.X64;
        public ulong ImageBase => 0;
        public bool ReusedDatabase => true;
        public TimeSpan OpenTime => TimeSpan.Zero;
        public bool DecompilerAvailable => true;
        public bool IsOpen => true;

        public Task<DecompiledFunction> DecompileAsync(uint rva, CancellationToken cancellationToken = default)
        {
            var f = provider.At(rva);
            return Task.FromResult(new DecompiledFunction(f.Start, f.Name, $"int {f.Name}(void) {{ return 0; }}", []));
        }

        public Task<NativeFrame> GetFrameAsync(uint rva, CancellationToken cancellationToken = default)
        {
            var f = provider.At(rva);
            return Task.FromResult(new NativeFrame(f.Start, f.Name, 0x20, 8, 0x28, [new NativeFrameMember(0, "var_28", "int", 4, "local")], [], null));
        }

        public Task<IReadOnlyList<NativeFunctionInfo>> ListFunctionsAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<NativeFunctionInfo>>(provider.Functions.Select(f => new NativeFunctionInfo(f.Start, f.End, f.Name, NativeFunctionFlags.None)).ToList());

        public Task<FunctionDisassembly> DisassembleAsync(uint rva, CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public Task<PatchSyncResult> SyncPatchesAsync(IReadOnlyList<NativeByteRange> wanted, CancellationToken cancellationToken = default) =>
            Task.FromResult(new PatchSyncResult(wanted.Count, 0, 0, 0, 0, 0, [], TimeSpan.Zero));
        public Task<IReadOnlyList<NativeXref>> GetXrefsToAsync(uint rva, CancellationToken cancellationToken = default) => Task.FromResult<IReadOnlyList<NativeXref>>([]);
        public Task<IReadOnlyList<NativeXref>> GetXrefsFromAsync(uint rva, bool wholeFunction = false, CancellationToken cancellationToken = default) =>
            Task.FromResult<IReadOnlyList<NativeXref>>([]);
        public Task<string> SetNameAsync(uint rva, string name, CancellationToken cancellationToken = default) => Task.FromResult(name);
        public Task<string> SetCommentAsync(uint rva, string text, bool repeatable = false, CancellationToken cancellationToken = default) => Task.FromResult(text);

        public Task<NameBatchResult> ApplyNamesAsync(IReadOnlyList<NativeNameItem> items, string? stampKey = null, string? stamp = null, bool save = false,
            CancellationToken cancellationToken = default) => Task.FromResult(new NameBatchResult(items.Count, 0, 0, 0, TimeSpan.Zero, []));

        public Task<string?> GetStampAsync(string key, CancellationToken cancellationToken = default) => Task.FromResult<string?>(null);
        public Task SaveAsync(CancellationToken cancellationToken = default) => Task.CompletedTask;
        public Task CloseAsync(bool save = true, CancellationToken cancellationToken = default) => Task.CompletedTask;
        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
        public void Dispose() { }
    }
}
