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

    /// <summary>The structured record a tool call hands to the call filter.</summary>
    internal static async Task<T> Structured<T>(Func<Task<string>> call)
    {
        var collector = Mcp.StructuredOutput.Begin();
        await call();
        return Assert.IsType<T>(collector.Value);
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

    /// <summary>Code tools over a small image whose 0x1000 reads the slot 0x5040 and calls 0x1100 (see <see cref="Il2CppNativeNamesTests.GameAssembly"/>).</summary>
    private async Task<(NativeCodeTools Tools, string Image)> CodeImage()
    {
        var rig = await Setup();
        var path = _dir.File("calls.dll");
        File.WriteAllBytes(path, Il2CppNativeNamesTests.GameAssembly());
        var id = rig.Workspace.LoadAny(path).Native!.Id;
        return (rig.CodeTools, id);
    }

    [Fact]
    public async Task Find_xrefs_lists_references_from_a_function_and_filters_by_kind()
    {
        var (tools, image) = await CodeImage();
        var to = await tools.FindXrefs(image, "rva:0x1100", engine: "ours");
        Assert.Contains("References to ", to);
        Assert.Contains("Call", to);
        Assert.DoesNotContain("->", to);

        var from = await tools.FindXrefs(image, "rva:0x1000", engine: "ours", direction: "from");
        Assert.Contains("References from 0x180001000", from);
        Assert.Contains("(the whole function,", from);
        Assert.Matches(@"0x18000100[0-9A-F]  Call\s+sub_1000\+0x[0-9A-F]+  -> 0x180001100 \(sub_1100\)", from);
        Assert.Matches(@"Read\s+sub_1000\+0x0  -> 0x180005040", from);
        var items = (await Structured<XrefList>(() => tools.FindXrefs(image, "rva:0x1000", engine: "ours", direction: "from"))).Items;
        Assert.Contains(items, i => i.Kind == "Call" && i.Target == "0x180001100");

        var data = await tools.FindXrefs(image, "rva:0x1000", engine: "ours", direction: "from", kind: "data");
        Assert.DoesNotContain("sub_1100)", data);
        Assert.Contains("data only", data);
        var code = (await Structured<XrefList>(() => tools.FindXrefs(image, "rva:0x1000", engine: "ours", direction: "from", kind: "code"))).Items;
        Assert.Equal(["Call"], code.Select(i => i.Kind).Distinct());

        // one instruction: only its own references
        var call = await tools.FindXrefs(image, "rva:0x1007", engine: "ours", direction: "from");
        Assert.Contains("-> 0x180001100", call);
        Assert.DoesNotContain("0x180005040", call);

        var both = await tools.FindXrefs(image, "rva:0x1100", engine: "ours", direction: "both");
        Assert.Contains("References to 0x180001100", both);
        Assert.Contains("References from 0x180001100", both);
        Assert.Contains("-> 0x180001200", both);

        var bad = await Assert.ThrowsAsync<ToolError>(() => tools.FindXrefs(image, "rva:0x1000", direction: "sideways"));
        Assert.Equal(ErrorCode.InvalidArgument, bad.Code);
        bad = await Assert.ThrowsAsync<ToolError>(() => tools.FindXrefs(image, "rva:0x1000", kind: "calls"));
        Assert.Equal(ErrorCode.InvalidArgument, bad.Code);
    }

    [Fact]
    public async Task Find_xrefs_from_through_an_engine_asks_for_the_whole_function_at_its_start()
    {
        var rig = await Setup();
        rig.Provider.From.Add(new NativeXref(rig.First, rig.Second, NativeXrefKind.Call, rig.First));
        rig.Provider.From.Add(new NativeXref(rig.First, rig.Second + 0x100, NativeXrefKind.Read, rig.First));
        var text = await rig.CodeTools.FindXrefs(rig.Native.Id, "First", engine: "ida", direction: "from");
        Assert.Contains((rig.First, true), rig.Provider.FromAsked);
        Assert.Contains("(the whole function) (via IDA)", text);
        Assert.Matches(@"Call\s+First\+0x0  -> 0x[0-9A-F]+ \(Second\)", text);
        Assert.Contains("Read", text);
        var data = await rig.CodeTools.FindXrefs(rig.Native.Id, "First", engine: "ida", direction: "from", kind: "data");
        Assert.DoesNotContain("(Second)", data);
        Assert.Contains("Read", data);
        await rig.CodeTools.FindXrefs(rig.Native.Id, $"rva:0x{rig.Second + 1:X}", engine: "ida", direction: "from");
        Assert.Contains((rig.Second + 1, false), rig.Provider.FromAsked);
    }

    [Fact]
    public async Task List_functions_filters_by_regex_glob_size_and_range_and_sorts()
    {
        var (tools, image) = await CodeImage();
        static List<string> Names(FunctionList list) => list.Items.Select(i => i.Name).ToList();
        var all = await Structured<FunctionList>(() => tools.ListFunctions(image, engine: "ours"));
        Assert.Contains("sub_1000", Names(all));
        Assert.Contains("sub_1100", Names(all));
        Assert.Equal(Names(all).Count, all.Total);

        Assert.Equal(["sub_1100"], Names(await Structured<FunctionList>(() => tools.ListFunctions(image, "/^sub_11/", engine: "ours"))));
        Assert.Equal(["sub_1100"], Names(await Structured<FunctionList>(() => tools.ListFunctions(image, "SUB_11*", engine: "ours"))));
        Assert.Equal(["sub_1000", "sub_1100", "sub_1200"], Names(await Structured<FunctionList>(() => tools.ListFunctions(image, "sub_1?00", engine: "ours"))).Take(3));
        Assert.Empty(Names(await Structured<FunctionList>(() => tools.ListFunctions(image, "/^SUB_11/s", engine: "ours")))); // a flag drops the default i
        var ranged = await tools.ListFunctions(image, engine: "ours", from: "rva:0x1100", to: "rva:0x1200");
        Assert.Contains("Matching (start >= 0x180001100, start < 0x180001200): 1", ranged);
        Assert.Equal(["sub_1100"], Names(await Structured<FunctionList>(() => tools.ListFunctions(image, engine: "ours", from: "rva:0x1100", to: "rva:0x1200"))));

        var sizes = all.Items.ToDictionary(i => i.Name, i => i.Size);
        int big = sizes.Values.Max();
        Assert.All((await Structured<FunctionList>(() => tools.ListFunctions(image, engine: "ours", minSize: big))).Items, i => Assert.Equal(big, i.Size));
        Assert.All((await Structured<FunctionList>(() => tools.ListFunctions(image, engine: "ours", maxSize: big - 1))).Items, i => Assert.True(i.Size < big));

        var byName = Names(await Structured<FunctionList>(() => tools.ListFunctions(image, sort: "name", descending: true, engine: "ours")));
        Assert.Equal(byName.OrderByDescending(n => n, StringComparer.OrdinalIgnoreCase), byName);
        var bySize = (await Structured<FunctionList>(() => tools.ListFunctions(image, sort: "size", descending: false, engine: "ours"))).Items.Select(i => i.Size).ToList();
        Assert.Equal(bySize.Order(), bySize);
        var byAddress = (await Structured<FunctionList>(() => tools.ListFunctions(image, descending: true, engine: "ours"))).Items.Select(i => i.Address).ToList();
        Assert.Equal(byAddress.OrderDescending(StringComparer.Ordinal), byAddress);

        foreach (var call in new Func<Task<string>>[]
                 {
                     () => tools.ListFunctions(image, "/[unclosed/", engine: "ours"), () => tools.ListFunctions(image, sort: "weight"),
                     () => tools.ListFunctions(image, minSize: 10, maxSize: 5), () => tools.ListFunctions(image, from: "rva:0x1200", to: "rva:0x1100", engine: "ours"),
                     () => tools.ListFunctions(image, hasType: true, engine: "ours"),
                 })
            Assert.Equal(ErrorCode.InvalidArgument, (await Assert.ThrowsAsync<ToolError>(call)).Code);
    }

    [Fact]
    public async Task List_functions_through_an_engine_filters_by_type()
    {
        var rig = await Setup();
        rig.Provider.Typed.Add(rig.Second);
        static List<string> Names(FunctionList list) => list.Items.Select(i => i.Name).ToList();
        Assert.Equal(["Second"], Names(await Structured<FunctionList>(() => rig.CodeTools.ListFunctions(rig.Native.Id, engine: "ida", hasType: true))));
        Assert.Equal(["First"], Names(await Structured<FunctionList>(() => rig.CodeTools.ListFunctions(rig.Native.Id, engine: "ida", hasType: false))));
        Assert.Equal(["Second", "First"], Names(await Structured<FunctionList>(() => rig.CodeTools.ListFunctions(rig.Native.Id, engine: "ida", sort: "name", descending: true))));
        var text = await rig.CodeTools.ListFunctions(rig.Native.Id, "/^f/", engine: "ida");
        Assert.Contains("Matching (name '/^f/'): 1", text);
    }

    internal sealed class FakeProvider : INativeDecompilerProvider
    {
        public List<(uint Start, uint End, string Name)> Functions { get; set; } = [];
        public List<NativeXref> From { get; } = [];
        public HashSet<uint> Typed { get; } = [];
        public List<(uint Rva, bool Whole)> FromAsked { get; } = [];
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
            Task.FromResult<IReadOnlyList<NativeFunctionInfo>>(provider.Functions.Select(f => new NativeFunctionInfo(f.Start, f.End, f.Name, provider.Typed.Contains(f.Start) ? NativeFunctionFlags.Typed : NativeFunctionFlags.None)).ToList());

        public Task<FunctionDisassembly> DisassembleAsync(uint rva, CancellationToken cancellationToken = default) => throw new NotSupportedException();
        public Task<PatchSyncResult> SyncPatchesAsync(IReadOnlyList<NativeByteRange> wanted, CancellationToken cancellationToken = default) =>
            Task.FromResult(new PatchSyncResult(wanted.Count, 0, 0, 0, 0, 0, [], TimeSpan.Zero));
        public Task<IReadOnlyList<NativeXref>> GetXrefsToAsync(uint rva, CancellationToken cancellationToken = default) => Task.FromResult<IReadOnlyList<NativeXref>>([]);
        public Task<IReadOnlyList<NativeXref>> GetXrefsFromAsync(uint rva, bool wholeFunction = false, CancellationToken cancellationToken = default)
        {
            provider.FromAsked.Add((rva, wholeFunction));
            return Task.FromResult<IReadOnlyList<NativeXref>>(provider.From.Where(x => wholeFunction ? provider.At(x.FromRva).Start == rva : x.FromRva == rva).ToList());
        }
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
