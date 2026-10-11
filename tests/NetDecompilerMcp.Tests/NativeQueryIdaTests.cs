using NetDecompilerMcp.Core;
using NetDecompilerMcp.Native.Providers;
using NetDecompilerMcp.Native.Providers.Ida;
using NetDecompilerMcp.Services;
using NetDecompilerMcp.Tools;
using Xunit.Abstractions;

namespace NetDecompilerMcp.Tests;

/// <summary>The native query surface through IDA on a real system DLL: headers, cross-reference directions, function filters, decompiler references, types.</summary>
[Trait("Speed", "Slow")]
public sealed class NativeQueryIdaTests(ITestOutputHelper output) : IDisposable
{
    private const string Function = "CheckSumMappedFile";
    private readonly TempDir _dir = new();
    private readonly List<IDisposable> _owned = [];

    public void Dispose()
    {
        foreach (var d in _owned) d.Dispose();
        _dir.Dispose();
    }

    private sealed record Rig(AssemblyWorkspace Workspace, NativeCodeService Code, NativeEngineService Engines, NativeTypeTools Types, NativeAnalysisTools Analysis,
        NativeCodeTools CodeTools)
    {
        public LoadedNative Native => Workspace.Read(() => Workspace.Natives[0]);
        public Task<INativeDecompilerSession> Session() => Engines.Session(Native, "ida", null, default);
        public async Task<uint> Rva(string name) => (await Code.Index(Native, null, default)).AddressOfName(name)!.Value;
    }

    private Rig Setup()
    {
        var dir = Directory.CreateDirectory(_dir.File("input")).FullName;
        var copy = Path.Combine(dir, Path.GetFileName(NativeIdaProviderTests.System64));
        if (!File.Exists(copy)) File.Copy(NativeIdaProviderTests.System64, copy);
        var options = new ServerOptions { TimeoutSeconds = 600, BackgroundIndexing = false };
        var workspace = new AssemblyWorkspace(options);
        var code = new NativeCodeService(workspace, options, null, new Native.Annotations.AnnotationStore(_dir.File("annotations")));
        var engines = new NativeEngineService(new IdaProviderOptions { CacheRoot = _dir.File("cache") }, code, workspace, options);
        _owned.Add(engines);
        _owned.Add(workspace);
        var names = new NativeNamePush(code);
        var types = new NativeTypePush();
        var user = new NativeUserTypePush(code);
        var pager = new OutputPager(options);
        workspace.LoadAny(copy);
        return new Rig(workspace, code, engines, new NativeTypeTools(workspace, engines, user, code, names, types),
            new NativeAnalysisTools(workspace, engines, pager, names, code, types, user), new NativeCodeTools(workspace, code, pager, null, engines, names, types, user));
    }

    [IdaFact]
    public async Task Decompile_and_frame_headers_demangle_IDA_names()
    {
        var rig = Setup();
        var rva = await rig.Rva(Function);
        var session = await rig.Session();
        var set = await session.RunScriptAsync($"ida_name.set_name(base + 0x{rva:X}, '?Run@Widget@@QEAAXXZ', ida_name.SN_NOCHECK)");
        Assert.Equal("True", set.Result?.Trim());
        var text = await rig.Analysis.DecompileNative(rig.Native.Id, $"rva:0x{rva:X}", engine: "ida");
        output.WriteLine(text.Split('\n')[0]);
        Assert.Contains("// Widget::Run at ", text);
        Assert.Contains("; symbol ?Run@Widget@@QEAAXXZ)", text);
        var frame = await rig.Types.GetNativeFrame(rig.Native.Id, $"rva:0x{rva:X}", engine: "ida");
        output.WriteLine(frame.Split('\n')[0]);
        Assert.StartsWith("Frame of Widget::Run at ", frame);
        Assert.Contains("(symbol ?Run@Widget@@QEAAXXZ)", frame);
    }

    [IdaFact]
    public async Task Find_xrefs_from_a_function_through_IDA_by_kind()
    {
        var rig = Setup();
        var from = await rig.CodeTools.FindXrefs(rig.Native.Id, Function, engine: "ida", direction: "from");
        output.WriteLine(string.Join('\n', from.Split('\n').Take(12)));
        Assert.Contains($"References from 0x", from);
        Assert.Contains("(the whole function) (via IDA)", from);
        Assert.Matches(@"(?m)^\s*0x[0-9A-F]+  Call\s+\S+\+0x[0-9A-F]+  -> 0x[0-9A-F]+", from);
        var code = await rig.CodeTools.FindXrefs(rig.Native.Id, Function, engine: "ida", direction: "from", kind: "code");
        var data = await rig.CodeTools.FindXrefs(rig.Native.Id, Function, engine: "ida", direction: "from", kind: "data");
        Assert.DoesNotMatch(@"(?m)^\s*0x[0-9A-F]+  (Read|Write|Offset)\s", code);
        Assert.DoesNotMatch(@"(?m)^\s*0x[0-9A-F]+  (Call|Jump|Code)\s", data);
        // every row is in one of the two
        static int Rows(string text) => System.Text.RegularExpressions.Regex.Count(text, @"(?m)^\s*0x[0-9A-F]+  \S");
        Assert.Equal(Rows(from), Rows(code) + Rows(data));
        var both = await rig.CodeTools.FindXrefs(rig.Native.Id, Function, engine: "ida", direction: "both");
        Assert.Contains("References to ", both);
        Assert.Contains("References from ", both);
    }
}
