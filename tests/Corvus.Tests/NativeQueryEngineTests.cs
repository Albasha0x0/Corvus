using Corvus.Core;
using Corvus.Native.Providers;
using Corvus.Native.Providers.Ida;
using Corvus.Services;
using Corvus.Tools;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>The native query surface through IDA and Ghidra on a real system DLL: headers, cross-reference directions, function filters, decompiler references, types.</summary>
[Trait("Speed", "Slow")]
public sealed class NativeQueryEngineTests(ITestOutputHelper output) : IDisposable
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
        public Task<INativeDecompilerSession> Session(string engine = "ida") => Engines.Session(Native, engine, null, default);
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
        // the name in effect (the export) wins in pseudocode headers, as in list_functions (DN-4); the frame shows the engine's
        Assert.Contains($"// {Function} at ", text);
        var frame = await rig.Types.GetNativeFrame(rig.Native.Id, $"rva:0x{rva:X}", engine: "ida", locals: true);
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

    [IdaFact]
    public Task List_functions_through_IDA_filters_by_type_name_and_size() => FunctionFilters("ida");

    [GhidraFact]
    public Task List_functions_through_Ghidra_filters_by_type_name_and_size() => FunctionFilters("ghidra");

    private async Task FunctionFilters(string engine)
    {
        var rig = Setup();
        static List<FunctionEntry> Items(FunctionList list) => [.. list.Items];
        var all = await NativeQuerySurfaceTests.Structured<FunctionList>(() => rig.CodeTools.ListFunctions(rig.Native.Id, engine: engine, limit: 5000));
        // a PDB or the exports give the engine prototypes for some functions, not for every one
        var typed = await NativeQuerySurfaceTests.Structured<FunctionList>(() => rig.CodeTools.ListFunctions(rig.Native.Id, engine: engine, hasType: true, limit: 5000));
        var untyped = await NativeQuerySurfaceTests.Structured<FunctionList>(() => rig.CodeTools.ListFunctions(rig.Native.Id, engine: engine, hasType: false, limit: 5000));
        output.WriteLine($"{engine}: {all.Total} functions, {typed.Total} typed, {untyped.Total} untyped");
        Assert.Equal(all.Total, typed.Total + untyped.Total);
        Assert.True(typed.Total > 0);
        var glob = Items(await NativeQuerySurfaceTests.Structured<FunctionList>(() => rig.CodeTools.ListFunctions(rig.Native.Id, "checksum*file", engine: engine)));
        Assert.Contains(glob, f => f.Name == Function);
        Assert.All(glob, f => Assert.Matches("(?i)^checksum.*file$", f.Name));
        var regex = Items(await NativeQuerySurfaceTests.Structured<FunctionList>(() => rig.CodeTools.ListFunctions(rig.Native.Id, "/^CheckSum/", engine: engine)));
        Assert.Contains(regex, f => f.Name == Function);
        var large = Items(await NativeQuerySurfaceTests.Structured<FunctionList>(() => rig.CodeTools.ListFunctions(rig.Native.Id, engine: engine, minSize: 256, sort: "size", descending: false)));
        Assert.All(large, f => Assert.True(f.Size >= 256));
        Assert.Equal(large.Select(f => f.Size).Order(), large.Select(f => f.Size));
    }

    [GhidraFact]
    public async Task Find_xrefs_from_a_function_through_Ghidra()
    {
        var rig = Setup();
        var from = await rig.CodeTools.FindXrefs(rig.Native.Id, Function, engine: "ghidra", direction: "from");
        output.WriteLine(string.Join('\n', from.Split('\n').Take(12)));
        Assert.Contains("(the whole function) (via Ghidra)", from);
        Assert.Matches(@"(?m)^\s*0x[0-9A-F]+  Call\s+\S+\+0x[0-9A-F]+  -> 0x[0-9A-F]+", from);
        Assert.DoesNotMatch(@"(?m)^\s*0x[0-9A-F]+  (Call|Jump|Code)\s", await rig.CodeTools.FindXrefs(rig.Native.Id, Function, engine: "ghidra", direction: "from", kind: "data"));
    }

    [IdaFact]
    public async Task Decompile_refs_lists_the_ctree_objects_through_IDA()
    {
        var rig = Setup();
        var report = await NativeQuerySurfaceTests.Structured<NativeAnalysisTools.DecompileReport>(() => rig.Analysis.DecompileNative(rig.Native.Id, Function, engine: "ida", refs: true));
        var text = await rig.Analysis.DecompileNative(rig.Native.Id, Function, engine: "ida", refs: true);
        output.WriteLine(text[text.IndexOf("// refs:", StringComparison.Ordinal)..]);
        Assert.Matches(@"// refs: .*import", text);
        Assert.DoesNotContain("(from ida's references)", text);
        var refs = report.Items[0].Refs!;
        Assert.Contains(refs, r => r.Kind == "import" && r.Name.EndsWith("!RtlImageNtHeaderEx", StringComparison.Ordinal));
        Assert.All(refs, r => Assert.True(r.Uses >= 1));
    }

    [GhidraFact]
    public async Task Decompile_refs_come_from_the_function_references_through_Ghidra()
    {
        var rig = Setup();
        var text = await rig.Analysis.DecompileNative(rig.Native.Id, Function, engine: "ghidra", refs: true);
        output.WriteLine(text[text.IndexOf("// refs:", StringComparison.Ordinal)..]);
        Assert.Matches(@"// refs: .*import.* \(from ghidra's references\)", text);
        Assert.Contains("!RtlImageNtHeaderEx", text);
    }

    [IdaFact]
    public async Task List_native_types_through_IDA_by_pattern_kind_order_and_members()
    {
        var rig = Setup();
        await rig.Types.DeclareNativeTypes(rig.Native.Id, "struct QzPkt { int len; char data[12]; }; typedef struct QzPkt *PQzPkt; " +
                                                          "enum QzColor { QzRed = 1, QzGreen = 2 };", engine: "ida");
        static List<string> Names(string text) => [.. text.Split('\n').Where(l => l.StartsWith("  ", StringComparison.Ordinal) && !l.StartsWith("    ", StringComparison.Ordinal))
            .Select(l => l.Trim().Split(' ')[1])];
        var glob = await rig.Types.ListNativeTypes(rig.Native.Id, "*qz*", engine: "ida", sort: "name");
        output.WriteLine(glob);
        Assert.Equal(["PQzPkt", "QzColor", "QzPkt"], Names(glob));
        Assert.Equal(["PQzPkt"], Names(await rig.Types.ListNativeTypes(rig.Native.Id, "/qz/", kind: "ptr", engine: "ida")));
        Assert.Equal(["QzPkt"], Names(await rig.Types.ListNativeTypes(rig.Native.Id, "/^Qz/", kind: "udt", engine: "ida")));
        Assert.Empty(Names(await rig.Types.ListNativeTypes(rig.Native.Id, "/^qz/s", engine: "ida"))); // a flag drops the default i
        Assert.Equal(["QzPkt", "PQzPkt", "QzColor"], Names(await rig.Types.ListNativeTypes(rig.Native.Id, "*Qz*", engine: "ida", sort: "size", descending: true)));
        var members = await rig.Types.ListNativeTypes(rig.Native.Id, "/qz(pkt|color)$/", engine: "ida", members: true);
        output.WriteLine(members);
        Assert.Contains("      +0x4  data  char[12]  12", members);
        Assert.Contains("      QzGreen = 2", members);
    }

    [GhidraFact]
    public async Task List_native_types_through_Ghidra_by_pattern_kind_order_and_members()
    {
        var rig = Setup();
        await rig.Types.DeclareNativeTypes(rig.Native.Id, "struct QzPkt { int len; char data[12]; }; union QzWord { int i; float f; }; typedef struct QzPkt *PQzPkt;", engine: "ghidra");
        static List<string> Names(string text) => [.. text.Split('\n').Where(l => l.StartsWith("  ", StringComparison.Ordinal) && !l.StartsWith("    ", StringComparison.Ordinal))
            .Select(l => l.Trim().Split(' ')[1])];
        Assert.Equal(["QzPkt", "QzWord"], Names(await rig.Types.ListNativeTypes(rig.Native.Id, "qz*", kind: "udt", engine: "ghidra", sort: "name")));
        Assert.Equal(["QzPkt", "QzWord"], Names(await rig.Types.ListNativeTypes(rig.Native.Id, "/^Qz/", engine: "ghidra", sort: "size", descending: true)));
        var members = await rig.Types.ListNativeTypes(rig.Native.Id, "QzPkt", engine: "ghidra", members: true);
        output.WriteLine(members);
        Assert.Matches(@"      \+0x4  data  char\[12\]  12", members);
        Assert.Equal(["PQzPkt"], Names(await rig.Types.ListNativeTypes(rig.Native.Id, "/qz/", kind: "ptr", engine: "ghidra")));
    }
}
