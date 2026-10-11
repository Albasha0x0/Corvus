using NetDecompilerMcp.Core;
using NetDecompilerMcp.Native.Code;
using NetDecompilerMcp.Native.Providers;
using NetDecompilerMcp.Native.Providers.Ida;
using NetDecompilerMcp.Services;
using NetDecompilerMcp.Tools;
using Xunit.Abstractions;

namespace NetDecompilerMcp.Tests;

/// <summary>Type renames, deletions and struct member edits through the tools in IDA and Ghidra: applied, kept over recovered types, and pushed into a new database.</summary>
[Trait("Speed", "Slow")]
public sealed class NativeTypeEditEngineTests(ITestOutputHelper output) : IDisposable
{
    private const string Function = "CheckSumMappedFile";
    private readonly TempDir _dir = new();
    private readonly List<IDisposable> _owned = [];

    public void Dispose()
    {
        foreach (var d in _owned) d.Dispose();
        _dir.Dispose();
    }

    private sealed record Rig(AssemblyWorkspace Workspace, NativeCodeService Code, NativeEngineService Engines, NativeTypeTools Types)
    {
        public LoadedNative Native => Workspace.Read(() => Workspace.Natives[0]);
        public Task<INativeDecompilerSession> Session(string engine) => Engines.Session(Native, engine, null, default);
        public uint Data => Native.Image.Sections.First(s => !s.IsExecutable && s.Name == ".data").Rva;
    }

    private string Image()
    {
        var dir = Directory.CreateDirectory(_dir.File("input")).FullName;
        var copy = Path.Combine(dir, Path.GetFileName(NativeIdaProviderTests.System64));
        if (!File.Exists(copy)) File.Copy(NativeIdaProviderTests.System64, copy);
        return copy;
    }

    private Rig Setup(string cache)
    {
        var options = new ServerOptions { TimeoutSeconds = 600, BackgroundIndexing = false };
        var workspace = new AssemblyWorkspace(options);
        var code = new NativeCodeService(workspace, options, null, new Native.Annotations.AnnotationStore(_dir.File("annotations")));
        var engines = new NativeEngineService(new IdaProviderOptions { CacheRoot = _dir.File(cache) }, code, workspace, options);
        _owned.Add(engines);
        _owned.Add(workspace);
        workspace.LoadAny(Image());
        return new Rig(workspace, code, engines, new NativeTypeTools(workspace, engines, new NativeUserTypePush(code), code, new NativeNamePush(code), new NativeTypePush()));
    }

    private void Restart()
    {
        foreach (var d in _owned) d.Dispose();
        _owned.Clear();
    }

    private static async Task Missing(INativeDecompilerSession s, string type) =>
        Assert.Equal(ErrorCode.NotFound, (await Assert.ThrowsAsync<ToolError>(() => s.GetTypeAsync(type))).Code);

    /// <summary>Renames and deletes in one engine, checks the kept layer, a recovered type push and a new database.</summary>
    private async Task RenameAndDelete(string engine, string cache, string freshCache, Func<INativeDecompilerSession, uint, Task>? checkGlobal = null)
    {
        var rig = Setup(cache);
        var path = Image();
        await rig.Types.DeclareNativeTypes(path, "struct NdmPkt { int length; char tag[4]; };\nenum NdmGone { NdmGoneA = 1 };", engine: engine);
        await rig.Types.SetNativeType(path, $"rva:0x{rig.Data:X}", "NdmPkt", engine: engine);
        await rig.Types.DeclareNativeTypes(path, typeName: "NdmGone", members: "NdmGoneB=2", engine: engine);
        output.WriteLine(await rig.Types.DeclareNativeTypes(path, rename: "NdmPkt=NdmMsg", engine: engine));
        Assert.Contains("Deleted type NdmGone", await rig.Types.DeclareNativeTypes(path, delete: "NdmGone", engine: engine));
        var layer = rig.Code.Annotations(rig.Native).UserTypes;
        Assert.Equal("NdmMsg", layer.Types[rig.Data]);
        Assert.Empty(layer.EnumMembers);
        var s = await rig.Session(engine);
        Assert.Equal("struct", (await s.GetTypeAsync("NdmMsg")).Kind);
        await Missing(s, "NdmPkt");
        await Missing(s, "NdmGone");
        // a recovered type push declares the user's declarations again; the edits are applied after them
        await s.ApplyTypesAsync(new NativeTypeBatch("struct NdmUnrelated { int a; };", [], [], [], 8));
        await Missing(s, "NdmPkt");
        await Missing(s, "NdmGone");
        Assert.Equal("struct", (await s.GetTypeAsync("NdmMsg")).Kind);

        Restart();
        var fresh = Setup(freshCache);
        output.WriteLine(await fresh.Types.GetNativeFrame(path, Function, engine: engine));
        var again = await fresh.Session(engine);
        Assert.Equal(8, (await again.GetTypeAsync("NdmMsg")).Size);
        await Missing(again, "NdmPkt");
        await Missing(again, "NdmGone");
        if (checkGlobal != null) await checkGlobal(again, fresh.Data);
        // declaring a deleted name again undoes the deletion, also after a recovered type push
        await fresh.Types.DeclareNativeTypes(path, "enum NdmGone { NdmBack = 3 };", engine: engine);
        Assert.DoesNotContain(fresh.Code.Annotations(fresh.Native).UserTypes.TypeEdits, e => e.Name == "NdmGone");
        await again.ApplyTypesAsync(new NativeTypeBatch("struct NdmUnrelated2 { int a; };", [], [], [], 8));
        Assert.Equal("enum", (await again.GetTypeAsync("NdmGone")).Kind);
    }

    /// <summary>The members of a type as "name@offset:size".</summary>
    private static async Task<string> Members(INativeDecompilerSession s, string type) =>
        string.Join(" ", (await s.GetTypeAsync(type)).Members.Select(m => $"{m.Name}@{m.Offset:X}:{m.Size}"));

    /// <summary>Retypes, places, moves and removes struct and union members, then checks them over a recovered type push and in a new database.</summary>
    private async Task MemberEdits(string engine, string cache, string freshCache)
    {
        var rig = Setup(cache);
        var path = Image();
        await rig.Types.DeclareNativeTypes(path, "struct NdmRec { int a; int b; };\nunion NdmU { int x; short y; };", engine: engine);
        var text = await rig.Types.DeclareNativeTypes(path, typeName: "NdmRec", fields: "b: char[8]; c@0x10: short; @0x0: unsigned int", engine: engine);
        output.WriteLine(text);
        var s = await rig.Session(engine);
        output.WriteLine(await Members(s, "NdmRec"));
        Assert.Equal("a@0:4 b@4:8 c@10:2", await Members(s, "NdmRec"));
        Assert.Matches("unsigned int|uint", (await s.GetTypeAsync("NdmRec")).Members[0].Type);
        output.WriteLine(await rig.Types.DeclareNativeTypes(path, typeName: "NdmRec", fields: "a@0x14: int\nc:", engine: engine));
        Assert.Equal("b@4:8 a@14:4", await Members(s, "NdmRec"));
        await rig.Types.DeclareNativeTypes(path, typeName: "NdmU", fields: "z: long long; y:", engine: engine);
        Assert.Equal("x@0:4 z@0:8", await Members(s, "NdmU"));
        Assert.Equal(ErrorCode.InvalidArgument, (await Assert.ThrowsAsync<ToolError>(() => rig.Types.DeclareNativeTypes(path, typeName: "NdmNoSuch", fields: "a: int", engine: engine))).Code);
        Assert.Equal(6, rig.Code.Annotations(rig.Native).UserTypes.Fields.Count);

        // a recovered type push declares NdmRec again from the user's text; the member edits are applied after it
        await s.ApplyTypesAsync(new NativeTypeBatch("struct NdmUnrelated { int a; };", [], [], [], 8));
        Assert.Equal("b@4:8 a@14:4", await Members(s, "NdmRec"));

        Restart();
        var fresh = Setup(freshCache);
        output.WriteLine(await fresh.Types.GetNativeFrame(path, Function, engine: engine));
        var again = await fresh.Session(engine);
        Assert.Equal("b@4:8 a@14:4", await Members(again, "NdmRec"));
        Assert.Equal("x@0:4 z@0:8", await Members(again, "NdmU"));
    }

    [IdaFact]
    public Task Struct_and_union_member_edits_apply_in_IDA_stay_over_declarations_and_reach_a_new_database() => MemberEdits("ida", "ida-m", "ida-n");

    [GhidraFact]
    public Task Struct_and_union_member_edits_apply_in_Ghidra_stay_over_declarations_and_reach_a_new_project() => MemberEdits("ghidra", "ghidra-m", "ghidra-n");

    [GhidraFact]
    public async Task Define_native_refreshes_the_ghidra_name_layer_in_the_background()
    {
        var rig = Setup("ghidra-g");
        var path = Image();
        output.WriteLine(await rig.Types.GetNativeFrame(path, Function, engine: "ghidra"));
        Assert.True(await rig.Engines.GhidraNameLayer(rig.Native)! > 0);
        var index = await rig.Code.Index(rig.Native, null, default);
        NativeNameLayers.Of(rig.Native).Remove(NativeNameSource.Ghidra, index);
        Assert.Null(NativeNameLayers.Of(rig.Native).Get(NativeNameSource.Ghidra));
        var fn = rig.Native.Image.Exports.First(e => e.Name == Function).Rva;
        await rig.Types.DefineNative(path, $"rva:0x{fn:X}", "function", engine: "ghidra");
        Assert.True(await GhidraNames.LastRefresh(rig.Native)! > 0);
        Assert.NotNull(NativeNameLayers.Of(rig.Native).Get(NativeNameSource.Ghidra));
    }

    [IdaFact]
    public Task Type_renames_and_deletions_apply_in_IDA_stay_over_recovered_types_and_reach_a_new_database() =>
        RenameAndDelete("ida", "ida-t", "ida-u", async (ida, data) => Assert.Contains("NdmMsg", (await ida.RunScriptAsync($"idc.get_type(base + 0x{data:X})")).Result));

    [GhidraFact]
    public Task Type_renames_and_deletions_apply_in_Ghidra_stay_over_recovered_types_and_reach_a_new_project() =>
        RenameAndDelete("ghidra", "ghidra-t", "ghidra-u");
}
