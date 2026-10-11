using System.Diagnostics;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Native.Providers;
using NetDecompilerMcp.Native.Providers.Ida;
using NetDecompilerMcp.Services;
using NetDecompilerMcp.Tools;
using Xunit.Abstractions;

namespace NetDecompilerMcp.Tests;

/// <summary>
/// Engine edits beyond types through the tools on a real system DLL, with IDA and with Ghidra: applied, journaled over a
/// worker restart, and pushed into a new database from the sidecar.
/// </summary>
[Trait("Speed", "Slow")]
public sealed class NativeEngineEditTests(ITestOutputHelper output) : IDisposable
{
    private const string Function = "CheckSumMappedFile";
    private readonly TempDir _dir = new();
    private readonly List<IDisposable> _owned = [];

    public void Dispose()
    {
        foreach (var d in _owned) d.Dispose();
        _dir.Dispose();
    }

    private sealed record Rig(AssemblyWorkspace Workspace, NativeCodeService Code, NativeEngineService Engines, NativeTypeTools Types, NativeAnalysisTools Analysis)
    {
        public LoadedNative Native => Workspace.Read(() => Workspace.Natives[0]);
        public Task<INativeDecompilerSession> Session(string engine) => Engines.Session(Native, engine, null, default);
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
        var names = new NativeNamePush(code);
        var types = new NativeTypePush();
        var user = new NativeUserTypePush(code);
        workspace.LoadAny(Image());
        return new Rig(workspace, code, engines, new NativeTypeTools(workspace, engines, user, code, names, types),
            new NativeAnalysisTools(workspace, engines, new OutputPager(options), names, code, types, user));
    }

    private void Restart()
    {
        foreach (var d in _owned) d.Dispose();
        _owned.Clear();
    }

    private static string Rva(uint rva) => $"rva:0x{rva:X}";

    /// <summary>IDA: the size of the item at an RVA and whether a function starts there.</summary>
    private static async Task<(long Size, bool Function)> IdaItem(INativeDecompilerSession s, uint rva)
    {
        var r = await s.RunScriptAsync($"(ida_bytes.get_item_size(base + 0x{rva:X}), ida_funcs.get_func(base + 0x{rva:X}) is not None and ida_funcs.get_func(base + 0x{rva:X}).start_ea == base + 0x{rva:X})");
        var parts = (r.Result ?? r.Error ?? "").Trim('(', ')').Split(',');
        return (long.Parse(parts[0].Trim()), parts[1].Trim() == "True");
    }

    [IdaFact]
    public async Task Define_native_makes_data_functions_and_undefined_bytes_in_IDA_and_replays_them()
    {
        var rig = Setup("ida-a");
        var path = Image();
        var data = rig.Native.Image.Sections.First(s => !s.IsExecutable && s.Name == ".data").Rva;
        var fn = rig.Native.Image.Exports.First(e => e.Name == Function).Rva;
        output.WriteLine(await rig.Types.DefineNative(path, Rva(data), "data", type: "dword[4]"));
        await rig.Types.DeclareNativeTypes(path, "struct NdmRec { int a; short b; char c[10]; };");
        Assert.Contains("NdmRec", await rig.Types.DefineNative(path, Rva(data + 0x40), "data", type: "NdmRec"));
        Assert.Contains("string", await rig.Types.DefineNative(path, Rva(data + 0x60), "data", end: Rva(data + 0x68), type: "string"));
        Assert.Contains("byte(s) undefined", await rig.Types.DefineNative(path, Function, "undefine"));
        var ida = await rig.Session("ida");
        Assert.False((await IdaItem(ida, fn)).Function);
        Assert.Contains($"function {Function}", await rig.Types.DefineNative(path, Rva(fn), "function"));

        Assert.Equal(ErrorCode.InvalidArgument, (await Assert.ThrowsAsync<ToolError>(() => rig.Types.DefineNative(path, Rva(data), "data"))).Code);
        Assert.Equal(ErrorCode.InvalidArgument, (await Assert.ThrowsAsync<ToolError>(() => rig.Types.DefineNative(path, Rva(data + 8), "undefine", end: Rva(data)))).Code);
        Assert.Equal(ErrorCode.InvalidArgument, (await Assert.ThrowsAsync<ToolError>(() => rig.Types.DefineNative(path, Rva(data), "data", type: "no_such_ndm_t"))).Code);
        // the function edit replaced the undefine at the same address
        var layer = rig.Code.Annotations(rig.Native).UserTypes;
        Assert.Equal([data, data + 0x40, data + 0x60, fn], layer.Analysis.Select(a => a.Rva));

        // journaled: a worker killed before any save replays the edits
        using (var worker = Process.GetProcessById(((IdaSession)ida).WorkerProcessId!.Value)) worker.Kill();
        await Task.Delay(300);
        Assert.Equal((16L, false), await IdaItem(ida, data));
        Assert.Equal((16L, false), await IdaItem(ida, data + 0x40));
        Assert.True((await IdaItem(ida, fn)).Function);

        // a new database gets them from the sidecar
        Restart();
        var fresh = Setup("ida-b");
        output.WriteLine(await fresh.Types.GetNativeFrame(path, Function));
        var again = await fresh.Session("ida");
        Assert.Equal((16L, false), await IdaItem(again, data));
        Assert.Equal((8L, false), await IdaItem(again, data + 0x60));
    }

    [GhidraFact]
    public async Task Define_native_makes_data_functions_and_undefined_bytes_in_Ghidra_and_a_new_project_gets_them()
    {
        var rig = Setup("ghidra-a");
        var path = Image();
        var data = rig.Native.Image.Sections.First(s => !s.IsExecutable && s.Name == ".data").Rva;
        var fn = rig.Native.Image.Exports.First(e => e.Name == Function).Rva;
        var made = await rig.Types.DefineNative(path, Rva(data), "data", type: "dword[4]", engine: "ghidra");
        output.WriteLine(made);
        Assert.Contains("dword[4], 16 bytes", made);
        var text = await rig.Types.DefineNative(path, Rva(data + 0x60), "data", type: "string[8]", engine: "ghidra");
        output.WriteLine(text);
        Assert.Contains("char[8], 8 bytes", text);
        Assert.Contains("byte(s) undefined", await rig.Types.DefineNative(path, Function, "undefine", engine: "ghidra"));
        var ghidra = await rig.Session("ghidra");
        Assert.DoesNotContain(await ghidra.ListFunctionsAsync(), f => f.StartRva == fn);
        Assert.Contains($"function {Function}", await rig.Types.DefineNative(path, Rva(fn), "function", engine: "ghidra"));
        Assert.Contains(await ghidra.ListFunctionsAsync(), f => f.StartRva == fn);

        Restart();
        var fresh = Setup("ghidra-b");
        output.WriteLine(await fresh.Types.GetNativeFrame(path, Function, engine: "ghidra"));
        var range = await (await fresh.Session("ghidra")).DisassembleRangeAsync(data, 1);
        output.WriteLine(range.Instructions[0].Text);
        Assert.Equal(16, range.Instructions[0].Bytes.Length);
    }
}
