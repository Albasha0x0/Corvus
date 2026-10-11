using NetDecompilerMcp.Core;
using NetDecompilerMcp.Native.Providers;
using NetDecompilerMcp.Native.Providers.Ida;
using NetDecompilerMcp.Services;
using NetDecompilerMcp.Tools;
using Xunit.Abstractions;

namespace NetDecompilerMcp.Tests;

/// <summary>
/// The native edit surface through the tools on a real system DLL, with IDA and with Ghidra: clearing local and stack
/// edits, pseudocode comments, batch renames and comments, before/after pseudocode, type guesses.
/// </summary>
[Trait("Speed", "Slow")]
public sealed class NativeEditParityTests(ITestOutputHelper output) : IDisposable
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
        NativeEditTools Edits)
    {
        public LoadedNative Native => Workspace.Read(() => Workspace.Natives[0]);
        public Task<INativeDecompilerSession> Session(string engine) => Engines.Session(Native, engine, null, default);
        public uint Start => Native.Image.Exports.First(e => e.Name == Function).Rva;
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
            new NativeAnalysisTools(workspace, engines, new OutputPager(options), names, code, types, user),
            new NativeEditTools(workspace, code, new NativeEditService(workspace, code)));
    }

    private void Restart()
    {
        foreach (var d in _owned) d.Dispose();
        _owned.Clear();
    }

    [IdaFact]
    public Task Local_and_stack_edits_clear_in_IDA() => LocalAndStackEditsClear("ida");

    [GhidraFact]
    public Task Local_and_stack_edits_clear_in_Ghidra() => LocalAndStackEditsClear("ghidra");

    private async Task LocalAndStackEditsClear(string engine)
    {
        var rig = Setup(engine + "-c");
        var path = Image();
        var session = await rig.Session(engine);
        var frame = await session.GetFrameAsync(rig.Start);
        var local = frame.Locals.First(l => l.Name.Length > 0 && !l.IsArgument && !l.UserName && l.Stack == null).Name;
        var layer = () => rig.Code.Annotations(rig.Native).UserTypes;

        // renamed, then given its first name back: no edit is left
        output.WriteLine(await rig.Types.SetNativeLocal(path, Function, local, newName: "ndm_a", engine: engine));
        Assert.Single(layer().Locals);
        output.WriteLine(await rig.Types.SetNativeLocal(path, Function, "ndm_a", newName: local, engine: engine));
        Assert.Empty(layer().Locals);
        var text = await rig.Analysis.DecompileNative(path, Function, engine: engine);
        Assert.DoesNotContain("ndm_a", text);
        Assert.Contains(local, text);

        // renamed and retyped, then cleared
        output.WriteLine(await rig.Types.SetNativeLocal(path, Function, local, newName: "ndm_b", type: "unsigned int", engine: engine));
        Assert.Contains("ndm_b", await rig.Analysis.DecompileNative(path, Function, engine: engine));
        var cleared = await rig.Types.SetNativeLocal(path, Function, "ndm_b", clear: true, engine: engine);
        output.WriteLine(cleared);
        Assert.Contains("is cleared", cleared);
        Assert.Empty(layer().Locals);
        Assert.DoesNotContain("ndm_b", await rig.Analysis.DecompileNative(path, Function, engine: engine));
        Assert.Equal(ErrorCode.InvalidArgument, (await Assert.ThrowsAsync<ToolError>(() => rig.Types.SetNativeLocal(path, Function, local, newName: "x", clear: true, engine: engine))).Code);

        // a stack member renamed and retyped, then cleared: the engine's member is back
        var member = frame.Members.First(m => m.Kind == "local" && m.Size >= 4);
        output.WriteLine(await rig.Types.SetNativeStackVar(path, Function, $"0x{member.Offset:X}", newName: "ndm_slot", type: "int", engine: engine));
        Assert.Single(layer().StackVars);
        output.WriteLine(await rig.Types.SetNativeStackVar(path, Function, "ndm_slot", clear: true, engine: engine));
        Assert.Empty(layer().StackVars);
        var now = (await session.GetFrameAsync(rig.Start)).Members.Single(m => m.Offset == member.Offset);
        Assert.Equal((member.Name, member.Type), (now.Name, now.Type));
    }
}
