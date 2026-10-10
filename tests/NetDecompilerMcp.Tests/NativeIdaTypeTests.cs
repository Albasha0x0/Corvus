using System.Diagnostics;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Native.Providers;
using NetDecompilerMcp.Native.Providers.Ida;
using NetDecompilerMcp.Services;
using NetDecompilerMcp.Tools;
using Xunit.Abstractions;

namespace NetDecompilerMcp.Tests;

/// <summary>
/// The user's types in IDA through the tools, on a real system DLL: applied, shown in pseudocode, replayed after a worker
/// restart, pushed into a new database from the sidecar, and kept over recovered types.
/// </summary>
[Trait("Speed", "Slow")]
public sealed class NativeIdaTypeTests(ITestOutputHelper output) : IDisposable
{
    private const string Function = "CheckSumMappedFile";
    private readonly TempDir _dir = new();
    private readonly List<IDisposable> _owned = [];

    public void Dispose()
    {
        foreach (var d in _owned) d.Dispose();
        _dir.Dispose();
    }

    private static string Image => NativeIdaProviderTests.System64;

    internal sealed record Rig(AssemblyWorkspace Workspace, NativeCodeService Code, NativeEngineService Engines, NativeAnalysisTools Analysis, NativeTypeTools Types)
    {
        public LoadedNative Native => Workspace.Read(() => Workspace.Natives[0]);
        public async Task<IdaSession> Session() => (IdaSession)await Engines.Session(Native, null, null, default);
    }

    /// <summary>A server on <paramref name="cache"/> (its IDA databases) and the shared annotation sidecars.</summary>
    private Rig Setup(string cache)
    {
        var options = new ServerOptions { TimeoutSeconds = 300, BackgroundIndexing = false };
        var workspace = new AssemblyWorkspace(options);
        var code = new NativeCodeService(workspace, options, null, new Native.Annotations.AnnotationStore(_dir.File("annotations")));
        var engines = new NativeEngineService(new IdaProviderOptions { CacheRoot = _dir.File(cache) }, code, workspace, options);
        _owned.Add(engines);
        _owned.Add(workspace);
        var pager = new OutputPager(options);
        var names = new NativeNamePush(code);
        var types = new NativeTypePush();
        var user = new NativeUserTypePush(code);
        workspace.LoadAny(Image);
        return new Rig(workspace, code, engines, new NativeAnalysisTools(workspace, engines, pager, names, code, types, user),
            new NativeTypeTools(workspace, engines, user, code, names, types));
    }

    [IdaFact]
    public async Task Prototype_and_global_type_apply_replay_after_a_restart_and_reach_a_new_database()
    {
        var rig = Setup("cache-a");
        var prototype = "int __fastcall CheckSumMappedFile(void *base, unsigned int length, unsigned int *headerSum, unsigned int *checkSum)";
        output.WriteLine(await rig.Types.SetNativeType(Image, Function, prototype));
        var text = await rig.Analysis.DecompileNative(Image, Function);
        output.WriteLine(text);
        Assert.Contains("unsigned int *headerSum", text);

        var data = rig.Native.Image.Sections.First(s => !s.IsExecutable && s.Name == ".data");
        var global = await rig.Types.SetNativeType(Image, $"rva:0x{data.Rva:X}", "unsigned int[4]");
        Assert.Contains("unsigned int[4]", global);
        var bad = await Assert.ThrowsAsync<ToolError>(() => rig.Types.SetNativeType(Image, Function, "int f(no_such_type_t *p)"));
        Assert.Equal(ErrorCode.InvalidArgument, bad.Code);
        Assert.Equal(2, rig.Code.Annotations(rig.Native).UserTypes.Types.Count);

        // the edits are journaled: a worker killed before any save replays them
        var session = await rig.Session();
        using (var worker = Process.GetProcessById(session.WorkerProcessId!.Value)) worker.Kill();
        await Task.Delay(300);
        var rva = rig.Native.Image.Exports.First(e => e.Name == Function).Rva;
        Assert.Contains("headerSum", (await session.DecompileAsync(rva)).Text);

        // another database (another IDA cache) gets them from the sidecar
        foreach (var d in _owned) d.Dispose();
        _owned.Clear();
        var fresh = Setup("cache-b");
        var again = await fresh.Analysis.DecompileNative(Image, Function);
        Assert.Contains("user types: pushed 2 item(s)", again);
        Assert.Contains("unsigned int *headerSum", again);

        // clearing restores IDA's own type
        await fresh.Types.SetNativeType(Image, Function, "");
        Assert.DoesNotContain("headerSum", await fresh.Analysis.DecompileNative(Image, Function));
        Assert.Single(fresh.Code.Annotations(fresh.Native).UserTypes.Types);
    }

    [IdaFact]
    public async Task Recovered_types_never_replace_user_types()
    {
        var rig = Setup("cache-c");
        var session = await rig.Session();
        var rva = rig.Native.Image.Exports.First(e => e.Name == Function).Rva;
        var user = await session.ApplyUserTypesAsync(new NativeUserTypeBatch([], [new NativePrototype(rva, "int __fastcall f(void *userBase, int userLength)")], [], []));
        Assert.True(user.Items[0].Applied, user.Items[0].Error);
        var pushed = await session.ApplyTypesAsync(new NativeTypeBatch(null, [new NativePrototype(rva, "int __fastcall f(char *pushedBase)")], [], [], 8));
        Assert.Equal(0, pushed.Typed);
        var text = (await session.DecompileAsync(rva)).Text;
        Assert.Contains("userBase", text);
        Assert.DoesNotContain("pushedBase", text);
    }
}
