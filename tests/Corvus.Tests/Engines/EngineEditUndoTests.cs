using Corvus.Core;
using Corvus.Native.Annotations;
using Corvus.Native.Providers;
using Corvus.Native.Providers.Ida;
using Corvus.Services;
using Corvus.Tools;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>
/// The engine edit tools against real engines: each edit names its editId, and undo_native_edit takes back a local, a
/// stack member, an enum member, a struct field, a declaration and a type deletion in the engine's database.
/// </summary>
[Trait("Speed", "Slow")]
[Trait("Data", "Real")]
public sealed class EngineEditUndoTests(ITestOutputHelper output) : IDisposable
{
    private const string Function = "CheckSumMappedFile";
    private readonly TempDir _dir = new();
    private readonly List<IDisposable> _owned = [];

    public void Dispose()
    {
        foreach (var d in _owned) d.Dispose();
        _dir.Dispose();
    }

    private sealed record Rig(AssemblyWorkspace Workspace, NativeCodeService Code, NativeEngineService Engines, NativeTypeTools Types, NativeEditJournal Journal)
    {
        public LoadedNative Native => Workspace.Read(() => Workspace.Natives[0]);
    }

    private Rig Setup(string engine)
    {
        var options = new ServerOptions { TimeoutSeconds = 600, BackgroundIndexing = false };
        var workspace = new AssemblyWorkspace(options);
        var code = new NativeCodeService(workspace, options, null, new AnnotationStore(_dir.File("annotations-" + engine)));
        var engines = new NativeEngineService(new IdaProviderOptions { CacheRoot = _dir.File("cache-" + engine) }, code, workspace, options);
        _owned.Add(engines);
        _owned.Add(workspace);
        var names = new NativeNamePush(code);
        var user = new NativeUserTypePush(code);
        var journal = new NativeEditJournal(workspace, code, engines, names, user);
        var dir = Directory.CreateDirectory(_dir.File("input-" + engine)).FullName;
        var copy = Path.Combine(dir, Path.GetFileName(NativeIdaProviderTests.System64));
        File.Copy(NativeIdaProviderTests.System64, copy, overwrite: true);
        workspace.LoadAny(copy);
        return new Rig(workspace, code, engines, new NativeTypeTools(workspace, engines, user, code, names, new NativeTypePush(), journal), journal);
    }

    /// <summary>Runs an edit tool and returns its text and the editId of its outcome.</summary>
    private async Task<(string Text, EditId Id)> Edit(Func<Task<string>> call)
    {
        var (text, c) = await EngineMeta.Run(call);
        output.WriteLine(text.Split('\n')[0]);
        var outcome = Assert.IsType<EditResult>(c.Record);
        Assert.True(outcome.Applied);
        Assert.True(EditId.TryParse(Assert.Single(outcome.EditIds), out var id));
        return (text, id);
    }

    [IdaFact]
    public Task Engine_edits_undo_in_IDA() => EngineEditsUndo("ida");

    [GhidraFact]
    public Task Engine_edits_undo_in_Ghidra() => EngineEditsUndo("ghidra");

    private async Task EngineEditsUndo(string engine)
    {
        var rig = Setup(engine);
        var native = rig.Native;
        var fn = native.Image.Exports.First(e => e.Name == Function).Rva;
        var session = await rig.Engines.Session(native, engine, null, default);
        async Task<string> Pseudocode() => (await session.DecompileAsync(fn)).Text;
        async Task<NativeFrame> Frame() => await session.GetFrameAsync(fn, true, default);

        // a decompiler local renamed, then undone
        var local = (await Frame()).Locals.First(l => !l.IsArgument && l.Name.Length > 0 && Regex(l.Name)).Name;
        var (_, localEdit) = await Edit(() => rig.Types.SetNativeLocal(native.Id, Function, local, "corvus_local", engine: engine));
        Assert.Contains("corvus_local", await Pseudocode());
        await rig.Journal.UndoAsync(native, localEdit, default);
        Assert.DoesNotContain("corvus_local", await Pseudocode());
        Assert.Contains((await Frame()).Locals, l => l.Name == local);

        // a stack member renamed, then undone
        var member = (await Frame()).Members.First(m => m.Kind != "special" && m.Name.Length > 0);
        var (_, memberEdit) = await Edit(() => rig.Types.SetNativeStackVar(native.Id, Function, $"0x{member.Offset:X}", "corvus_slot", engine: engine));
        Assert.Contains((await Frame()).Members, m => m.Name == "corvus_slot");
        await rig.Journal.UndoAsync(native, memberEdit, default);
        Assert.DoesNotContain((await Frame()).Members, m => m.Name == "corvus_slot");

        // a declaration; an enum member and a struct field added to it; each undone
        var (_, declared) = await Edit(() => rig.Types.DeclareNativeTypes(native.Id, "enum CorvusColor { CorvusRed = 1 }; struct CorvusPacket { int length; };", engine: engine));
        var (_, enumEdit) = await Edit(() => rig.Types.DeclareNativeTypes(native.Id, typeName: "CorvusColor", members: "CorvusGreen=2", engine: engine));
        var (_, fieldEdit) = await Edit(() => rig.Types.DeclareNativeTypes(native.Id, typeName: "CorvusPacket", fields: "flags@0x4: int", engine: engine));
        Assert.Contains("CorvusGreen", (await session.GetTypeAsync("CorvusColor")).Declaration);
        Assert.Contains((await session.GetTypeAsync("CorvusPacket")).Members, m => m.Name == "flags");
        await rig.Journal.UndoAsync(native, fieldEdit, default);
        Assert.DoesNotContain((await session.GetTypeAsync("CorvusPacket")).Members, m => m.Name == "flags");
        await rig.Journal.UndoAsync(native, enumEdit, default);
        Assert.DoesNotContain("CorvusGreen", (await session.GetTypeAsync("CorvusColor")).Declaration);
        await rig.Journal.UndoAsync(native, declared, default);
        Assert.Equal(ErrorCode.NotFound, (await Assert.ThrowsAsync<ToolError>(() => session.GetTypeAsync("CorvusPacket"))).Code);

        // a redeclared type comes back as it was; a deleted one comes back from its declaration
        await Edit(() => rig.Types.DeclareNativeTypes(native.Id, "struct CorvusHeader { int magic; };", engine: engine));
        var (_, redeclared) = await Edit(() => rig.Types.DeclareNativeTypes(native.Id, "struct CorvusHeader { int magic; int size; };", engine: engine));
        await rig.Journal.UndoAsync(native, redeclared, default);
        Assert.DoesNotContain((await session.GetTypeAsync("CorvusHeader")).Members, m => m.Name == "size");
        var (_, deleted) = await Edit(() => rig.Types.DeclareNativeTypes(native.Id, delete: "CorvusHeader", engine: engine));
        Assert.Equal(ErrorCode.NotFound, (await Assert.ThrowsAsync<ToolError>(() => session.GetTypeAsync("CorvusHeader"))).Code);
        await rig.Journal.UndoAsync(native, deleted, default);
        Assert.Contains((await session.GetTypeAsync("CorvusHeader")).Members, m => m.Name == "magic");

        static bool Regex(string name) => System.Text.RegularExpressions.Regex.IsMatch(name, @"^[A-Za-z_]\w*$");
    }
}
