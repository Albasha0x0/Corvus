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

    [IdaFact]
    public Task Struct_layout_edits_in_IDA() => StructLayout("ida");

    [GhidraFact]
    public Task Struct_layout_edits_in_Ghidra() => StructLayout("ghidra");

    /// <summary>Stack members and operands in one call each: per-item refusals, one editId whose undo takes back every applied item.</summary>
    [IdaFact]
    public async Task Stack_and_operand_batches_in_IDA()
    {
        var rig = Setup("ida");
        var native = rig.Native;
        var fn = native.Image.Exports.First(e => e.Name == Function).Rva;
        var session = await rig.Engines.Session(native, "ida", null, default);
        var members = (await session.GetFrameAsync(fn, false, default)).Members.Where(m => m.Kind != "special" && m.Name.Length > 0).Take(2).ToList();
        Assert.Equal(2, members.Count);
        var (text, id) = await Edit(() => rig.Types.SetNativeStackVar(native.Id, Function, engine: "ida",
            items: $"{members[0].Name} = corvus_a\n{members[1].Name} = corvus_b\nno_such_member = x"));
        output.WriteLine(text);
        Assert.Contains("2 of 3 stack edit(s) applied", text);
        Assert.Equal(2, (await session.GetFrameAsync(fn, false, default)).Members.Count(m => m.Name.StartsWith("corvus_", StringComparison.Ordinal)));
        await rig.Journal.UndoAsync(native, id, default);
        Assert.DoesNotContain((await session.GetFrameAsync(fn, false, default)).Members, m => m.Name.StartsWith("corvus_", StringComparison.Ordinal));

        var constants = (await session.DisassembleAsync(fn)).Instructions.Where(i => i.Text.Contains(", 0x", StringComparison.OrdinalIgnoreCase) || i.Text.Contains(", 1", StringComparison.Ordinal)).Take(2).ToList();
        Assert.Equal(2, constants.Count);
        var json = "[" + string.Join(",", constants.Select(i => $$"""{"address":"0x{{native.Image.ImageBase + i.Rva:X}}","operand":1,"display":"dec"}""")) + """,{"address":"0x1","operand":9,"display":"dec"}]""";
        var (ops, _) = await Edit(() => rig.Types.SetNativeOperand(native.Id, $"0x{native.Image.ImageBase + fn:X}", engine: "ida", items: json));
        output.WriteLine(ops);
        Assert.Contains("2 of 3 operand edit(s) applied", ops);
    }

    [IdaFact]
    public Task Argument_storage_in_IDA() => ArgumentStorage("ida");

    [GhidraFact]
    public Task Argument_storage_in_Ghidra() => ArgumentStorage("ghidra");

    /// <summary>The first argument moved to r10, then undone to where the convention puts it; a non-argument is refused.</summary>
    private async Task ArgumentStorage(string engine)
    {
        var rig = Setup(engine);
        var native = rig.Native;
        var fn = native.Image.Exports.First(e => e.Name == Function).Rva;
        var session = await rig.Engines.Session(native, engine, null, default);
        async Task<NativeLocal> First() => (await session.GetFrameAsync(fn, true, default)).Locals.Where(l => l.IsArgument).OrderBy(l => l.Name, StringComparer.Ordinal).First();
        var arg = await First();
        output.WriteLine($"{arg.Name} {arg.Type} in {arg.Location}");
        var (moved, edit) = await Edit(() => rig.Types.SetNativeLocal(native.Id, Function, arg.Name, engine: engine, storage: "r10"));
        output.WriteLine(moved);
        Assert.Contains(" in r10", moved);
        Assert.Equal("r10", (await First()).Location, ignoreCase: true);
        await rig.Journal.UndoAsync(native, edit, default);
        Assert.Equal(arg.Location, (await First()).Location, ignoreCase: true);

        var local = (await session.GetFrameAsync(fn, true, default)).Locals.First(l => !l.IsArgument && l.Name.Length > 0);
        Assert.Equal(ErrorCode.InvalidArgument, (await Assert.ThrowsAsync<ToolError>(() => rig.Types.SetNativeLocal(native.Id, Function, local.Name, engine: engine, storage: "r10"))).Code);
    }

    /// <summary>On a 40-field struct: one field retyped keeps the rest; an insert moves the later fields and its undo moves them back; resize and gap names undo.</summary>
    private async Task StructLayout(string engine)
    {
        var rig = Setup(engine);
        var native = rig.Native;
        var session = await rig.Engines.Session(native, engine, null, default);
        async Task<Dictionary<string, long>> Offsets() => (await session.GetTypeAsync("Corvus40")).Members.Where(m => !m.Name.StartsWith("gap", StringComparison.Ordinal))
            .ToDictionary(m => m.Name, m => m.Offset);
        async Task<long> Size() => (await session.GetTypeAsync("Corvus40")).Size;

        await Edit(() => rig.Types.DeclareNativeTypes(native.Id, "struct Corvus40 { " + string.Concat(Enumerable.Range(0, 40).Select(i => $"int f{i}; ")) + "};", engine: engine));
        var before = await Offsets();
        await Edit(() => rig.Types.DeclareNativeTypes(native.Id, typeName: "Corvus40", fields: "f20: short", engine: engine));
        var after = await Offsets();
        Assert.Equal(before, after);
        Assert.Equal(2, (await session.GetTypeAsync("Corvus40")).Members.Single(m => m.Name == "f20").Size);

        var (inserted, insert) = await Edit(() => rig.Types.DeclareNativeTypes(native.Id, typeName: "Corvus40", fields: "+ins@0x8: int", engine: engine));
        Assert.Contains("moved down 4 bytes", inserted);
        var shifted = await Offsets();
        Assert.Equal(8, shifted["ins"]);
        Assert.Equal(12, shifted["f2"]);
        Assert.Equal(before["f39"] + 4, shifted["f39"]);
        await rig.Journal.UndoAsync(native, insert, default);
        Assert.Equal(before, await Offsets());

        var size = await Size();
        var (_, resized) = await Edit(() => rig.Types.DeclareNativeTypes(native.Id, typeName: "Corvus40", resize: "0x100", engine: engine));
        Assert.Equal(0x100, await Size());
        await rig.Journal.UndoAsync(native, resized, default);
        Assert.Equal(size, await Size());

        await Edit(() => rig.Types.DeclareNativeTypes(native.Id, typeName: "Corvus40", fields: "f30:", engine: engine));
        var (_, named) = await Edit(() => rig.Types.DeclareNativeTypes(native.Id, typeName: "Corvus40", nameGaps: true, engine: engine));
        Assert.Contains((await session.GetTypeAsync("Corvus40")).Members, m => m.Name == $"gap_{before["f30"]:X}");
        await rig.Journal.UndoAsync(native, named, default);
        Assert.DoesNotContain((await session.GetTypeAsync("Corvus40")).Members, m => m.Name.StartsWith("gap_", StringComparison.Ordinal));
    }

    private async Task EngineEditsUndo(string engine)
    {
        var rig = Setup(engine);
        var native = rig.Native;
        var fn = native.Image.Exports.First(e => e.Name == Function).Rva;
        var session = await rig.Engines.Session(native, engine, null, default);
        async Task<string> Pseudocode() => (await session.DecompileAsync(fn)).Text;
        async Task<NativeFrame> Frame() => await session.GetFrameAsync(fn, true, default);

        // a decompiler local renamed, then undone
        var original = (await Frame()).Locals.First(l => !l.IsArgument && l.Name.Length > 0 && Regex(l.Name));
        var local = original.Name;
        var (_, localEdit) = await Edit(() => rig.Types.SetNativeLocal(native.Id, Function, local, "corvus_local", engine: engine));
        Assert.Contains("corvus_local", await Pseudocode());
        await rig.Journal.UndoAsync(native, localEdit, default);
        Assert.DoesNotContain("corvus_local", await Pseudocode());
        // the slot is back to an engine default name; Ghidra may derive another default than before (local_res8 / puStackX_8)
        Assert.Contains((await Frame()).Locals, l => l.Location == original.Location && l.Stack == original.Stack && !l.UserName && l.Name != "corvus_local");

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
