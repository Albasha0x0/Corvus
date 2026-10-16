using Corvus.Core;
using Corvus.Native.Annotations;
using Corvus.Native.Providers;
using Corvus.Native.Providers.Ida;
using Corvus.Services;
using Corvus.Tools;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>
/// The native edit journal against real engines (EL-6): a rename and each engine edit kind journaled, then undone, and the
/// engine's database shows the state from before the edit again.
/// </summary>
[Trait("Speed", "Slow")]
[Trait("Data", "Real")]
public sealed class NativeEditUndoEngineTests(ITestOutputHelper output) : IDisposable
{
    private const string Function = "CheckSumMappedFile";
    private readonly TempDir _dir = new();
    private readonly List<IDisposable> _owned = [];

    public void Dispose()
    {
        foreach (var d in _owned) d.Dispose();
        _dir.Dispose();
    }

    private sealed record Rig(AssemblyWorkspace Workspace, NativeCodeService Code, NativeEngineService Engines, NativeEditTools Tools, NativeEditJournal Journal)
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
        var edits = new NativeEditService(workspace, code, journal);
        var dir = Directory.CreateDirectory(_dir.File("input-" + engine)).FullName;
        var copy = Path.Combine(dir, Path.GetFileName(NativeIdaProviderTests.System64));
        File.Copy(NativeIdaProviderTests.System64, copy, overwrite: true);
        workspace.LoadAny(copy);
        return new Rig(workspace, code, engines, new NativeEditTools(workspace, code, edits, null, engines, names, new NativeTypePush(), user), journal);
    }

    /// <summary>The nine native-edit tools by name on a real library: previews by default, edit ids, paging, undo, save and exports.</summary>
    [Fact]
    public async Task Native_edit_tools_round_trip_on_a_real_library()
    {
        using var copy = new OwnCopy(RealPackages.File("SQLitePCLRaw.lib.e_sqlite3", "2.1.11", "runtimes", "win-x64", "native", "e_sqlite3.dll"), _dir.File("e_sqlite3.dll"));
        var path = copy.Path;
        await using var server = await InProcessServer.StartAsync();
        async Task<System.Text.Json.JsonElement> Call(string tool, Dictionary<string, object?> args)
        {
            var r = await server.Client.CallToolAsync(tool, args);
            var text = string.Concat(r.Content.OfType<ModelContextProtocol.Protocol.TextContentBlock>().Select(b => b.Text));
            Assert.True(r.IsError != true, $"{tool}: {text}");
            output.WriteLine($"{tool}: {text.Split('\n')[0]}");
            return r.StructuredContent!.Value;
        }
        const string Fn = "sqlite3_libversion_number";
        const string name = "corvus_libversion_number";
        var preview = await Call("rename_native", new() { ["image"] = path, ["address"] = Fn, ["name"] = name });
        Assert.True(preview.GetProperty("dryRun").GetBoolean());
        Assert.Equal("e_sqlite3.dll#1", (await Call("rename_native", new() { ["image"] = "e_sqlite3.dll", ["address"] = Fn, ["name"] = name, ["dryRun"] = false }))
            .GetProperty("editIds")[0].GetString());
        await Call("comment_native", new() { ["image"] = "e_sqlite3.dll", ["address"] = name, ["text"] = "returns the version " + name, ["dryRun"] = false });
        Assert.False((await Call("patch_asm", new() { ["image"] = "e_sqlite3.dll", ["address"] = name, ["assembly"] = "xor eax, eax\nret" })).GetProperty("applied").GetBoolean());
        await Call("patch_asm", new() { ["image"] = "e_sqlite3.dll", ["address"] = name, ["assembly"] = "xor eax, eax\nret", ["dryRun"] = false });
        var patch = await Call("patch_bytes", new() { ["image"] = "e_sqlite3.dll", ["address"] = "sqlite3_libversion", ["hex"] = "CC", ["dryRun"] = false });
        Assert.Equal("e_sqlite3.dll#4", patch.GetProperty("editIds")[0].GetString());
        var page = await Call("list_native_edits", new() { ["image"] = "e_sqlite3.dll", ["limit"] = 2 });
        Assert.Equal((4, true, 2), (page.GetProperty("total").GetInt32(), page.GetProperty("hasMore").GetBoolean(), page.GetProperty("nextOffset").GetInt32()));
        var saved = await Call("save_native", new() { ["image"] = "e_sqlite3.dll", ["outputPath"] = _dir.File("patched.dll") });
        Assert.True(saved.GetProperty("verified").GetBoolean());
        Assert.Equal(2, saved.GetProperty("patches").GetInt32());
        await Call("export_native_patches", new() { ["image"] = "e_sqlite3.dll", ["outputPath"] = _dir.File("patches.json"), ["format"] = "json" });
        Assert.Equal(1, (await Call("export_native_annotations", new() { ["image"] = "e_sqlite3.dll", ["outputPath"] = _dir.File("ann.json") })).GetProperty("names").GetInt32());
        var undone = await Call("undo_native_edit", new() { ["image"] = "e_sqlite3.dll", ["editId"] = "e_sqlite3.dll#1" });
        Assert.Equal("e_sqlite3.dll#1", undone.GetProperty("editIds")[0].GetString());
        Assert.Equal(3, (await Call("list_native_edits", new() { ["image"] = "e_sqlite3.dll" })).GetProperty("total").GetInt32());
    }

    [IdaFact]
    public Task Rename_and_engine_edits_undo_in_IDA() => RenameAndEngineEditsUndo("ida");

    [GhidraFact]
    public Task Rename_and_engine_edits_undo_in_Ghidra() => RenameAndEngineEditsUndo("ghidra");

    private async Task RenameAndEngineEditsUndo(string engine)
    {
        var rig = Setup(engine);
        var native = rig.Native;
        var fn = native.Image.Exports.First(e => e.Name == Function).Rva;
        var session = await rig.Engines.Session(native, engine, null, default);
        async Task<string> NameInEngine() => (await session.ListFunctionsAsync()).First(f => f.StartRva == fn).Name;
        async Task<string> Pseudocode() => (await session.DecompileAsync(fn)).Text;

        // rename: pushed to the engine, undone and pushed back
        var original = await NameInEngine();
        await rig.Tools.RenameNative(native.Id, $"rva:0x{fn:X}", "corvus_undo_probe", dryRun: false, engine: engine);
        Assert.Equal("corvus_undo_probe", await NameInEngine());
        var undone = await rig.Tools.UndoNativeEdit(native.Id);
        output.WriteLine(undone);
        Assert.Contains(engine == "ida" ? "IDA" : "Ghidra", undone);
        Assert.Equal(original, await NameInEngine());

        // engine edits: a prototype, an operand display, an analysis edit; each undone in turn
        Assert.DoesNotContain("corvus_", await Pseudocode());
        var proto = await rig.Journal.ApplyUserTypesAsync(native, session, "engine type",
            new NativeUserTypeBatch([], [new NativePrototype(fn, $"int __fastcall {Function}(void *corvus_base, unsigned int corvus_length, unsigned int *a3, unsigned int *a4);")], [], []),
            (r, layer) => r.Items.All(i => i.Applied) ? layer.WithType(fn, $"int __fastcall {Function}(void *corvus_base, unsigned int corvus_length, unsigned int *a3, unsigned int *a4);") : null, default);
        Assert.NotNull(proto.EditId);
        Assert.Contains("corvus_base", await Pseudocode());

        var insn = (await session.DisassembleAsync(fn)).Instructions.First(i => i.Text.Contains("10B", StringComparison.OrdinalIgnoreCase));
        var operand = new NativeOperandEdit(insn.Rva, 1, "dec", null);
        var shown = await rig.Journal.ApplyUserTypesAsync(native, session, "engine operand", NativeUserTypeBatch.Empty with { Operands = [operand] },
            (r, layer) => r.Items.All(i => i.Applied) ? layer.WithOperand(operand) : null, default);
        Assert.NotNull(shown.EditId);
        async Task<string> InsnText() => (await session.DisassembleAsync(fn)).Instructions.First(i => i.Rva == insn.Rva).Text;
        Assert.Contains("267", await InsnText());

        var data = native.Image.Sections.First(s => !s.IsExecutable && s.Name == ".data").Rva + 0x80;
        var define = new NativeAnalysisEdit(data, NativeAnalysisEdit.Data, null, "dword[4]");
        var defined = await rig.Journal.ApplyUserTypesAsync(native, session, "engine define", NativeUserTypeBatch.Empty with { Analysis = [define] },
            (r, layer) => r.Items.All(i => i.Applied) ? layer.WithAnalysis(define) : null, default);
        Assert.NotNull(defined.EditId);

        // undone out of order: the prototype first, then the operand, then the data item
        var r1 = await rig.Journal.UndoAsync(native, proto.EditId, default);
        output.WriteLine(string.Join("; ", r1.Notes));
        Assert.Equal([engine], r1.PushedTo);
        Assert.DoesNotContain("corvus_base", await Pseudocode());
        Assert.DoesNotContain(r1.Notes, n => n.Contains("did not take back", StringComparison.Ordinal));

        var r2 = await rig.Journal.UndoAsync(native, shown.EditId, default);
        Assert.DoesNotContain("267", await InsnText());
        Assert.Equal(insn.Text, await InsnText());
        Assert.DoesNotContain(r2.Notes, n => n.Contains("did not take back", StringComparison.Ordinal));

        var r3 = await rig.Journal.UndoAsync(native, defined.EditId, default);
        output.WriteLine(string.Join("; ", r3.Notes));
        Assert.DoesNotContain(r3.Notes, n => n.Contains("did not take back", StringComparison.Ordinal));
        Assert.True(rig.Code.Annotations(native).UserTypes.IsEmpty);
        // a cleared prototype is the engine's own again (IDA may derive another calling convention than its type library gave)
        Assert.DoesNotContain("corvus_", await Pseudocode());
        Assert.Empty(rig.Journal.Entries(native));
    }

}
