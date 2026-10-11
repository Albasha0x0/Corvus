using Corvus.Core;
using Corvus.Native.Providers;
using Corvus.Native.Providers.Ida;
using Corvus.Services;
using Corvus.Tools;
using Xunit.Abstractions;

namespace Corvus.Tests;

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
            new NativeEditTools(workspace, code, new NativeEditService(workspace, code), null, engines, names, types, user));
    }

    private void Restart()
    {
        foreach (var d in _owned) d.Dispose();
        _owned.Clear();
    }

    private static string Rva(uint rva) => $"rva:0x{rva:X}";

    [IdaFact]
    public Task Pseudocode_comments_show_clear_and_reach_a_new_database_in_IDA() => PseudocodeComments("ida");

    [GhidraFact]
    public Task Pseudocode_comments_show_clear_and_reach_a_new_database_in_Ghidra() => PseudocodeComments("ghidra");

    private async Task PseudocodeComments(string engine)
    {
        var rig = Setup(engine + "-p");
        var path = Image();
        var session = await rig.Session(engine);
        var lines = (await session.DecompileAsync(rig.Start)).LineAddresses.Where(l => l.Rva > rig.Start).ToList();
        var at = lines[lines.Count / 2].Rva;

        var set = await rig.Edits.CommentNative(path, Rva(at), "ndm pseudo note", scope: "pseudocode", engine: engine);
        output.WriteLine(set);
        Assert.Contains("Pushed to the engine", set);
        var text = await rig.Analysis.DecompileNative(path, Function, engine: engine);
        output.WriteLine(text);
        Assert.Contains("ndm pseudo note", text);
        // appended and deduped in the sidecar, then shown as two lines
        await rig.Edits.CommentNative(path, Rva(at), "ndm second line", scope: "pseudocode", append: true, engine: engine);
        Assert.Contains("already has this line", await rig.Edits.CommentNative(path, Rva(at), "ndm second line", scope: "pseudocode", append: true, engine: engine));
        Assert.Contains("ndm second line", await rig.Analysis.DecompileNative(path, Function, engine: engine));

        // cleared
        await rig.Edits.CommentNative(path, Rva(at), "", scope: "pseudocode", engine: engine);
        Assert.DoesNotContain("ndm pseudo note", await rig.Analysis.DecompileNative(path, Function, engine: engine));

        // an address inside an instruction lands on the statement made from it; a new database gets it from the sidecar
        await rig.Edits.CommentNative(path, Rva(at + 1), "ndm inside", scope: "pseudocode", engine: engine);
        Assert.Contains("ndm inside", await rig.Analysis.DecompileNative(path, Function, engine: engine));
        Restart();
        var fresh = Setup(engine + "-q");
        var again = await fresh.Analysis.DecompileNative(path, Function, engine: engine);
        Assert.Contains("ndm inside", again);
    }

    [GhidraFact]
    public async Task Comment_kinds_reach_Ghidra_and_a_pre_comment_shows_in_its_pseudocode()
    {
        var rig = Setup("ghidra-k");
        var path = Image();
        var session = await rig.Session("ghidra");
        var lines = (await session.DecompileAsync(rig.Start)).LineAddresses.Where(l => l.Rva > rig.Start).ToList();
        var at = lines[lines.Count / 2].Rva;
        await rig.Edits.CommentNative(path, Rva(at), "ndm kind note", scope: "pre", engine: "ghidra");
        Assert.Contains("ndm kind note", await rig.Analysis.DecompileNative(path, Function, engine: "ghidra"));
        // another kind: the pre comment is removed (the decompiler does not print end-of-line comments)
        await rig.Edits.CommentNative(path, Rva(at), "ndm kind note", scope: "eol", engine: "ghidra");
        Assert.DoesNotContain("ndm kind note", await rig.Analysis.DecompileNative(path, Function, engine: "ghidra"));
    }

    [IdaFact]
    public async Task Comment_kinds_reach_IDA_as_regular_and_anterior_comments()
    {
        var rig = Setup("ida-k");
        var path = Image();
        var session = await rig.Session("ida");
        var at = (await session.DisassembleAsync(rig.Start)).Instructions[3].Rva;
        async Task<string> Ida(string expr) => (await session.RunScriptAsync(expr)).Result ?? "";
        await rig.Edits.CommentNative(path, Rva(at), "ndm pre", scope: "pre", engine: "ida");
        Assert.Contains("ndm pre", await Ida($"__import__('ida_lines').get_extra_cmt(base + 0x{at:X}, __import__('ida_lines').E_PREV)"));
        await rig.Edits.CommentNative(path, Rva(at), "ndm eol", scope: "eol", engine: "ida");
        Assert.Contains("ndm eol", await Ida($"ida_bytes.get_cmt(base + 0x{at:X}, False)"));
        Assert.DoesNotContain("ndm pre", await Ida($"__import__('ida_lines').get_extra_cmt(base + 0x{at:X}, __import__('ida_lines').E_PREV)"));
    }

    [IdaFact]
    public Task Batch_renames_comments_and_locals_reach_IDA_in_one_push() => BatchEdits("ida");

    [GhidraFact]
    public Task Batch_renames_comments_and_locals_reach_Ghidra_in_one_push() => BatchEdits("ghidra");

    private async Task BatchEdits(string engine)
    {
        var rig = Setup(engine + "-b");
        var path = Image();
        var session = await rig.Session(engine);
        var callees = (await session.GetXrefsFromAsync(rig.Start, wholeFunction: true)).Where(x => x.Kind == NativeXrefKind.Call).Select(x => x.ToRva).Distinct()
            .Where(t => rig.Native.Image.SectionAt(t) is { IsExecutable: true }).Take(2).ToList();
        Assert.True(callees.Count >= 1, "no direct callee");
        var items = string.Join("\n", callees.Select((c, i) => $"{Rva(c)} = ndm_callee_{i}"));
        var renamed = await rig.Edits.RenameNative(path, items: items, engine: engine);
        output.WriteLine(renamed);
        Assert.StartsWith($"{callees.Count} name item(s): {callees.Count} ok, 0 failed", renamed);
        var lines = (await session.DecompileAsync(rig.Start)).LineAddresses.Where(l => l.Rva > rig.Start).ToList();
        var commented = await rig.Edits.CommentNative(path, items: $"{Rva(lines[lines.Count / 3].Rva)} = ndm batch one\n{Rva(lines[2 * lines.Count / 3].Rva)} = ndm batch two", scope: "pseudocode", engine: engine);
        output.WriteLine(commented);
        var text = await rig.Analysis.DecompileNative(path, Function, engine: engine);
        output.WriteLine(text);
        Assert.Contains("ndm_callee_0", text);
        Assert.Contains("ndm batch one", text);
        Assert.Contains("ndm batch two", text);

        var frame = await session.GetFrameAsync(rig.Start);
        var locals = frame.Locals.Where(l => l.Name.Length > 0 && !l.IsArgument && !l.UserName).Take(2).Select(l => l.Name).ToList();
        var edited = await rig.Types.SetNativeLocal(path, Function, items: $"{locals[0]} = ndm_l0\n{locals[1]} = ndm_l1\nno_such_local = x", engine: engine);
        output.WriteLine(edited);
        Assert.StartsWith("2 of 3 local edit(s) applied", edited);
        Assert.Equal(2, rig.Code.Annotations(rig.Native).UserTypes.Locals.Values.Sum(l => l.Count));
    }

    [IdaFact]
    public Task Edits_show_the_pseudocode_diff_and_a_prototype_names_the_function_in_IDA() => DiffAndPrototypeName("ida");

    [GhidraFact]
    public Task Edits_show_the_pseudocode_diff_and_a_prototype_names_the_function_in_Ghidra() => DiffAndPrototypeName("ghidra");

    private async Task DiffAndPrototypeName(string engine)
    {
        var rig = Setup(engine + "-d");
        var path = Image();
        var session = await rig.Session(engine);
        var local = (await session.GetFrameAsync(rig.Start)).Locals.First(l => l.Name.Length > 0 && !l.IsArgument && !l.UserName).Name;

        var diff = await rig.Types.SetNativeLocal(path, Function, local, newName: "ndm_diffed", showDecompile: "diff", engine: engine);
        output.WriteLine(diff);
        Assert.Contains("--- before", diff);
        Assert.Matches($@"(?m)^-.*\b{local}\b", diff);
        Assert.Matches(@"(?m)^\+.*\bndm_diffed\b", diff);
        var after = await rig.Types.SetNativeLocal(path, Function, "ndm_diffed", clear: true, showDecompile: "after", engine: engine);
        Assert.Contains("after the edit", after);
        Assert.DoesNotContain("ndm_diffed;", after);

        // a callee renamed: the caller's pseudocode is the one shown
        var callee = (await session.GetXrefsFromAsync(rig.Start, wholeFunction: true)).First(x => x.Kind == NativeXrefKind.Call
            && rig.Native.Image.SectionAt(x.ToRva) is { IsExecutable: true }).ToRva;
        var renamed = await rig.Edits.RenameNative(path, Rva(callee), "ndm_target", showDecompile: "diff", engine: engine);
        output.WriteLine(renamed);
        Assert.Matches(@"(?m)^\+.*ndm_target", renamed);

        // the prototype's name becomes the function's name in our layer and the engine; rename=false keeps it
        var proto = await rig.Types.SetNativeType(path, Rva(callee), "int __fastcall ndm_proto_name(void *a, void *b, unsigned int n)", engine: engine);
        output.WriteLine(proto);
        Assert.Contains("now named ndm_proto_name", proto);
        Assert.Equal("ndm_proto_name", rig.Code.Annotations(rig.Native).NameAt(callee));
        Assert.Contains("ndm_proto_name", await rig.Analysis.DecompileNative(path, Function, engine: engine));
        var kept = await rig.Types.SetNativeType(path, Rva(callee), "int __fastcall other_name(void *a, void *b, unsigned int n)", rename: false, engine: engine);
        Assert.DoesNotContain("now named", kept);
        Assert.Equal("ndm_proto_name", rig.Code.Annotations(rig.Native).NameAt(callee));
    }

    [IdaFact]
    public Task Type_guesses_come_from_the_decompiler_and_the_data_in_IDA() => TypeGuesses("ida");

    [GhidraFact]
    public Task Type_guesses_come_from_the_decompiler_and_the_data_in_Ghidra() => TypeGuesses("ghidra");

    private async Task TypeGuesses(string engine)
    {
        var rig = Setup(engine + "-g");
        var path = Image();
        var function = await rig.Types.SetNativeType(path, Function, guess: true, engine: engine);
        output.WriteLine(function);
        Assert.Matches(@"Guess at 0x[0-9A-F]+: .*CheckSumMappedFile\(.*\(from decompiler, high confidence; not applied", function);
        Assert.Empty(rig.Code.Annotations(rig.Native).UserTypes.Types);
        var data = rig.Native.Image.Sections.First(s => !s.IsExecutable && s.Name == ".data").Rva;
        await rig.Types.DefineNative(path, Rva(data), "data", type: "dword", engine: engine);
        var global = await rig.Types.SetNativeType(path, Rva(data), guess: true, engine: engine);
        output.WriteLine(global);
        Assert.StartsWith("Guess at", global);
        Assert.Equal(ErrorCode.InvalidArgument, (await Assert.ThrowsAsync<ToolError>(() => rig.Types.SetNativeType(path, Function, "int f(void)", guess: true, engine: engine))).Code);
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
