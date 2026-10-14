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
public abstract class NativeEditParityTests(ITestOutputHelper output) : IDisposable
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

    private async Task PseudocodeComments(string engine)
    {
        var rig = Setup(engine + "-p");
        var path = Image();
        var session = await rig.Session(engine);
        var lines = (await session.DecompileAsync(rig.Start)).LineAddresses.Where(l => l.Rva > rig.Start).ToList();
        var at = lines[lines.Count / 2].Rva;

        var set = await rig.Edits.CommentNative(path, Rva(at), "test pseudo note", scope: "pseudocode", engine: engine, dryRun: false);
        output.WriteLine(set);
        Assert.Contains("Pushed to the engine", set);
        var text = await rig.Analysis.DecompileNative(path, Function, engine: engine);
        output.WriteLine(text);
        Assert.Contains("test pseudo note", text);
        // appended and deduped in the sidecar, then shown as two lines
        await rig.Edits.CommentNative(path, Rva(at), "test second line", scope: "pseudocode", append: true, engine: engine, dryRun: false);
        Assert.Contains("already has this line", await rig.Edits.CommentNative(path, Rva(at), "test second line", scope: "pseudocode", append: true, engine: engine, dryRun: false));
        Assert.Contains("test second line", await rig.Analysis.DecompileNative(path, Function, engine: engine));

        // cleared
        await rig.Edits.CommentNative(path, Rva(at), "", scope: "pseudocode", engine: engine, dryRun: false);
        Assert.DoesNotContain("test pseudo note", await rig.Analysis.DecompileNative(path, Function, engine: engine));

        // an address inside an instruction lands on the statement made from it; a new database gets it from the sidecar
        await rig.Edits.CommentNative(path, Rva(at + 1), "test inside", scope: "pseudocode", engine: engine, dryRun: false);
        Assert.Contains("test inside", await rig.Analysis.DecompileNative(path, Function, engine: engine));
        Restart();
        var fresh = Setup(engine + "-q");
        var again = await fresh.Analysis.DecompileNative(path, Function, engine: engine);
        Assert.Contains("test inside", again);
    }

    private async Task BatchEdits(string engine)
    {
        var rig = Setup(engine + "-b");
        var path = Image();
        var session = await rig.Session(engine);
        var callees = (await session.GetXrefsFromAsync(rig.Start, wholeFunction: true)).Where(x => x.Kind == NativeXrefKind.Call).Select(x => x.ToRva).Distinct()
            .Where(t => rig.Native.Image.SectionAt(t) is { IsExecutable: true }).Take(2).ToList();
        Assert.True(callees.Count >= 1, "no direct callee");
        var items = string.Join("\n", callees.Select((c, i) => $"{Rva(c)} = sample_callee_{i}"));
        var renamed = await rig.Edits.RenameNative(path, items: items, engine: engine, dryRun: false);
        output.WriteLine(renamed);
        Assert.StartsWith($"{callees.Count} name item(s): {callees.Count} ok, 0 failed", renamed);
        var lines = (await session.DecompileAsync(rig.Start)).LineAddresses.Where(l => l.Rva > rig.Start).ToList();
        var commented = await rig.Edits.CommentNative(path, items: $"{Rva(lines[lines.Count / 3].Rva)} = test batch one\n{Rva(lines[2 * lines.Count / 3].Rva)} = test batch two", scope: "pseudocode", engine: engine, dryRun: false);
        output.WriteLine(commented);
        var text = await rig.Analysis.DecompileNative(path, Function, engine: engine);
        output.WriteLine(text);
        Assert.Contains("sample_callee_0", text);
        Assert.Contains("test batch one", text);
        Assert.Contains("test batch two", text);

        var frame = await session.GetFrameAsync(rig.Start);
        var locals = frame.Locals.Where(l => l.Name.Length > 0 && !l.IsArgument && !l.UserName).Take(2).Select(l => l.Name).ToList();
        var edited = await rig.Types.SetNativeLocal(path, Function, items: $"{locals[0]} = sample_l0\n{locals[1]} = sample_l1\nno_such_local = x", engine: engine);
        output.WriteLine(edited);
        Assert.StartsWith("2 of 3 local edit(s) applied", edited);
        Assert.Equal(2, rig.Code.Annotations(rig.Native).UserTypes.Locals.Values.Sum(l => l.Count));
    }

    private async Task DiffAndPrototypeName(string engine)
    {
        var rig = Setup(engine + "-d");
        var path = Image();
        var session = await rig.Session(engine);
        var local = (await session.GetFrameAsync(rig.Start)).Locals.First(l => l.Name.Length > 0 && !l.IsArgument && !l.UserName).Name;

        var diff = await rig.Types.SetNativeLocal(path, Function, local, newName: "sample_diffed", showDecompile: "diff", engine: engine);
        output.WriteLine(diff);
        Assert.Contains("--- before", diff);
        Assert.Matches($@"(?m)^-.*\b{local}\b", diff);
        Assert.Matches(@"(?m)^\+.*\bsample_diffed\b", diff);
        var after = await rig.Types.SetNativeLocal(path, Function, "sample_diffed", clear: true, showDecompile: "after", engine: engine);
        Assert.Contains("after the edit", after);
        Assert.DoesNotContain("sample_diffed;", after);

        // a callee renamed: the caller's pseudocode is the one shown
        var callee = (await session.GetXrefsFromAsync(rig.Start, wholeFunction: true)).First(x => x.Kind == NativeXrefKind.Call
            && rig.Native.Image.SectionAt(x.ToRva) is { IsExecutable: true }).ToRva;
        var renamed = await rig.Edits.RenameNative(path, Rva(callee), "sample_target", showDecompile: "diff", engine: engine, dryRun: false);
        output.WriteLine(renamed);
        Assert.Matches(@"(?m)^\+.*sample_target", renamed);

        // the prototype's name becomes the function's name in our layer and the engine; rename=false keeps it
        var proto = await rig.Types.SetNativeType(path, Rva(callee), "int __fastcall sample_proto_name(void *a, void *b, unsigned int n)", rename: true, engine: engine);
        output.WriteLine(proto);
        Assert.Contains("now named sample_proto_name", proto);
        Assert.Equal("sample_proto_name", rig.Code.Annotations(rig.Native).NameAt(callee));
        Assert.Contains("sample_proto_name", await rig.Analysis.DecompileNative(path, Function, engine: engine));
        var kept = await rig.Types.SetNativeType(path, Rva(callee), "int __fastcall other_name(void *a, void *b, unsigned int n)", rename: false, engine: engine);
        Assert.DoesNotContain("now named", kept);
        Assert.Equal("sample_proto_name", rig.Code.Annotations(rig.Native).NameAt(callee));
    }

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

    private async Task LocalAndStackEditsClear(string engine)
    {
        var rig = Setup(engine + "-c");
        var path = Image();
        var session = await rig.Session(engine);
        var frame = await session.GetFrameAsync(rig.Start);
        var local = frame.Locals.First(l => l.Name.Length > 0 && !l.IsArgument && !l.UserName && l.Stack == null).Name;
        var layer = () => rig.Code.Annotations(rig.Native).UserTypes;

        // renamed, then given its first name back: no edit is left
        output.WriteLine(await rig.Types.SetNativeLocal(path, Function, local, newName: "sample_a", engine: engine));
        Assert.Single(layer().Locals);
        output.WriteLine(await rig.Types.SetNativeLocal(path, Function, "sample_a", newName: local, engine: engine));
        Assert.Empty(layer().Locals);
        var text = await rig.Analysis.DecompileNative(path, Function, engine: engine);
        Assert.DoesNotContain("sample_a", text);
        Assert.Contains(local, text);

        // renamed and retyped, then cleared
        output.WriteLine(await rig.Types.SetNativeLocal(path, Function, local, newName: "sample_b", type: "unsigned int", engine: engine));
        Assert.Contains("sample_b", await rig.Analysis.DecompileNative(path, Function, engine: engine));
        var cleared = await rig.Types.SetNativeLocal(path, Function, "sample_b", clear: true, engine: engine);
        output.WriteLine(cleared);
        Assert.Contains("is cleared", cleared);
        Assert.Empty(layer().Locals);
        Assert.DoesNotContain("sample_b", await rig.Analysis.DecompileNative(path, Function, engine: engine));
        Assert.Equal(ErrorCode.InvalidArgument, (await Assert.ThrowsAsync<ToolError>(() => rig.Types.SetNativeLocal(path, Function, local, newName: "x", clear: true, engine: engine))).Code);

        // a stack member renamed and retyped, then cleared: the engine's member is back
        var member = frame.Members.First(m => m.Kind == "local" && m.Size >= 4);
        output.WriteLine(await rig.Types.SetNativeStackVar(path, Function, $"0x{member.Offset:X}", newName: "sample_slot", type: "int", engine: engine));
        Assert.Single(layer().StackVars);
        output.WriteLine(await rig.Types.SetNativeStackVar(path, Function, "sample_slot", clear: true, engine: engine));
        Assert.Empty(layer().StackVars);
        var now = (await session.GetFrameAsync(rig.Start)).Members.Single(m => m.Offset == member.Offset);
        Assert.Equal((member.Name, member.Type), (now.Name, now.Type));
    }

    private ITestOutputHelper Output => output;

    /// <summary>Comments and batch edits in Ghidra.</summary>
    [Trait("Speed", "Slow")]
    public sealed class GhidraComments(ITestOutputHelper output) : NativeEditParityTests(output)
    {
        [GhidraFact]
        public Task Pseudocode_comments_show_clear_and_reach_a_new_database_in_Ghidra() => PseudocodeComments("ghidra");

        [GhidraFact]
        public async Task Comment_kinds_reach_Ghidra_and_a_pre_comment_shows_in_its_pseudocode()
        {
            var rig = Setup("ghidra-k");
            var path = Image();
            var session = await rig.Session("ghidra");
            var lines = (await session.DecompileAsync(rig.Start)).LineAddresses.Where(l => l.Rva > rig.Start).ToList();
            var at = lines[lines.Count / 2].Rva;
            await rig.Edits.CommentNative(path, Rva(at), "test kind note", scope: "pre", engine: "ghidra", dryRun: false);
            Assert.Contains("test kind note", await rig.Analysis.DecompileNative(path, Function, engine: "ghidra"));
            // another kind: the pre comment is removed (the decompiler does not print end-of-line comments)
            await rig.Edits.CommentNative(path, Rva(at), "test kind note", scope: "eol", engine: "ghidra", dryRun: false);
            Assert.DoesNotContain("test kind note", await rig.Analysis.DecompileNative(path, Function, engine: "ghidra"));
        }

        [GhidraFact]
        public Task Batch_renames_comments_and_locals_reach_Ghidra_in_one_push() => BatchEdits("ghidra");
    }

    /// <summary>Type guesses, pseudocode diffs and local edits in Ghidra.</summary>
    [Trait("Speed", "Slow")]
    public sealed class GhidraTypesAndLocals(ITestOutputHelper output) : NativeEditParityTests(output)
    {
        [GhidraFact]
        public Task Edits_show_the_pseudocode_diff_and_a_prototype_names_the_function_in_Ghidra() => DiffAndPrototypeName("ghidra");

        [GhidraFact]
        public Task Type_guesses_come_from_the_decompiler_and_the_data_in_Ghidra() => TypeGuesses("ghidra");

        [GhidraFact]
        public Task Local_and_stack_edits_clear_in_Ghidra() => LocalAndStackEditsClear("ghidra");
    }

    /// <summary>The same edits through IDA.</summary>
    [Trait("Speed", "Slow")]
    public sealed class Ida(ITestOutputHelper output) : NativeEditParityTests(output)
    {
        [IdaFact]
        public Task Pseudocode_comments_show_clear_and_reach_a_new_database_in_IDA() => PseudocodeComments("ida");

        [IdaFact]
        public async Task Comment_kinds_reach_IDA_as_regular_and_anterior_comments()
        {
            var rig = Setup("ida-k");
            var path = Image();
            var session = await rig.Session("ida");
            var at = (await session.DisassembleAsync(rig.Start)).Instructions[3].Rva;
            async Task<string> Ida(string expr) => (await session.RunScriptAsync(expr)).Result ?? "";
            await rig.Edits.CommentNative(path, Rva(at), "test pre", scope: "pre", engine: "ida", dryRun: false);
            Assert.Contains("test pre", await Ida($"__import__('ida_lines').get_extra_cmt(base + 0x{at:X}, __import__('ida_lines').E_PREV)"));
            await rig.Edits.CommentNative(path, Rva(at), "test eol", scope: "eol", engine: "ida", dryRun: false);
            Assert.Contains("test eol", await Ida($"ida_bytes.get_cmt(base + 0x{at:X}, False)"));
            Assert.DoesNotContain("test pre", await Ida($"__import__('ida_lines').get_extra_cmt(base + 0x{at:X}, __import__('ida_lines').E_PREV)"));
        }

        [IdaFact]
        public Task Batch_renames_comments_and_locals_reach_IDA_in_one_push() => BatchEdits("ida");

        [IdaFact]
        public Task Edits_show_the_pseudocode_diff_and_a_prototype_names_the_function_in_IDA() => DiffAndPrototypeName("ida");

        [IdaFact]
        public Task Type_guesses_come_from_the_decompiler_and_the_data_in_IDA() => TypeGuesses("ida");

        [IdaFact]
        public Task Local_and_stack_edits_clear_in_IDA() => LocalAndStackEditsClear("ida");
    }
}
