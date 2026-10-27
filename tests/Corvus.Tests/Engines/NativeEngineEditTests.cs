using System.Diagnostics;
using Corvus.Core;
using Corvus.Native.Providers;
using Corvus.Native.Providers.Ida;
using Corvus.Services;
using Corvus.Tools;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>Engine edits on a real system DLL with IDA and Ghidra: applied, journaled across a worker restart, pushed into a new database.</summary>
[Trait("Speed", "Slow")]
public abstract class NativeEngineEditTests(ITestOutputHelper output) : IDisposable
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
        NativeTypeInfoTools Info, NativeCodeTools CodeTools)
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
        EngineSeed.Copy(_dir.File(cache), Image());
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
            new NativeAnalysisTools(workspace, engines, new OutputPager(options), names, code, types, user), new NativeTypeInfoTools(workspace, code, engines, user),
            new NativeCodeTools(workspace, code, new OutputPager(options), null, engines, names, types, user));
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

    /// <summary>The instruction of <see cref="Function"/> whose text contains <paramref name="text"/> (case-insensitive).</summary>
    private static async Task<uint> Instruction(INativeDecompilerSession s, uint function, string text) =>
        (await s.DisassembleAsync(function)).Instructions.First(i => i.Text.Contains(text, StringComparison.OrdinalIgnoreCase)).Rva;

    private static async Task<string> TextAt(INativeDecompilerSession s, uint function, uint rva) =>
        (await s.DisassembleAsync(function)).Instructions.First(i => i.Rva == rva).Text;

    private ITestOutputHelper Output => output;

    /// <summary>Ghidra: define_native and operand display formats.</summary>
    [Trait("Speed", "Slow")]
    public sealed class GhidraDefineAndOperands(ITestOutputHelper output) : NativeEngineEditTests(output)
    {
        [GhidraFact]
        public async Task Operand_display_formats_show_in_Ghidra_as_equates()
        {
            var rig = Setup("ghidra-o");
            var path = Image();
            var fn = rig.Native.Image.Exports.First(e => e.Name == Function).Rva;
            var ghidra = await rig.Session("ghidra");
            var magic = await Instruction(ghidra, fn, "0x10b");
            Assert.Contains("267", await rig.Types.SetNativeOperand(path, Rva(magic), 1, "dec", engine: "ghidra"));
            await rig.Types.DeclareNativeTypes(path, "enum SampleMagic { CORVUS_PE32 = 0x10B, CORVUS_PE64 = 0x20B };", engine: "ghidra");
            var shown = await rig.Types.SetNativeOperand(path, Rva(magic), 1, "enum", type: "SampleMagic", engine: "ghidra");
            Output.WriteLine(shown);
            Assert.Contains("CORVUS_PE32", shown);
            var pseudocode = await rig.Analysis.DecompileNative(path, Function, engine: "ghidra");
            Output.WriteLine(pseudocode);
            Assert.Contains("!= CORVUS_PE32", pseudocode);
            Assert.Equal(ErrorCode.InvalidArgument, (await Assert.ThrowsAsync<ToolError>(() => rig.Types.SetNativeOperand(path, Rva(magic), 1, "struct", type: "SampleMagic", engine: "ghidra"))).Code);

            Restart();
            var fresh = Setup("ghidra-p");
            await fresh.Types.GetNativeFrame(path, Function, engine: "ghidra", locals: true);
            Assert.Contains("CORVUS_PE32", await TextAt(await fresh.Session("ghidra"), fn, magic));
        }

        [GhidraFact]
        public async Task A_struct_is_inferred_from_a_pointer_argument_declared_and_the_argument_typed_in_Ghidra()
        {
            var rig = Setup("ghidra-i");
            var path = Image();
            var fn = rig.Native.Image.Exports.First(e => e.Name == Function).Rva;
            var ghidra = await rig.Session("ghidra");
            string? text = null;
            foreach (var arg in (await ghidra.GetFrameAsync(fn, true)).Locals.Where(l => l.IsArgument))
            {
                try { text = await rig.Types.SetNativeLocal(path, Function, arg.Name, engine: "ghidra", inferStruct: "CorvusInferred"); break; }
                catch (ToolError e) when (e.Code == ErrorCode.NotFound) { Output.WriteLine($"{arg.Name}: {e.Message}"); }
            }
            Output.WriteLine(text ?? "(no argument used as a struct pointer)");
            Assert.NotNull(text);
            Assert.Contains("struct CorvusInferred {", text);
            Assert.Contains("the local is now CorvusInferred *", text);
            Assert.True((await ghidra.GetTypeAsync("CorvusInferred")).Members.Count > 0);
            Assert.Contains("CorvusInferred *", await rig.Analysis.DecompileNative(path, Function, engine: "ghidra"));
            Assert.Equal(ErrorCode.InvalidArgument, (await Assert.ThrowsAsync<ToolError>(() => rig.Types.SetNativeLocal(path, Function, "param_1", newName: "p", engine: "ghidra", inferStruct: "X"))).Code);
            Assert.Equal(ErrorCode.InvalidArgument, (await Assert.ThrowsAsync<ToolError>(() => rig.Types.SetNativeLocal(path, Function, "param_1", engine: "ghidra", inferStruct: "not a name"))).Code);
        }

        [GhidraFact]
        public async Task A_refused_prototype_names_the_parser_message_or_the_conventions_Ghidra_has()
        {
            var rig = Setup("ghidra-t");
            var path = Image();
            var unknown = await Assert.ThrowsAsync<ToolError>(() => rig.Types.SetNativeType(path, Function, "int __pascal f(int a)", engine: "ghidra"));
            Output.WriteLine(unknown.Message);
            Assert.Contains("unknown calling convention __pascal", unknown.Message);
            Assert.Contains("__fastcall", unknown.Message);
            var broken = await Assert.ThrowsAsync<ToolError>(() => rig.Types.SetNativeType(path, Function, "int f(int a,, int b)", engine: "ghidra"));
            Output.WriteLine(broken.Message);
            Assert.Contains("does not parse:", broken.Message);
        }

        [GhidraFact]
        public async Task A_flow_override_is_set_and_cleared_with_the_function_repaired_in_Ghidra()
        {
            var rig = Setup("ghidra-f");
            var path = Image();
            var fn = rig.Native.Image.Exports.First(e => e.Name == Function).Rva;
            var call = await Instruction(await rig.Session("ghidra"), fn, "CALL");
            var set = await rig.Types.DefineNative(path, Rva(call), "flow", type: "branch", engine: "ghidra");
            Output.WriteLine(set);
            Assert.Contains("flow override none -> branch", set);
            var cleared = await rig.Types.DefineNative(path, Rva(call), "flow", engine: "ghidra");
            Output.WriteLine(cleared);
            Assert.Contains("flow override branch -> none", cleared);
            Assert.Contains($"{Function} is rva 0x{fn:X}", cleared);
            Assert.Equal(ErrorCode.InvalidArgument, (await Assert.ThrowsAsync<ToolError>(() => rig.Types.DefineNative(path, Rva(call), "flow", type: "sideways", engine: "ghidra"))).Code);
        }

        [GhidraFact]
        public async Task Define_native_makes_data_functions_and_undefined_bytes_in_Ghidra_and_a_new_project_gets_them()
        {
            var rig = Setup("ghidra-a");
            var path = Image();
            var data = rig.Native.Image.Sections.First(s => !s.IsExecutable && s.Name == ".data").Rva;
            var fn = rig.Native.Image.Exports.First(e => e.Name == Function).Rva;
            var made = await rig.Types.DefineNative(path, Rva(data), "data", type: "dword[4]", engine: "ghidra");
            Output.WriteLine(made);
            Assert.Contains("dword[4], 16 bytes", made);
            var text = await rig.Types.DefineNative(path, Rva(data + 0x60), "data", type: "string[8]", engine: "ghidra");
            Output.WriteLine(text);
            Assert.Contains("char[8], 8 bytes", text);
            Assert.Contains("byte(s) undefined", await rig.Types.DefineNative(path, Function, "undefine", engine: "ghidra"));
            var ghidra = await rig.Session("ghidra");
            Assert.DoesNotContain(await ghidra.ListFunctionsAsync(), f => f.StartRva == fn);
            Assert.Contains($"function {Function}", await rig.Types.DefineNative(path, Rva(fn), "function", engine: "ghidra"));
            Assert.Contains(await ghidra.ListFunctionsAsync(), f => f.StartRva == fn);

            Restart();
            var fresh = Setup("ghidra-b");
            Output.WriteLine(await fresh.Types.GetNativeFrame(path, Function, engine: "ghidra", locals: true));
            var range = await (await fresh.Session("ghidra")).DisassembleRangeAsync(data, 1);
            Output.WriteLine(range.Instructions[0].Text);
            Assert.Equal(16, range.Instructions[0].Bytes.Length);
        }
    }

    /// <summary>Ghidra: enum members, stack deletes, batch types and instruction search.</summary>
    [Trait("Speed", "Slow")]
    public sealed class GhidraTypesAndSearch(ITestOutputHelper output) : NativeEngineEditTests(output)
    {
        [GhidraFact]
        public async Task Enum_members_stack_deletes_and_batch_types_apply_in_Ghidra()
        {
            var rig = Setup("ghidra-e");
            var path = Image();
            var fn = rig.Native.Image.Exports.First(e => e.Name == Function).Rva;
            var data = rig.Native.Image.Sections.First(s => !s.IsExecutable && s.Name == ".data").Rva;
            await rig.Types.DeclareNativeTypes(path, "enum SampleMode { SampleSlow = 1 };", engine: "ghidra");
            Assert.Contains("SampleMode::SampleFast = 0x10", await rig.Types.DeclareNativeTypes(path, typeName: "SampleMode", members: "SampleFast=0x10, SampleSlow=2", engine: "ghidra"));
            var ghidra = await rig.Session("ghidra");
            await ghidra.ApplyTypesAsync(new NativeTypeBatch("struct SampleUnrelated { int a; };", [], [], [], 8));
            var mode = await ghidra.GetTypeAsync("SampleMode");
            Output.WriteLine(mode.Declaration);
            Assert.Contains("SampleFast", mode.Declaration);

            // A user-made member, so the deletion is not undone by analysis.
            Assert.Contains("sample_temp", await rig.Types.SetNativeStackVar(path, Function, "0x8", newName: "sample_temp", type: "int", engine: "ghidra"));
            Assert.Contains("deleted", await rig.Types.SetNativeStackVar(path, Function, "sample_temp", delete: true, engine: "ghidra"));
            Assert.DoesNotContain((await ghidra.GetFrameAsync(fn)).Members, m => m.Name == "sample_temp");
            Assert.Contains(rig.Code.Annotations(rig.Native).UserTypes.StackVars.Values.SelectMany(s => s), s => s.Delete);

            var batch = await rig.Types.SetNativeType(path, items: $"rva:0x{data:X} = uint[2]\nrva:0x{data + 0x10:X} = SampleMode\nrva:0x{data + 0x20:X} = no_such_sample_t", engine: "ghidra");
            Output.WriteLine(batch);
            Assert.StartsWith("2 of 3 type(s) applied", batch);
        }

        [GhidraFact]
        public async Task Instruction_search_runs_over_Ghidras_listing()
        {
            var rig = Setup("ghidra-s");
            var path = Image();
            var found = await rig.CodeTools.SearchInstructions(path, mnemonic: "^mov$", value: "0x10B", function: Function, engine: "ghidra");
            Output.WriteLine(found);
            Assert.Contains("Engine: ghidra", found);
            Assert.Contains($"{Function}+0x", found);
        }
    }

    /// <summary>The same edits through IDA.</summary>
    [Trait("Speed", "Slow")]
    public sealed class Ida(ITestOutputHelper output) : NativeEngineEditTests(output)
    {
        [IdaFact]
        public async Task Define_native_makes_data_functions_and_undefined_bytes_in_IDA_and_replays_them()
        {
            var rig = Setup("ida-a");
            var path = Image();
            var data = rig.Native.Image.Sections.First(s => !s.IsExecutable && s.Name == ".data").Rva;
            var fn = rig.Native.Image.Exports.First(e => e.Name == Function).Rva;
            Output.WriteLine(await rig.Types.DefineNative(path, Rva(data), "data", type: "dword[4]"));
            await rig.Types.DeclareNativeTypes(path, "struct SampleRec { int a; short b; char c[10]; };");
            Assert.Contains("SampleRec", await rig.Types.DefineNative(path, Rva(data + 0x40), "data", type: "SampleRec"));
            // An engine type read at an address from the image's bytes.
            var read = await rig.Info.GetNativeType(path, name: "SampleRec", address: Rva(data + 0x40), source: "engine", read: true);
            Output.WriteLine(read);
            Assert.Matches(@"\+0x4  2  b  .*= -?\d+", read);
            Assert.Contains("string", await rig.Types.DefineNative(path, Rva(data + 0x60), "data", end: Rva(data + 0x68), type: "string"));
            Assert.Contains("byte(s) undefined", await rig.Types.DefineNative(path, Function, "undefine"));
            var ida = await rig.Session("ida");
            Assert.False((await IdaItem(ida, fn)).Function);
            Assert.Contains($"function {Function}", await rig.Types.DefineNative(path, Rva(fn), "function"));

            Assert.Equal(ErrorCode.InvalidArgument, (await Assert.ThrowsAsync<ToolError>(() => rig.Types.DefineNative(path, Rva(data), "data"))).Code);
            Assert.Equal(ErrorCode.InvalidArgument, (await Assert.ThrowsAsync<ToolError>(() => rig.Types.DefineNative(path, Rva(data + 8), "undefine", end: Rva(data)))).Code);
            Assert.Equal(ErrorCode.InvalidArgument, (await Assert.ThrowsAsync<ToolError>(() => rig.Types.DefineNative(path, Rva(data), "data", type: "no_such_sample_t"))).Code);
            // The function edit replaced the undefine at the same address.
            var layer = rig.Code.Annotations(rig.Native).UserTypes;
            Assert.Equal([data, data + 0x40, data + 0x60, fn], layer.Analysis.Select(a => a.Rva));

            // Journaled: a worker killed before any save replays the edits.
            await WorkerKill.KillAsync(ida);
            Assert.Equal((16L, false), await IdaItem(ida, data));
            Assert.Equal((16L, false), await IdaItem(ida, data + 0x40));
            Assert.True((await IdaItem(ida, fn)).Function);

            // A new database gets them from the sidecar.
            Restart();
            var fresh = Setup("ida-b");
            Output.WriteLine(await fresh.Types.GetNativeFrame(path, Function, locals: true));
            var again = await fresh.Session("ida");
            Assert.Equal((16L, false), await IdaItem(again, data));
            Assert.Equal((8L, false), await IdaItem(again, data + 0x60));
        }

        [IdaFact]
        public async Task Operand_display_formats_show_in_IDA_and_replay()
        {
            var rig = Setup("ida-o");
            var path = Image();
            var fn = rig.Native.Image.Exports.First(e => e.Name == Function).Rva;
            var ida = await rig.Session("ida");
            var magic = await Instruction(ida, fn, "10Bh"); // mov ecx, 10Bh: the PE32 optional header magic
            Assert.Contains("267", await rig.Types.SetNativeOperand(path, Rva(magic), 1, "dec"));
            await rig.Types.DeclareNativeTypes(path, "enum SampleMagic { CORVUS_PE32 = 0x10B, CORVUS_PE64 = 0x20B };");
            Assert.Contains("CORVUS_PE32", await rig.Types.SetNativeOperand(path, Rva(magic), 1, "enum", type: "SampleMagic"));
            var load = await Instruction(ida, fn, "[rdi+18h]");
            await rig.Types.DeclareNativeTypes(path, "struct SampleHdr { char pad[0x18]; unsigned short Magic; };");
            Assert.Contains("SampleHdr.Magic", await rig.Types.SetNativeOperand(path, Rva(load), 1, "struct", type: "SampleHdr"));

            Assert.Equal(ErrorCode.InvalidArgument, (await Assert.ThrowsAsync<ToolError>(() => rig.Types.SetNativeOperand(path, Rva(magic), 1, "enum"))).Code);
            Assert.Equal(ErrorCode.InvalidArgument, (await Assert.ThrowsAsync<ToolError>(() => rig.Types.SetNativeOperand(path, Rva(magic), 5, "hex"))).Code);
            Assert.Equal(ErrorCode.InvalidArgument, (await Assert.ThrowsAsync<ToolError>(() => rig.Types.SetNativeOperand(path, Rva(magic + 1), 0, "hex"))).Code);
            Assert.Equal(ErrorCode.InvalidArgument, (await Assert.ThrowsAsync<ToolError>(() => rig.Types.SetNativeOperand(path, Rva(magic), 1, "enum", type: "NoSuchSampleEnum"))).Code);
            Assert.Equal(2, rig.Code.Annotations(rig.Native).UserTypes.Operands.Count);

            await WorkerKill.KillAsync(ida);
            Assert.Contains("CORVUS_PE32", await TextAt(ida, fn, magic));

            Restart();
            var fresh = Setup("ida-p");
            await fresh.Types.GetNativeFrame(path, Function, locals: true);
            var again = await fresh.Session("ida");
            Assert.Contains("SampleHdr.Magic", await TextAt(again, fn, load));
            // Default clears it, in the database and the sidecar.
            await fresh.Types.SetNativeOperand(path, Rva(load), 1, "default");
            Assert.Contains("18h", await TextAt(again, fn, load));
            Assert.Single(fresh.Code.Annotations(fresh.Native).UserTypes.Operands);
        }

        [IdaFact]
        public async Task Enum_members_stack_deletes_and_batch_types_apply_in_IDA_and_reach_a_new_database()
        {
            var rig = Setup("ida-e");
            var path = Image();
            var fn = rig.Native.Image.Exports.First(e => e.Name == Function).Rva;
            var data = rig.Native.Image.Sections.First(s => !s.IsExecutable && s.Name == ".data").Rva;
            await rig.Types.DeclareNativeTypes(path, "enum SampleMode { SampleSlow = 1 };");
            var upsert = await rig.Types.DeclareNativeTypes(path, typeName: "SampleMode", members: "SampleFast=0x10, SampleSlow=2");
            Output.WriteLine(upsert);
            Assert.Contains("SampleMode::SampleFast = 0x10", upsert);
            Assert.Contains("SampleCreated::SampleOne = 0x1", await rig.Types.DeclareNativeTypes(path, typeName: "SampleCreated", members: "SampleOne=1"));
            Assert.Equal(ErrorCode.InvalidArgument, (await Assert.ThrowsAsync<ToolError>(() => rig.Types.DeclareNativeTypes(path, typeName: "SampleMode", members: "bad name=1"))).Code);
            var ida = await rig.Session("ida");
            // A recovered type push declares the user's enums again; the upserts stay.
            await ida.ApplyTypesAsync(new NativeTypeBatch("struct SampleUnrelated { int a; };", [], [], [], 8));
            var mode = await ida.GetTypeAsync("SampleMode");
            Output.WriteLine(mode.Declaration);
            Assert.Contains("SampleFast = 0x10", mode.Declaration);
            Assert.Matches(@"SampleSlow = (0x)?2\b", mode.Declaration);

            var frame = await ida.GetFrameAsync(fn);
            var member = frame.Members.First(m => m.Kind == "arg");
            Assert.Contains("deleted", await rig.Types.SetNativeStackVar(path, Function, member.Name, delete: true));
            // An instruction that addresses the slot gets a default member there again when IDA reanalyzes it.
            Assert.DoesNotContain((await ida.GetFrameAsync(fn)).Members, m => m.Offset == member.Offset && m.Name == member.Name);
            Assert.Equal(ErrorCode.InvalidArgument, (await Assert.ThrowsAsync<ToolError>(() => rig.Types.SetNativeStackVar(path, Function, "__return_address", delete: true))).Code);

            var batch = await rig.Types.SetNativeType(path, items: $"rva:0x{data:X} = unsigned int[2]\nrva:0x{data + 0x10:X} = SampleMode\nrva:0x{data + 0x20:X} = no_such_sample_t\nnot an address = int");
            Output.WriteLine(batch);
            Assert.StartsWith("2 of 4 type(s) applied", batch);
            Assert.Contains("not applied: the type does not parse", batch);
            Assert.Equal(2, rig.Code.Annotations(rig.Native).UserTypes.Types.Count);

            Restart();
            var fresh = Setup("ida-f");
            await fresh.Types.GetNativeFrame(path, Function, locals: true);
            var again = await fresh.Session("ida");
            Assert.Contains("SampleFast = 0x10", (await again.GetTypeAsync("SampleMode")).Declaration);
            Assert.DoesNotContain((await again.GetFrameAsync(fn)).Members, m => m.Offset == member.Offset && m.Name == member.Name);
            Assert.Contains("SampleMode", (await again.RunScriptAsync($"idc.get_type(base + 0x{data + 0x10:X})")).Result);
        }

        [IdaFact]
        public async Task Instruction_search_agrees_between_the_built_in_index_and_IDA()
        {
            var rig = Setup("ida-s");
            var path = Image();
            var ours = await rig.CodeTools.SearchInstructions(path, mnemonic: "^mov$", value: "0x10B", engine: "ours");
            Output.WriteLine(ours);
            Assert.Contains($"{Function}+0x", ours);
            var ida = await rig.CodeTools.SearchInstructions(path, mnemonic: "^mov$", value: "0x10B", engine: "ida");
            Output.WriteLine(ida);
            Assert.Contains("Engine: ida", ida);
            Assert.Contains($"{Function}+0x", ida);
            var inFunction = await rig.CodeTools.SearchInstructions(path, operands: "10Bh", function: Function, engine: "ida");
            Assert.Contains("1 matching instruction ", inFunction);
        }
    }
}

/// <summary>Arguments of the engine edit tools that are checked before an engine starts.</summary>
public sealed class NativeEngineEditArgumentTests
{
    [Fact]
    public void Enum_members_parse_hex_decimal_negative_and_removal()
    {
        var members = NativeTypeTools.EnumMembers("Mode", "A=1, B=0x10\nC=-3, D=");
        Assert.Equal([new("Mode", "A", 1), new("Mode", "B", 0x10), new("Mode", "C", -3), new NativeEnumMemberEdit("Mode", "D", null)], members);
        Assert.Empty(NativeTypeTools.EnumMembers(null, null));
        Assert.Equal(ErrorCode.InvalidArgument, Assert.Throws<ToolError>(() => NativeTypeTools.EnumMembers("Mode", null)).Code);
        Assert.Equal(ErrorCode.InvalidArgument, Assert.Throws<ToolError>(() => NativeTypeTools.EnumMembers("Mode", "A")).Code);
        Assert.Equal(ErrorCode.InvalidArgument, Assert.Throws<ToolError>(() => NativeTypeTools.EnumMembers("Mode", "A=x")).Code);
        Assert.Equal(ErrorCode.InvalidArgument, Assert.Throws<ToolError>(() => NativeTypeTools.EnumMembers("bad name", "A=1")).Code);
    }
}
