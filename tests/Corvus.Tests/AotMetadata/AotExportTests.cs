using Corvus.Core;
using Corvus.Services;

namespace Corvus.Tests;

public class AotExportTests : IDisposable
{
    private readonly Env _env = new();
    private readonly TempDir _dir = new();

    public void Dispose()
    {
        _env.Dispose();
        _dir.Dispose();
    }

    [Fact]
    public async Task A_placeholder_body_is_labeled_with_its_native_next_step()
    {
        var tools = new Corvus.Tools.DecompileTools(_env.Workspace, _env.Decompiler, _env.Pager);
        var placeholder = await tools.DecompileMember("Fixture.Native.NativeThing::First");
        Assert.True(placeholder.Contains("// Placeholder bodies in"), placeholder);
        Assert.Contains("decompile_native", placeholder);
        Assert.Contains("RVA 0x1000", placeholder);
        var type = await tools.DecompileMember("Fixture.Native.NativeThing");
        Assert.Contains("// Placeholder bodies in", type);
        Assert.Contains("RVA 0x1100", type);
    }

    /// <summary>The warnings of a call: they are the lines the text and the record both carry.</summary>
    private static async Task<string> Warned(Func<Task<string>> call)
    {
        var collector = Corvus.Mcp.ToolOutput.Collect();
        await call();
        return string.Join(" | ", collector.Warnings);
    }

    private Corvus.Tools.EditTools EditTools() => new(_env.Workspace, _env.Edits, _env.History, _env.Decompiler, _env.Pager, _env.AotMetadata);

    [Fact]
    public async Task Stubbing_a_dummy_assembly_method_names_its_native_address_and_patch_call()
    {
        // FT-299 H2.
        foreach (var dryRun in new[] { true, false })
        {
            var text = await Warned(() => EditTools().StubMethod("Fixture.Native.NativeThing::First", dryRun: dryRun));
            Assert.Contains("Dummy assembly:", text);
            Assert.Contains("RVA 0x1000", text);
            Assert.Contains("patch_asm or patch_bytes with image=<native image> address=0x1000", text);
        }
    }

    [Fact]
    public async Task Saving_an_edited_dummy_assembly_says_the_file_is_a_dummy()
    {
        // FT-299 H2.
        var tools = EditTools();
        await tools.StubMethod("Fixture.Native.NativeThing::First", dryRun: false);
        var text = await Warned(() => tools.SaveAssembly(_env.Fixture.Id, _dir.File("Saved.dll")));
        Assert.Contains("Dummy assembly: the saved file is not what the program runs", text);
        Assert.Contains("patch_asm or patch_bytes", text);
    }

    [Fact]
    public async Task Rewriting_and_simplifying_a_dummy_assembly_method_say_the_edits_are_not_run()
    {
        // FT-299 H2.
        var tools = EditTools();
        var il = await Warned(() => tools.PatchMethodIL("Fixture.Native.NativeThing::First", "ret", dryRun: true));
        Assert.Contains("Dummy assembly: this edit is not what the program runs", il);
        Assert.Contains("RVA 0x1000", il);
        var simplified = await Warned(() => tools.SimplifyMethods(symbol: "Fixture.Native.NativeThing::First", dryRun: true));
        Assert.True(simplified.Contains("Dummy assembly: these edits are not what the program runs"), simplified);
        Assert.Contains("RVA 0x1000", simplified);
    }

    [Fact]
    public async Task An_edit_of_a_method_without_an_address_has_no_dummy_note()
    {
        // The fixture carries [Address] on a few methods only; the protocol samples
        // labelled it a dummy before the note looked at the edited method.
        var tools = EditTools();
        Assert.DoesNotContain("Dummy assembly", await Warned(() => tools.StubMethod("Fixture.Model.Secret::Validate(string)", "true", dryRun: false)));
        Assert.DoesNotContain("Dummy assembly", await Warned(() => tools.SaveAssembly(_env.Fixture.Id, _dir.File("Plain.dll"))));
    }

    [Fact]
    public async Task An_ordinary_assembly_edit_reply_has_no_dummy_note()
    {
        using var dir = new TempDir();
        var managed = dir.File("Plain.dll");
        File.WriteAllBytes(managed, ContainerFixtures.Module("Plain", m =>
        {
            var t = new dnlib.DotNet.TypeDefUser("Plain", "Thing", m.CorLibTypes.Object.TypeDefOrRef);
            var method = new dnlib.DotNet.MethodDefUser("Run", dnlib.DotNet.MethodSig.CreateStatic(m.CorLibTypes.Int32));
            method.Body = new dnlib.DotNet.Emit.CilBody();
            method.Body.Instructions.Add(dnlib.DotNet.Emit.OpCodes.Ldc_I4_0.ToInstruction());
            method.Body.Instructions.Add(dnlib.DotNet.Emit.OpCodes.Ret.ToInstruction());
            t.Methods.Add(method);
            m.Types.Add(t);
        }));
        var plain = _env.Workspace.Load(managed);
        var tools = EditTools();
        Assert.DoesNotContain("Dummy assembly", await Warned(() => tools.StubMethod("Plain.Thing::Run", "1", dryRun: false)));
        Assert.DoesNotContain("Dummy assembly", await Warned(() => tools.SaveAssembly(plain.Id, dir.File("Plain.out.dll"))));
    }

    [Fact]
    public async Task A_managed_body_and_an_invalid_address_get_no_placeholder_banner()
    {
        // One method carries an invalid address; the other assembly has no address attributes.
        var tools = new Corvus.Tools.DecompileTools(_env.Workspace, _env.Decompiler, _env.Pager);
        Assert.DoesNotContain("Placeholder bodies", await tools.DecompileMember("Fixture.Native.NativeThing::Shared"));
        using var dir = new TempDir();
        var managed = dir.File("Plain.dll");
        File.WriteAllBytes(managed, ContainerFixtures.Module("Plain", m => m.Types.Add(new dnlib.DotNet.TypeDefUser("Plain", "Thing", m.CorLibTypes.Object.TypeDefOrRef))));
        _env.Workspace.Load(managed);
        Assert.DoesNotContain("Placeholder bodies", await tools.DecompileMember("Plain.Thing"));
    }

    [Fact]
    public async Task Export_after_an_edit_is_reverted_reads_the_restored_module()
    {
        // The contract sweep on 9f361986: the index kept methods of the module the revert replaced.
        var tools = EditTools();
        await tools.StubMethod("Fixture.Native.NativeThing::First", dryRun: false);
        await tools.RevertEdits(_env.Fixture.Id);
        var exporter = new AotExporter(_env.AotMetadata);
        var result = _env.Workspace.Read(() => exporter.Export(_env.Workspace.Assemblies, _dir.Path, "all", "rv", default));
        Assert.Equal(2, result.Methods);
    }

    [Fact]
    public void Export_writes_scripts_a_header_and_JSON()
    {
        var exporter = new AotExporter(_env.AotMetadata);
        var result = _env.Workspace.Read(() => exporter.Export(_env.Workspace.Assemblies, _dir.Path, "all", "fx", default));
        Assert.Equal(2, result.Methods);
        Assert.Equal(4, result.Files.Count);

        var ida = File.ReadAllText(_dir.File("fx_ida.py"));
        Assert.Contains("(0x1000, \"Fixture.Native.NativeThing$$First\"", ida);
        Assert.Contains("(0x1100, \"Fixture.Native.NativeThing$$Second\"", ida);
        Assert.Contains("idc.parse_decls", ida);
        Assert.Contains("createFunction", File.ReadAllText(_dir.File("fx_ghidra.py")));

        var header = File.ReadAllText(_dir.File("fx.h"));
        Assert.Contains("struct Fixture_Native_NativeThing {", header);
        Assert.Contains("nd_i32 Counter;  /* 0x10 int */", header);
        Assert.Contains("\"Address\": 4096", File.ReadAllText(_dir.File("fx_script.json")));

        Assert.Throws<ToolError>(() => exporter.Export(_env.Workspace.Assemblies, _dir.Path, "pdf", "x", default));
        using var consumer = new Env(Env.ConsumerPath);
        Assert.Throws<ToolError>(() => new AotExporter(consumer.AotMetadata).Export(consumer.Workspace.Assemblies, _dir.Path, "all", "x", default));

        // baseName is a file name: a path in it would put the files outside outputDirectory.
        var outside = Path.Combine(_dir.Path, "out");
        foreach (var baseName in new[] { Path.Combine("..", "escaped"), Path.Combine(_dir.Path, "rooted"), "", " " })
        {
            var error = Assert.Throws<ToolError>(() => _env.Workspace.Read(() => exporter.Export(_env.Workspace.Assemblies, outside, "all", baseName, default)));
            Assert.Equal(ErrorCode.InvalidArgument, error.Code);
        }
        Assert.False(File.Exists(_dir.File("escaped.h")));
        Assert.False(File.Exists(_dir.File("rooted.h")));
    }

    private const string Clang = @"C:\Program Files\LLVM\bin\clang.exe";

    /// <summary>For real dummy assemblies the header compiles and the scripts are valid Python.</summary>
    [Permit("reference-tool")]
    [Trait("Speed", "Slow")]
    [RequiresRealDataFact(RealData.AotDummyDir)]
    public void Real_dump_header_compiles_and_scripts_parse()
    {
        using var ws = new AssemblyWorkspace();
        ws.LoadDirectory(RealData.Path(RealData.AotDummyDir), false);
        var result = ws.Read(() => new AotExporter(new AotMetadataService(ws)).Export(ws.Assemblies, _dir.Path, "all", "app", default));
        Assert.True(result.Methods > 0 && result.Structs > 0);
        if (File.Exists(Clang))
            foreach (var lang in new[] { "c", "c++" })
                Assert.Equal(0, Tools.Run(Clang, $"-fsyntax-only -x {lang} \"{_dir.File("app.h")}\"").ExitCode);
        var python = Tools.Run("python", $"-c \"import py_compile,sys; [py_compile.compile(p, doraise=True) for p in sys.argv[1:]]\" \"{_dir.File("app_ida.py")}\" \"{_dir.File("app_ghidra.py")}\"");
        // -1: python not installed.
        Assert.True(python.ExitCode == 0 || python.ExitCode == -1, python.Output);
    }
}
