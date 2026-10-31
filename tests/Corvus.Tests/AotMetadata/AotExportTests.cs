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
