using NetDecompilerMcp.Core;
using NetDecompilerMcp.Services;

namespace NetDecompilerMcp.Tests;

public class Il2CppExportTests : IDisposable
{
    private readonly Env _env = new();
    private readonly TempDir _dir = new();

    public void Dispose()
    {
        _env.Dispose();
        _dir.Dispose();
    }

    [Fact]
    public void ExportsScriptsHeaderAndJson()
    {
        var exporter = new Il2CppExporter(_env.Il2Cpp);
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
        Assert.Throws<ToolError>(() => new Il2CppExporter(consumer.Il2Cpp).Export(consumer.Workspace.Assemblies, _dir.Path, "all", "x", default));
    }

    private const string GameDummy = @"C:\work\RE\Game\tools\Il2CppDumper\DummyDll";
    private const string Clang = @"C:\Program Files\LLVM\bin\clang.exe";

    /// <summary>The real dump: the header must compile and the scripts must be valid Python.</summary>
    [RequiresPathFact(GameDummy)]
    public void RealDumpHeaderCompilesAndScriptsParse()
    {
        using var ws = new AssemblyWorkspace();
        ws.LoadDirectory(GameDummy, false);
        var result = ws.Read(() => new Il2CppExporter(new Il2CppService(ws)).Export(ws.Assemblies, _dir.Path, "all", "game", default));
        Assert.True(result.Methods > 50_000 && result.Structs > 5_000);
        if (File.Exists(Clang))
            Assert.Equal(0, Tools.Run(Clang, $"-fsyntax-only -x c \"{_dir.File("game.h")}\"").ExitCode);
        var python = Tools.Run("python", $"-c \"import py_compile,sys; [py_compile.compile(p, doraise=True) for p in sys.argv[1:]]\" \"{_dir.File("game_ida.py")}\" \"{_dir.File("game_ghidra.py")}\"");
        Assert.True(python.ExitCode == 0 || python.ExitCode == -1, python.Output); // -1: no python on this machine
    }
}
