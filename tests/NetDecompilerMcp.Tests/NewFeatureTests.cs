using System.Diagnostics;
using dnlib.DotNet;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Services;
using Xunit.Abstractions;

namespace NetDecompilerMcp.Tests;

public class ComparerTests(ITestOutputHelper output)
{
    /// <summary>Builds a "v2" of the fixture with known renames, body changes and additions, then compares.</summary>
    [Fact]
    public void DetectsRenamesBodyChangesAndAdditions()
    {
        using var dir = new TempDir();
        var v2 = dir.File("TestFixture.dll");
        using (var build = new Env())
        {
            build.Edit(() => build.Edits.Rename(build.One("Secret", SymbolKind.Type), "LicenseGuard"));
            build.Edit(() => build.Edits.Rename(build.One("Shop::Describe"), "Summary"));
            build.Edit(() => build.Edits.Rename(build.One("Shop::_gold"), "_coins"));
            build.Edit(() => build.Edits.StubMethod(build.One("Player::Score"), "5"));
            build.Edit(() => build.Edits.AddMembersCSharp(build.One("Shop", SymbolKind.Type), "public int Twice(int x) { return x * 2; }", false, default));
            build.Edit(() => build.Edits.AddTypesCSharp(build.Fixture, "namespace Mods { public class Extra { public int V; } }", false, default));
            build.Edits.Save(build.Fixture, v2, false);
        }

        using var env = new Env();
        var newAsm = env.Workspace.Load(v2);
        var comparer = new AssemblyComparer(env.Workspace);
        var cmp = env.Workspace.Read(() => comparer.Compare(env.Fixture, newAsm, default));

        var secret = cmp.Types.Single(t => t.Old?.Name == "Secret");
        Assert.Equal("renamed", secret.Change);
        Assert.Equal("LicenseGuard", secret.New!.Name);

        var shop = cmp.Types.Single(t => t.Old?.Name == "Shop").Members;
        Assert.Contains(shop, m => m.Change == "renamed" && m.Old!.Name == "Describe" && m.New!.Name == "Summary");
        Assert.Contains(shop, m => m.Change == "renamed" && m.Old!.Name == "_gold" && m.New!.Name == "_coins");
        Assert.Contains(shop, m => m.Change == "added" && m.New!.Name == "Twice");
        Assert.Contains(cmp.Types.Single(t => t.Old?.Name == "Player").Members, m => m.Change == "body" && m.Old!.Name == "Score");
        Assert.Contains(cmp.Types, t => t.Change == "added" && t.New!.FullName == "Mods.Extra");
        Assert.DoesNotContain(cmp.Types, t => t.Change == "removed" && t.Old!.FullName.StartsWith("Fixture.Game"));

        var (match, how) = comparer.FindCounterpart(cmp, env.One("Shop::Describe").Member);
        Assert.Equal("Summary", match!.Name);
        Assert.Contains("renamed", how);
        Assert.Throws<ToolError>(() => comparer.Compare(env.Fixture, env.Fixture, default));
    }

    private const string January = @"C:\work\RE\Game\dumps\memory_dump";
    private const string September = @"C:\work\RE\Game\dumps\memory_dump_v2";

    [RequiresPathFact(January)]
    public void RealGameUpdate()
    {
        using var ws = new AssemblyWorkspace();
        var jan = ws.LoadDirectory(January, false).Loaded.Single(a => a.AssemblyName == "EcsClient");
        var sep = ws.LoadDirectory(September, false).Loaded.Single(a => a.AssemblyName == "EcsClient");
        var sw = Stopwatch.StartNew();
        var cmp = ws.Read(() => new AssemblyComparer(ws).Compare(jan, sep, default));
        output.WriteLine($"compared in {sw.ElapsedMilliseconds} ms: {cmp.TypeMap.Count} matched, {cmp.Types.Count} changes");
        // Known moves/renames between these builds.
        Assert.Contains(cmp.Types, t => t.Old?.FullName == "Sazabi.Scene.Share.ClinetShared.Modules.PartyGame.MorphComponent"
                                        && t.New?.FullName == "XDT.Scene.Shared.Modules.PartyGame.MorphComponent");
        Assert.Contains(cmp.Types, t => t.Old?.FullName == "TableAnimalBehaviacConf" && t.New?.FullName == "TableAnimalBehaviourConf");
        Assert.True(cmp.TypeMap.Count > 8000);
    }
}

public class CallGraphTests : IDisposable
{
    private readonly Env _env = new(withConsumer: true);
    private readonly CallGraphService _graph;

    public CallGraphTests() => _graph = new CallGraphService(_env.Workspace);

    public void Dispose() => _env.Dispose();

    private string Tree(string method, bool callers, int depth = 3, bool external = false) =>
        _env.Workspace.Read(() => _graph.Tree(_env.Fixture, _env.Def<MethodDef>(method), callers, depth, 300, external, default));

    [Fact]
    public void CallerAndCalleeTrees()
    {
        Assert.Contains("Fixture.Game.Player::CheckLicense()", Tree("Secret::Validate", callers: true));
        var callees = Tree("Player::TakeDamage(int, string)", callers: false);
        Assert.Contains("Fixture.Game.Player::Log(string)", callees);
        Assert.Contains("Fixture.Game.Player::TakeDamage(int)", callees);
        Assert.Contains("String::Concat", Tree("Player::TakeDamage(int, string)", callers: false, external: true));
        Assert.Contains("no callers", Tree("Player::CheckLicense", callers: true));
    }

    [Fact]
    public void VirtualDispatchAndCrossAssembly()
    {
        var callers = Tree("Player::TakeDamage(int)", callers: true);
        Assert.Contains("Consumer.Arena::Hit(IDamageable)", callers);
        Assert.Contains("via Fixture.Game.IDamageable::TakeDamage(int)", callers);
        Assert.Contains("[TestFixture.Consumer]", callers);
    }

    [Fact]
    public void RecursionAndRepeatsAreMarked()
    {
        // TakeDamage(int, string) calls TakeDamage(int); Shop.PriceOf(string, int) calls PriceOf(string).
        var tree = Tree("Shop::PriceOf(string)", callers: true, depth: 5);
        Assert.Contains("Fixture.Game.Shop::PriceOf(string, int)", tree);
    }

    [Fact]
    public void PathsFromStartAndFromEntryPoints()
    {
        var hit = _env.Def<MethodDef>("Consumer.Arena::Hit");
        var target = _env.Def<MethodDef>("Player::TakeDamage(int)");
        var fromHit = _env.Workspace.Read(() => _graph.Paths(hit, target, 8, 10, default));
        Assert.Contains(fromHit, p => p.First() == hit && p.Last() == target);

        var validate = _env.Def<MethodDef>("Secret::Validate");
        var fromRoots = _env.Workspace.Read(() => _graph.Paths(null, validate, 8, 10, default));
        Assert.Contains(fromRoots, p => p.First().Name == "CheckLicense" && p.Last() == validate);
    }

    [Fact]
    public void GraphIsRebuiltAfterEdits()
    {
        _env.Workspace.Read(() => { _graph.EnsureBuilt(default); return 0; });
        Assert.True(_graph.IsBuilt);
        _env.Edit(() => _env.Edits.StubMethod(_env.One("Player::CheckLicense"), "true")); // removes the call to Validate
        Assert.False(_graph.IsBuilt);
        Assert.Contains("no callers", Tree("Secret::Validate", callers: true));
    }
}

/// <summary>Timing-sensitive real-game checks run alone (after the parallel tests), so CPU contention can't skew them.</summary>
[CollectionDefinition(nameof(SerialTimingTests), DisableParallelization = true)]
public class SerialTimingCollection;

[Collection(nameof(SerialTimingTests))]
public class SerialTimingTests
{
    private const string GameDlls = @"C:\work\ModHost\dlls";

    /// <summary>A real game's call graph is full of cycles: the path search must stay linear, not enumerate every path.</summary>
    [RequiresPathFact(GameDlls)]
    public void PathSearchIsFastOnARealGame()
    {
        using var ws = new AssemblyWorkspace();
        ws.LoadDirectory(GameDlls, false);
        var graph = new CallGraphService(ws);
        ws.Read(() => { graph.EnsureBuilt(default); return 0; });
        var target = ws.Read(() => (MethodDef)SymbolResolver.ResolveOne(ws, null, "XDTGameSystem.GameplaySystem.Tool.ToolSystem::GetCurrentTool").Member);
        var sw = Stopwatch.StartNew();
        var paths = ws.Read(() => graph.Paths(null, target, 12, 5, default));
        Assert.True(sw.Elapsed < TimeSpan.FromSeconds(10), $"{sw.Elapsed}");
        Assert.All(paths, p => Assert.Equal(target, p.Last()));
        Assert.NotEmpty(paths);
        foreach (var p in paths) // every step is a real call edge (direct or through a base/interface method)
            for (int i = 0; i + 1 < p.Count; i++)
                Assert.Contains($"{p[i].DeclaringType.FullName.Replace('/', '+')}::{p[i].Name}(",
                    ws.Read(() => graph.Tree(ws.Assemblies.First(), p[i + 1], true, 1, 5000, false, default)));
    }
}

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
            Assert.Equal(0, Run(Clang, $"-fsyntax-only -x c \"{_dir.File("game.h")}\"").ExitCode);
        var python = Run("python", $"-c \"import py_compile,sys; [py_compile.compile(p, doraise=True) for p in sys.argv[1:]]\" \"{_dir.File("game_ida.py")}\" \"{_dir.File("game_ghidra.py")}\"");
        Assert.True(python.ExitCode == 0 || python.ExitCode == -1, python.Output); // -1: no python on this machine
    }

    internal static (int ExitCode, string Output) Run(string file, string args)
    {
        try
        {
            using var p = Process.Start(new ProcessStartInfo(file, args) { RedirectStandardError = true, RedirectStandardOutput = true, UseShellExecute = false })!;
            var text = p.StandardOutput.ReadToEnd() + p.StandardError.ReadToEnd();
            p.WaitForExit(600_000);
            return (p.ExitCode, text);
        }
        catch (System.ComponentModel.Win32Exception)
        {
            return (-1, $"{file} not found");
        }
    }
}

public class CppBindingTests : IDisposable
{
    private readonly Env _env = new();
    public void Dispose() => _env.Dispose();

    private string Generate(string type, string? only = null, bool inherited = false) =>
        new CppBindingGenerator().Generate(_env.Fixture, _env.Def<TypeDef>(type, SymbolKind.Type), only?.Split(','), inherited);

    [Fact]
    public void GeneratesHostApiBinding()
    {
        var code = Generate("Player");
        Assert.Contains("klass = h->FindClass(\"TestFixture\", \"Fixture.Game\", \"Player\");", code);
        Assert.Contains("m_healthOff = h->FieldOffset(klass, \"_health\");", code);
        Assert.Contains("m_playerCountStaticOff = h->StaticFieldOffset(klass, \"PlayerCount\");", code);
        Assert.Contains("m_static = h->GetStaticFieldData(klass);", code);
        Assert.Contains("int32_t Health(const HostApi* h, const void* obj) const { return ReadField<int32_t>(h, obj, m_healthOff); }", code);
        Assert.Contains("h->GetMethod(klass, \"CheckLicense\", 0);", code);
        Assert.Contains("return CallValue<bool>(h, m_getIsAlive, obj);", code);
        Assert.Contains("namespace plugin {", code);
    }

    [Fact]
    public void OverloadsUseExactSignaturesAndFiltersWork()
    {
        var code = Generate("Shop", "Apply,_gold");
        Assert.Contains("GetMethodExact(h, klass, \"Apply\", \"Int32\")", code);
        Assert.Contains("GetMethodExact(h, klass, \"Apply\", \"String\")", code);
        Assert.Contains("_gold", code);
        Assert.DoesNotContain("Buy", code);
        Assert.Throws<ToolError>(() => Generate("Shop", "NoSuchMember"));
        Assert.Throws<ToolError>(() => Generate("Container"));
        Assert.Contains("GetMethodInHierarchy", Generate("Boss", inherited: true));
    }

    private const string ModHostPlugin = @"C:\work\ModHost\plugin";
    private const string ClangPlusPlus = @"C:\Program Files\LLVM\bin\clang++.exe";

    /// <summary>The generated code compiles against ModHost's real headers.</summary>
    [RequiresPathFact(ModHostPlugin)]
    public void CompilesAgainstModHostHeaders()
    {
        if (!File.Exists(ClangPlusPlus)) return;
        using var dir = new TempDir();
        foreach (var type in new[] { "Player", "Shop", "Boss" })
        {
            File.WriteAllText(dir.File(type + ".h"), Generate(type, inherited: true));
            File.WriteAllText(dir.File(type + ".cpp"), $"#include \"{type}.h\"\nint main() {{ plugin::{type}Binding b; return b.Resolved() ? 0 : 1; }}\n");
            var (code, text) = Il2CppExportTests.Run(ClangPlusPlus, $"-std=c++20 -fsyntax-only -I \"{ModHostPlugin}\" -I \"{dir.Path}\" \"{dir.File(type + ".cpp")}\"");
            Assert.True(code == 0, text);
        }
    }
}

public class BackgroundTests
{
    [Fact]
    public void IndexingWarmsCachesAndBuildsTheCallGraph()
    {
        using var ws = new AssemblyWorkspace();
        var graph = new CallGraphService(ws);
        using var indexing = new IndexingService(ws, graph, new ServerOptions());
        ws.Load(typeof(ModuleDefMD).Assembly.Location); // dnlib: a few thousand methods
        Assert.True(indexing.WaitForIdle(TimeSpan.FromMinutes(2)));
        Assert.Equal("done", indexing.Status);
        Assert.True(ws.Read(() => graph.IsBuilt));
    }

    [Fact]
    public void EditsAreNotBlockedOrBrokenByIndexing()
    {
        using var env = new Env(typeof(ModuleDefMD).Assembly.Location);
        var graph = new CallGraphService(env.Workspace);
        using var indexing = new IndexingService(env.Workspace, graph, new ServerOptions());
        indexing.Start();
        for (int i = 0; i < 5; i++)
            env.Edit(() => env.Edits.StubMethod(env.One("dnlib.DotNet.UTF8String::ToString()"), $"\"v{i}\""));
        Assert.True(indexing.WaitForIdle(TimeSpan.FromMinutes(2)));
        Assert.Equal(5, env.Fixture.Edits.Count);
    }

    [Fact]
    public async Task FileChangesReloadCleanAssembliesAndProtectEditedOnes()
    {
        using var dir = new TempDir();
        var path = dir.File("TestFixture.dll");
        File.Copy(Env.FixturePath, path);
        var patched = dir.File("patched.dll");
        using (var build = new Env())
        {
            build.Edit(() => build.Edits.Rename(build.One("Shop::Describe"), "DescribeV2"));
            build.Edits.Save(build.Fixture, patched, false);
        }

        using var ws = new AssemblyWorkspace();
        using var watcher = new FileWatchService(ws, new ServerOptions());
        ws.Load(path);
        File.Copy(patched, path, overwrite: true);
        Assert.True(await Eventually(() => ws.Read(() => ws.Assemblies.Single().Module.Find("Fixture.Game.Shop", false)?.FindMethod("DescribeV2") != null)));
        Assert.Contains(ws.DrainNotices(), n => n.Contains("reloaded"));

        // With unsaved edits the assembly is not reloaded; the client is told instead.
        var edits = new EditService(ws, new IlAssembler(ws), new CSharpPatcher(ws, new DecompilerService(ws, new ServerOptions())));
        ws.Write(() => edits.StubMethod(SymbolResolver.ResolveOne(ws, null, "Player::Score"), "1"));
        File.Copy(Env.FixturePath, path, overwrite: true);
        Assert.True(await Eventually(() => ws.DrainNotices() is { Count: > 0 } n && n.Any(x => x.Contains("unsaved edit"))));
        Assert.True(ws.Read(() => ws.Assemblies.Single().IsDirty));
    }

    private static async Task<bool> Eventually(Func<bool> condition)
    {
        for (int i = 0; i < 100; i++)
        {
            if (condition()) return true;
            await Task.Delay(100);
        }
        return false;
    }
}
