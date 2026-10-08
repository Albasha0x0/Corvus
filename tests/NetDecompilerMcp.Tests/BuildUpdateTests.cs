using NetDecompilerMcp.Core;
using NetDecompilerMcp.Services;
using NetDecompilerMcp.Tools;

namespace NetDecompilerMcp.Tests;

/// <summary>
/// Moving to a new build: compare_assemblies without compiler-generated noise, and an edit script that follows a
/// target renamed in the new build.
/// </summary>
public class BuildUpdateTests : IDisposable
{
    private readonly TempDir _dir = new();
    public void Dispose() => _dir.Dispose();

    private const string V1 = """
        public class Calc
        {
            public int Add(int a, int b) { return a + b + 1000; }
            public System.Func<int, int> F() => x => x + 1;
            public int Other() => 7;
        }
        """;

    // Add renamed (same body), the lambda changed, a member added
    private const string V2 = """
        public class Calc
        {
            public int AddNumbers(int a, int b) { return a + b + 1000; }
            public int Extra() => 3;
            public System.Func<int, int> F() => x => x * 2;
            public int Other() => 7;
        }
        """;

    private (string Old, string New) Builds()
    {
        string Write(string folder, string source)
        {
            var dir = _dir.File(folder);
            Directory.CreateDirectory(dir);
            var path = Path.Combine(dir, "Lib.dll");
            File.WriteAllBytes(path, ReferenceResolutionTests.Compile("Lib", source));
            return path;
        }
        return (Write("v1", V1), Write("v2", V2));
    }

    [Fact]
    public async Task Compare_HidesCompilerGeneratedChanges_AndCountsThem()
    {
        var (oldPath, newPath) = Builds();
        using var env = new Env(oldPath);
        var newer = env.Workspace.Load(newPath);
        var tools = new CompareTools(env.Workspace, new AssemblyComparer(env.Workspace), env.Pager);
        var text = await tools.CompareAssemblies(env.Fixture.Id, newer.Id);
        Assert.Contains("renamed   method Add(int, int) -> AddNumbers(int, int)", text);
        Assert.Contains("added     method Extra()", text);
        Assert.DoesNotContain("<>c", text);
        Assert.Matches(@"Hidden: \d+ compiler-generated type change\(s\) and \d+ member change\(s\)", text);
        Assert.Contains("<>c", await tools.CompareAssemblies(env.Fixture.Id, newer.Id, includeCompilerGenerated: true));
    }

    [Fact]
    public void EditScript_FollowsATargetRenamedInTheNewBuild()
    {
        var (oldPath, newPath) = Builds();
        var script = _dir.File("edits.json");
        using (var original = new Env(oldPath))
        {
            original.Edit(() => original.Edits.PatchMethodCSharp(original.One("Calc::Add"), "return a * b;", false, default));
            original.History.Export(original.Fixture, script);
        }

        // Only the new build loaded: the target is unresolved.
        using (var alone = new Env(newPath))
        {
            var report = alone.Edit(() => alone.History.Apply(script, alone.Fixture.Id, dryRun: true, stopOnError: true, default));
            Assert.Contains("#1 FAILED", report);
            Assert.Contains("(load the build the script was made from, MVID", report);
        }

        // Both builds loaded: Add is followed to AddNumbers.
        using var env = new Env(newPath);
        env.Workspace.Load(oldPath);
        var applied = env.Edit(() => env.History.Apply(script, env.Fixture.Id, dryRun: false, stopOnError: true, default));
        Assert.Contains("renamed ones through Lib#2 (the build the script was made from)", applied);
        Assert.Contains("#1 ok", applied);
        Assert.Contains("target renamed in this build: Calc::Add(int, int) -> Calc::AddNumbers(int, int)", applied);
        Assert.Contains("return a * b;", env.Decompile("Calc::AddNumbers"));
    }

    [Fact]
    public async Task RealLibraryUpgrade_ShowsTheApiChangesFirst()
    {
        var v12 = RealPackages.Lib("Newtonsoft.Json", "12.0.2", "netstandard2.0", "Newtonsoft.Json.dll");
        var v13 = RealPackages.Lib("Newtonsoft.Json", "13.0.1", "netstandard2.0", "Newtonsoft.Json.dll");
        using var env = new Env(v12);
        var newer = env.Workspace.Load(v13);
        var text = await new CompareTools(env.Workspace, new AssemblyComparer(env.Workspace), env.Pager).CompareAssemblies(env.Fixture.Id, newer.Id, maxChars: 200_000);
        Assert.Contains("Newtonsoft.Json.Utilities.StringUtils/SnakeCaseState -> Newtonsoft.Json.Utilities.StringUtils/SeparatedCaseState", text);
        Assert.DoesNotContain("<PrivateImplementationDetails>", text);
        Assert.DoesNotContain("DisplayClass", text);
    }
}
