using Corvus.Core;
using Corvus.Services;
using Corvus.Tools;

namespace Corvus.Tests;

/// <summary>compare_assemblies without compiler-generated changes, and an edit script that follows a target renamed in the new build.</summary>
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

    // Compiled once per test run, shared by the tests here.
    private static readonly Lazy<byte[]> V1Image = new(() => ReferenceResolutionTests.Compile("Lib", V1));
    private static readonly Lazy<byte[]> V2Image = new(() => ReferenceResolutionTests.Compile("Lib", V2));

    private (string Old, string New) Builds()
    {
        string Write(string folder, byte[] image)
        {
            var dir = _dir.File(folder);
            Directory.CreateDirectory(dir);
            var path = Path.Combine(dir, "Lib.dll");
            File.WriteAllBytes(path, image);
            return path;
        }
        return (Write("v1", V1Image.Value), Write("v2", V2Image.Value));
    }

    [Trait("Smoke", "push")]
    [Fact]
    public async Task Compare_hides_compiler_generated_changes_and_counts_them()
    {
        var (oldPath, newPath) = Builds();
        using var env = new Env(oldPath);
        var newer = env.Workspace.Load(newPath);
        var tools = new CompareTools(env.Workspace, new AssemblyComparer(env.Workspace), env.Decompiler);
        var text = await tools.CompareAssemblies(env.Fixture.Id, newer.Id);
        Assert.Contains("renamed   method Add(int, int) -> AddNumbers(int, int)", text);
        Assert.Contains("added     method Extra()", text);
        Assert.DoesNotContain("<>c", text);
        Assert.Matches(@"Hidden: \d+ compiler-generated type change\(s\) and \d+ member change\(s\)", text);
        Assert.Contains("<>c", await tools.CompareAssemblies(env.Fixture.Id, newer.Id, includeCompilerGenerated: true));
    }

    [Fact]
    public void An_edit_script_is_bound_to_its_build_and_crosses_builds_only_when_asked()
    {
        var (oldPath, newPath) = Builds();
        var script = _dir.File("bound.json");
        string sha;
        using (var original = new Env(oldPath))
        {
            original.Edit(() => original.Edits.StubMethod(original.One("Calc::Other"), "9"));
            Assert.Contains("Bound to the build: sha256 ", original.History.Export(original.Fixture, script));
            sha = original.Fixture.OriginalSha256;
        }
        var json = File.ReadAllText(script);
        Assert.Contains($"\"sha256\": \"{sha}\"", json);
        Assert.Contains("\"identity\": \"Lib, Version=", json);

        using (var same = new Env(oldPath))
        {
            var report = same.Edit(() => same.History.Apply(script, null, dryRun: true, stopOnError: true, default));
            Assert.Contains($"Build check: same build (sha256 {sha[..16]}", report);
            Assert.Contains("1 would apply, 0 would fail", report);
        }

        using var other = new Env(newPath);
        var refused = Assert.Throws<ToolError>(() => other.Edit(() => other.History.Apply(script, null, dryRun: true, stopOnError: true, default)));
        Assert.Equal(ErrorCode.Conflict, refused.Code);
        Assert.Contains($"made for sha256 {sha}", refused.Message);
        Assert.Contains($"Lib is sha256 {other.Fixture.OriginalSha256}", refused.Message);
        Assert.Contains("targetBuild=other", refused.Remediation);
        Assert.False(other.Fixture.IsDirty);
        Assert.Throws<ToolError>(() => EditHistoryService.ParseTargetBuild("newer"));

        var carried = other.Edit(() => other.History.Apply(script, null, dryRun: false, stopOnError: true, default, EditHistoryService.TargetBuild.Other));
        Assert.Contains("Build check: different build, carried over (targetBuild=other)", carried);
        Assert.Contains("1 applied, 0 failed", carried);
        Assert.Contains("Cross-build: 1 edit(s) resolved by name, 0 target(s) followed", carried);
        Assert.Equal("stub_method", Assert.Single(other.Fixture.Edits).Kind);

        // A script written before the binding: applied with a warning.
        var legacy = _dir.File("legacy.json");
        File.WriteAllLines(legacy, File.ReadAllLines(script).Where(l => !l.Contains("\"sha256\"") && !l.Contains("\"identity\"")));
        other.Edit(() => other.Edits.RevertAll(other.Fixture, default));
        var old = other.Edit(() => other.History.Apply(legacy, null, dryRun: false, stopOnError: true, default));
        Assert.Contains("WARNING: the script predates build binding", old);
        Assert.Contains("differs from this build's", old);
        Assert.Contains("1 applied", old);
    }

    [Trait("Speed", "Slow")]
    [Fact]
    public void Edit_script_follows_a_target_renamed_in_the_new_build()
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
            var report = alone.Edit(() => alone.History.Apply(script, alone.Fixture.Id, dryRun: true, stopOnError: true, default, EditHistoryService.TargetBuild.Other));
            Assert.Contains("#1 FAILED", report);
            Assert.Contains("(load the build the script was made from, MVID", report);
        }

        // Both builds loaded: Add is followed to AddNumbers.
        using var env = new Env(newPath);
        env.Workspace.Load(oldPath);
        var applied = env.Edit(() => env.History.Apply(script, env.Fixture.Id, dryRun: false, stopOnError: true, default, EditHistoryService.TargetBuild.Other));
        Assert.Contains("renamed ones through Lib#2 (the build the script was made from)", applied);
        Assert.Contains("#1 ok", applied);
        Assert.Contains("target renamed in this build: Calc::Add(int, int) -> Calc::AddNumbers(int, int)", applied);
        Assert.Contains("return a * b;", env.Decompile("Calc::AddNumbers"));
    }

    [Trait("Speed", "Slow")]
    [Fact]
    public async Task Real_library_upgrade_shows_the_API_changes_first()
    {
        var v12 = RealPackages.Lib("Newtonsoft.Json", "12.0.2", "netstandard2.0", "Newtonsoft.Json.dll");
        var v13 = RealPackages.Lib("Newtonsoft.Json", "13.0.1", "netstandard2.0", "Newtonsoft.Json.dll");
        using var env = new Env(v12);
        var newer = env.Workspace.Load(v13);
        var text = await new CompareTools(env.Workspace, new AssemblyComparer(env.Workspace), env.Decompiler).CompareAssemblies(env.Fixture.Id, newer.Id, maxTokens: 50_000);
        Assert.Contains("Newtonsoft.Json.Utilities.StringUtils/SnakeCaseState -> Newtonsoft.Json.Utilities.StringUtils/SeparatedCaseState", text);
        Assert.DoesNotContain("<PrivateImplementationDetails>", text);
        Assert.DoesNotContain("DisplayClass", text);
    }
}
