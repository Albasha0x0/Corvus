using System.Diagnostics;
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
