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

    /// <summary>
    /// Two real builds of one app (NDM_COMPARE_OLD_DIR / NDM_COMPARE_NEW_DIR). Compares NDM_COMPARE_ASSEMBLY, or the
    /// largest application assembly present in both; NDM_COMPARE_EXPECT lists known moves ("Old=>New;Old2=>New2").
    /// </summary>
    [RequiresRealDataFact(RealData.CompareOldDir, RealData.CompareNewDir)]
    public void RealBuildUpdate()
    {
        using var ws = new AssemblyWorkspace();
        var older = ws.LoadDirectory(RealData.Path(RealData.CompareOldDir), false).Loaded;
        var newer = ws.LoadDirectory(RealData.Path(RealData.CompareNewDir), false).Loaded;
        var name = RealData.Get(RealData.CompareAssembly)
                   ?? older.Where(RealData.IsAppAssembly).Where(a => newer.Any(b => b.AssemblyName == a.AssemblyName))
                       .MaxBy(a => a.Module.GetTypes().Count())?.AssemblyName;
        Assert.True(name != null, "no application assembly is present in both builds");
        var old = older.Single(a => a.AssemblyName == name);
        var @new = newer.Single(a => a.AssemblyName == name);
        var sw = Stopwatch.StartNew();
        var cmp = ws.Read(() => new AssemblyComparer(ws).Compare(old, @new, default));
        output.WriteLine($"{name}: compared in {sw.ElapsedMilliseconds} ms: {cmp.TypeMap.Count} matched, {cmp.Types.Count} changes");
        Assert.NotEmpty(cmp.TypeMap);
        foreach (var move in (RealData.Get(RealData.CompareExpect) ?? "").Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var parts = move.Split("=>", StringSplitOptions.TrimEntries);
            Assert.Contains(cmp.Types, t => t.Old?.FullName == parts[0] && t.New?.FullName == parts[1]);
        }
    }
}
