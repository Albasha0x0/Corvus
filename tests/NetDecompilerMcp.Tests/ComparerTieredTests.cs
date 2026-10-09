using dnlib.DotNet;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Services;
using NetDecompilerMcp.Tools;
using Xunit.Abstractions;

namespace NetDecompilerMcp.Tests;

/// <summary>
/// Tiered matching in compare_assemblies / find_counterpart: each pairing names its tier and confidence, a key shared by
/// several members is reported as ambiguous with its candidates, and flag or attribute changes over an identical body
/// are reported as metadata changes.
/// </summary>
public class ComparerTieredTests(ITestOutputHelper output) : IDisposable
{
    private readonly TempDir _dir = new();
    public void Dispose() => _dir.Dispose();

    private const string V1 = """
        public class Calc
        {
            public int Scale(int x) { return x * 31 + 7; }
            public int Moved(int x) { return x * 5 + 11; }
            public int Kept(int x) { return x - 1; }
            public int Shown(int x) { return x ^ 9; }
            public int Same(int x) { return x + 2; }
            public int Edit(int x) { return x + 3; }
        }
        """;

    // Scale duplicated under two new names; Moved renamed; Kept marked obsolete; Shown made internal; Edit's body changed.
    private const string V2 = """
        public class Calc
        {
            public int ScaleA(int x) { return x * 31 + 7; }
            public int ScaleB(int x) { return x * 31 + 7; }
            public int MovedRenamed(int x) { return x * 5 + 11; }
            [System.Obsolete] public int Kept(int x) { return x - 1; }
            internal int Shown(int x) { return x ^ 9; }
            public int Same(int x) { return x + 2; }
            public int Edit(int x) { return x + 4; }
        }
        """;

    private string Write(string folder, string source)
    {
        var dir = _dir.File(folder);
        Directory.CreateDirectory(dir);
        var path = Path.Combine(dir, "Tiers.dll");
        File.WriteAllBytes(path, Roslyn.Release("Tiers", source));
        return path;
    }

    [Fact]
    public async Task CompareAndCounterpart_NameTiersAmbiguityAndMetadataChanges()
    {
        using var env = new Env(Write("v1", V1));
        var newer = env.Workspace.Load(Write("v2", V2));
        var tools = new CompareTools(env.Workspace, new AssemblyComparer(env.Workspace), env.Pager);

        var text = await tools.CompareAssemblies(env.Fixture.Id, newer.Id);
        output.WriteLine(text);
        // The old comparer paired Scale with whichever copy came first; both copies are equally good.
        Assert.Contains("ambiguous method Scale(int): 2 candidates share the IL hash key: ScaleA(int) | ScaleB(int)", text);
        Assert.DoesNotContain("added     method ScaleA", text);
        Assert.Contains("renamed   method Moved(int) -> MovedRenamed(int)  (identical body (renamed); tier: IL hash, strong)", text);
        Assert.Contains("metadata  method Kept(int): attributes added: ObsoleteAttribute", text);
        Assert.Contains("metadata  method Shown(int): flags -Public +Assembly", text);
        Assert.Contains("body      method Edit(int): 4 -> 4 instructions", text);
        Assert.DoesNotContain("method Same(int)", text);
        Assert.Matches(@"Member matches: \d+ exact, 1 strong, 0 structural, 1 ambiguous \(by tier: full name \+ signature \d+, IL hash 1\)", text);

        var scale = await tools.FindCounterpart("Calc::Scale", env.Fixture.Id, newer.Id);
        Assert.Contains("-> ambiguous: 2 candidates share the IL hash key", scale);
        Assert.Contains("Calc::ScaleA(int)", scale);
        Assert.Contains("Calc::ScaleB(int)", scale);
        var moved = await tools.FindCounterpart("Calc::Moved", env.Fixture.Id, newer.Id);
        Assert.Contains("-> Calc::MovedRenamed(int)", moved);
        Assert.Contains("tier: IL hash, strong", moved);
        Assert.Contains("body: unchanged (IL hash ", moved);
        var same = await tools.FindCounterpart("Calc::Same", env.Fixture.Id, newer.Id);
        Assert.Contains("tier: full name + signature, exact", same);
        Assert.Contains("body: unchanged", same);
        Assert.Contains("body: changed (IL hash ", await tools.FindCounterpart("Calc::Edit", env.Fixture.Id, newer.Id));
        Assert.Contains("tier: full name, exact", await tools.FindCounterpart("Calc", env.Fixture.Id, newer.Id));
    }

    /// <summary>
    /// Newtonsoft.Json 12.0.2 -> 13.0.1 -> 13.0.4: matches per tier and the ambiguous members. Against the comparer before
    /// tiers, no match was lost; five array-data fields of &lt;PrivateImplementationDetails&gt; that it had paired by position
    /// are now paired by identical data.
    /// </summary>
    [Trait("Speed", "Slow")]
    [Fact]
    public void RealLibraryUpgrades_MatchesPerTier()
    {
        AssemblyComparer.Comparison Compare(AssemblyWorkspace ws, string a, string b)
        {
            var o = ws.Load(RealPackages.Lib("Newtonsoft.Json", a, "netstandard2.0", "Newtonsoft.Json.dll"));
            var n = ws.Load(RealPackages.Lib("Newtonsoft.Json", b, "netstandard2.0", "Newtonsoft.Json.dll"));
            var cmp = ws.Read(() => new AssemblyComparer(ws).Compare(o, n, default));
            output.WriteLine($"{a} -> {b}: {cmp.TypeMap.Count} types, {cmp.MemberMap.Count} members matched, {cmp.Ambiguous.Count} ambiguous");
            output.WriteLine("  changes: " + string.Join(", ", cmp.Types.SelectMany(t => t.Members).GroupBy(m => m.Change).Select(g => $"{g.Count()} {g.Key}")));
            foreach (var g in cmp.MemberMap.Values.GroupBy(m => (m.Tier, m.Confidence)).OrderByDescending(g => g.Count()))
                output.WriteLine($"  {g.Key.Tier} ({g.Key.Confidence}): {g.Count()}");
            foreach (var (m, a2) in cmp.Ambiguous)
                output.WriteLine($"  ambiguous {m.FullName} ({a2.Tier}): {string.Join(" | ", a2.Candidates.Select(c => c.FullName))}");
            return cmp;
        }
        string? Counterpart(AssemblyComparer.Comparison cmp, string fullName)
        {
            var old = cmp.Old.Module.GetTypes().SelectMany(t => t.Methods.Cast<IMemberDef>().Concat(t.Fields)).Single(m => m.FullName == fullName);
            return cmp.MemberMap.TryGetValue(old, out var m) ? $"{m.New.Name} | {m.Tier}" : null;
        }

        using var ws = new AssemblyWorkspace();
        var first = Compare(ws, "12.0.2", "13.0.1");
        Assert.Empty(first.Ambiguous);
        Assert.Equal(482, first.TypeMap.Count);
        Assert.InRange(first.MemberMap.Count, 6950, 7000);
        Assert.Equal("UniversalTicksToJavaScriptTicks | IL hash",
            Counterpart(first, "System.Int64 Newtonsoft.Json.Utilities.DateTimeUtils::UniversialTicksToJavaScriptTicks(System.Int64)"));
        Assert.Equal("<CreateObjectUsingCreatorWithParameters>b__38_2 | generated name", Counterpart(first,
            "System.String Newtonsoft.Json.Serialization.JsonSerializerInternalReader/<>c::<CreateObjectUsingCreatorWithParameters>b__37_2(Newtonsoft.Json.Serialization.JsonProperty)"));
        Assert.Equal("StateArrayTemplate | field type",
            Counterpart(first, "Newtonsoft.Json.JsonWriter/State[][] Newtonsoft.Json.JsonWriter::StateArrayTempate"));
        Assert.All(first.MemberMap.Values, m => Assert.Contains(m.Confidence, new[] { "exact", "strong", "structural" }));

        var second = Compare(ws, "13.0.1", "13.0.4");
        Assert.Equal(7023, second.MemberMap.Count);
        // Both overloads changed their parameters: the name alone cannot tell which became which.
        Assert.Equal(["AssignableToTypeName", "AssignableToTypeName"], second.Ambiguous.Keys.Select(k => k.Name.String));
        Assert.All(second.Ambiguous.Values, a => Assert.Equal(("name", 2), (a.Tier, a.Candidates.Count)));
    }
}
