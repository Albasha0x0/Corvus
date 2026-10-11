using dnlib.DotNet;
using Corvus.Core;
using Corvus.Services;
using Corvus.Tools;
using Xunit.Abstractions;

namespace Corvus.Tests;

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
        var tools = new CompareTools(env.Workspace, new AssemblyComparer(env.Workspace), env.Pager, env.Decompiler);

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

    [Fact]
    public async Task CompareAndCounterpart_MethodsMovedToAnotherType()
    {
        const string before = """
            public class Source
            {
                public int Keep(int x) { return x + 1; }
                public string Helper(string s) { return s.Trim().ToUpperInvariant() + "!" + s.Length; }
                public static int Compute(int a, int b) { int r = a * 17; for (int i = 0; i < b; i++) r ^= i * 3; return r + 99; }
                public static int Dup(int a) { int r = a * 41; for (int i = 0; i < a; i++) r += i ^ 5; return r - 3; }
            }
            public class Target { public int T(int x) { return x * 2; } }
            public class Gone { public static long Twice(long v) { long r = v; for (long i = 0; i < v; i++) r = r * 2 + 7; return r ^ 0x55; } }
            """;
        const string after = """
            public class Source { public int Keep(int x) { return x + 1; } }
            public class Target
            {
                public int T(int x) { return x * 2; }
                public string Helper(string s) { return s.Trim().ToUpperInvariant() + "!" + s.Length; }
                public static long Twice2(long v) { long r = v; for (long i = 0; i < v; i++) r = r * 2 + 7; return r ^ 0x55; }
                public static int Dup(int a) { int r = a * 41; for (int i = 0; i < a; i++) r += i ^ 5; return r - 3; }
            }
            public static class Util
            {
                public static int Compute(int a, int b) { int r = a * 17; for (int i = 0; i < b; i++) r ^= i * 3; return r + 99; }
                public static int Dup(int a) { int r = a * 41; for (int i = 0; i < a; i++) r += i ^ 5; return r - 3; }
            }
            """;
        using var env = new Env(Write("mv1", before));
        var newer = env.Workspace.Load(Write("mv2", after));
        var tools = new CompareTools(env.Workspace, new AssemblyComparer(env.Workspace), env.Pager, env.Decompiler);

        var text = await tools.CompareAssemblies(env.Fixture.Id, newer.Id);
        output.WriteLine(text);
        Assert.Contains("moved     method Helper(string) -> Target::Helper(string)  (identical body (moved); tier: IL hash, other type, strong)", text);
        Assert.Contains("moved     method Compute(int, int) -> Util::Compute(int, int)", text);
        Assert.Contains("Gone  (removed)", text);
        Assert.Contains("moved     method Twice(long) -> Target::Twice2(long)", text);
        Assert.Contains("+renamed: identical body (moved)", text);
        Assert.Contains("ambiguous method Dup(int): 2 candidates share the IL hash, other type key: Target::Dup(int) | Util::Dup(int)", text);
        Assert.DoesNotContain("removed   method Helper", text);
        Assert.DoesNotContain("added     method Helper", text);
        Assert.DoesNotContain("added     method Dup", text);
        Assert.Matches(@"Members \(each change of a member counted\): \d+ renamed, 3 moved,", text);

        var helper = await tools.FindCounterpart("Source::Helper", env.Fixture.Id, newer.Id);
        Assert.Contains("-> Target::Helper(string)", helper);
        Assert.Contains("tier: IL hash, other type, strong", helper);
        Assert.Contains("changes: moved", helper);
        Assert.Contains("-> ambiguous: 2 candidates share the IL hash, other type key", await tools.FindCounterpart("Source::Dup", env.Fixture.Id, newer.Id));
    }

    [Trait("Speed", "Slow")]
    [Fact]
    public async Task Counterpart_DiffOfDecompiledCodeAndNormalizedIl_Bounded()
    {
        static string Big(int k) => "public class Big { public int Edit(int x) { return x + " + k + "; } public static int Many(int s) {\n" +
            string.Concat(Enumerable.Range(0, 400).Select(i => $"s = s * {i + k} + {i};\n")) + "return s; } }";
        using var env = new Env(Write("d1", Big(3)));
        var newer = env.Workspace.Load(Write("d2", Big(4)));
        var tools = new CompareTools(env.Workspace, new AssemblyComparer(env.Workspace), env.Pager, env.Decompiler);

        var edit = await tools.FindCounterpart("Big::Edit", env.Fixture.Id, newer.Id, diff: true, il: true);
        output.WriteLine(edit);
        var lines = edit.ReplaceLineEndings("\n").Split('\n').Select(l => l.Replace("\t", "").Trim()).ToList();
        Assert.Contains("C# diff:", lines);
        Assert.Contains($"--- {env.Fixture.Id} Big::Edit(int)", lines);
        Assert.Contains($"+++ {newer.Id} Big::Edit(int)", lines);
        Assert.Contains("-return x + 3;", lines);
        Assert.Contains("+return x + 4;", lines);
        Assert.Contains("normalized IL diff:", lines);
        Assert.Contains("-ldc.i4 i:3", lines);
        Assert.Contains("+ldc.i4 i:4", lines);
        Assert.DoesNotContain("diff:", await tools.FindCounterpart("Big::Edit", env.Fixture.Id, newer.Id));

        var many = await tools.FindCounterpart("Big::Many", env.Fixture.Id, newer.Id, diff: true);
        Assert.Matches(@"… diff cut at 300 of \d+ lines; decompile_member / get_il on each build show the rest\.", many);
    }

    [Fact]
    public async Task Counterpart_DiffReadsRenamesAsTheNewBuildAndDiffsATypeByMember()
    {
        const string before = """
            public class Engine
            {
                public int Helper(int x) { return x * 3 + 17; }
                public int Run(int x) { return Helper(x) + 1; }
                public int Stable(int x) { return x - 9; }
                public int Gone() { return 5; }
            }
            """;
        const string after = """
            public class Engine
            {
                public int Triple(int x) { return x * 3 + 17; }
                public int Run(int x) { return Triple(x) + 1; }
                public int Stable(int x) { return x - 9; }
                public string Added(string s) { return s + "!"; }
            }
            """;
        using var env = new Env(Write("r1", before));
        var newer = env.Workspace.Load(Write("r2", after));
        var tools = new CompareTools(env.Workspace, new AssemblyComparer(env.Workspace), env.Pager, env.Decompiler);

        var run = await tools.FindCounterpart("Engine::Run", env.Fixture.Id, newer.Id, diff: true, il: true);
        output.WriteLine(run);
        Assert.Contains("body: changed", run); // the callee's name is part of the IL hash
        Assert.Contains("C# diff: none (old names read as renamed: Helper -> Triple)", run);
        Assert.Contains("normalized IL diff: none", run);
        Assert.DoesNotContain("[token", run);

        Assert.Contains("C# diff: none needed (the same normalized IL)", await tools.FindCounterpart("Engine::Stable", env.Fixture.Id, newer.Id, diff: true));

        var type = await tools.FindCounterpart("Engine", env.Fixture.Id, newer.Id, diff: true);
        output.WriteLine(type);
        var lines = type.ReplaceLineEndings("\n").Split('\n').Select(l => l.Replace("\t", "").Trim()).ToList();
        Assert.Contains(lines, l => l.StartsWith("-public int Gone()", StringComparison.Ordinal));
        Assert.Contains(lines, l => l.StartsWith("+public string Added(string s)", StringComparison.Ordinal));
        Assert.DoesNotContain(lines, l => l.StartsWith("-public int Helper", StringComparison.Ordinal)); // a pure rename is no change
    }

    [Fact]
    public async Task Compare_StructuredResult_AndTokenMapExport()
    {
        using var env = new Env(Write("v1", V1));
        var newer = env.Workspace.Load(Write("v2", V2));
        var tools = new CompareTools(env.Workspace, new AssemblyComparer(env.Workspace), env.Pager, env.Decompiler);
        var mapPath = _dir.File("map.json");

        var collector = Corvus.Mcp.StructuredOutput.Begin();
        var text = await tools.CompareAssemblies(env.Fixture.Id, newer.Id, tokenMapPath: mapPath);
        var result = Assert.IsType<CompareTools.AssemblyComparison>(collector.Value);
        Assert.Equal((env.Fixture.OriginalSha256, newer.OriginalSha256), (result.Old.Sha256, result.New.Sha256));
        Assert.Equal(env.Fixture.Module.Mvid.ToString(), result.Old.Mvid);
        Assert.Equal(1, result.MemberChanges.Single(k => k.Kind == "renamed").Count);
        Assert.Equal(1, result.AmbiguousMembers);
        var moved = result.Items.Single(i => i.Old == "Calc::Moved(int)");
        Assert.Equal(("method", "renamed", "Calc::MovedRenamed(int)", "IL hash", "strong"), (moved.Kind, moved.Change, moved.New, moved.Tier, moved.Confidence));
        Assert.Equal(2, result.Items.Single(i => i.Change == "ambiguous").Candidates!.Count);
        Assert.Equal(result.Items.Count, result.Total);
        Assert.Contains($"Token map: {result.TokenMapEntries} old types and members written to {mapPath}.", text);

        using var json = System.Text.Json.JsonDocument.Parse(File.ReadAllText(mapPath));
        var root = json.RootElement;
        Assert.Equal("ndm-token-map", root.GetProperty("format").GetString());
        Assert.Equal(env.Fixture.OriginalSha256, root.GetProperty("old").GetProperty("sha256").GetString());
        var entries = root.GetProperty("entries").EnumerateArray().ToDictionary(e => e.GetProperty("old").GetString()!);
        Assert.Equal(result.TokenMapEntries, entries.Count);
        var movedEntry = entries["Calc::Moved(int)"];
        Assert.Equal("matched", movedEntry.GetProperty("status").GetString());
        Assert.Equal(Format.Token(newer.Module.Find("Calc", false).FindMethod("MovedRenamed")), movedEntry.GetProperty("newToken").GetString());
        Assert.True(movedEntry.GetProperty("bodyHashEqual").GetBoolean());
        Assert.False(entries["Calc::Edit(int)"].GetProperty("bodyHashEqual").GetBoolean());
        Assert.Equal("ambiguous", entries["Calc::Scale(int)"].GetProperty("status").GetString());
        Assert.Equal(2, entries["Calc::Scale(int)"].GetProperty("candidates").GetArrayLength());
        Assert.Equal(("matched", "full name"), (entries["Calc"].GetProperty("status").GetString(), entries["Calc"].GetProperty("tier").GetString()));

        // An existing file is replaced only when asked.
        Assert.Equal(ErrorCode.Conflict, (await Assert.ThrowsAsync<ToolError>(() => tools.CompareAssemblies(env.Fixture.Id, newer.Id, tokenMapPath: mapPath))).Code);
        Assert.Contains("Token map:", await tools.CompareAssemblies(env.Fixture.Id, newer.Id, tokenMapPath: mapPath, overwrite: true));
    }

    [Fact]
    public async Task CompareAndCounterpart_EveryChangeOfAMember_AndEventsAddedRemoved()
    {
        const string before = """
            public class Multi
            {
                public int Both(int x) { return x * 7 + 1; }
                public event System.Action Gone;
                public event System.Action Kept;
            }
            """;
        const string after = """
            public class Multi
            {
                internal int Both(long x) { return (int)x * 7 + 2; }
                public event System.Action Kept;
                public event System.Action Fresh;
            }
            """;
        using var env = new Env(Write("m1", before));
        var newer = env.Workspace.Load(Write("m2", after));
        var tools = new CompareTools(env.Workspace, new AssemblyComparer(env.Workspace), env.Pager, env.Decompiler);

        var text = await tools.CompareAssemblies(env.Fixture.Id, newer.Id);
        output.WriteLine(text);
        Assert.Contains("signature method Both(int): int(int) -> int(long)  +body: ", text);
        Assert.Contains("  +metadata: flags -Public +Assembly", text);
        Assert.Contains("removed   event Gone", text);
        Assert.Contains("added     event Fresh", text);
        Assert.DoesNotContain("event Kept", text);
        Assert.Matches(@"Members \(each change of a member counted\): \d+ renamed, 0 moved, 1 signature, 1 body, 1 metadata", text);
        // Filtering by a secondary change still lists the member with all of its changes.
        Assert.Contains("signature method Both(int)", await tools.CompareAssemblies(env.Fixture.Id, newer.Id, changes: "metadata"));

        Assert.Contains($"({env.Fixture.FilePath}; SHA-256 {env.Fixture.OriginalSha256}, MVID {env.Fixture.Module.Mvid})", text);
        Assert.Contains($"-> {newer.Id} ({newer.FilePath}; SHA-256 {newer.OriginalSha256}, MVID {newer.Module.Mvid})", text);

        var both = await tools.FindCounterpart("Multi::Both", env.Fixture.Id, newer.Id);
        Assert.StartsWith($"Old: {env.Fixture.Id} (SHA-256 {env.Fixture.OriginalSha256}, MVID {env.Fixture.Module.Mvid})", both);
        Assert.Contains($"New: {newer.Id} (SHA-256 {newer.OriginalSha256}, MVID {newer.Module.Mvid})", both);
        Assert.Contains("changes: signature, body, metadata", both);
        Assert.Contains("metadata: flags -Public +Assembly", both);
        Assert.Contains("changes: none", await tools.FindCounterpart("Multi::Kept", env.Fixture.Id, newer.Id));
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
