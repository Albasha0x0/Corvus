using System.Text.Json;
using dnlib.DotNet;
using ModelContextProtocol.Client;
using ModelContextProtocol.Protocol;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Services.Analysis;

namespace NetDecompilerMcp.Tests;

/// <summary>search_container: name search over every managed assembly in a container, in memory.</summary>
public partial class UnpackTests
{
    private UnpackService.ContainerSearch Search(string path, string query, string? kind = null, int limit = 200) =>
        Unpacker.Search(path, query, UnpackService.ParseSearchKind(kind), limit, AnalysisLimits.Default, default);

    private const string NoSuchSymbol = "zzNoSuchSymbolzz";

    private static void AssertNothingFound(UnpackService.ContainerSearch s)
    {
        Assert.Empty(s.Matches);
        Assert.Equal(0, s.Total);
        Assert.False(s.Truncated);
        Assert.True(s.AssembliesSearched > 0);
    }

    /// <summary>A kind filter keeps exactly the unfiltered matches of that kind.</summary>
    private void AssertKindFilterNarrows(string path, string query, params string[] kinds)
    {
        var all = Search(path, query);
        foreach (var kind in kinds)
        {
            var filtered = Search(path, query, kind);
            Assert.NotEmpty(filtered.Matches);
            Assert.All(filtered.Matches, m => Assert.Equal(kind, m.Kind));
            Assert.Equal(all.Matches.Where(m => m.Kind == kind).Select(m => (m.Path, m.Name)).Order(), filtered.Matches.Select(m => (m.Path, m.Name)).Order());
        }
        Assert.True(all.Matches.Select(m => m.Kind).Distinct().Count() >= kinds.Length);
    }

    private static byte[] CosturaHostWithFixture() => ContainerFixtures.Module("CosturaHost",
        ("costura.testfixture.dll.compressed", ContainerFixtures.Deflate(System.IO.File.ReadAllBytes(Env.FixturePath))));

    // ------------------------------------------------------------------ per container type

    [Fact]
    public void Search_SingleFileBundle()
    {
        var program = Assert.Single(Search(fx.Bundle, "Program", "type").Matches);
        Assert.Equal(new UnpackService.ContainerSymbol("Hello.dll", "Hello", "Program", "type"), program);

        var main = Assert.Single(Search(fx.Bundle, "<Main>$").Matches);
        Assert.Equal(("Hello.dll", "method"), (main.Path, main.Kind));
        Assert.StartsWith("Program::<Main>$(", main.Name);

        AssertNothingFound(Search(fx.Bundle, NoSuchSymbol));
        Assert.Empty(Search(fx.Bundle, "Program", "method").Matches); // the type matches, but no method is named that
        Assert.Equal(".NET single-file bundle", Search(fx.Bundle, "Program").Container);
    }

    [Fact]
    public void Search_NuGetPackage()
    {
        var package = ContainerFixtures.NuGetPackage("K4os.Compression.LZ4");
        var codec = Search(package, "LZ4Codec", "type").Matches.Where(m => m.Name == "K4os.Compression.LZ4.LZ4Codec").ToList();
        var assemblies = List(package).Assemblies;
        Assert.Equal(assemblies.Count, codec.Count); // one per target framework
        Assert.All(codec, m => Assert.Matches(@"^lib/[^/]+/K4os\.Compression\.LZ4\.dll$", m.Path));
        Assert.All(codec, m => Assert.Equal("K4os.Compression.LZ4", m.Assembly));

        AssertNothingFound(Search(package, NoSuchSymbol));
        AssertKindFilterNarrows(package, "Decode", "type", "method"); // LZ4Decoder* types, Decode methods
    }

    [Fact]
    public void Search_ApkStyleZip()
    {
        var apk = Save("app.apk", BuildApk().Apk);
        var player = Assert.Single(Search(apk, "Player", "type").Matches, m => m.Name == "Fixture.Game.Player");
        Assert.Equal(("assemblies/TestFixture.dll", "TestFixture"), (player.Path, player.Assembly)); // decoded from XALZ
        Assert.Contains(Search(apk, "Marker", "type").Matches, m => m.Assembly == "StoreRaw" && m.Path.StartsWith("carved_0x"));

        AssertNothingFound(Search(apk, NoSuchSymbol));
        Assert.Equal(["Fixture.Game.Player::MaxHealth", "Fixture.Game.Player::_health"], Search(apk, "health", "field").Matches.Select(m => m.Name).Order(StringComparer.Ordinal));
        Assert.Equal(["Fixture.Game.Player::Health"], Search(apk, "health", "property").Matches.Select(m => m.Name));
        Assert.Empty(Search(apk, "health", "type").Matches);
        AssertKindFilterNarrows(apk, "health", "field", "property");
    }

    [Fact]
    public void Search_NestedContainers()
    {
        var nupkg = System.IO.File.ReadAllBytes(ContainerFixtures.NuGetPackage("K4os.Compression.LZ4"));
        var outer = Save("outer.zip", ContainerFixtures.Zip(("packages/k4os.nupkg", nupkg), ("app/CosturaHost.exe", CosturaHostWithFixture())));

        var player = Assert.Single(Search(outer, "Player", "type").Matches, m => m.Name == "Fixture.Game.Player");
        Assert.Equal("app/CosturaHost.exe_unpacked/testfixture.dll", player.Path);
        Assert.All(Search(outer, "LZ4Codec", "type").Matches, m => Assert.Matches(@"^packages/k4os\.nupkg_unpacked/lib/[^/]+/K4os\.Compression\.LZ4\.dll$", m.Path));

        AssertNothingFound(Search(outer, NoSuchSymbol));
        AssertKindFilterNarrows(outer, "TakeDamage", "method");
        Assert.Empty(Search(outer, "TakeDamage", "property").Matches);
    }

    [Fact]
    public void Search_PlainAssembly_AndFullNameQueries()
    {
        var s = Search(Env.FixturePath, "Player::TakeDamage", "method");
        Assert.Equal("none (plain .NET assembly)", s.Container);
        Assert.Equal(2, s.Matches.Count); // both overloads, matched on the full name
        Assert.All(s.Matches, m => Assert.Equal("TestFixture.dll", m.Path));
        Assert.Contains(Search(Env.FixturePath, "Take*").Matches, m => m.Name.StartsWith("Fixture.Game.Player::TakeDamage("));
    }

    // ------------------------------------------------------------------ limits, safety, errors

    [Fact]
    public void Search_CapsResults_BestMatchesFirst()
    {
        var many = Save("Many.dll", ContainerFixtures.Module("Many", m =>
        {
            for (int i = 0; i < 300; i++)
            {
                var t = new TypeDefUser("Many", $"HitType{i}", m.CorLibTypes.Object.TypeDefOrRef);
                var method = new MethodDefUser("HitMe", MethodSig.CreateInstance(m.CorLibTypes.Void), MethodAttributes.Public);
                method.Body = new dnlib.DotNet.Emit.CilBody { Instructions = { dnlib.DotNet.Emit.OpCodes.Ret.ToInstruction() } };
                t.Methods.Add(method);
                m.Types.Add(t);
            }
            m.Types.Add(new TypeDefUser("Many", "Hit", m.CorLibTypes.Object.TypeDefOrRef));
        }));
        var zip = Save("many.zip", ContainerFixtures.Zip(("lib/Many.dll", System.IO.File.ReadAllBytes(many))));

        var s = Search(zip, "hit", limit: 50);
        Assert.Equal(50, s.Matches.Count);
        Assert.Equal(601, s.Total); // 300 types + 300 methods + the exact one
        Assert.True(s.Truncated);
        Assert.Equal("Many.Hit", s.Matches[0].Name); // case-insensitive exact match ranks first
        Assert.All(s.Matches, m => Assert.Equal("lib/Many.dll", m.Path));

        var all = Search(zip, "hit", limit: 5000);
        Assert.Equal(601, all.Matches.Count);
        Assert.False(all.Truncated);
    }

    [Fact]
    public void Search_WritesNothing()
    {
        using var sandbox = new TempDir();
        var input = Path.Combine(sandbox.Path, $"app-{Guid.NewGuid():N}.apk");
        System.IO.File.WriteAllBytes(input, BuildApk().Apk);
        var tempBefore = Directory.Exists(Path.Combine(Path.GetTempPath(), "netdecomp-unpacked"))
            ? Directory.GetDirectories(Path.Combine(Path.GetTempPath(), "netdecomp-unpacked")).Length : 0;

        Assert.NotEmpty(Search(input, "Player").Matches);

        Assert.Equal([input], Directory.GetFileSystemEntries(sandbox.Path));
        var tempAfter = Directory.Exists(Path.Combine(Path.GetTempPath(), "netdecomp-unpacked"))
            ? Directory.GetDirectories(Path.Combine(Path.GetTempPath(), "netdecomp-unpacked")).Length : 0;
        Assert.Equal(tempBefore, tempAfter);
        Assert.Empty(_workspace.Assemblies);
    }

    [Fact]
    public void Search_BadArguments()
    {
        Assert.Contains("Unknown kind 'event'", Assert.Throws<ToolError>(() => UnpackService.ParseSearchKind("event")).Message);
        Assert.Contains("Query is empty", Assert.Throws<ToolError>(() => Search(fx.Bundle, "")).Message);
        Assert.Contains("File not found", Assert.Throws<ToolError>(() => Search(_dir.File("missing.zip"), "x")).Message);
    }

    // ------------------------------------------------------------------ over MCP

    [Fact]
    public async Task SearchContainerTool_CorruptContainers_ErrorClearly_AndTheServerKeepsServing()
    {
        await using var client = await McpProtocolTests.StartServerAsync("--no-index");

        var nupkg = System.IO.File.ReadAllBytes(ContainerFixtures.NuGetPackage("K4os.Compression.LZ4"));
        var bundle = System.IO.File.ReadAllBytes(fx.Bundle);
        ContainerFixtures.SetBundleHeaderOffset(bundle, bundle.Length - 6);
        var corrupt = new Dictionary<string, (string File, string Error)>
        {
            ["zip"] = (Save("cut.nupkg", nupkg[..(nupkg.Length / 2)]), "corrupt zip"),
            ["bundle"] = (Save("bad.exe", bundle), "Corrupt single-file bundle"),
            ["xalz"] = (Save("bad.dll", [.. "XALZ"u8, 0, 0, 0, 0, 100, 0, 0, 0, 1, 2, 3]), "corrupt XALZ"),
            ["missing"] = (_dir.File("missing.apk"), "File not found"),
        };
        foreach (var (label, (file, error)) in corrupt)
        {
            var r = await client.CallToolAsync("search_container", new Dictionary<string, object?> { ["path"] = file, ["query"] = "Player" });
            Assert.True(r.IsError, label);
            Assert.Contains(error, string.Join("\n", r.Content.OfType<TextContentBlock>().Select(c => c.Text)));
        }

        var bad = await client.CallToolAsync("search_container", new Dictionary<string, object?> { ["path"] = fx.Bundle, ["query"] = "x", ["kind"] = "namespace" });
        Assert.True(bad.IsError);

        // still serving: a real search over stdio, with the structured result
        var ok = await client.CallToolAsync("search_container", new Dictionary<string, object?>
        {
            ["path"] = Save("ok.apk", BuildApk().Apk), ["query"] = "health", ["kind"] = "property",
        });
        Assert.NotEqual(true, ok.IsError);
        await McpProtocolTests.AssertMatchesOutputSchema(client, "search_container", ok);
        var json = JsonDocument.Parse(ok.StructuredContent!.ToString()!).RootElement;
        Assert.False(Prop(json, "truncated").GetBoolean());
        var match = Assert.Single(Prop(json, "matches").EnumerateArray());
        Assert.Equal("assemblies/TestFixture.dll", Prop(match, "path").GetString());
        Assert.Equal("TestFixture", Prop(match, "assembly").GetString());
        Assert.Equal("Fixture.Game.Player::Health", Prop(match, "name").GetString());
        Assert.Equal("property", Prop(match, "kind").GetString());
    }
}
