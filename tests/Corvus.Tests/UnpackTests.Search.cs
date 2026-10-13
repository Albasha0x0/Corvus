using System.Text.Json;
using dnlib.DotNet;
using ModelContextProtocol.Client;
using ModelContextProtocol.Protocol;
using Corvus.Core;
using Corvus.Services.Analysis;

namespace Corvus.Tests;

/// <summary>search_container: name search over every managed assembly in a container, in memory.</summary>
public partial class UnpackTests
{
    private UnpackService.ContainerSearch Search(string path, string query, string? kind = null, int limit = 200) =>
        Unpacker.Search(path, query, UnpackService.ParseSearchKind(kind), limit, AnalysisLimits.Default, default);

    private const string NoSuchSymbol = "zzNoSuchSymbolzz";

    private static void AssertNothingFound(UnpackService.ContainerSearch s)
    {
        Assert.Empty(s.Items);
        Assert.Equal(0, s.Total);
        Assert.False(s.Truncated);
        Assert.True(s.Searched > 0);
    }

    /// <summary>A kind filter keeps exactly the unfiltered matches of that kind.</summary>
    private void AssertKindFilterNarrows(string path, string query, params string[] kinds)
    {
        var all = Search(path, query);
        foreach (var kind in kinds)
        {
            var filtered = Search(path, query, kind);
            Assert.NotEmpty(filtered.Items);
            Assert.All(filtered.Items, m => Assert.Equal(kind, m.Kind));
            Assert.Equal(all.Items.Where(m => m.Kind == kind).Select(m => (m.Path, m.Name)).Order(), filtered.Items.Select(m => (m.Path, m.Name)).Order());
        }
        Assert.True(all.Items.Select(m => m.Kind).Distinct().Count() >= kinds.Length);
    }

    private static byte[] CosturaHostWithFixture() => ContainerFixtures.Module("CosturaHost",
        ("costura.testfixture.dll.compressed", ContainerFixtures.Deflate(System.IO.File.ReadAllBytes(Env.FixturePath))));

    [Fact]
    public void Search_SingleFileBundle()
    {
        var program = Assert.Single(Search(fx.Bundle, "Program", "type").Items);
        Assert.Equal(new ContainerMatch("Hello.dll", "Program", "type") { Assembly = "Hello" }, program);

        var main = Assert.Single(Search(fx.Bundle, "<Main>$").Items);
        Assert.Equal(("Hello.dll", "method"), (main.Path, main.Kind));
        Assert.StartsWith("Program::<Main>$(", main.Name);

        AssertNothingFound(Search(fx.Bundle, NoSuchSymbol));
        Assert.Empty(Search(fx.Bundle, "Program", "method").Items); // only the type has that name
        Assert.Equal(".NET single-file bundle", Search(fx.Bundle, "Program").Container);
    }

    [Fact]
    public void Search_NuGetPackage()
    {
        var package = ContainerFixtures.NuGetPackage("K4os.Compression.LZ4");
        var codec = Search(package, "LZ4Codec", "type").Items.Where(m => m.Name == "K4os.Compression.LZ4.LZ4Codec").ToList();
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
        var account = Assert.Single(Search(apk, "Account", "type").Items, m => m.Name == "Fixture.Model.Account");
        Assert.Equal(("assemblies/TestFixture.dll", "TestFixture"), (account.Path, account.Assembly)); // decoded from XALZ
        Assert.Contains(Search(apk, "Marker", "type").Items, m => m.Assembly == "StoreRaw" && m.Path.StartsWith("carved_0x"));

        AssertNothingFound(Search(apk, NoSuchSymbol));
        Assert.Equal(["Fixture.Model.Account::MaxBalance", "Fixture.Model.Account::_balance"], Search(apk, "balance", "field").Items.Select(m => m.Name).Order(StringComparer.Ordinal));
        Assert.Equal(["Fixture.Model.Account::Balance"], Search(apk, "balance", "property").Items.Select(m => m.Name));
        Assert.Empty(Search(apk, "balance", "type").Items);
        AssertKindFilterNarrows(apk, "balance", "field", "property");
    }

    [Fact]
    public void Search_NestedContainers()
    {
        var nupkg = System.IO.File.ReadAllBytes(ContainerFixtures.NuGetPackage("K4os.Compression.LZ4"));
        var outer = Save("outer.zip", ContainerFixtures.Zip(("packages/k4os.nupkg", nupkg), ("app/CosturaHost.exe", CosturaHostWithFixture())));

        var account = Assert.Single(Search(outer, "Account", "type").Items, m => m.Name == "Fixture.Model.Account");
        Assert.Equal("app/CosturaHost.exe_unpacked/testfixture.dll", account.Path);
        Assert.All(Search(outer, "LZ4Codec", "type").Items, m => Assert.Matches(@"^packages/k4os\.nupkg_unpacked/lib/[^/]+/K4os\.Compression\.LZ4\.dll$", m.Path));

        AssertNothingFound(Search(outer, NoSuchSymbol));
        AssertKindFilterNarrows(outer, "Charge", "method");
        Assert.Empty(Search(outer, "Charge", "property").Items);
    }

    [Fact]
    public void Search_PlainAssembly_AndFullNameQueries()
    {
        var s = Search(Env.FixturePath, "Account::Charge", "method");
        Assert.Equal("none (plain .NET assembly)", s.Container);
        Assert.Equal(2, s.Items.Count); // both overloads, matched on the full name
        Assert.All(s.Items, m => Assert.Equal("TestFixture.dll", m.Path));
        Assert.Contains(Search(Env.FixturePath, "Charg*").Items, m => m.Name.StartsWith("Fixture.Model.Account::Charge("));
    }

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
        Assert.Equal(50, s.Items.Count);
        Assert.Equal(601, s.Total); // 300 types + 300 methods + the exact one
        Assert.True(s.Truncated);
        Assert.Equal("Many.Hit", s.Items[0].Name); // case-insensitive exact match ranks first
        Assert.All(s.Items, m => Assert.Equal("lib/Many.dll", m.Path));

        var all = Search(zip, "hit", limit: 5000);
        Assert.Equal(601, all.Items.Count);
        Assert.False(all.Truncated);

        // offset pages the same ranked order (G1: the continuation is a row offset in the record).
        var next = Unpacker.Search(zip, "hit", SymbolKind.Any, 50, AnalysisLimits.Default, default, offset: 50);
        Assert.Equal(50, next.Offset);
        Assert.Equal(all.Items.Skip(50).Take(50), next.Items);
        var last = Unpacker.Search(zip, "hit", SymbolKind.Any, 50, AnalysisLimits.Default, default, offset: 600);
        Assert.Single(last.Items);
        Assert.False(last.Truncated);
    }

    [Fact]
    public void Search_WritesNothing()
    {
        using var sandbox = new TempDir();
        var input = Path.Combine(sandbox.Path, $"app-{Guid.NewGuid():N}.apk");
        System.IO.File.WriteAllBytes(input, BuildApk().Apk);

        Assert.NotEmpty(Search(input, "Account").Items);

        Assert.Equal([input], Directory.GetFileSystemEntries(sandbox.Path));
        // default unpack folders are named after their input, which no other run shares
        var unpacked = Path.GetDirectoryName(UnpackService.DefaultOutput(input, new string('0', 64)))!;
        Assert.Empty(Directory.Exists(unpacked) ? Directory.GetDirectories(unpacked, Path.GetFileNameWithoutExtension(input) + "*") : []);
        Assert.Empty(_workspace.Assemblies);
    }

    [Fact]
    public void Search_BadArguments()
    {
        Assert.Contains("Unknown kind 'event'", Assert.Throws<ToolError>(() => UnpackService.ParseSearchKind("event")).Message);
        Assert.Contains("Query is empty", Assert.Throws<ToolError>(() => Search(fx.Bundle, "")).Message);
        Assert.Contains("File not found", Assert.Throws<ToolError>(() => Search(_dir.File("missing.zip"), "x")).Message);
    }

    [Trait("Speed", "Slow")]
    [Fact]
    public async Task SearchContainerTool_CorruptContainers_ErrorClearly_AndTheServerKeepsServing()
    {
        await using var client = await McpProtocolTests.StartServerAsync("--no-index");

        var nupkg = System.IO.File.ReadAllBytes(ContainerFixtures.NuGetPackage("K4os.Compression.LZ4"));
        var bundle = System.IO.File.ReadAllBytes(fx.Bundle);
        ContainerFixtures.SetBundleHeaderOffset(bundle, bundle.Length - 6);
        var corrupt = new Dictionary<string, (string File, string Error)>
        {
            ["zip"] = (Save("cut.nupkg", nupkg[..20]), "corrupt zip"),
            ["bundle"] = (Save("bad.exe", bundle), "Corrupt single-file bundle"),
            ["xalz"] = (Save("bad.dll", [.. "XALZ"u8, 0, 0, 0, 0, 100, 0, 0, 0, 1, 2, 3]), "corrupt XALZ"),
            ["missing"] = (_dir.File("missing.apk"), "File not found"),
        };
        foreach (var (label, (file, error)) in corrupt)
        {
            var r = await client.CallToolAsync("search_container", new Dictionary<string, object?> { ["path"] = file, ["query"] = "Account" });
            Assert.True(r.IsError, label);
            Assert.Contains(error, string.Join("\n", r.Content.OfType<TextContentBlock>().Select(c => c.Text)));
        }

        var bad = await client.CallToolAsync("search_container", new Dictionary<string, object?> { ["path"] = fx.Bundle, ["query"] = "x", ["kind"] = "namespace" });
        Assert.True(bad.IsError);

        // The server still serves a valid structured result.
        var ok = await client.CallToolAsync("search_container", new Dictionary<string, object?>
        {
            ["path"] = Save("ok.apk", BuildApk().Apk), ["query"] = "balance", ["kind"] = "property",
        });
        Assert.NotEqual(true, ok.IsError);
        await McpProtocolTests.AssertMatchesOutputSchema(client, "search_container", ok);
        var json = JsonDocument.Parse(ok.StructuredContent!.ToString()!).RootElement;
        Assert.False(Prop(json, "hasMore").GetBoolean());
        var match = Assert.Single(Prop(json, "matches").EnumerateArray());
        // A page carries its continuation in the record (S4.1), as a row offset.
        var page = await client.CallToolAsync("search_container", new Dictionary<string, object?>
        {
            ["path"] = _dir.File("ok.apk"), ["query"] = "a", ["limit"] = 1,
        });
        var paged = JsonDocument.Parse(page.StructuredContent!.ToString()!).RootElement;
        Assert.Equal(1, Prop(paged, "nextOffset").GetInt32());
        Assert.Contains("[More: offset=1]", page.Content.OfType<TextContentBlock>().First().Text);
        Assert.Equal("assemblies/TestFixture.dll", Prop(match, "path").GetString());
        Assert.Equal("TestFixture", Prop(match, "assembly").GetString());
        Assert.Equal("Fixture.Model.Account::Balance", Prop(match, "name").GetString());
        Assert.Equal("property", Prop(match, "kind").GetString());
    }
}
