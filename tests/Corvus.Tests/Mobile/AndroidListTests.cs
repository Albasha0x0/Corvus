using System.Text.Json;
using ModelContextProtocol.Client;
using ModelContextProtocol.Protocol;
using static Corvus.Tests.AndroidSamples;

namespace Corvus.Tests;

/// <summary>The Android list tools over MCP: readable rows with their noun, the list envelope, and cut resource values.</summary>
[Collection(InProcessCatalogCollection.Name)]
public sealed class AndroidListTests : IDisposable
{
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    private static string Text(CallToolResult r) => string.Concat(r.Content.OfType<TextContentBlock>().Select(b => b.Text));

    [Trait("Speed", "Slow")]
    [Fact]
    public async Task Pages_AreRowsWithTheListEnvelope()
    {
        var apk = Save(_dir, "app.apk", Apk(30, ("classes.dex", Dex())));
        await using var server = await InProcessServer.StartAsync();
        var classes = await server.Client.CallToolAsync("list_dex_classes", new Dictionary<string, object?> { ["path"] = apk, ["limit"] = 2 });
        var text = Text(classes);
        Assert.Contains("4 classes (showing 1-2):", text);
        Assert.Contains("[More: offset=2]", text);
        Assert.DoesNotContain("{", text);
        var record = classes.StructuredContent!.Value;
        Assert.Equal((2, 2, true, 4), (record.GetProperty("items").GetArrayLength(), record.GetProperty("nextOffset").GetInt32(), record.GetProperty("hasMore").GetBoolean(),
            record.GetProperty("total").GetInt32()));
        Assert.Equal("com.example.app", record.GetProperty("packages")[0].GetProperty("package").GetString());

        var refs = await server.Client.CallToolAsync("find_dex_references", new Dictionary<string, object?> { ["path"] = apk, ["target"] = Log });
        Assert.Contains($"To method {Log}", Text(refs));
        Assert.Contains("2 references (showing 1-2):", Text(refs));
        var hits = await server.Client.CallToolAsync("search_dex", new Dictionary<string, object?> { ["path"] = apk, ["kind"] = "string", ["query"] = "api.example" });
        Assert.Contains("string https://api.example.com/v1  in", Text(hits));

        // a class's members page; the header stays
        var methods = await server.Client.CallToolAsync("get_dex_class", new Dictionary<string, object?> { ["path"] = apk, ["class"] = Main, ["members"] = "methods", ["limit"] = 3 });
        Assert.Contains("2 fields, 8 methods\n8 members (showing 1-3):", Text(methods));
        Assert.Equal(3, methods.StructuredContent!.Value.GetProperty("nextOffset").GetInt32());
        var compute = await server.Client.CallToolAsync("get_dex_class", new Dictionary<string, object?> { ["path"] = apk, ["class"] = Main, ["query"] = "compute" });
        Assert.Equal([ComputeInt, ComputeString], compute.StructuredContent!.Value.GetProperty("items").EnumerateArray().Select(i => i.GetProperty("id").GetString()));

        // a resource written to outputPath names it, its size and hash
        var written = await server.Client.CallToolAsync("get_android_resource", new Dictionary<string, object?> { ["path"] = apk, ["name"] = "@layout/main", ["outputPath"] = _dir.File("main.xml") });
        var file = written.StructuredContent!.Value;
        Assert.Equal(("res/layout/main.xml", _dir.File("main.xml"), 64), (file.GetProperty("entry").GetString(), file.GetProperty("outputPath").GetString(), file.GetProperty("sha256").GetString()!.Length));
    }

    [Fact]
    public void ResourceValues_AreCutInTheList()
    {
        var res = new ArscWriter(0x7f, "com.example.app");
        res.String("string", "short", "Example");
        res.String("string", "long", new string('x', 500));
        var apk = Save(_dir, "long.apk", ContainerFixtures.Zip([("AndroidManifest.xml", Manifest()), ("resources.arsc", res.Build())]));
        var rows = new Corvus.Services.Mobile.AndroidPackageService().Resources(apk, null, null, null, 0, 10).Items;
        var cut = rows.Single(r => r.Name == "long");
        Assert.Equal((Corvus.Services.Mobile.AndroidPackageService.MaxValueChars, true), (cut.Value.Length, cut.ValueTruncated));
        Assert.Null(rows.Single(r => r.Name == "short").ValueTruncated);
        Assert.Matches("^0x7f[0-9a-f]{6}$", cut.Id);
    }
}
