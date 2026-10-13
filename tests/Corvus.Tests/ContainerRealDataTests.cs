using System.Text.Json;
using ModelContextProtocol.Client;
using ModelContextProtocol.Protocol;
using Corvus.Core;
using Corvus.Mcp;

namespace Corvus.Tests;

/// <summary>
/// The containers tools on real packages over stdio (F-CT acceptance): default pages within their class budget per part,
/// row walks that reach every row once, readable text beside the record.
/// </summary>
[Trait("Speed", "Slow")]
[Trait("Data", "Real")]
public sealed class ContainerRealDataTests(Xunit.Abstractions.ITestOutputHelper output) : IAsyncLifetime
{
    private readonly TempDir _dir = new();
    private McpClient _client = null!;

    private static string Package => RealPackages.File("Newtonsoft.Json", "13.0.4", "newtonsoft.json.13.0.4.nupkg");
    private static string NLog => RealPackages.Lib("NLog", "6.1.4", "netstandard2.0", "NLog.dll");
    private static string BouncyCastle => RealPackages.Lib("BouncyCastle.Cryptography", "2.6.2", "net6.0", "BouncyCastle.Cryptography.dll");

    public async Task InitializeAsync() => _client = await McpProtocolTests.StartServerAsync(null, null, ["--no-watch"]);

    public async Task DisposeAsync()
    {
        await _client.DisposeAsync();
        _dir.Dispose();
    }

    private async Task<(string Text, JsonElement Record)> Call(string tool, Dictionary<string, object?> args)
    {
        var r = await _client.CallToolAsync(tool, args);
        var text = string.Concat(r.Content.OfType<TextContentBlock>().Select(b => b.Text));
        Assert.True(r.IsError != true, $"{tool}: {text[..Math.Min(500, text.Length)]}");
        var raw = r.StructuredContent!.Value.GetRawText();
        int limit = OutputClasses.Budget(ToolContract.Of(tool).Output) * 105 / 100;
        output.WriteLine($"{tool}({string.Join(", ", args.Select(a => $"{a.Key}={a.Value}"))}): text {TokenEstimate.Of(text)}, record {TokenEstimate.Of(raw)} (limit {limit})");
        Assert.True(TokenEstimate.Of(text) <= limit, $"{tool}: text over {limit}");
        Assert.True(TokenEstimate.Of(raw) <= limit, $"{tool}: record over {limit}");
        Assert.DoesNotContain("{\"", text); // readable rows, not the record's JSON
        return (text, JsonDocument.Parse(raw).RootElement.Clone());
    }

    /// <summary>Every row of a list tool through nextOffset, each once.</summary>
    private async Task<List<string>> Walk(string tool, Dictionary<string, object?> args, Func<JsonElement, string> key)
    {
        var rows = new List<string>();
        int? total = null;
        for (int offset = 0, pages = 0; ; pages++)
        {
            Assert.True(pages < 50, "too many pages");
            var (_, record) = await Call(tool, new Dictionary<string, object?>(args) { ["offset"] = offset });
            total ??= record.GetProperty("total").GetInt32();
            Assert.Equal(total, record.GetProperty("total").GetInt32());
            rows.AddRange(record.GetProperty("items").EnumerateArray().Select(key));
            if (!record.TryGetProperty("nextOffset", out var next)) break;
            offset = next.GetInt32();
        }
        Assert.Equal(total, rows.Count);
        return rows;
    }

    [Fact]
    public async Task SummarizeFileOverviewAndViews()
    {
        var (text, record) = await Call("summarize_file", new() { ["path"] = Package });
        Assert.Equal("NuGet package", record.GetProperty("container").GetString());
        Assert.Contains("managed", record.GetProperty("views").EnumerateArray().Select(v => v.GetString()));
        Assert.Contains("Newtonsoft.Json 13.0.0.0 library", text);
        var (_, managed) = await Call("summarize_file", new() { ["path"] = Package, ["view"] = "managed" });
        Assert.Equal("Newtonsoft.Json", managed.GetProperty("detail").GetProperty("assemblies")[0].GetProperty("identity").GetProperty("name").GetString()); // one build of each assembly
    }

    [Fact]
    public async Task SurveyFeaturesCountsByDefaultAndListsEvidenceByCategory()
    {
        var (text, record) = await Call("survey_features", new() { ["path"] = BouncyCastle });
        Assert.Contains(record.GetProperty("features").EnumerateArray(), f => f.GetProperty("category").GetString() == "crypto");
        Assert.All(record.GetProperty("features").EnumerateArray(), f => Assert.False(f.TryGetProperty("evidence", out _)));
        var (_, crypto) = await Call("survey_features", new() { ["path"] = BouncyCastle, ["category"] = "crypto" });
        Assert.All(crypto.GetProperty("features").EnumerateArray(), f => Assert.True(f.GetProperty("evidence").GetArrayLength() > 0));
    }

    [Fact]
    public async Task ExtractStringsPagesEveryValueOnce()
    {
        var values = await Walk("extract_strings", new() { ["path"] = NLog, ["limit"] = 40 }, v => $"{v.GetProperty("type")} {v.GetProperty("value")}");
        Assert.Equal(values.Count, values.Distinct().Count());
        var (_, first) = await Call("extract_strings", new() { ["path"] = NLog });
        var kept = first.GetProperty("valuesResultId").GetString()!;
        var file = _dir.File("values.csv");
        var written = await _client.CallToolAsync("read_result", new Dictionary<string, object?> { ["id"] = kept, ["outputPath"] = file });
        Assert.True(written.IsError != true);
        Assert.Equal(values.Count + 1, File.ReadAllLines(file).Length);
    }

    [Fact]
    public async Task ExtractEmbeddedReadsAPackage()
    {
        var (_, record) = await Call("extract_embedded", new() { ["path"] = Package });
        Assert.Equal("newtonsoft.json.13.0.4.nupkg", record.GetProperty("assembly").GetString());
        Assert.All(record.GetProperty("items").EnumerateArray(), i => Assert.StartsWith("lib/", i.GetProperty("source").GetString()));
    }

    [Fact]
    public async Task SearchContainerAndUnpackContainerPageTheirRows()
    {
        var (_, found) = await Call("search_container", new() { ["path"] = Package, ["query"] = "JsonConvert", ["kind"] = "type" });
        Assert.Equal("type", found.GetProperty("items")[0].GetProperty("kind").GetString());
        var (_, files) = await Call("search_container", new() { ["path"] = Package, ["query"] = "*.nuspec", ["kind"] = "file" });
        Assert.Equal("Newtonsoft.Json.nuspec", files.GetProperty("items")[0].GetProperty("path").GetString());

        var outputDir = _dir.File("unpacked");
        var rows = await Walk("unpack_container", new() { ["path"] = Package, ["outputDirectory"] = outputDir, ["load"] = false, ["limit"] = 4 },
            f => f.GetProperty("path").GetString()!);
        Assert.Equal(rows.Count, rows.Distinct().Count());
        Assert.All(rows, r => Assert.True(File.Exists(Path.Combine(outputDir, r)), r));
    }
}
