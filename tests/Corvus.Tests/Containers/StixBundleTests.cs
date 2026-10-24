using System.IO.Compression;
using System.Text.Json;
using Json.Schema;
using Corvus.Core;
using Corvus.Services;
using Corvus.Services.Analysis;

namespace Corvus.Tests;

/// <summary>The STIX 2.1 bundle summarize_file stixPath writes, checked against the OASIS STIX 2.1 JSON schemas.</summary>
public sealed class StixBundleTests : IDisposable
{
    private readonly TempDir _dir = new();
    private readonly AssemblyWorkspace _workspace = new(new ServerOptions());

    public void Dispose()
    {
        _workspace.Dispose();
        _dir.Dispose();
    }

    private static readonly Lazy<JsonSchema> BundleSchema = new(() =>
    {
        var root = Path.Combine(AppContext.BaseDirectory, "Containers", "StixSchemas");
        var options = new BuildOptions { SchemaRegistry = new SchemaRegistry() };
        JsonSchema? bundle = null;
        // Every schema is registered before the bundle's references are resolved; the bundle goes last.
        foreach (var file in Directory.EnumerateFiles(root, "*.json", SearchOption.AllDirectories).OrderBy(f => f.EndsWith("bundle.json", StringComparison.Ordinal)))
        {
            var schema = JsonSchema.FromFile(file, options);
            options.SchemaRegistry.Register(schema);
            if (file.EndsWith("bundle.json", StringComparison.Ordinal)) bundle = schema;
        }
        return bundle!;
    });

    /// <summary>Fails with the schema errors unless <paramref name="bytes"/> is a valid STIX 2.1 bundle.</summary>
    private static void AssertValid(byte[] bytes)
    {
        using var doc = JsonDocument.Parse(bytes);
        var result = BundleSchema.Value.Evaluate(doc.RootElement, new EvaluationOptions { OutputFormat = OutputFormat.List });
        Assert.True(result.IsValid, string.Join("\n", (result.Details ?? []).Where(d => d.Errors is { Count: > 0 })
            .SelectMany(d => d.Errors!.Select(e => $"{d.InstanceLocation} {d.EvaluationPath}: {e.Value}")).Take(20)));
    }

    /// <summary>A zip holding one assembly whose literals name a URL and an IP address.</summary>
    private string Fixture()
    {
        var app = InspectionTests.Compile("UpdateCheck", """
            public static class UpdateCheck
            {
                public static string Endpoint() => "https://updates.example.com/check";
                public static string Mirror() => "192.0.2.10";
            }
            """);
        var path = _dir.File("app.zip");
        using (var zip = ZipFile.Open(path, ZipArchiveMode.Create))
        using (var entry = zip.CreateEntry("bin/UpdateCheck.dll").Open())
            entry.Write(app);
        return path;
    }

    private byte[] Bundle(string path) =>
        StixBundle.Write(new InspectionService(_workspace).Summarize(null, path, default, new FileViewOptions { Stix = true }), "1.0.0", DateTimeOffset.UnixEpoch,
            Guid.NewGuid(), Guid.NewGuid());

    private static List<JsonElement> Objects(byte[] bytes) =>
        [.. JsonDocument.Parse(bytes).RootElement.GetProperty("objects").EnumerateArray()];

    [Fact]
    public void The_bundle_validates_against_the_STIX_2_1_schemas_and_names_where_each_object_was_found()
    {
        var bytes = Bundle(Fixture());
        AssertValid(bytes);
        var objects = Objects(bytes);
        var sample = objects.Single(o => o.GetProperty("type").GetString() == "file" && o.GetProperty("name").GetString() == "app.zip");
        var member = objects.Single(o => o.GetProperty("type").GetString() == "file" && o.GetProperty("name").GetString() == "UpdateCheck.dll");
        Assert.Equal("bin/UpdateCheck.dll", member.GetProperty("x_corvus_locations")[0].GetString());
        var url = objects.Single(o => o.GetProperty("type").GetString() == "url");
        Assert.Equal("https://updates.example.com/check", url.GetProperty("value").GetString());
        Assert.StartsWith("bin/UpdateCheck.dll: ", url.GetProperty("x_corvus_locations")[0].GetString());
        Assert.Equal("192.0.2.10", objects.Single(o => o.GetProperty("type").GetString() == "ipv4-addr").GetProperty("value").GetString());
        var analysis = objects.Single(o => o.GetProperty("type").GetString() == "malware-analysis");
        Assert.Equal(sample.GetProperty("id").GetString(), analysis.GetProperty("sample_ref").GetString());
        Assert.Equal(objects.Single(o => o.GetProperty("type").GetString() == "identity").GetProperty("id").GetString(), analysis.GetProperty("created_by_ref").GetString());
        Assert.Equal(sample.GetProperty("contains_refs").EnumerateArray().Select(r => r.GetString()).Order(), analysis.GetProperty("analysis_sco_refs").EnumerateArray().Select(r => r.GetString()).Order());
    }

    [Fact]
    public void Network_values_past_the_cap_are_cut_and_the_bundle_says_partial()
    {
        // One more URL literal than the cap, in one assembly.
        var urls = string.Join(", ", Enumerable.Range(0, InspectionService.MaxNetworkValues + 1).Select(i => $"\"https://h{i}.example.com/p\""));
        var path = _dir.File("Many.dll");
        File.WriteAllBytes(path, InspectionTests.Compile("Many", $"public static class Many {{ public static string[] All = {{ {urls} }}; }}"));
        var objects = Objects(Bundle(path));
        Assert.Equal(InspectionService.MaxNetworkValues, objects.Count(o => o.GetProperty("type").GetString() is "url" or "domain-name"));
        Assert.Contains($"past the first {InspectionService.MaxNetworkValues:N0} are not listed",
            objects.Single(o => o.GetProperty("type").GetString() == "malware-analysis").GetProperty("description").GetString());
        // Without stixPath the summary keeps its first ten values.
        Assert.Equal(10, new InspectionService(_workspace).Summarize(null, path, default).Assemblies[0].Values.Top.Count);
    }

    [Fact]
    public void Observable_and_identity_ids_are_the_same_in_two_runs()
    {
        var path = Fixture();
        string[] Ids(byte[] b) => [.. Objects(b).Where(o => o.GetProperty("type").GetString() != "malware-analysis").Select(o => o.GetProperty("id").GetString()!)];
        Assert.Equal(Ids(Bundle(path)), Ids(Bundle(path)));
    }

    [Fact]
    public void Observable_ids_match_the_OASIS_python_stix2_library()
    {
        // Expected ids computed with python-stix2 3.0.2 (stix2.File, stix2.URL, stix2.DomainName, stix2.IPv4Address).
        const string md5 = "d41d8cd98f00b204e9800998ecf8427e", sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        Assert.Equal("file--1b179a36-311b-5a56-be06-c71f3db5cf16", StixBundle.ObservableId("file", new() { ["hashes"] = new Dictionary<string, string> { ["MD5"] = md5 }, ["name"] = "a.dll" }));
        Assert.Equal("file--22f8ff52-8f62-5f03-a53a-6f50f54fd74c", StixBundle.ObservableId("file", new() { ["hashes"] = new Dictionary<string, string> { ["SHA-256"] = sha256 } }));
        Assert.Equal("url--5cfdfcec-13e5-535f-bc5c-b601d5839acb", StixBundle.ObservableId("url", new() { ["value"] = "http://example.com/x" }));
        Assert.Equal("url--2995f30e-e9ab-5a61-9488-2407bf92f784", StixBundle.ObservableId("url", new() { ["value"] = "http://ex.com/\u00fc\"" }));
        Assert.Equal("domain-name--bedb4899-d24b-5401-bc86-8f6b4cc18ec7", StixBundle.ObservableId("domain-name", new() { ["value"] = "example.com" }));
        Assert.Equal("ipv4-addr--8dded90c-40c0-545a-8027-5b212bb37e8e", StixBundle.ObservableId("ipv4-addr", new() { ["value"] = "192.0.2.1" }));
    }

    [Fact]
    public async Task The_stix_path_refuses_an_existing_file_unless_overwrite_is_set()
    {
        var path = Fixture();
        var tools = new Corvus.Tools.InspectionTools(new InspectionService(_workspace), _workspace);
        var stix = _dir.File("app.stix.json");
        Assert.Contains($"STIX 2.1 bundle written to {stix}", await tools.SummarizeFile(path: path, stixPath: stix));
        AssertValid(File.ReadAllBytes(stix));
        var refused = await Assert.ThrowsAsync<ToolError>(() => tools.SummarizeFile(path: path, stixPath: stix));
        Assert.Equal(ErrorCode.Conflict, refused.Code);
        Assert.Contains("STIX 2.1 bundle written to", await tools.SummarizeFile(path: path, stixPath: stix, overwrite: true));
    }
}
