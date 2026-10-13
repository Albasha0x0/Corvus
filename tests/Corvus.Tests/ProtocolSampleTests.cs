using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using ModelContextProtocol.Protocol;

namespace Corvus.Tests;

/// <summary>
/// S12.2 recorded samples: ProtocolSamples/&lt;tool&gt;.json holds a call on the fixture and its normalized response; a change
/// of shape shows as a diff. CORVUS_UPDATE_DOCS=1 records every sample again (and the <see cref="Seed"/> calls).
/// </summary>
[Collection(InProcessCatalogCollection.Name)]
public partial class ProtocolSampleTests
{
    private static string Folder => Path.Combine(DocsTests.RepoRoot(), "tests", "Corvus.Tests", "ProtocolSamples");

    public static string SampleFile(string tool) => Path.Combine(Folder, tool + ".json");

    /// <summary>The calls recorded when no sample exists yet.</summary>
    private static readonly Dictionary<string, Dictionary<string, object?>> Seed = new(StringComparer.Ordinal)
    {
        ["list_assemblies"] = [],
        ["list_namespaces"] = new() { ["assembly"] = "TestFixture" },
        ["list_types"] = new() { ["assembly"] = "TestFixture", ["limit"] = 3 },
        ["get_type_info"] = new() { ["type"] = "Account" },
        ["search_symbols"] = new() { ["query"] = "Charge", ["limit"] = 5 },
        ["decompile_member"] = new() { ["member"] = "Account::CheckLicense" },
        ["get_il"] = new() { ["symbol"] = "Account::CheckLicense" },
        ["find_references"] = new() { ["symbol"] = "Account::Charge(int)" },
        ["get_assembly_info"] = new() { ["assembly"] = "TestFixture" },
        ["get_attributes"] = new() { ["symbol"] = "NativeThing::First" },
        ["get_type_hierarchy"] = new() { ["type"] = "Entity" },
        ["resolve_symbol"] = new() { ["symbol"] = "Account::Charge" },
        ["search_strings"] = new() { ["query"] = "LICENSE" },
        ["search_constants"] = new() { ["value"] = "0x3E8" },
        ["search_il"] = new() { ["pattern"] = "ldstr *LICENSE*; call *Validate*", ["context"] = 3 },
        ["find_callees"] = new() { ["method"] = "Account::Charge(int, string)", ["distinct"] = true },
        ["get_call_tree"] = new() { ["method"] = "Account::Charge(int)", ["depth"] = 2 },
        ["find_call_paths"] = new() { ["to"] = "Account::Charge(int)", ["limit"] = 3 },
        ["list_resources"] = new() { ["assembly"] = "TestFixture" },
        ["get_resource"] = new() { ["assembly"] = "TestFixture", ["name"] = "Fixture.hello.txt" },
        ["export_project"] = new() { ["assembly"] = "TestFixture", ["outputDirectory"] = "sample-export" },
        ["get_r2r_code"] = new() { ["method"] = "Account::Charge(int)" },
        ["find_r2r_method"] = new() { ["assembly"] = "TestFixture", ["address"] = "rva:0x2050" },
    };

    [Fact]
    public async Task SamplesMatch()
    {
        bool update = Environment.GetEnvironmentVariable("CORVUS_UPDATE_DOCS") == "1";
        var calls = Directory.Exists(Folder)
            ? Directory.GetFiles(Folder, "*.json").ToDictionary(f => Path.GetFileNameWithoutExtension(f),
                f => JsonNode.Parse(File.ReadAllText(f))!["arguments"]!.AsObject().ToDictionary(p => p.Key, p => (object?)JsonSerializer.Deserialize<JsonElement>(p.Value!.ToJsonString())))
            : [];
        if (update)
            foreach (var (tool, args) in Seed) calls.TryAdd(tool, args);

        await using var server = await InProcessServer.StartAsync();
        var stale = new List<string>();
        foreach (var (tool, args) in calls.OrderBy(c => c.Key, StringComparer.Ordinal))
        {
            // An export starts from no directory, so every run records the same outcome.
            if (args.GetValueOrDefault("outputDirectory") is { } output && Directory.Exists(output.ToString())) Directory.Delete(output.ToString()!, recursive: true);
            var result = await server.Client.CallToolAsync(tool, args);
            var sample = new JsonObject
            {
                ["tool"] = tool,
                ["arguments"] = JsonSerializer.SerializeToNode(args),
                ["isError"] = result.IsError == true,
                ["content"] = new JsonArray([.. result.Content.OfType<TextContentBlock>().Select(b => (JsonNode)Normalize(b.Text))]),
                ["structuredContent"] = result.StructuredContent is { } s ? JsonNode.Parse(Normalize(s.GetRawText())) : null,
            };
            var text = sample.ToJsonString(new JsonSerializerOptions { WriteIndented = true, Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping, NewLine = "\n" }) + "\n";
            var file = SampleFile(tool);
            if (update)
            {
                Directory.CreateDirectory(Folder);
                File.WriteAllText(file, text);
            }
            else if (File.ReadAllText(file).ReplaceLineEndings("\n") != text) stale.Add(tool);
        }
        Assert.True(stale.Count == 0, "protocol samples changed (check the diff, then CORVUS_UPDATE_DOCS=1 records them): " + string.Join(", ", stale));
    }

    [GeneratedRegex("[0-9a-fA-F]{64}|[0-9a-fA-F]{40}|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}|r-[0-9a-f]{12}")]
    private static partial Regex Volatile();

    /// <summary>Machine paths, hashes, GUIDs and result ids become labels.</summary>
    private static string Normalize(string text)
    {
        foreach (var (path, label) in new[] { (Path.GetDirectoryName(Env.FixturePath)!, "<fixtures>"), (DocsTests.RepoRoot(), "<repo>") })
            foreach (var form in new[] { path, path.Replace('\\', '/'), JsonEncodedText.Encode(path).ToString() })
                text = text.Replace(form, label, StringComparison.OrdinalIgnoreCase);
        text = text.Replace(@"<fixtures>\\", "<fixtures>/").Replace(@"<fixtures>\", "<fixtures>/");
        return Volatile().Replace(text, "<id>").ReplaceLineEndings("\n");
    }
}
