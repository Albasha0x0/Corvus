using System.Text.Json;
using Corvus.Mcp;

namespace Corvus.Tests;

/// <summary>docs/schemas/&lt;tool&gt;.json: each structured tool's described output schema (tools/list sends the compact form).</summary>
public class SchemaDocsTests
{
    private static readonly JsonSerializerOptions Indented = new() { WriteIndented = true, Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping, NewLine = "\n" };

    [Fact]
    public void SchemaFilesMatchTheCatalog()
    {
        var dir = Path.Combine(DocsTests.RepoRoot(), "docs", "schemas");
        var expected = Catalog.DescribedOutputSchemas().ToDictionary(s => s.Key + ".json", s => JsonSerializer.Serialize(s.Value, Indented).ReplaceLineEndings("\n") + "\n");
        expected["envelope.json"] = JsonSerializer.Serialize(Envelope(), Indented) + "\n";
        if (Environment.GetEnvironmentVariable("CORVUS_UPDATE_DOCS") == "1")
        {
            Directory.CreateDirectory(dir);
            foreach (var stale in Directory.GetFiles(dir, "*.json").Where(f => !expected.ContainsKey(Path.GetFileName(f)))) File.Delete(stale);
            foreach (var (name, text) in expected) File.WriteAllText(Path.Combine(dir, name), text);
        }
        var present = Directory.Exists(dir) ? Directory.GetFiles(dir, "*.json").Select(Path.GetFileName).ToHashSet()! : [];
        var problems = expected.Where(e => !present.Contains(e.Key) || File.ReadAllText(Path.Combine(dir, e.Key)).ReplaceLineEndings("\n") != e.Value).Select(e => e.Key)
            .Concat(present.Where(p => !expected.ContainsKey(p!)).Select(p => p + " (no such structured tool)")).ToList();
        Assert.True(problems.Count == 0, "docs/schemas is out of date (run the tests once with CORVUS_UPDATE_DOCS=1): " + string.Join(", ", problems));
    }

    /// <summary>The optional fields any record may carry: declared here once, left out of each compact schema in tools/list.</summary>
    private static System.Text.Json.Nodes.JsonObject Envelope()
    {
        var root = new System.Text.Json.Nodes.JsonObject { ["type"] = "object", ["properties"] = new System.Text.Json.Nodes.JsonObject() };
        ToolOutput.Envelope(root, OutputClass.Report);
        var properties = root["properties"]!.AsObject();
        foreach (var name in properties.Select(p => p.Key).Where(k => !OutputSchemas.SharedEnvelope.Contains(k)).ToList()) properties.Remove(name);
        return new()
        {
            ["$comment"] = "Optional fields of every tool's structured content; tools/list leaves them out of each output schema.",
            ["type"] = "object",
            ["properties"] = properties.DeepClone(),
        };
    }
}
