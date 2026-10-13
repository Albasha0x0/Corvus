using System.Text.Json;
using System.Text.Json.Nodes;
using Corvus.Mcp;

namespace Corvus.Tests;

/// <summary>The output-schema policy: compact schemas in tools/list, nullable properties optional, results without nulls.</summary>
[Collection(InProcessCatalogCollection.Name)]
public class OutputSchemaTransformTests
{
    private static JsonElement Parse(string json) => JsonDocument.Parse(json).RootElement;

    /// <summary>Output schemas in tools/list: 194.6 KB for 87 tools before the compact form (SC-11), 111.4 KB after (with the list and page envelope).</summary>
    private const int MaxOutputSchemaTotalBytes = 136_700; // Interim per D18 (SX-1 edit and S4 engine records); S-TRIM returns it to ≤ 120 KB before G2.

    [Fact]
    public void CatalogOutputSchemasAreCompact()
    {
        long total = 0;
        foreach (var tool in Catalog.OfThisBuild(Corvus.Core.Toolsets.All).Tools)
        {
            if (tool["outputSchema"] is not JsonObject output) continue;
            total += System.Text.Encoding.UTF8.GetByteCount(output.ToJsonString());
            Assert.True(Annotation(output) is null, $"{tool["name"]}: output schema keeps {Annotation(output)} (docs/schemas has the described form)");
        }
        Assert.True(total <= MaxOutputSchemaTotalBytes, $"output schemas are {total:N0} bytes, over {MaxOutputSchemaTotalBytes:N0}");

        // a property named description is data, not an annotation: only keywords count
        static string? Annotation(JsonNode? node, string path = "#") => node switch
        {
            JsonObject o when o.ContainsKey("description") || o.ContainsKey("title") => path,
            JsonObject o => o.Where(p => p.Key is not "properties" and not "$defs").Select(p => Annotation(p.Value, $"{path}/{p.Key}"))
                .Concat((o["properties"] as JsonObject ?? []).Concat(o["$defs"] as JsonObject ?? []).Select(p => Annotation(p.Value, $"{path}/{p.Key}")))
                .FirstOrDefault(p => p != null),
            JsonArray a => a.Select((v, i) => Annotation(v, $"{path}/{i}")).FirstOrDefault(p => p != null),
            _ => null,
        };
    }

    [Fact]
    public void Compact_StripsAnnotationsMakesNullablesOptionalAndOpensDeepObjects()
    {
        var schema = Parse("""
            {"type":"object","description":"d","properties":{
              "description":{"type":"string","title":"t"},
              "note":{"type":["string","null"],"description":"x"},
              "kind":{"type":["string","null"],"enum":["a",null]},
              "offset":{"type":"integer","description":"first row"},
              "rows":{"type":"array","items":{"type":"object","properties":{
                "inner":{"type":"object","properties":{
                  "deep":{"type":["object","null"],"properties":{"x":{"type":"integer"}},"required":["x"]}},"required":["deep"]}},"required":["inner"]}},
              "again":{"$ref":"#/properties/rows/items/properties/inner/properties/deep/properties/x"}},
             "required":["description","note","kind","offset","rows","again"]}
            """);
        var compact = JsonNode.Parse(OutputSchemas.Compact(schema).GetRawText())!;
        Assert.Null(compact["description"]);
        Assert.Equal("""{"type":"string"}""", compact["properties"]!["description"]!.ToJsonString());
        Assert.Equal("string", (string?)compact["properties"]!["note"]!["type"]);
        Assert.Equal("""["a"]""", compact["properties"]!["kind"]!["enum"]!.ToJsonString());
        Assert.Equal("""{"type":"integer"}""", compact["properties"]!["offset"]!.ToJsonString());
        // nullable is optional; the rest stays required
        Assert.Equal("""["description","offset","rows","again"]""", compact["required"]!.ToJsonString());
        // objects below the third level are open: any object
        Assert.Equal("""{"type":"object"}""", compact["properties"]!["rows"]!["items"]!["properties"]!["inner"]!["properties"]!["deep"]!.ToJsonString());
        // a reference into an opened object accepts any value
        Assert.Equal("{}", compact["properties"]!["again"]!.ToJsonString());
        Assert.Empty(ContractSweep.SchemaProblems(OutputSchemas.Compact(schema)));

        var described = JsonNode.Parse(OutputSchemas.Described(schema).GetRawText())!;
        Assert.Equal("x", (string?)described["properties"]!["note"]!["description"]);
        Assert.NotNull(described["properties"]!["rows"]!["items"]!["properties"]!["inner"]!["properties"]!["deep"]!["properties"]);
    }

    [Fact]
    public void SharedEnvelopeFieldsAreDeclaredOnceOutsideTheCompactForm()
    {
        var notices = """{"type":"array","items":{"type":"string"}}""";
        var schema = Parse("""
            {"type":"object","properties":{"notices":N,"warnings":N,"coverage":{"type":"object"},"resultId":{"type":"string"},"items":{"type":"array"},
             "batch":{"type":"array","items":{"type":"object","properties":{"notices":N}}}},"required":["items"]}
            """.Replace("N", notices));
        var compact = JsonNode.Parse(OutputSchemas.Compact(schema).GetRawText())!;
        Assert.Equal(["batch", "items"], compact["properties"]!.AsObject().Select(p => p.Key).Order(StringComparer.Ordinal));
        Assert.NotNull(compact["properties"]!["batch"]!["items"]!["properties"]!["notices"]);
        Assert.Empty(OutputSchema.Validate(OutputSchemas.Compact(schema), Parse("""{"items":[],"notices":["a"],"resultId":"r-0123456789ab","batch":[{"notices":[]}]}""")));
        Assert.NotNull(JsonNode.Parse(OutputSchemas.Described(schema).GetRawText())!["properties"]!["resultId"]);
    }

    private sealed record Row(string Name, string? Note, int? Count);

    [Fact]
    public void ResultsLeaveNullsOut_AndStillValidate()
    {
        var json = JsonSerializer.Serialize(new Row("a", null, null), Catalog.ToolSerializerOptions);
        Assert.Equal("""{"name":"a"}""", json);
        var schema = Parse("""{"type":"object","properties":{"name":{"type":"string"},"note":{"type":["string","null"]},"count":{"type":["integer","null"]}},"required":["name","note","count"]}""");
        Assert.Empty(OutputSchema.Validate(OutputSchemas.Compact(schema), Parse(json)));
        Assert.NotEmpty(OutputSchema.Validate(schema, Parse(json)));
    }
}
