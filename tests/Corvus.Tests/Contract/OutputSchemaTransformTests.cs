using System.Text.Json;
using System.Text.Json.Nodes;
using Corvus.Mcp;

namespace Corvus.Tests;

/// <summary>The output-schema policy: compact schemas in tools/list, nullable properties optional, results without nulls.</summary>
public class OutputSchemaTransformTests
{
    private static JsonElement Parse(string json) => JsonDocument.Parse(json).RootElement;

    /// <summary>Output schemas in tools/list: 194.6 KB for 87 tools before the compact form (SC-11); 102,565 B for 152 tools as fields and types to depth 2; 103,008 at 156 with analyze_js; 103,300 with read_result verify checks; 103,600 for C-ENG2b; 104,000 for ARCH-1 (row types inlined instead of $ref); 104,100 for ARCH-2 (measured 104,094); 104,400 for NATIVE-1 (measured 104,351); 104,700 for WEB-1 and MANAGED-1 (measured 104,680); 105,200 for EM-3 (measured 105,143); 107,100 for DF-2 and ARCH-3 (measured 107,076); 107,200 for SL-4 and X4 (measured 107,157); 107,250 for SL-4 storage and X3 (measured 107,237); 107,300 for OI-E5 batches (measured 107,294); 109,000 for WEB-2 (measured 107,803 with analyze_js endpoints and secrets; diff and runtime records to come) (Phase 4 target 110 KB); 109,200 with the Hermes views and MM-11's survey_features findings (measured 109,094).</summary>
    private const int MaxOutputSchemaTotalBytes = 109_200;

    /// <summary>
    /// MM-9: a record field that says a result stopped early is one coverage reads (truncated, cut, incomplete, partial), so
    /// the provenance says partial; the others named here mean something else.
    /// </summary>
    [Fact]
    public void Stop_fields_are_ones_coverage_reads()
    {
        string[] read = ["truncated", "cut", "incomplete", "partial"];
        var other = new Dictionary<string, string>
        {
            ["hasMore"] = "another page exists",
            ["complete"] = "reanalyze_native: whether the reanalysis finished",
            ["stoppedAt"] = "emulate_native: where the emulation halted",
            ["stoppedBy"] = "search_decompiled sets coverage itself",
        };
        var stopLike = new System.Text.RegularExpressions.Regex("truncat|capped|stopped|incomplete|partial|^cut$|limited|hasmore|exhaust|timedout|complete",
            System.Text.RegularExpressions.RegexOptions.IgnoreCase);
        var unknown = new List<string>();
        foreach (var tool in Catalog.OfThisBuild(Corvus.Core.Toolsets.All).Tools)
            if (tool["outputSchema"]?["properties"] is JsonObject props)
                unknown.AddRange(props.Select(p => p.Key).Where(k => stopLike.IsMatch(k) && !read.Contains(k) && !other.ContainsKey(k)).Select(k => $"{tool["name"]}.{k}"));
        Assert.True(unknown.Count == 0, "stop-like fields coverage does not read: " + string.Join(", ", unknown));
    }

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
    public void Compact_StripsAnnotationsAndRequiredListsAndOpensDeepObjects()
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
        // no required lists (the described form keeps them); objects below the rows are open: any object
        Assert.Null(compact["required"]);
        Assert.Null(compact["properties"]!["rows"]!["items"]!["required"]);
        Assert.Equal("""{"type":"object"}""", compact["properties"]!["rows"]!["items"]!["properties"]!["inner"]!.ToJsonString());
        // a reference into an opened object accepts any value
        Assert.Equal("{}", compact["properties"]!["again"]!.ToJsonString());
        Assert.Empty(ContractSweep.SchemaProblems(OutputSchemas.Compact(schema)));

        var described = JsonNode.Parse(OutputSchemas.Described(schema).GetRawText())!;
        Assert.Equal("x", (string?)described["properties"]!["note"]!["description"]);
        Assert.NotNull(described["properties"]!["rows"]!["items"]!["properties"]!["inner"]!["properties"]!["deep"]!["properties"]);
        Assert.NotNull(described["properties"]!["rows"]!["items"]!["required"]);
        // nullable is optional; the rest stays required
        Assert.Equal("""["description","offset","rows","again"]""", described["required"]!.ToJsonString());
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
