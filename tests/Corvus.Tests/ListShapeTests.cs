using System.Text.Json.Nodes;
using Corvus.Core;
using Corvus.Mcp;

namespace Corvus.Tests;

/// <summary>S2.1 list shape over the catalog: a tool whose record has an items array pages by rows and says where to go on.</summary>
[Collection(InProcessCatalogCollection.Name)]
public class ListShapeTests
{
    private static readonly List<JsonNode> Tools = Catalog.OfThisBuild(Toolsets.All).Tools;

    private static readonly string[] RecordFields = ["items", "offset", "limit", "total", "totalExact", "hasMore", "nextOffset"];
    private static readonly string[] InputFields = ["offset", "limit"];

    [Fact]
    public void ListToolsCarryTheListShape()
    {
        var violations = new Dictionary<string, string>();
        foreach (var tool in Tools)
        {
            if (tool["outputSchema"]?["properties"] is not JsonObject record || record["items"]?["type"] is not JsonValue t || (string?)t != "array") continue;
            // an edit outcome's items are its failed batch items (S6.5), not a page of rows
            if (ToolContract.Of((string)tool["name"]!).Output == OutputClass.Edit) continue;
            var input = tool["inputSchema"]!["properties"] as JsonObject ?? [];
            var missing = RecordFields.Where(f => !record.ContainsKey(f)).Concat(InputFields.Where(f => !input.ContainsKey(f)).Select(f => "input " + f)).ToList();
            if (missing.Count > 0) violations[(string)tool["name"]!] = "missing " + string.Join(", ", missing);
        }
        Ratchet.Check("list-shape", "a list tool takes offset and limit and returns items, offset, limit, total, totalExact, hasMore, nextOffset (S2.1)", violations);
    }

    [Fact]
    public void ListClassToolsReturnRows()
    {
        // a List-class tool (D1 budget) without an items array in its record cannot be paged by rows
        var violations = Tools.Where(t => ToolContract.Of((string)t["name"]!).Output == OutputClass.List && t["outputSchema"]?["properties"]?["items"] is null)
            .ToDictionary(t => (string)t["name"]!, _ => "List class without an items array");
        Ratchet.Check("list-class-items", "a tool of the list output class returns its rows as items (S2.1)", violations);
    }
}
