using System.Text.Json.Nodes;
using Corvus.Core;
using Corvus.Mcp;

namespace Corvus.Tests;

/// <summary>S4 structured output over the catalog: every tool returns a record with an output schema.</summary>
public class StructuredCoverageTests
{
    private static readonly List<JsonNode> Tools = Catalog.OfThisBuild(Toolsets.All).Tools;

    [Fact]
    public void Every_tool_has_an_output_schema()
    {
        var violations = Tools.Where(t => t["outputSchema"] is null).ToDictionary(t => (string)t["name"]!, _ => "no output schema (no structured record)");
        Ratchet.Check("structured-output", "every tool returns structured content described by an output schema (S4)", violations);
    }

    [Fact]
    public void Every_structured_tool_has_a_described_schema()
    {
        var described = Catalog.DescribedOutputSchemas();
        Assert.Equal(Tools.Where(t => t["outputSchema"] is not null).Select(t => (string)t["name"]!).Order(StringComparer.Ordinal), described.Keys);
    }
}
