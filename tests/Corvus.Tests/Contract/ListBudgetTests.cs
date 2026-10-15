using System.Text.Json.Nodes;
using Corvus.Core;
using Corvus.Mcp;

namespace Corvus.Tests;

/// <summary>Every tool whose output is a list takes maxTokens, so a client can size a page of it.</summary>
public class ListBudgetTests
{
    [Fact]
    public void Every_list_tool_takes_maxTokens()
    {
        var missing = Catalog.OfThisBuild(Toolsets.All).Tools
            .Where(t => ToolContract.Of((string)t["name"]!).Output == OutputClass.List)
            .Where(t => t["inputSchema"]?["properties"]?["maxTokens"] == null)
            .Select(t => (string)t["name"]!).Order(StringComparer.Ordinal).ToList();
        Assert.True(missing.Count == 0, "list tools without maxTokens: " + string.Join(", ", missing));
    }
}
