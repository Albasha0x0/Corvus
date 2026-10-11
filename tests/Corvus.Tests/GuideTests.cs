using System.Text.RegularExpressions;
using Corvus.Mcp;

namespace Corvus.Tests;

/// <summary>The instructions fit the client cut, every tool description too, and the guide names every tool and only real ones.</summary>
[Collection(InProcessCatalogCollection.Name)]
public class GuideTests
{
    private static readonly List<System.Text.Json.Nodes.JsonNode> Tools = Catalog.OfThisBuild().Tools;
    private static readonly HashSet<string> Names = Tools.Select(t => (string)t["name"]!).ToHashSet(StringComparer.Ordinal);

    /// <summary>Words that read like tool names but are not (a nextSteps code).</summary>
    private static readonly string[] NotTools = ["dump_from_memory"];

    [Fact]
    public void CoreFitsTheClientLimit()
    {
        Assert.Equal(Guide.Core, ServerInstructions.Text);
        Assert.True(Guide.Core.Length <= Guide.ClientLimit, $"the instruction core is {Guide.Core.Length} characters, over {Guide.ClientLimit}");
    }

    [Fact]
    public void EveryToolDescriptionFitsTheClientLimit()
    {
        var over = Tools.Select(t => ((string)t["name"]!, ((string?)t["description"] ?? "").Length)).Where(t => t.Item2 > Guide.ClientLimit)
            .Select(t => $"{t.Item1}: {t.Item2}").ToList();
        Assert.True(over.Count == 0, $"descriptions over {Guide.ClientLimit} characters: {string.Join(", ", over)}");
    }

    [Fact]
    public void GuideNamesOnlyRegisteredTools()
    {
        Assert.Empty(McpProtocolTests.UnknownTools(Guide.Core, Names, NotTools));
        foreach (var (topic, text) in Guide.Topics)
            Assert.True(McpProtocolTests.UnknownTools(text, Names, NotTools) is [] , $"{topic}: {string.Join(", ", McpProtocolTests.UnknownTools(text, Names, NotTools))}");
    }

    [Fact]
    public void CoreAndTopicsCoverEveryTool()
    {
        var text = Guide.Core + "\n" + string.Join("\n", Guide.Topics.Values);
        var named = Regex.Matches(text, @"\b[a-z0-9]+(?:_[a-z0-9]+)*\b").Select(m => m.Value).ToHashSet(StringComparer.Ordinal);
        var orphans = Names.Where(n => !named.Contains(n)).Order(StringComparer.Ordinal).ToList();
        Assert.True(orphans.Count == 0, $"tools no guide text names (add them to the core or a topic in Mcp/Guide.cs): {string.Join(", ", orphans)}");
    }

    [Fact]
    public void TopicsAreLookedUpByName()
    {
        Assert.Equal(["dotnet", "il2cpp", "containers", "edits", "builds", "native", "dumps", "errors"], Guide.Topics.Keys);
        Assert.Same(Guide.Topics["native"], Guide.Topic(" Native "));
        Assert.Null(Guide.Topic("nope"));
    }
}
