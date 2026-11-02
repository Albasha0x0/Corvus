using System.Text.Json.Nodes;
using Corvus.Core;
using Corvus.Mcp;

namespace Corvus.Tests;

/// <summary>Every parameter in tools/list has a description, paging parameters included.</summary>
public class ParameterDescriptionTests
{
    [Fact]
    public void A_parameter_without_a_description_is_named()
    {
        var gaps = new SortedDictionary<string, List<string>>(StringComparer.Ordinal);
        foreach (var tool in Catalog.OfThisBuild(Toolsets.All).Tools)
        {
            var tname = (string)tool["name"]!;
            if (tool["inputSchema"]?["properties"] is not JsonObject props) continue;
            foreach (var (pname, schema) in props)
            {
                if (string.IsNullOrWhiteSpace((string?)schema?["description"]))
                {
                    if (!gaps.TryGetValue(pname, out var list)) gaps[pname] = list = [];
                    list.Add(tname);
                }
            }
        }
        Assert.True(gaps.Count == 0, $"{gaps.Values.Sum(l => l.Count)} parameters lack a description:\n" +
            string.Join("\n", gaps.Select(g => $"{g.Key} ({g.Value.Count}): {string.Join(", ", g.Value)}")));
    }
}
