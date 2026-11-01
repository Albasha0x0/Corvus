using System.ComponentModel;
using System.Reflection;
using System.Text.Json.Nodes;
using ModelContextProtocol.Server;
using Corvus.Core;
using Corvus.Mcp;

namespace Corvus.Tests;

/// <summary>Every parameter in tools/list has a description, except the paging text the server instructions give once.</summary>
public class ParameterDescriptionTests
{
    private static readonly Lazy<Dictionary<string, MethodInfo>> ToolMethods = new(() =>
        typeof(Catalog).Assembly.GetTypes()
            .SelectMany(t => t.GetMethods(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance | BindingFlags.Static | BindingFlags.DeclaredOnly))
            .Select(m => (Method: m, Attr: m.GetCustomAttribute<McpServerToolAttribute>()))
            .Where(x => x.Attr?.Name != null)
            .GroupBy(x => x.Attr!.Name!)
            .ToDictionary(g => g.Key, g => g.First().Method));

    // True when the tool's own parameter carries the generic paging text that the catalog drops.
    private static bool IsGenericPaging(string tool, string parameter) =>
        ToolMethods.Value.TryGetValue(tool, out var method) &&
        method.GetParameters().FirstOrDefault(p => p.Name == parameter)?.GetCustomAttribute<DescriptionAttribute>()?.Description is { } text &&
        Catalog.PagingParameters[parameter].Contains(text);

    [Fact]
    public void A_non_paging_parameter_without_a_description_is_named()
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
                    // A paging name is exempt only where its generic text was dropped; the tool's own text stays.
                    if (Catalog.PagingParameters.ContainsKey(pname) && IsGenericPaging(tname, pname)) continue;
                    if (!gaps.TryGetValue(pname, out var list)) gaps[pname] = list = [];
                    list.Add(tname);
                }
            }
        }
        Assert.True(gaps.Count == 0, $"{gaps.Values.Sum(l => l.Count)} parameters lack a description:\n" +
            string.Join("\n", gaps.Select(g => $"{g.Key} ({g.Value.Count}): {string.Join(", ", g.Value)}")));
    }
}
