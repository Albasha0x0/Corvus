using System.Text.Json.Nodes;
using Corvus.Core;
using Corvus.Mcp;

namespace Corvus.Tests;

/// <summary>S7.1 canonical parameter names and S7.2 schema conventions, over the catalog.</summary>
public class ParameterNamingTests
{
    private static readonly List<JsonNode> Tools = Catalog.OfThisBuild(Toolsets.All).Tools;

    /// <summary>Non-canonical spelling to the canonical name (S7.1).</summary>
    private static readonly Dictionary<string, string> Forbidden = new(StringComparer.Ordinal)
    {
        ["asm"] = "assembly", ["module"] = "assembly", ["binary"] = "image", ["file"] = "image",
        ["start"] = "offset", ["max"] = "limit", ["count"] = "limit", ["maxResults"] = "limit", ["maxChars"] = "maxTokens",
        ["savePath"] = "outputPath", ["tokenMapPath"] = "outputPath", ["force"] = "overwrite", ["preview"] = "dryRun", ["check"] = "dryRun",
        ["provider"] = "engine", ["backend"] = "engine", ["seconds"] = "timeoutSeconds", ["timeout"] = "timeoutSeconds",
    };

    private static IEnumerable<(string Tool, string Name, JsonObject Schema)> Parameters() => Tools.SelectMany(t =>
        (t["inputSchema"]!["properties"] as JsonObject ?? []).Select(p => ((string)t["name"]!, p.Key, p.Value!.AsObject())));

    [Fact]
    public void NamesAreCamelCase()
    {
        foreach (var (tool, name, _) in Parameters())
            Assert.Matches("^[a-z][a-zA-Z0-9]{0,39}$", name);
    }

    [Fact]
    public void NamesAreCanonical()
    {
        var violations = Parameters().Where(p => Forbidden.ContainsKey(p.Name)).ToDictionary(p => $"{p.Tool}.{p.Name}", p => $"use {Forbidden[p.Name]}");
        Ratchet.Check("parameter-names", "parameters use the canonical names of S7.1", violations);
    }

    [Fact]
    public void BooleansDefaultToFalse()
    {
        var violations = Parameters().Where(p => Type(p.Schema) == "boolean" && p.Schema["default"] is JsonValue d && d.TryGetValue<bool>(out var b) && b)
            .ToDictionary(p => $"{p.Tool}.{p.Name}", _ => "defaults to true");
        // dryRun defaults to true by design (D7)
        foreach (var key in violations.Keys.Where(k => k.EndsWith(".dryRun", StringComparison.Ordinal)).ToList()) violations.Remove(key);
        Ratchet.Check("boolean-defaults", "a boolean parameter defaults to false, except dryRun (S7.2, D7)", violations);
    }

    private static string? Type(JsonObject schema) => schema["type"] switch
    {
        JsonValue v => (string?)v,
        JsonArray a => a.Select(t => (string?)t).FirstOrDefault(t => t != "null"),
        _ => null,
    };
}
