using System.Text.Json;
using System.Text.Json.Nodes;
using Corvus.Core;
using Corvus.Mcp;

namespace Corvus.Tests;

/// <summary>Closed value sets: advertised as "enum" and enforced before the tool runs.</summary>
[Collection(InProcessCatalogCollection.Name)]
public class ParameterDomainTests
{
    private static readonly Dictionary<string, JsonObject> Schemas =
        Catalog.OfThisBuild().Tools.ToDictionary(t => (string)t["name"]!, t => t["inputSchema"]!.AsObject());

    private static JsonElement Schema(string tool) => JsonSerializer.SerializeToElement(Schemas[tool]);

    private static Dictionary<string, JsonElement> Args(params (string Name, object? Value)[] args) =>
        args.ToDictionary(a => a.Name, a => JsonSerializer.SerializeToElement(a.Value));

    /// <summary>D6: simplify_methods' passes lists the passes and names no default outside them (omitted means all three).</summary>
    [Fact]
    public void SimplifyPassesDescriptionMatchesItsValues()
    {
        var passes = Schemas["simplify_methods"]["properties"]!["passes"]!;
        Assert.Equal(["fold", "cfg", "inline"], passes["items"]!["enum"]!.AsArray().Select(v => (string?)v));
        Assert.DoesNotContain("default", (string?)passes["description"] ?? "", StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void EveryDomainIsAdvertisedOnAStringParameter()
    {
        foreach (var (tool, parameters) in ParameterDomains.Table)
            foreach (var (name, domain) in parameters)
            {
                Assert.True(Schemas.TryGetValue(tool, out var schema), $"{tool} is not a tool");
                var property = schema["properties"]?[name] as JsonObject;
                Assert.True(property != null, $"{tool} has no parameter {name}");
                var types = property!["type"] is JsonArray a ? a.Select(t => (string?)t).ToList() : [(string?)property["type"]];
                bool array = types.Contains("array");
                if (array)
                {
                    // An array of closed values: the items carry the enum, without null.
                    property = (JsonObject)property["items"]!;
                    types = property["type"] is JsonArray i ? i.Select(t => (string?)t).ToList() : [(string?)property["type"]];
                }
                Assert.Contains("string", types);
                var advertised = property["enum"]!.AsArray().Select(v => v?.GetValue<string>()).ToList();
                Assert.Equal([.. domain.Values, .. !array && types.Contains("null") ? new string?[] { null } : []], advertised);
                Assert.Empty(domain.Aliases.Intersect(domain.Values, StringComparer.OrdinalIgnoreCase));
            }
    }

    [Fact]
    public void EveryEngineParameterHasADomain()
    {
        foreach (var (tool, schema) in Schemas)
            if (schema["properties"]?["engine"] != null)
                Assert.True(ParameterDomains.Table.TryGetValue(tool, out var p) && p.ContainsKey("engine"), $"{tool}: engine has no value set");
    }

    [Fact]
    public void OutOfSetValuesAreRejectedWithSuggestions()
    {
        var error = Assert.Throws<ToolError>(() => ArgumentCheck.Apply(Schema("list_functions"), Args(("image", "x"), ("sort", "calers")), "list_functions"));
        Assert.Equal(ErrorCode.InvalidArgument, error.Code);
        Assert.Equal("parameter 'sort' must be one of address, name, size, callers, not 'calers'. Did you mean 'callers'?", error.Message);
        Assert.Equal("Pass one of: address, name, size, callers.", error.Remediation);

        var engine = Assert.Throws<ToolError>(() => ArgumentCheck.Apply(Schema("decompile_native"), Args(("engine", "ours")), "decompile_native"));
        Assert.StartsWith("parameter 'engine' must be one of auto, ida, ghidra, not 'ours'.", engine.Message);
        var script = Assert.Throws<ToolError>(() => ArgumentCheck.Apply(Schema("ida_python"), Args(("engine", "ghidra")), "ida_python"));
        Assert.StartsWith("parameter 'engine' must be one of auto, ida, not 'ghidra'.", script.Message);
        // Each item of an array of closed values is checked.
        var pass = Assert.Throws<ToolError>(() => ArgumentCheck.Apply(Schema("simplify_methods"), Args(("passes", new[] { "fold", "cgf" })), "simplify_methods"));
        Assert.Equal("parameter 'passes' must be one of fold, cfg, inline, not 'cgf'. Did you mean 'cfg'?", pass.Message);
        ArgumentCheck.Apply(Schema("simplify_methods"), Args(("passes", new[] { "CFG", "all" })), "simplify_methods");
    }

    [Theory]
    [InlineData("find_xrefs", "engine", "IDA")]
    [InlineData("find_xrefs", "engine", " built-in ")]
    [InlineData("get_call_tree", "direction", "up")]
    [InlineData("patch_method_il", "mode", "prefix")]
    [InlineData("search_symbols", "kind", "methods")]
    [InlineData("list_functions", "sort", "")]
    public void ListedValuesAliasesCaseAndEmptyPass(string tool, string parameter, string value) =>
        ArgumentCheck.Apply(Schema(tool), Args((parameter, value)), tool);

    [Fact]
    public void NullForAnOptionalParameterPassesAsOmitted()
    {
        var args = Args(("engine", null));
        ArgumentCheck.Apply(Schema("find_xrefs"), args, "find_xrefs");
        Assert.False(args.ContainsKey("engine"));
        // the catalog advertises no null: an optional parameter is left out
        Assert.DoesNotContain(null, Schemas["find_xrefs"]["properties"]!["engine"]!["enum"]!.AsArray());
        Assert.Equal("string", (string?)Schemas["find_xrefs"]["properties"]!["engine"]!["type"]);
    }
}
