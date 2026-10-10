using System.Text.Json;
using System.Text.Json.Nodes;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Mcp;

namespace NetDecompilerMcp.Tests;

/// <summary>Closed value sets: advertised as "enum" and enforced before the tool runs.</summary>
[Collection(InProcessCatalogCollection.Name)]
public class ParameterDomainTests
{
    private static readonly Dictionary<string, JsonObject> Schemas =
        Catalog.OfThisBuild().Tools.ToDictionary(t => (string)t["name"]!, t => t["inputSchema"]!.AsObject());

    private static JsonElement Schema(string tool) => JsonSerializer.SerializeToElement(Schemas[tool]);

    private static Dictionary<string, JsonElement> Args(params (string Name, object? Value)[] args) =>
        args.ToDictionary(a => a.Name, a => JsonSerializer.SerializeToElement(a.Value));

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
                Assert.Contains("string", types);
                var advertised = property["enum"]!.AsArray().Select(v => v?.GetValue<string>()).ToList();
                Assert.Equal([.. domain.Values, .. types.Contains("null") ? new string?[] { null } : []], advertised);
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
        Assert.Equal("parameter 'sort' must be one of address, size, callers, not 'calers'. Did you mean 'callers'?", error.Message);
        Assert.Equal("Pass one of: address, size, callers.", error.Remediation);

        var engine = Assert.Throws<ToolError>(() => ArgumentCheck.Apply(Schema("decompile_native"), Args(("engine", "ghidra")), "decompile_native"));
        Assert.StartsWith("parameter 'engine' must be one of auto, ida, not 'ghidra'.", engine.Message);
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
    public void NullPassesWhereTheParameterTakesNull()
    {
        ArgumentCheck.Apply(Schema("find_xrefs"), Args(("engine", null)), "find_xrefs");
        Assert.Contains(null, Schemas["find_xrefs"]["properties"]!["engine"]!["enum"]!.AsArray());
    }
}
