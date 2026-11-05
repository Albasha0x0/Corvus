using System.Text.Json;
using Corvus.Mcp;

namespace Corvus.Tests;

/// <summary>A tool that declares filter accepts query and pattern, and the reverse for query.</summary>
public class FilterQueryAliasTests
{
    private static readonly Dictionary<string, JsonElement> Schemas =
        Catalog.OfThisBuild().Tools.ToDictionary(t => (string)t["name"]!, t => JsonSerializer.SerializeToElement(t["inputSchema"]!));

    private static Dictionary<string, JsonElement> Args(string name, string value) =>
        new() { [name] = JsonSerializer.SerializeToElement(value) };

    [Fact]
    public void List_imports_binds_query_to_filter()
    {
        var args = Args("query", "Create");
        args["image"] = JsonSerializer.SerializeToElement("x");
        ArgumentCheck.Apply(Schemas["list_imports"], args, "list_imports");
        Assert.Equal("Create", args["filter"].GetString());
        Assert.False(args.ContainsKey("query"));
    }

    [Fact]
    public void Differing_filter_and_query_are_refused()
    {
        var args = Args("filter", "A");
        args["query"] = JsonSerializer.SerializeToElement("B");
        var e = Assert.Throws<Corvus.Core.ToolError>(() => ArgumentCheck.Apply(Schemas["list_imports"], args, "list_imports"));
        Assert.Equal(Corvus.Core.ErrorCode.InvalidArgument, e.Code);
        Assert.Contains("query", e.Message);
        Assert.Contains("filter", e.Message);
    }

    [Fact]
    public void Equal_filter_and_query_keep_one()
    {
        var args = Args("filter", "A");
        args["query"] = JsonSerializer.SerializeToElement("A");
        args["image"] = JsonSerializer.SerializeToElement("x");
        ArgumentCheck.Apply(Schemas["list_imports"], args, "list_imports");
        Assert.Equal("A", args["filter"].GetString());
        Assert.False(args.ContainsKey("query"));
    }

    [Fact]
    public void A_query_only_tool_binds_filter_to_query()
    {
        var args = Args("filter", "A");
        ArgumentCheck.Apply(Schemas["search_symbols"], args, "search_symbols");
        Assert.Equal("A", args["query"].GetString());
        Assert.False(args.ContainsKey("filter"));
    }

    [Theory]
    [InlineData("list_android_packages", "query")]
    [InlineData("list_dex_classes", "query")]
    [InlineData("get_dex_class", "query")]
    [InlineData("bucket_minidumps", "pattern")]
    public void A_retired_name_binds_to_filter_and_the_schema_lists_filter_only(string tool, string alias)
    {
        var schema = Schemas[tool].GetProperty("properties");
        Assert.True(schema.TryGetProperty("filter", out _));
        Assert.False(schema.TryGetProperty(alias, out _));
        var args = Args(alias, "A");
        ArgumentCheck.Apply(Schemas[tool], args, tool);
        Assert.Equal("A", args["filter"].GetString());
        Assert.False(args.ContainsKey(alias));
    }
}
