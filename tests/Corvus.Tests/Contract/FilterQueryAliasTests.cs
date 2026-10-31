using System.Text.Json;
using Corvus.Mcp;

namespace Corvus.Tests;

/// <summary>A tool that declares filter accepts query, and the reverse.</summary>
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
        ArgumentCheck.Apply(Schemas["list_android_packages"], args, "list_android_packages");
        Assert.Equal("A", args["query"].GetString());
        Assert.False(args.ContainsKey("filter"));
    }
}
