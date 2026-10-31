using System.Text.Json;
using Corvus.Mcp;

namespace Corvus.Tests;

/// <summary>get_il, decompile_member and stub_method accept each other's selector name.</summary>
public class MemberSelectorAliasTests
{
    private static readonly Dictionary<string, JsonElement> Schemas =
        Catalog.OfThisBuild().Tools.ToDictionary(t => (string)t["name"]!, t => JsonSerializer.SerializeToElement(t["inputSchema"]!));

    private static Dictionary<string, JsonElement> Args(string name, string value) =>
        new() { [name] = JsonSerializer.SerializeToElement(value) };

    [Theory]
    [InlineData("get_il", "symbol", "member")]
    [InlineData("get_il", "symbol", "method")]
    [InlineData("decompile_member", "member", "symbol")]
    [InlineData("decompile_member", "member", "method")]
    [InlineData("stub_method", "method", "symbol")]
    [InlineData("stub_method", "method", "member")]
    public void An_alias_selector_is_bound_to_the_canonical_parameter(string tool, string canonical, string alias)
    {
        var args = Args(alias, "N.T::M");
        ArgumentCheck.Apply(Schemas[tool], args, tool);
        ArgumentCheck.RequireAll(Schemas[tool], args, tool);
        Assert.Equal("N.T::M", args[canonical].GetString());
        Assert.False(args.ContainsKey(alias));
    }

    [Fact]
    public void A_canonical_selector_is_left_unchanged()
    {
        var args = Args("symbol", "N.T::M");
        ArgumentCheck.Apply(Schemas["get_il"], args, "get_il");
        Assert.Equal(["symbol"], args.Keys);
    }

    [Theory]
    [InlineData("get_il", "symbol", "member")]
    [InlineData("decompile_member", "member", "method")]
    [InlineData("stub_method", "method", "symbol")]
    public void Differing_canonical_and_alias_selectors_are_refused(string tool, string canonical, string alias)
    {
        var args = Args(canonical, "A");
        args[alias] = JsonSerializer.SerializeToElement("B");
        var error = Assert.Throws<Corvus.Core.ToolError>(() => ArgumentCheck.Apply(Schemas[tool], args, tool));
        Assert.Equal(Corvus.Core.ErrorCode.InvalidArgument, error.Code);
    }

    [Fact]
    public void Equal_canonical_and_alias_selectors_keep_only_the_canonical()
    {
        var args = Args("symbol", "N.T::M");
        args["member"] = JsonSerializer.SerializeToElement("N.T::M");
        ArgumentCheck.Apply(Schemas["get_il"], args, "get_il");
        Assert.Equal(["symbol"], args.Keys);
    }

    [Fact]
    public void Two_differing_aliases_without_the_canonical_are_refused_by_name()
    {
        var args = Args("symbol", "A");
        args["method"] = JsonSerializer.SerializeToElement("B");
        var error = Assert.Throws<Corvus.Core.ToolError>(() => ArgumentCheck.Apply(Schemas["decompile_member"], args, "decompile_member"));
        Assert.Equal(Corvus.Core.ErrorCode.InvalidArgument, error.Code);
        Assert.Contains("'method'", error.Message);
        Assert.Contains("'symbol'", error.Message);
    }

    [Fact]
    public void A_null_alias_does_not_equal_an_empty_string_canonical()
    {
        var args = Args("symbol", "");
        args["member"] = JsonSerializer.SerializeToElement<string?>(null);
        Assert.Throws<Corvus.Core.ToolError>(() => ArgumentCheck.Apply(Schemas["get_il"], args, "get_il"));
    }
}
