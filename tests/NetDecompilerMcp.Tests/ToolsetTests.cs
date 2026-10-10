using NetDecompilerMcp.Core;
using NetDecompilerMcp.Mcp;

namespace NetDecompilerMcp.Tests;

/// <summary>Tool families: every tool in exactly one, option parsing, and a server lists only what it was started with.</summary>
public class ToolsetTests
{
    [Fact]
    public void EveryToolIsInExactlyOneFamily()
    {
        var registered = Catalog.OfThisBuild().Tools.Select(t => (string)t["name"]!).ToHashSet(StringComparer.Ordinal);
        var listed = Toolsets.Families.SelectMany(f => f.Tools).ToList();
        var twice = listed.GroupBy(t => t).Where(g => g.Count() > 1).Select(g => g.Key).ToList();
        Assert.True(twice.Count == 0, $"tools in more than one family: {string.Join(", ", twice)}");
        var unlisted = registered.Where(t => Toolsets.FamilyOf(t) == null).Order(StringComparer.Ordinal).ToList();
        Assert.True(unlisted.Count == 0, $"tools in no family (add them to Core/Toolsets.cs): {string.Join(", ", unlisted)}");
        var unknown = listed.Where(t => !registered.Contains(t)).ToList();
        Assert.True(unknown.Count == 0, $"family entries that are not tools: {string.Join(", ", unknown)}");
    }

    [Fact]
    public void ParseAndFormat()
    {
        Assert.Equal(["dotnet", Toolsets.Session], Toolsets.Parse("dotnet").Order());
        Assert.True(Toolsets.Parse("ALL").SetEquals(Toolsets.All));
        Assert.True(Toolsets.Parse("default").SetEquals(Toolsets.All));
        Assert.True(Toolsets.Parse(" core , dumps ").SetEquals([.. Toolsets.CoreProfile, "dumps"]));
        Assert.Contains("unknown toolset 'nope'", Assert.Throws<ArgumentException>(() => Toolsets.Parse("dotnet,nope")).Message);
        Assert.Equal("core,dumps", Toolsets.Format(Toolsets.Parse("dumps,core")));
        Assert.Equal("all", Toolsets.Format(Toolsets.All));
        Assert.Equal("core", Toolsets.Format(Toolsets.CoreProfile));
        Assert.Equal("dotnet,edit", Toolsets.Format(Toolsets.Parse("edit dotnet")));
        Assert.True(ServerOptions.Parse([Toolsets.Option, "native"]).Toolsets.SetEquals(["native", Toolsets.Session]));
        Assert.True(new ServerOptions().Toolsets.SetEquals(Toolsets.All));
    }

    [Fact]
    public void DefaultIsEveryToolAndCoreLeavesOutTheRest()
    {
        Assert.Equal(Catalog.OfThisBuild(Toolsets.All).Tools.Count, Catalog.OfThisBuild().Tools.Count);
        var core = Catalog.OfThisBuild(Toolsets.CoreProfile).Tools.Select(t => (string)t["name"]!).ToList();
        Assert.Contains("load_assembly", core);
        Assert.Contains("decompile_native", core);
        Assert.DoesNotContain("open_minidump", core);
        Assert.DoesNotContain("set_native_type", core);
        Assert.DoesNotContain("inspect_process", core);
        Assert.All(core, n => Assert.True(Toolsets.CoreProfile.Contains(Toolsets.FamilyOf(n)!), n));
    }

    [Fact]
    public async Task ServerRegistersOnlyItsToolsets()
    {
        await using var client = await McpProtocolTests.StartServerAsync(Toolsets.Option, "dotnet");
        var tools = (await client.ListToolsAsync()).Select(t => t.Name).ToHashSet();
        Assert.Equal(Catalog.OfThisBuild(Toolsets.Parse("dotnet")).Tools.Select(t => (string)t["name"]!).ToHashSet(), tools);
        Assert.Contains("server_status", tools);
        Assert.DoesNotContain("get_pe_info", tools);
    }
}
