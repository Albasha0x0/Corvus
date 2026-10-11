using Corvus.Core;
using Corvus.Mcp;

namespace Corvus.Tests;

/// <summary>Tool families: every tool in exactly one, option parsing, and a server lists only what it was started with.</summary>
[Collection(InProcessCatalogCollection.Name)]
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

    [Fact]
    public void ShippedToolListsNameRealTools_AndReadonlyChangesNothing()
    {
        foreach (var (name, list) in Toolsets.ToolLists)
            Assert.True(Toolsets.LoadToolList(name).SetEquals(list), name);
        Assert.All(Toolsets.ToolLists["readonly"], t => Assert.True(ToolEffects.Of(t).ReadOnly, t));
        // every read-only tool is in it, but the session tools (always on), device tools and live processes
        var missing = Catalog.OfThisBuild().Tools.Select(t => (string)t["name"]!)
            .Where(t => ToolEffects.Of(t).ReadOnly && Toolsets.FamilyOf(t) is not (Toolsets.Session or "live") && !ToolAvailability.DeviceTools.Contains(t))
            .Except(Toolsets.ToolLists["readonly"]).ToList();
        Assert.True(missing.Count == 0, "add to the readonly list: " + string.Join(", ", missing));
        Assert.Subset(Toolsets.ToolLists["readonly"].ToHashSet(), Toolsets.ToolLists["triage"].ToHashSet());
    }

    [Fact]
    public void ToolsFile_IsAWhitelistAppliedAfterToolsets()
    {
        using var dir = new TempDir();
        var file = dir.File("tools.txt");
        File.WriteAllText(file, "# a profile\nget_pe_info, list_imports   # native\n\ndecompile_member\n");
        var allowed = Toolsets.LoadToolList(file);
        Assert.Equal(["decompile_member", "get_pe_info", "list_imports"], allowed.Order());
        Assert.True(Toolsets.Registers(Toolsets.All, allowed, "get_pe_info"));
        Assert.True(Toolsets.Registers(Toolsets.All, allowed, "server_status")); // session stays
        Assert.False(Toolsets.Registers(Toolsets.All, allowed, "disassemble"));
        Assert.False(Toolsets.Registers(Toolsets.Parse("dotnet"), allowed, "get_pe_info")); // toolsets first
        Assert.Contains("unknown tool(s) nope", Assert.Throws<ArgumentException>(() => Toolsets.ParseToolList("get_pe_info nope", "x")).Message);
        Assert.Throws<ArgumentException>(() => Toolsets.LoadToolList(dir.File("missing.txt")));
        Assert.True(ServerOptions.Parse([Toolsets.ToolsFileOption, file]).ToolAllowList!.SetEquals(allowed));
        Assert.True(ServerOptions.Parse([Toolsets.ToolsFileOption, "triage"]).ToolAllowList!.SetEquals(Toolsets.ToolLists["triage"]));
        Assert.Null(new ServerOptions().ToolAllowList);
        // server_status names the whitelist: a list name, or the file's full path
        Assert.Equal("triage", ServerOptions.Parse([Toolsets.ToolsFileOption, "Triage"]).ToolAllowListSource);
        Assert.Equal(Path.GetFullPath(file), ServerOptions.Parse([Toolsets.ToolsFileOption, file]).ToolAllowListSource);
    }

    [Fact]
    public async Task ServerRegistersOnlyTheWhitelistedTools()
    {
        await using var client = await McpProtocolTests.StartServerAsync(Toolsets.ToolsFileOption, "triage");
        var tools = (await client.ListToolsAsync()).Select(t => t.Name).ToHashSet();
        var expected = Toolsets.ToolLists["triage"].Concat(Toolsets.Families.Single(f => f.Name == Toolsets.Session).Tools).ToHashSet();
        Assert.Equal(expected, tools);
    }
}
