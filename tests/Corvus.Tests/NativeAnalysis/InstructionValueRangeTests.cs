using ModelContextProtocol.Protocol;

namespace Corvus.Tests;

/// <summary>search_instructions value=min..max: a one-value range equals the value, a wider range finds more.</summary>
public sealed class InstructionValueRangeTests
{
    [Fact]
    public async Task A_value_range_matches_every_constant_in_it()
    {
        var dll = RealPackages.File("SQLitePCLRaw.lib.e_sqlite3", "2.1.11", "runtimes", "win-x64", "native", "e_sqlite3.dll");
        await using var server = await InProcessServer.StartAsync();
        await server.Client.CallToolAsync("load_assembly", new Dictionary<string, object?> { ["path"] = dll });
        async Task<int> Total(string value)
        {
            var r = await server.Client.CallToolAsync("search_instructions", new Dictionary<string, object?>
                { ["image"] = "e_sqlite3.dll", ["mnemonic"] = "^cmp$", ["value"] = value, ["limit"] = 2000, ["engine"] = "ours" });
            Assert.True(r.IsError != true, string.Concat(r.Content.OfType<TextContentBlock>().Select(b => b.Text)));
            return r.StructuredContent!.Value.GetProperty("total").GetInt32();
        }
        int single = await Total("0x10");
        Assert.True(single > 0);
        Assert.Equal(single, await Total("0x10..0x10"));
        Assert.True(await Total("0x0..0x10") > single);
    }
}
