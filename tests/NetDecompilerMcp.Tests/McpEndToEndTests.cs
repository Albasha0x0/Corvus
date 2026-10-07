using ModelContextProtocol.Client;
using ModelContextProtocol.Protocol;

namespace NetDecompilerMcp.Tests;

/// <summary>Starts the real server over stdio and talks to it with the MCP client, like Claude Code does.</summary>
public class McpEndToEndTests
{
    private static async Task<McpClient> StartServerAsync(params string[] extraArgs)
    {
        var serverDll = typeof(NetDecompilerMcp.Core.AssemblyWorkspace).Assembly.Location;
        var transport = new StdioClientTransport(new StdioClientTransportOptions
        {
            Name = "net-decompiler",
            Command = "dotnet",
            Arguments = [serverDll, .. extraArgs],
        });
        return await McpClient.CreateAsync(transport);
    }

    private static string Text(CallToolResult r) => string.Join("\n", r.Content.OfType<TextContentBlock>().Select(c => c.Text));

    [Fact]
    public async Task ListsToolsAndDecompilesOverStdio()
    {
        await using var client = await StartServerAsync("--load", Env.FixturePath);

        var tools = await client.ListToolsAsync();
        var names = tools.Select(t => t.Name).ToHashSet();
        foreach (var expected in new[] { "load_assembly", "decompile_type", "decompile_member", "get_il", "search_symbols", "search_strings",
                     "find_references", "find_callees", "get_il2cpp_info", "find_method_by_address", "stub_method", "save_assembly" })
            Assert.Contains(expected, names);

        var list = await client.CallToolAsync("list_assemblies", new Dictionary<string, object?>());
        Assert.Contains("TestFixture", Text(list));

        var code = await client.CallToolAsync("decompile_member", new Dictionary<string, object?> { ["member"] = "Player::CheckLicense" });
        Assert.NotEqual(true, code.IsError);
        Assert.Contains("Secret.Validate(\"LICENSE-KEY-123\")", Text(code));

        var refs = await client.CallToolAsync("find_references", new Dictionary<string, object?> { ["symbol"] = "Secret::Validate" });
        Assert.Contains("CheckLicense", Text(refs));
    }

    [Fact]
    public async Task ErrorsAreReportedAsToolErrorsAndServerSurvives()
    {
        await using var client = await StartServerAsync("--load", Env.FixturePath);

        var missing = await client.CallToolAsync("decompile_type", new Dictionary<string, object?> { ["type"] = "Nope.DoesNotExist" });
        Assert.True(missing.IsError);
        Assert.Contains("not found", Text(missing));

        var badFile = await client.CallToolAsync("load_assembly", new Dictionary<string, object?> { ["path"] = @"C:\definitely\missing.dll" });
        Assert.True(badFile.IsError);
        Assert.Contains("File not found", Text(badFile));

        var ok = await client.CallToolAsync("get_type_info", new Dictionary<string, object?> { ["type"] = "Player" });
        Assert.NotEqual(true, ok.IsError);
        Assert.Contains("TakeDamage", Text(ok));
    }

    [Fact]
    public async Task ParallelCallsAreSafe()
    {
        await using var client = await StartServerAsync("--load", Env.FixturePath);
        var calls = Enumerable.Range(0, 12).Select(i => client.CallToolAsync(
            i % 3 == 0 ? "decompile_type" : i % 3 == 1 ? "search_strings" : "find_references",
            i % 3 == 0 ? new Dictionary<string, object?> { ["type"] = "Player" }
            : i % 3 == 1 ? new Dictionary<string, object?> { ["query"] = "LICENSE" }
            : new Dictionary<string, object?> { ["symbol"] = "Player::_health" }).AsTask());
        var results = await Task.WhenAll(calls);
        Assert.All(results, r => Assert.NotEqual(true, r.IsError));
    }
}
