using System.Text.Json;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;
using Corvus.Core;
using Corvus.Mcp;

namespace Corvus.Tests;

/// <summary>S13.3: the list, record and error shapes hold at every protocol version clients speak, and tools/list is answered from the cache.</summary>
public class ProtocolMatrixTests
{
    [Theory]
    [InlineData("2024-11-05")]
    [InlineData("2025-03-26")]
    [InlineData("2025-06-18")]
    [InlineData("2025-11-25")]
    [InlineData("2026-07-28")]
    public async Task ShapesHoldAtEveryVersion(string version)
    {
        await using var server = await InProcessServer.StartAsync(version);
        var client = server.Client;
        Assert.Equal(version, client.NegotiatedProtocolVersion);

        // tools/list: every registered tool, as the catalog describes it
        var listed = (await client.ListToolsAsync()).ToDictionary(t => t.Name, t => JsonSerializer.SerializeToNode(t.ProtocolTool, McpJsonUtilities.DefaultOptions)!.ToJsonString());
        var expected = Catalog.OfThisBuild().Tools.ToDictionary(t => (string)t["name"]!, t => t.ToJsonString());
        Assert.Equal(expected.Keys.Order(StringComparer.Ordinal), listed.Keys.Order(StringComparer.Ordinal));
        Assert.All(expected, e => Assert.True(JsonEquals(e.Value, listed[e.Key]), $"{e.Key} differs from the catalog"));

        // a list: rows and paging in the record, no nulls
        var list = await client.CallToolAsync("list_types", new Dictionary<string, object?> { ["assembly"] = "TestFixture", ["limit"] = 2 });
        Assert.NotEqual(true, list.IsError);
        var record = JsonDocument.Parse(list.StructuredContent!.ToString()!).RootElement;
        Assert.Equal(JsonValueKind.Array, record.GetProperty("items").ValueKind);
        Assert.True(record.GetProperty("total").GetInt32() >= record.GetProperty("items").GetArrayLength());
        Assert.DoesNotContain(":null", list.StructuredContent!.Value.GetRawText());

        // an error: the error first, no record
        var error = await client.CallToolAsync("decompile_member", new Dictionary<string, object?> { ["member"] = "No.Such::Thing" });
        Assert.True(error.IsError);
        Assert.Null(error.StructuredContent);
        Assert.StartsWith("Error (", Assert.IsType<TextContentBlock>(error.Content[0]).Text);
        Assert.Contains("Next:", Assert.IsType<TextContentBlock>(error.Content[0]).Text);
    }

    [Fact]
    public async Task ClientsThatCapToolsAreListedTheLeanProfile()
    {
        await using (var vscode = await InProcessServer.StartAsync(clientName: "Visual Studio Code"))
        {
            var names = (await vscode.Client.ListToolsAsync()).Select(t => t.Name).Order(StringComparer.Ordinal).ToList();
            Assert.Equal(Profiles.ToolsOf(Toolsets.LeanProfile).Order(StringComparer.Ordinal), names);
            // left out of the list, still answered
            Assert.NotEqual(true, (await vscode.Client.CallToolAsync("list_namespaces", new Dictionary<string, object?>())).IsError);
            var status = JsonDocument.Parse((await vscode.Client.CallToolAsync("server_status", new Dictionary<string, object?>())).StructuredContent!.ToString()!).RootElement;
            Assert.StartsWith($"t{names.Count}-", status.GetProperty("catalogDigest").GetString());
        }
        // an explicit --toolsets wins over the client's default
        var options = ServerOptions.Parse([Toolsets.Option, "full", "--no-index", "--no-watch"]);
        await using var explicitFull = await InProcessServer.StartAsync(clientName: "Visual Studio Code", options: options);
        Assert.Equal(Catalog.OfThisBuild().Tools.Count, (await explicitFull.Client.ListToolsAsync()).Count);
    }

    private static bool JsonEquals(string a, string b) => JsonElement.DeepEquals(JsonDocument.Parse(a).RootElement, JsonDocument.Parse(b).RootElement);
}
