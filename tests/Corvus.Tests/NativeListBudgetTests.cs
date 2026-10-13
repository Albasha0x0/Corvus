using System.Text.Json;
using ModelContextProtocol.Client;
using ModelContextProtocol.Protocol;
using Corvus.Core;

namespace Corvus.Tests;

/// <summary>Native list tools take maxTokens: a smaller budget gives a smaller page with the continuation in both parts.</summary>
public class NativeListBudgetTests
{
    private static readonly string Kernel32 = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "kernel32.dll");

    [WindowsFact]
    public async Task List_exports_and_imports_fit_maxTokens()
    {
        await using var server = await InProcessServer.StartAsync();
        foreach (var tool in new[] { "list_exports", "list_imports" })
        {
            var result = await server.Client.CallToolAsync(tool, new Dictionary<string, object?> { ["image"] = Kernel32, ["maxTokens"] = 600 });
            var text = string.Concat(result.Content.OfType<TextContentBlock>().Select(b => b.Text));
            Assert.True(TokenEstimate.Of(text) <= 650, $"{tool}: {TokenEstimate.Of(text)} tokens\n{text}");
            var record = JsonDocument.Parse(result.StructuredContent!.Value.GetRawText()).RootElement;
            var next = record.GetProperty("nextOffset").GetInt32();
            Assert.Equal(next, record.GetProperty("items").GetArrayLength());
            Assert.Contains($"offset={next}", text);
        }
    }
}
