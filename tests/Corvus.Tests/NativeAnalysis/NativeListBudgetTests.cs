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

    [WindowsFact, Trait("Speed", "Slow")]
    public async Task Read_bytes_pages_64_KiB_by_bytes_with_contiguous_pages()
    {
        await using var server = await InProcessServer.StartAsync();
        int offset = 0, pages = 0, bytes = 0;
        string? expected = null;
        while (true)
        {
            var result = await server.Client.CallToolAsync("read_bytes", new Dictionary<string, object?> { ["image"] = Kernel32, ["address"] = "rva:0x1000", ["length"] = 65536, ["offset"] = offset });
            var text = string.Concat(result.Content.OfType<TextContentBlock>().Select(b => b.Text));
            Assert.True(TokenEstimate.Of(text) <= 6300, $"page {pages}: {TokenEstimate.Of(text)} tokens");
            var record = JsonDocument.Parse(result.StructuredContent!.Value.GetRawText()).RootElement;
            if (expected != null) Assert.Equal(expected, record.GetProperty("address").GetString());
            bytes += record.GetProperty("length").GetInt32();
            pages++;
            if (!record.TryGetProperty("nextOffset", out var next)) break;
            offset = next.GetInt32();
            expected = record.GetProperty("nextAddress").GetString();
            Assert.Contains($"offset={offset}", text);
        }
        Assert.Equal(65536, bytes);
        Assert.InRange(pages, 16, 64);
    }

    [WindowsFact, Trait("Speed", "Slow")]
    public async Task Disassemble_pages_are_contiguous_and_the_record_carries_the_code()
    {
        await using var server = await InProcessServer.StartAsync();
        var codes = new List<string>();
        int offset = 0;
        for (int i = 0; i < 20; i++)
        {
            var result = await server.Client.CallToolAsync("disassemble", new Dictionary<string, object?>
                { ["image"] = Kernel32, ["address"] = "BaseThreadInitThunk", ["fromAddress"] = true, ["maxInstructions"] = 3000, ["offset"] = offset, ["maxTokens"] = 2000 });
            var record = JsonDocument.Parse(result.StructuredContent!.Value.GetRawText()).RootElement;
            Assert.Equal(offset, record.GetProperty("offset").GetInt32());
            Assert.NotNull(record.GetProperty("address").GetString());
            codes.Add(record.GetProperty("code").GetString()!);
            if (!record.TryGetProperty("nextOffset", out var next)) break;
            offset = next.GetInt32();
        }
        Assert.True(codes.Count > 2, $"{codes.Count} pages");
        Assert.Contains("3000 instructions from", string.Concat(codes));
    }

    [WindowsFact]
    public async Task Default_pages_follow_the_native_list_defaults()
    {
        await using var server = await InProcessServer.StartAsync();
        foreach (var (tool, limit) in new[] { ("list_exports", 300), ("list_imports", 200) })
        {
            var result = await server.Client.CallToolAsync(tool, new Dictionary<string, object?> { ["image"] = Kernel32 });
            var record = JsonDocument.Parse(result.StructuredContent!.Value.GetRawText()).RootElement;
            Assert.Equal(limit, record.GetProperty("limit").GetInt32());
            Assert.True(record.GetProperty("items").GetArrayLength() <= limit);
        }
    }

    [WindowsFact]
    public async Task Read_bytes_without_a_budget_pages_at_the_server_page_size()
    {
        using var env = new Env();
        var text = await new Corvus.Tools.NativeTools(env.Workspace, env.Pager).ReadBytes(Kernel32, "rva:0x1000", 65536);
        Assert.True(text.Length <= env.Options.MaxOutputChars, $"{text.Length} chars");
        Assert.Contains("[More: offset=", text);
    }
}
