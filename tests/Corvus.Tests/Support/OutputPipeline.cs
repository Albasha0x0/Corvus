using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using ModelContextProtocol.Protocol;
using Corvus.Core;
using Corvus.Mcp;
using Corvus.Services;

namespace Corvus.Tests;

/// <summary>A tool call through the server's output layer (budget, cuts, kept results), with the record it returns.</summary>
internal sealed class OutputPipeline : IDisposable
{
    private readonly AssemblyWorkspace _workspace = new();
    private readonly ServiceProvider _services;

    public OutputPipeline() =>
        _services = new ServiceCollection().AddSingleton(new ServerOptions()).AddSingleton(new ResultStore(ResultCacheOptions.MemoryOnly))
            .AddSingleton(_workspace).BuildServiceProvider();

    /// <summary>The record <paramref name="run"/> returns as <paramref name="tool"/> with <paramref name="maxTokens"/>.</summary>
    public async Task<JsonElement> Record(string tool, int maxTokens, Func<CancellationToken, Task<string>> run)
    {
        var args = new Dictionary<string, JsonElement> { ["maxTokens"] = JsonSerializer.SerializeToElement(maxTokens) };
        var result = await CallFilter.Run(new CallToolRequestParams { Name = tool, Arguments = args }, null, _services,
            async ct => new CallToolResult { Content = [new TextContentBlock { Text = await run(ct) }] }, default);
        return result.StructuredContent!.Value;
    }

    /// <summary>Every page from the first, following the record's cursor; the numbers <paramref name="number"/> finds in each row's <paramref name="field"/>.</summary>
    public async Task<List<int>> PageAll(string tool, int maxTokens, Func<string?, CancellationToken, Task<string>> page, string number, string field = "text")
    {
        var seen = new List<int>();
        string? cursor = null;
        for (int pages = 0; pages < 1000; pages++)
        {
            var record = await Record(tool, maxTokens, ct => page(cursor, ct));
            foreach (var row in record.GetProperty("items").EnumerateArray())
                if (System.Text.RegularExpressions.Regex.Match(row.GetProperty(field).GetString()!, number) is { Success: true } m) seen.Add(int.Parse(m.Groups[1].Value));
            cursor = record.TryGetProperty("cursor", out var c) && c.ValueKind == JsonValueKind.String ? c.GetString() : null;
            if (cursor == null) break;
        }
        return seen;
    }

    public void Dispose()
    {
        _services.Dispose();
        _workspace.Dispose();
    }
}
