using System.Text.Json;
using ModelContextProtocol.Protocol;
using NetDecompilerMcp.Core;

namespace NetDecompilerMcp.Mcp;

/// <summary>
/// Bounds every tool result. A result larger than the page size the call asked for (plus room for headers and
/// footers) is kept in the <see cref="ResultStore"/> and replaced by a limit_exceeded error naming the kept result,
/// so no tool can send a frame the client would truncate or reject.
/// </summary>
internal static class ResponseBudget
{
    private static readonly JsonSerializerOptions IndentedJson = new(Catalog.ToolSerializerOptions) { WriteIndented = true };

    /// <summary>Room for paging headers/footers on top of the page size.</summary>
    public const int Slack = 16_000;

    public static int Budget(ServerOptions options, CallToolRequestParams? request)
    {
        var page = options.MaxOutputChars;
        if (request?.Arguments is { } args && args.TryGetValue("maxChars", out var value) && value.ValueKind == JsonValueKind.Number
            && value.TryGetInt32(out var requested) && requested > page)
            page = Math.Min(requested, 500_000);
        return page + Slack;
    }

    /// <summary>Characters the client receives: the text blocks, or the structured content when it is the larger.</summary>
    public static long Size(CallToolResult result)
    {
        long text = 0;
        foreach (var block in result.Content)
            text += block is TextContentBlock t ? t.Text.Length : 0;
        var structured = result.StructuredContent is { } s ? s.GetRawText().Length : 0;
        return Math.Max(text, structured);
    }

    public static CallToolResult Enforce(CallToolResult result, string? tool, ServerOptions options, ResultStore store, CallToolRequestParams? request)
    {
        if (result.IsError == true) return result;
        var budget = Budget(options, request);
        var size = Size(result);
        if (size <= budget) return result;

        var text = string.Join("\n", result.Content.OfType<TextContentBlock>().Select(b => b.Text));
        if (text.Length == 0 && result.StructuredContent is { } s)
            text = JsonSerializer.Serialize(s, IndentedJson);
        var id = store.Add(tool ?? "?", text);
        var error = new ToolError(ErrorCode.LimitExceeded,
            $"the result is {size:N0} characters, over the {budget:N0}-character response limit. It is kept as {id}.",
            $"read_result id={id} pages through it; or narrow the call (limit, filters, one member instead of a type)")
        {
            Details = new { resultId = id, chars = size, limit = budget },
        };
        return ErrorResult.From(error, tool);
    }
}
