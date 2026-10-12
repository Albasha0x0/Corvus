using System.Text.Json;
using ModelContextProtocol.Protocol;
using Corvus.Core;

namespace Corvus.Mcp;

/// <summary>
/// Bounds every tool result, errors included. A result larger than the page size the call asked for (plus room for
/// headers and footers) is kept in the <see cref="ResultStore"/>: a success becomes a limit_exceeded error naming the
/// kept result, an error keeps its code and sends the head of its message with the kept result's id. A tool that can
/// change state stays a success with the head of its result, since an error would read as if nothing had changed.
/// No tool can send a frame the client would truncate or reject.
/// </summary>
internal static class ResponseBudget
{
    private static readonly JsonSerializerOptions IndentedJson = new(Catalog.ToolSerializerOptions) { WriteIndented = true };

    /// <summary>Room for paging headers/footers on top of the page size.</summary>
    public const int Slack = 16_000;

    /// <summary>Characters of an oversized error's message that are sent; the rest is in the kept result.</summary>
    public const int ErrorHeadChars = 4_000;

    public static int Budget(ServerOptions options, CallToolRequestParams? request)
    {
        var page = options.MaxOutputChars;
        if (request?.Arguments is { } args && args.TryGetValue("maxChars", out var value) && value.ValueKind == JsonValueKind.Number
            && value.TryGetInt32(out var requested) && requested > page)
            page = Math.Min(requested, 500_000);
        return page + Slack;
    }

    /// <summary>Characters sent: the text blocks plus the structured content, both of which go over the wire.</summary>
    public static long Size(CallToolResult result)
    {
        long size = result.StructuredContent is { } s ? s.GetRawText().Length : 0;
        foreach (var block in result.Content)
            size += block is TextContentBlock t ? t.Text.Length : 0;
        return size;
    }

    public static CallToolResult Enforce(CallToolResult result, string? tool, ServerOptions options, ResultStore store, CallToolRequestParams? request)
    {
        var budget = Budget(options, request);
        // Text and structured content each carry one page.
        long limit = result.StructuredContent is null ? budget : 2L * budget;
        var size = Size(result);
        if (size <= limit) return result;
        if (result.IsError == true) return BoundError(result, tool, store, size, limit, request);
        if (tool != null && !ToolEffects.Of(tool).ReadOnly) return Head(result, tool, store, size, budget, limit, request);

        var text = string.Join("\n", result.Content.OfType<TextContentBlock>().Select(b => b.Text));
        if (text.Length == 0 && result.StructuredContent is { } s)
            text = JsonSerializer.Serialize(s, IndentedJson);
        var id = store.Keep(text, CallLog.Origin(tool, request?.Arguments), result.StructuredContent?.GetRawText());
        var error = new ToolError(ErrorCode.LimitExceeded,
            $"the result is {size:N0} characters, over the {limit:N0}-character response limit. It is kept as {id}.",
            $"read_result id={id} pages through it; or narrow the call (limit, filters, one member instead of a type)")
        {
            Details = new { resultId = id, chars = size, limit },
        };
        return ErrorResult.From(error, tool);
    }

    private static CallToolResult Head(CallToolResult result, string tool, ResultStore store, long size, int budget, long limit, CallToolRequestParams? request)
    {
        var text = string.Join("\n", result.Content.OfType<TextContentBlock>().Select(b => b.Text));
        if (text.Length == 0 && result.StructuredContent is { } s)
            text = JsonSerializer.Serialize(s, IndentedJson);
        var id = store.Keep(text, CallLog.Origin(tool, request?.Arguments), result.StructuredContent?.GetRawText());
        int keep = Math.Min(text.Length, budget - Slack);
        if (keep > 0 && keep < text.Length && char.IsHighSurrogate(text[keep - 1])) keep--;
        return new CallToolResult
        {
            Content = [new TextContentBlock { Text = text[..keep] + $"\n\n[The call completed. Its result is {size:N0} characters, over the {limit:N0}-character response limit, " +
                                                     $"so it is cut here; the whole result is kept as {id}: read_result id={id} pages through it.]" }],
            StructuredContent = result.StructuredContent is { } structured && structured.GetRawText().Length <= budget ? structured : null,
            Meta = result.Meta,
        };
    }

    /// <summary>The same error (code, retryable) with the head of its message; the full error text is kept for read_result.</summary>
    private static CallToolResult BoundError(CallToolResult result, string? tool, ResultStore store, long size, long limit, CallToolRequestParams? request)
    {
        var id = store.Keep(string.Join("\n", result.Content.OfType<TextContentBlock>().Select(b => b.Text)), CallLog.Origin(tool, request?.Arguments));
        string code = "failed", message = result.Content.OfType<TextContentBlock>().FirstOrDefault()?.Text ?? "";
        bool retryable = false;
        if (ErrorResult.JsonOf(result) is { } json)
        {
            try
            {
                var root = JsonDocument.Parse(json).RootElement;
                if (root.TryGetProperty("code", out var c) && c.GetString() is { } cs) code = cs;
                if (root.TryGetProperty("retryable", out var r)) retryable = r.ValueKind == JsonValueKind.True;
                if (root.TryGetProperty("message", out var m) && m.GetString() is { } ms) message = ms;
            }
            catch (JsonException) { /* keep the text */ }
        }
        var head = message.Length > ErrorHeadChars ? message[..ErrorHeadChars] + "..." : message;
        return ErrorResult.Of(code, retryable, $"{head} [error of {size:N0} characters cut to fit the {limit:N0}-character response limit; kept as {id}]",
            $"read_result id={id} shows the full error", new { resultId = id, chars = size, limit }, tool);
    }
}
