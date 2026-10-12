using System.Text.Json;
using ModelContextProtocol.Protocol;
using Corvus.Core;

namespace Corvus.Mcp;

/// <summary>
/// The frame safety net (S1.7) behind <see cref="ToolOutput"/>: no part of a result may pass the call's budget × 4 + 16,000
/// characters. Results are fitted by tokens long before that; this only bounds what escaped (an error with a huge message).
/// An error keeps its code and sends the head of its message with the kept result's id; a success keeps its head, never an error.
/// </summary>
internal static class ResponseBudget
{
    /// <summary>Characters beside budget × 4 that a part may take.</summary>
    public const int Slack = 16_000;

    /// <summary>Characters of an oversized error's message that are sent; the rest is in the kept result.</summary>
    public const int ErrorHeadChars = 4_000;

    /// <summary>The character cap of each part for a call with <paramref name="tokens"/> of budget.</summary>
    public static long Frame(int tokens) => tokens * 4L + Slack;

    /// <summary>Characters sent: the text blocks plus the structured content, both of which go over the wire.</summary>
    public static long Size(CallToolResult result)
    {
        long size = result.StructuredContent is { } s ? s.GetRawText().Length : 0;
        foreach (var block in result.Content)
            size += block is TextContentBlock t ? t.Text.Length : 0;
        return size;
    }

    public static CallToolResult Enforce(CallToolResult result, string? tool, int tokens, ResultStore store, CallToolRequestParams? request = null)
    {
        long limit = Frame(tokens);
        long text = result.Content.OfType<TextContentBlock>().Sum(b => (long)b.Text.Length);
        long structured = result.StructuredContent is { } s ? s.GetRawText().Length : 0;
        if (text <= limit && structured <= limit) return result;
        if (result.IsError == true) return BoundError(result, tool, store, text + structured, limit, request);
        return Head(result, tool ?? "?", store, Size(result), limit, request);
    }

    private static CallToolResult Head(CallToolResult result, string tool, ResultStore store, long size, long limit, CallToolRequestParams? request)
    {
        var text = string.Concat(result.Content.OfType<TextContentBlock>().Select(b => b.Text));
        if (text.Length == 0 && result.StructuredContent is { } s) text = s.GetRawText();
        var id = store.Keep(text, CallLog.Origin(tool, request?.Arguments), result.StructuredContent?.GetRawText());
        var note = $"\n[Cut to fit the response: the whole result ({size:N0} chars) is kept as {id}; read_result id={id} pages through it]";
        int keep = (int)Math.Min(text.Length, limit - note.Length);
        if (keep > 0 && keep < text.Length && char.IsHighSurrogate(text[keep - 1])) keep--;
        return new CallToolResult
        {
            Content = [new TextContentBlock { Text = text[..keep] + note }],
            StructuredContent = result.StructuredContent is { } structured && structured.GetRawText().Length <= limit ? structured : null,
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
