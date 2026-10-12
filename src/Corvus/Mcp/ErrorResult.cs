using ModelContextProtocol.Protocol;
using Corvus.Core;

namespace Corvus.Mcp;

/// <summary>
/// Tool errors as call results: IsError=true and two text blocks. The first is the error text agents read
/// ("Error (code[, retryable]) in tool: message\nNext: ..."); the second starts with <see cref="JsonMarker"/> followed by
/// the error as one line of JSON: { code, retryable, message, next, partial, details }.
/// The JSON is not sent as structuredContent: clients validate structuredContent against the tool's output schema, some
/// even on error results (the TypeScript SDK validates whatever structuredContent is present), and an error object never
/// matches a success schema.
/// </summary>
internal static class ErrorResult
{
    /// <summary>The start of the second text block; the rest of the block is the JSON object.</summary>
    public const string JsonMarker = "\n\nerror (json): ";

    public static CallToolResult From(ToolError error, string? tool) =>
        Create(Format.EscapeInvisible(error.Render(tool)), error.ToJson());

    /// <summary>An exception the tool did not classify: code "internal", not retryable.</summary>
    public static CallToolResult Internal(Exception ex, string? tool) =>
        Of("internal", false, $"{ex.GetType().Name}: {ex.Message}", ToolError.InternalNext, null, tool);

    /// <summary>An error result for any code (also "internal"), rendered as <see cref="ToolError.Render"/> does.</summary>
    public static CallToolResult Of(string code, bool retryable, string message, string? next, object? details, string? tool)
    {
        message = Format.EscapeInvisible(message);
        next = next is { Length: > 0 } ? Format.EscapeInvisible(next) : null;
        var text = $"Error ({code}{(retryable ? ", retryable" : "")}){(tool != null ? " in " + tool : "")}: {message}" + (next != null ? "\nNext: " + next : "");
        return Create(text, ToolError.ErrorJson(code, retryable, message, next, null, details));
    }

    private static CallToolResult Create(string text, string json) => new()
    {
        IsError = true,
        Content = [new TextContentBlock { Text = text }, new TextContentBlock { Text = JsonMarker + json }],
    };

    /// <summary>docs/errors.md: the error result format and every code.</summary>
    public static string ContractMarkdown()
    {
        var sb = new System.Text.StringBuilder();
        sb.Append("""
            # Error results

            <!-- Generated from Core/ToolError.cs and Mcp/ErrorResult.cs by ErrorContractTests; run the tests with CORVUS_UPDATE_DOCS=1 to update. -->

            A failed tool call returns a result with `isError: true`, no `structuredContent` and two text blocks:

            1. `Error (<code>[, retryable]) in <tool>: <message>`, then `Next: <step>` on a second line when a next step is known.
            2. The marker `error (json): ` (after a blank line) followed by the same error as one line of JSON:
               `{ "code", "retryable", "message", "next", "partial", "details" }`.
               - `retryable`: repeating the same call can succeed without changing its arguments.
               - `next`: the next step that can succeed, or null.
               - `partial`: results produced before the failure (matches found before a time limit, files written), or null;
                 over 32,000 characters it is dropped and `details.partialOmittedChars` gives its size.
               - `details`: further machine-readable facts (the parameter, limits, candidates, a kept result id), or null.

            An error larger than the response limit keeps its code; its message is cut and the full text is kept for
            `read_result` (`details.resultId`). Workspace notices (`[workspace] ...`) may precede the two blocks.

            | Code | Meaning | Retryable |
            |---|---|---|

            """);
        foreach (var code in Enum.GetValues<ErrorCode>())
            sb.Append($"| `{ToolError.CodeName(code)}` | {ToolError.Meaning(code)} | {(ToolError.IsRetryable(code) ? "yes" : "no")} |\n");
        sb.Append("| `internal` | An unexpected exception; the message names its type. Please report it. | no |\n");
        return sb.ToString();
    }

    /// <summary>The JSON of an error result made by <see cref="From"/>, or null.</summary>
    public static string? JsonOf(CallToolResult result) =>
        result.Content.OfType<TextContentBlock>().Select(b => b.Text).FirstOrDefault(t => t.StartsWith(JsonMarker, StringComparison.Ordinal))?[JsonMarker.Length..];
}
