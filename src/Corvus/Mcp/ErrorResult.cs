using System.Text.Json.Nodes;
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

    /// <param name="store">Keeps a partial result over <see cref="ToolError.MaxPartialTokens"/>; without one it is dropped.</param>
    public static CallToolResult From(ToolError error, string? tool, ResultStore? store = null)
    {
        if (store != null && Shorten(error, tool, store) is { } head) error = head;
        return Create(Format.EscapeInvisible(error.Render(tool)), error.ToJson(tool, store == null ? null : partial => Keep(store, tool, partial)));
    }

    /// <summary>Estimated tokens of the first block: the error budget (S1.3) less a tenth, for text the estimate counts low.</summary>
    public static int MaxTokens => OutputClasses.Budget(OutputClass.Error) * 9 / 10;

    /// <summary>
    /// An error longer than <see cref="MaxTokens"/> (160 compiler diagnostics): the head of its message, whole lines, and the
    /// full error kept for read_result (details.resultId); null when it fits.
    /// </summary>
    private static ToolError? Shorten(ToolError error, string? tool, ResultStore store)
    {
        var text = error.Render(tool);
        int tokens = TokenEstimate.Of(text);
        if (tokens <= MaxTokens) return null;
        var id = store.Keep(text, CallLog.Origin(tool, null));
        var note = $"\n[the full error ({text.Length:N0} chars) is kept as {id}; read_result id={id} shows it]";
        int room = MaxTokens - (tokens - TokenEstimate.Of(error.Message)) - TokenEstimate.Of(note) - 16;
        int end = OutputPager.FitEnd(error.Message, 0, Math.Max(100, room), null);
        var details = error.Details == null ? new JsonObject()
            : System.Text.Json.JsonSerializer.SerializeToNode(error.Details, error.Details.GetType()) as JsonObject ?? new JsonObject { ["value"] = System.Text.Json.JsonSerializer.SerializeToNode(error.Details, error.Details.GetType()) };
        details["resultId"] = id;
        return new ToolError(error.Code, error.Message[..end].TrimEnd('\n') + note, error.Remediation)
            { Details = details, Partial = error.Partial, RetryAfter = error.RetryAfter, Retryable = error.Retryable };
    }

    private static string Keep(ResultStore store, string? tool, string text) => store.Keep(text, CallLog.Origin(tool, null));

    /// <summary>An exception the tool did not classify: code "internal", not retryable.</summary>
    public static CallToolResult Internal(Exception ex, string? tool) =>
        Of("internal", false, $"{ex.GetType().Name}: {ex.Message}", NextFor(ex), null, tool);

    private static string NextFor(Exception ex) => ex switch
    {
        // dnlib (internal type): its metadata list locks are not re-entrant, so a retry fails the same way.
        _ when ex.GetType().FullName == "dnlib.Threading.LockException" => "please report it with the tool and arguments; other members of the assembly can still be read, and reload_assembly gives it a fresh metadata reader (in-memory edits are dropped)",
        _ => ToolError.InternalNext,
    };

    /// <summary>An error result for any code (also "internal"), rendered as <see cref="ToolError.Render"/> does; no next gets the code's default.</summary>
    public static CallToolResult Of(string code, bool retryable, string message, string? next, object? details, string? tool)
    {
        message = Format.EscapeMarkers(message);
        next = Format.EscapeMarkers(next is { Length: > 0 } ? next : ToolError.DefaultNext(code, tool));
        var text = $"Error ({code}{(retryable ? ", retryable" : "")}){(tool != null ? " in " + tool : "")}: {message}\nNext: {next}";
        return Create(text, ToolError.ErrorJson(code, retryable, message, next, null, details));
    }

    private static CallToolResult Create(string text, string json) => new()
    {
        IsError = true,
        Content = [new TextContentBlock { Text = text }, new TextContentBlock { Text = JsonMarker + json }],
    };

    /// <summary>
    /// Adds workspace notices to a result. On an error they follow the two error blocks: some clients show the model only
    /// the first block of an error. On a success they lead.
    /// </summary>
    public static void AddNotices(CallToolResult result, IReadOnlyCollection<string> notices)
    {
        if (notices.Count == 0) return;
        var text = string.Join("\n", notices.Select(n => "[workspace] " + Format.EscapeInvisible(n)));
        if (result.IsError == true)
        {
            // Clients join blocks without a separator.
            if (result.Content.LastOrDefault() is TextContentBlock last) last.Text += "\n\n";
            result.Content.Add(new TextContentBlock { Text = text });
        }
        else result.Content.Insert(0, new TextContentBlock { Text = text + "\n\n" });
    }

    /// <summary>The codes an error can carry: every <see cref="ErrorCode"/> and "internal".</summary>
    public static IEnumerable<string> Codes => Enum.GetValues<ErrorCode>().Select(ToolError.CodeName).Append("internal");

    /// <summary>docs/error.schema.json: the error JSON of the second block, with a closed code set and a required next.</summary>
    public static string Schema()
    {
        static JsonArray Strings(IEnumerable<string> values) => [.. values.Select(v => (JsonNode)JsonValue.Create(v))];
        var waits = Strings(Enum.GetValues<ErrorCode>().Where(ToolError.TakesRetryAfter).Select(ToolError.CodeName));
        var schema = new JsonObject
        {
            ["$schema"] = "https://json-schema.org/draft/2020-12/schema",
            ["title"] = "Corvus tool error",
            ["description"] = "The JSON after 'error (json): ' in the second text block of an error result. Generated from Core/ToolError.cs.",
            ["type"] = "object",
            ["required"] = Strings(["code", "retryable", "message", "next", "partial", "details"]),
            ["additionalProperties"] = false,
            ["properties"] = new JsonObject
            {
                ["code"] = new JsonObject { ["enum"] = Strings(Codes) },
                ["retryable"] = new JsonObject { ["type"] = "boolean", ["description"] = "The same call can succeed unchanged." },
                ["message"] = new JsonObject { ["type"] = "string", ["minLength"] = 1 },
                ["next"] = new JsonObject { ["type"] = "string", ["minLength"] = 1, ["description"] = "The next step that can succeed." },
                ["partial"] = new JsonObject { ["description"] = "What finished before the failure, or null." },
                ["details"] = new JsonObject
                {
                    ["type"] = Strings(["object", "null"]),
                    ["properties"] = new JsonObject
                    {
                        ["retryAfterMs"] = new JsonObject { ["type"] = "integer", ["minimum"] = 0 },
                        ["partialResultId"] = new JsonObject { ["type"] = "string", ["description"] = "The kept partial result, for read_result." },
                        ["partialOmittedChars"] = new JsonObject { ["type"] = "integer", ["minimum"] = 0 },
                        ["resultId"] = new JsonObject { ["type"] = "string", ["description"] = "The kept full result or error, for read_result." },
                        ["parameter"] = new JsonObject { ["type"] = "string", ["description"] = "The argument at fault." },
                    },
                },
            },
            // retryAfterMs only on the codes that can succeed after a wait.
            ["if"] = new JsonObject
            {
                ["required"] = Strings(["details"]),
                ["properties"] = new JsonObject { ["details"] = new JsonObject { ["type"] = "object", ["required"] = Strings(["retryAfterMs"]) } },
            },
            ["then"] = new JsonObject { ["properties"] = new JsonObject { ["code"] = new JsonObject { ["enum"] = waits } } },
        };
        return schema.ToJsonString(new System.Text.Json.JsonSerializerOptions { WriteIndented = true, Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping }).ReplaceLineEndings("\n") + "\n";
    }

    /// <summary>docs/errors.md: the error result format and every code.</summary>
    public static string ContractMarkdown()
    {
        var sb = new System.Text.StringBuilder();
        sb.Append($$"""
            # Error results

            <!-- Generated from Core/ToolError.cs and Mcp/ErrorResult.cs by ErrorContractTests; run the tests with CORVUS_UPDATE_DOCS=1 to update. -->

            A failed tool call returns a result with `isError: true`, no `structuredContent` and two text blocks:

            1. `Error (<code>[, retryable]) in <tool>: <message>`, then `Next: <step>` on a second line.
            2. The marker `error (json): ` (after a blank line) followed by the same error as one line of JSON:
               `{ "code", "retryable", "message", "next", "partial", "details" }`, described by
               [error.schema.json](error.schema.json).
               - `retryable`: repeating the same call can succeed without changing its arguments.
               - `next`: the next step that can succeed; never empty. Without a specific one, the code's default below.
               - `partial`: results produced before the failure (matches found before a time limit, files written), or null.
                 Above {{ToolError.MaxPartialTokens:N0}} tokens it is kept for `read_result` (`details.partialResultId`).
               - `details`: further machine-readable facts (the parameter, limits, candidates, a kept result id), or null.
                 `details.retryAfterMs` appears only on {{string.Join(", ", Enum.GetValues<ErrorCode>().Where(ToolError.TakesRetryAfter).Select(c => $"`{ToolError.CodeName(c)}`"))}}:
                 an engine restarting or a busy server, a database lock held by another process, a timed-out call whose work still runs.

            The error is always the first block. Workspace notices (`[workspace] ...`) follow the two blocks. An error larger than
            the response limit keeps its code; its message is cut and the full text is kept for `read_result` (`details.resultId`).
            Text quoted from the analyzed file is escaped: a line of it that starts like a server marker (`Error (`, `Next:`,
            `[More:`, `[End:`, `[workspace]`) gets `{{Format.MarkerEscape}}` in front, and invisible characters are written as `\uXXXX`.

            | Code | Meaning | Retryable | Default next step |
            |---|---|---|---|

            """);
        foreach (var code in Enum.GetValues<ErrorCode>())
            sb.Append($"| `{ToolError.CodeName(code)}` | {ToolError.Meaning(code)} | {(ToolError.IsRetryable(code) ? "yes" : "no")} | {ToolError.DefaultNext(code, "<tool>").Replace("|", "\\|").Replace("<", "&lt;")} |\n");
        sb.Append($"| `internal` | An unexpected exception; the message names its type. Please report it. | no | {ToolError.InternalNext} |\n");
        return sb.ToString();
    }

    /// <summary>The JSON of an error result made by <see cref="From"/>, or null.</summary>
    public static string? JsonOf(CallToolResult result) =>
        result.Content.OfType<TextContentBlock>().Select(b => b.Text).FirstOrDefault(t => t.StartsWith(JsonMarker, StringComparison.Ordinal))?[JsonMarker.Length..].TrimEnd();
}
