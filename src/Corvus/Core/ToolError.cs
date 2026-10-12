using ModelContextProtocol;

namespace Corvus.Core;

/// <summary>
/// Why a tool call failed; rendered as a snake_case code at the start of the error text. Meanings and retryability:
/// <see cref="ToolError.Meaning"/> and <see cref="ToolError.IsRetryable"/> (published as docs/errors.md).
/// </summary>
public enum ErrorCode
{
    Failed,
    InvalidArgument,
    NotFound,
    Ambiguous,
    NotLoaded,
    Unsupported,
    MalformedInput,
    LimitExceeded,
    Conflict,
    ChangedOnDisk,
    IoError,
    Timeout,
    Cancelled,
    ProviderUnavailable,
    AccessDenied,
}

/// <summary>
/// A user-facing error, returned to the client as an IsError result (<see cref="Mcp.ErrorResult"/>): the rendered text,
/// then the same error as JSON. <see cref="Code"/> classifies it; <see cref="Remediation"/> names the next step that can succeed.
/// </summary>
public sealed class ToolError : McpException
{
    public ToolError(string message) : this(ErrorCode.Failed, message) { }

    public ToolError(ErrorCode code, string message, string? remediation = null) : base(message)
    {
        Code = code;
        Remediation = remediation;
    }

    public ErrorCode Code { get; }
    public string? Remediation { get; }

    /// <summary>
    /// Results produced before the failure (matches found before a time limit, files written before a timeout, the phase an
    /// index build reached); serialized as the "partial" member of the error's JSON. Keep it bounded: larger than
    /// <see cref="MaxPartialChars"/> serialized, it is dropped and only its size reported.
    /// </summary>
    public object? Partial { get; set; }

    /// <summary>Further machine-readable facts (limits, ids, candidates); the "details" member of the error's JSON.</summary>
    public object? Details { get; set; }

    public const int MaxPartialChars = 32_000;

    /// <summary>The next step of an "internal" error (an exception no tool classified), also per item where a tool collects failures.</summary>
    public const string InternalNext = "a fault in Corvus, not in the input: report it with the tool, its arguments and this message; the same call fails the same way";

    /// <summary>
    /// Whether repeating the same call can succeed without changing its arguments: by code, unless the thrower knows better
    /// (a provider that is not configured stays unavailable).
    /// </summary>
    public bool Retryable { get => _retryable ?? IsRetryable(Code); init => _retryable = value; }

    private readonly bool? _retryable;

    public static bool IsRetryable(ErrorCode code) => code is ErrorCode.Timeout or ErrorCode.Cancelled or ErrorCode.IoError or ErrorCode.ProviderUnavailable;

    /// <summary>What a code means, for client authors.</summary>
    public static string Meaning(ErrorCode code) => code switch
    {
        ErrorCode.Failed => "Not classified.",
        ErrorCode.InvalidArgument => "An argument is missing, malformed, out of range or outside its value set, or a parameter is not declared.",
        ErrorCode.NotFound => "The named symbol, address, file, entry or kept result does not exist.",
        ErrorCode.Ambiguous => "A name matches several things and the call needs one; the candidates are listed.",
        ErrorCode.NotLoaded => "The call needs a loaded target that is not loaded (or was unloaded meanwhile).",
        ErrorCode.Unsupported => "The target kind, architecture or construct is not handled.",
        ErrorCode.MalformedInput => "The input is corrupt or not of the expected format.",
        ErrorCode.LimitExceeded => "A size or count limit was reached; an oversized result is kept for read_result.",
        ErrorCode.Conflict => "The change conflicts with the current state (stale edit, existing file, failed compile).",
        ErrorCode.ChangedOnDisk => "The file changed on disk since it was loaded; writing would lose those changes.",
        ErrorCode.IoError => "Reading or writing a file failed.",
        ErrorCode.Timeout => "The operation or the call took longer than its time limit; partial holds what was done.",
        ErrorCode.Cancelled => "The server cancelled the work (the target was unloaded, reloaded or superseded).",
        ErrorCode.ProviderUnavailable => "An external engine (IDA, a reference pack download) is missing or failed.",
        ErrorCode.AccessDenied => "The operating system refused access (another user's or a protected process, missing privileges).",
        _ => "Not classified.",
    };

    public static string CodeName(ErrorCode code) => code switch
    {
        ErrorCode.Failed => "failed",
        ErrorCode.InvalidArgument => "invalid_argument",
        ErrorCode.NotFound => "not_found",
        ErrorCode.Ambiguous => "ambiguous",
        ErrorCode.NotLoaded => "not_loaded",
        ErrorCode.Unsupported => "unsupported",
        ErrorCode.MalformedInput => "malformed_input",
        ErrorCode.LimitExceeded => "limit_exceeded",
        ErrorCode.Conflict => "conflict",
        ErrorCode.ChangedOnDisk => "changed_on_disk",
        ErrorCode.IoError => "io_error",
        ErrorCode.Timeout => "timeout",
        ErrorCode.Cancelled => "cancelled",
        ErrorCode.ProviderUnavailable => "provider_unavailable",
        ErrorCode.AccessDenied => "access_denied",
        _ => "failed",
    };

    /// <summary>The error text sent to the client: code and message, then the next step when there is one.</summary>
    public string Render(string? tool)
    {
        var head = $"Error ({CodeName(Code)}{(Retryable ? ", retryable" : "")}){(tool != null ? " in " + tool : "")}: {Message}";
        return Remediation is { Length: > 0 } r ? head + "\nNext: " + r : head;
    }

    /// <summary>The error as JSON: { code, retryable, message, next, partial, details }; invisible characters escaped as in the text.</summary>
    public string ToJson() =>
        ErrorJson(CodeName(Code), Retryable, Format.EscapeInvisible(Message), Remediation is { Length: > 0 } r ? Format.EscapeInvisible(r) : null, Partial, Details);

    private static readonly System.Text.Json.JsonSerializerOptions JsonOptions = new(System.Text.Json.JsonSerializerDefaults.Web)
    {
        DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.Never,
        Converters = { new System.Text.Json.Serialization.JsonStringEnumConverter() },
        MaxDepth = 32,
        Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
    };

    /// <summary>The error JSON for any code (also "internal", which has no <see cref="ErrorCode"/>).</summary>
    public static string ErrorJson(string code, bool retryable, string message, string? next, object? partial = null, object? details = null)
    {
        var partialNode = Serialize(partial, out var partialChars);
        var detailsNode = Serialize(details, out _);
        if (partialNode != null && partialChars > MaxPartialChars)
        {
            // Too large to send with an error: report that there was one.
            partialNode = null;
            var extended = detailsNode as System.Text.Json.Nodes.JsonObject ?? new System.Text.Json.Nodes.JsonObject();
            extended["partialOmittedChars"] = partialChars;
            detailsNode = extended;
        }
        var json = new System.Text.Json.Nodes.JsonObject
        {
            ["code"] = code,
            ["retryable"] = retryable,
            ["message"] = message,
            ["next"] = next,
            ["partial"] = partialNode,
            ["details"] = detailsNode,
        };
        return json.ToJsonString(JsonOptions);
    }

    private static System.Text.Json.Nodes.JsonNode? Serialize(object? value, out int chars)
    {
        chars = 0;
        if (value == null) return null;
        try
        {
            var text = System.Text.Json.JsonSerializer.Serialize(value, value.GetType(), JsonOptions);
            chars = text.Length;
            return System.Text.Json.Nodes.JsonNode.Parse(text);
        }
        catch (Exception ex) when (ex is NotSupportedException or System.Text.Json.JsonException or InvalidOperationException)
        {
            return System.Text.Json.Nodes.JsonValue.Create($"(not serializable: {ex.GetType().Name})");
        }
    }
}
