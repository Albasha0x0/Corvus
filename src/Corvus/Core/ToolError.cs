using ModelContextProtocol;

namespace Corvus.Core;

/// <summary>Why a tool call failed, rendered as a snake_case code; meanings are in <see cref="ToolError.Meaning"/> (docs/errors.md).</summary>
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

/// <summary>A user-facing error sent as text and JSON; every error has a next step, the code's default when none is given.</summary>
public sealed class ToolError : McpException
{
    public ToolError(string message) : this(ErrorCode.Failed, message) { }

    public ToolError(ErrorCode code, string message, string? remediation = null) : base(message)
    {
        Code = code;
        Remediation = remediation;
    }

    public ErrorCode Code { get; }

    /// <summary>The throw site's next step, or null for the code's default (<see cref="NextFor"/>).</summary>
    public string? Remediation { get; }

    /// <summary>Results produced before the failure, the JSON "partial" member; above <see cref="MaxPartialTokens"/> kept for read_result or dropped.</summary>
    /// <remarks>Kept as details.partialResultId when the caller can keep results, else dropped with its size reported.</remarks>
    public object? Partial { get; set; }

    /// <summary>Further machine-readable facts (limits, ids, candidates); the "details" member of the error's JSON.</summary>
    public object? Details { get; set; }

    /// <summary>The wait after which the same call can succeed (details.retryAfterMs); sent only for <see cref="TakesRetryAfter"/> codes.</summary>
    public TimeSpan? RetryAfter { get; init; }

    /// <summary>The token budget of the partial result sent with an error.</summary>
    public const int MaxPartialTokens = 4_000;

    /// <summary>The next step of an "internal" error (an exception no tool classified), also per item where a tool collects failures.</summary>
    public const string InternalNext = "retry once; if it repeats, report it with the tool and its arguments (server_status shows the version)";

    /// <summary>Whether repeating the same call can succeed; by code unless the thrower sets it (an unconfigured provider stays unavailable).</summary>
    public bool Retryable { get => _retryable ?? IsRetryable(Code); init => _retryable = value; }

    private readonly bool? _retryable;

    public static bool IsRetryable(ErrorCode code) => code is ErrorCode.Timeout or ErrorCode.Cancelled or ErrorCode.IoError or ErrorCode.ProviderUnavailable;

    /// <summary>The codes that may carry details.retryAfterMs.</summary>
    public static bool TakesRetryAfter(ErrorCode code) => code is ErrorCode.ProviderUnavailable or ErrorCode.Conflict or ErrorCode.Timeout;

    /// <summary>The next step: the throw site's, else the code's default; never empty.</summary>
    public string NextFor(string? tool) => Remediation is { Length: > 0 } r ? r : DefaultNext(Code, tool);

    /// <summary>The next step of a code when the throw site gives none; <paramref name="tool"/> is the failed tool, if known.</summary>
    public static string DefaultNext(ErrorCode code, string? tool) => code switch
    {
        ErrorCode.InvalidArgument => tool != null
            ? $"fix the argument the message names; `corvus describe {tool}` or the tool's input schema lists its parameters, types and ranges"
            : "fix the argument the message names; the tool's input schema lists its parameters, types and ranges",
        ErrorCode.NotFound => "check the name, address or path: list_assemblies shows what is loaded, search_symbols and list_functions find names, and a relative path resolves against the server's working directory",
        ErrorCode.Ambiguous => "call again with one of the candidates (a full name, a token, or the assembly or image parameter)",
        ErrorCode.NotLoaded => "load_assembly path=<file> loads it (a target parameter also takes the file's path); list_assemblies shows what is loaded",
        ErrorCode.Unsupported => "summarize_file names the kind of the target and the tools that read it",
        ErrorCode.MalformedInput => "check that the file is complete and of the expected kind; summarize_file reports what it is",
        ErrorCode.LimitExceeded => "narrow the call (a smaller limit, a filter, one member instead of a type); a kept result is paged with read_result",
        ErrorCode.Conflict => "read the current state and repeat the change against it; for an existing output file pass overwrite=true or another path",
        ErrorCode.ChangedOnDisk => "reload_assembly reads the file on disk (in-memory edits are dropped), or save to another path",
        ErrorCode.IoError => "check that the path is reachable and not locked by another program, then call again",
        ErrorCode.Timeout => "narrow the call (one member instead of a type, a smaller limit or scope); partial holds what finished",
        ErrorCode.Cancelled => "call again; if the target was unloaded or reloaded, list_assemblies shows what is loaded",
        ErrorCode.ProviderUnavailable => "server_status names the missing engine or download and how to enable it; when details.retryAfterMs is given, retry after it",
        ErrorCode.AccessDenied => "pick a target this user may read, or run the server with the rights it needs",
        _ => "read the message for the cause, change the arguments or the target, and call again",
    };

    /// <summary>The default next step of a code name, "internal" included.</summary>
    public static string DefaultNext(string code, string? tool) =>
        code == "internal" ? InternalNext : DefaultNext(Enum.GetValues<ErrorCode>().FirstOrDefault(c => CodeName(c) == code), tool);

    /// <summary>The standard error for a call that needs a loaded target; <paramref name="what"/> names it ("No native images are").</summary>
    public static ToolError NotLoaded(string what, string? next = null) => new(ErrorCode.NotLoaded, $"{what} loaded.", next);

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
        ErrorCode.Conflict => "The change conflicts with the current state (stale edit, existing file, failed compile, a database another process holds).",
        ErrorCode.ChangedOnDisk => "The file changed on disk since it was loaded; writing would lose those changes.",
        ErrorCode.IoError => "Reading or writing a file failed.",
        ErrorCode.Timeout => "The operation or the call took longer than its time limit; partial holds what was done.",
        ErrorCode.Cancelled => "The server cancelled the work (the target was unloaded, reloaded or superseded).",
        ErrorCode.ProviderUnavailable => "An external engine (IDA, a reference pack download) is missing or failed, or the server is busy.",
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

    /// <summary>The error text sent to the client: code and message, then the next step; echoed markers escaped.</summary>
    public string Render(string? tool) =>
        $"Error ({CodeName(Code)}{(Retryable ? ", retryable" : "")}){(tool != null ? " in " + tool : "")}: {Format.EscapeMarkers(Message)}\nNext: {Format.EscapeMarkers(NextFor(tool))}";

    /// <summary>The error as JSON { code, retryable, message, next, partial, details }; <paramref name="keep"/> stores an oversized partial.</summary>
    public string ToJson(string? tool = null, Func<string, string>? keep = null) =>
        ErrorJson(CodeName(Code), Retryable, Format.EscapeMarkers(Message), Format.EscapeMarkers(NextFor(tool)), Partial, Details,
            TakesRetryAfter(Code) && RetryAfter is { } wait ? (long)wait.TotalMilliseconds : null, keep);

    /// <summary>How partial and details are written into the error's JSON.</summary>
    internal static readonly System.Text.Json.JsonSerializerOptions JsonOptions = new(System.Text.Json.JsonSerializerDefaults.Web)
    {
        DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.Never,
        Converters = { new System.Text.Json.Serialization.JsonStringEnumConverter() },
        MaxDepth = 32,
        Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
    };

    internal static int EstimateTokens(string text) => TokenEstimate.Of(text);

    /// <summary>The error JSON for any code (also "internal", which has no <see cref="ErrorCode"/>); an empty next gets the code's default.</summary>
    public static string ErrorJson(string code, bool retryable, string message, string? next, object? partial = null, object? details = null,
        long? retryAfterMs = null, Func<string, string>? keep = null)
    {
        var partialNode = Serialize(partial, out var partialText);
        var detailsNode = Serialize(details, out _);
        System.Text.Json.Nodes.JsonObject Extended()
        {
            if (detailsNode is not System.Text.Json.Nodes.JsonObject obj) detailsNode = obj = [];
            return obj;
        }
        if (partialNode != null && EstimateTokens(partialText) > MaxPartialTokens)
        {
            partialNode = null;
            if (keep?.Invoke(partialText) is { } id) Extended()["partialResultId"] = id;
            else Extended()["partialOmittedChars"] = partialText.Length;
        }
        if (retryAfterMs is { } wait) Extended()["retryAfterMs"] = Math.Max(0, wait);
        var json = new System.Text.Json.Nodes.JsonObject
        {
            ["code"] = code,
            ["retryable"] = retryable,
            ["message"] = message,
            ["next"] = next is { Length: > 0 } ? next : DefaultNext(code, null),
            ["partial"] = partialNode,
            ["details"] = detailsNode,
        };
        Format.EscapeInvisible(json);
        return json.ToJsonString(JsonOptions);
    }

    private static System.Text.Json.Nodes.JsonNode? Serialize(object? value, out string text)
    {
        text = "";
        if (value == null) return null;
        try
        {
            text = System.Text.Json.JsonSerializer.Serialize(value, value.GetType(), JsonOptions);
            return System.Text.Json.Nodes.JsonNode.Parse(text);
        }
        catch (Exception ex) when (ex is NotSupportedException or System.Text.Json.JsonException or InvalidOperationException)
        {
            return System.Text.Json.Nodes.JsonValue.Create($"(not serializable: {ex.GetType().Name})");
        }
    }
}

/// <summary>A worker process's exception raised again in the server with its type name and message, so it reads as if the work ran there.</summary>
public sealed class ForwardedException(string typeName, string message) : Exception(message)
{
    public string TypeName { get; } = typeName;
}
