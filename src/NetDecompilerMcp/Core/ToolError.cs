using ModelContextProtocol;

namespace NetDecompilerMcp.Core;

/// <summary>Why a tool call failed; rendered as a snake_case code at the start of the error text.</summary>
public enum ErrorCode
{
    /// <summary>Not classified yet.</summary>
    Failed,
    /// <summary>An argument is missing, malformed or out of range.</summary>
    InvalidArgument,
    /// <summary>The named symbol, address, file or entry does not exist.</summary>
    NotFound,
    /// <summary>A name matches several things and the call needs one.</summary>
    Ambiguous,
    /// <summary>The call needs a loaded target that is not loaded.</summary>
    NotLoaded,
    /// <summary>The target kind, architecture or construct is not handled.</summary>
    Unsupported,
    /// <summary>The input is corrupt or not of the expected format.</summary>
    MalformedInput,
    /// <summary>A size, count or time limit was reached.</summary>
    LimitExceeded,
    /// <summary>The change conflicts with the current state (stale edit, changed file, failed compile).</summary>
    Conflict,
    /// <summary>Reading or writing a file failed.</summary>
    IoError,
    /// <summary>The operation took longer than its time limit.</summary>
    Timeout,
    /// <summary>An external engine (IDA, Ghidra, a reference pack download) is missing or failed.</summary>
    ProviderUnavailable,
}

/// <summary>
/// A user-facing error; as an McpException its message is returned verbatim to the client as a tool error result.
/// <see cref="Code"/> classifies it and <see cref="Remediation"/> names the next step that can succeed.
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

    /// <summary>Whether repeating the same call can succeed without changing its arguments.</summary>
    public bool Retryable => Code is ErrorCode.Timeout or ErrorCode.IoError or ErrorCode.ProviderUnavailable;

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
        ErrorCode.IoError => "io_error",
        ErrorCode.Timeout => "timeout",
        ErrorCode.ProviderUnavailable => "provider_unavailable",
        _ => "failed",
    };

    /// <summary>The error text sent to the client: code and message, then the next step when there is one.</summary>
    public string Render(string? tool)
    {
        var head = $"Error ({CodeName(Code)}{(Retryable ? ", retryable" : "")}){(tool != null ? " in " + tool : "")}: {Message}";
        return Remediation is { Length: > 0 } r ? head + "\nNext: " + r : head;
    }
}
