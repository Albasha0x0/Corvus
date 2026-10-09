using System.Text.Json;
using NetDecompilerMcp.Core;

namespace NetDecompilerMcp.Mcp;

/// <summary>
/// Checks tool call arguments against the tool's input schema before they are bound to the method's parameters, so a
/// wrong JSON type is an invalid_argument error that names the parameter instead of a serializer exception.
/// </summary>
public static class ArgumentCheck
{
    /// <summary>
    /// Throws <see cref="ToolError"/> for an argument of the wrong JSON type. A null for an optional parameter that does not
    /// take null is removed, so the parameter's default applies (some clients send null for "not given").
    /// Integer parameters are all <see cref="int"/>, so integers outside its range are rejected here too.
    /// </summary>
    public static void Apply(JsonElement inputSchema, IDictionary<string, JsonElement>? arguments)
    {
        if (arguments == null || !inputSchema.TryGetProperty("properties", out var properties)) return;
        var required = inputSchema.TryGetProperty("required", out var r) ? r.EnumerateArray().Select(e => e.GetString()).ToHashSet() : [];
        foreach (var (name, value) in arguments.ToList())
        {
            if (!properties.TryGetProperty(name, out var property) || !property.TryGetProperty("type", out var type)) continue;
            var types = type.ValueKind == JsonValueKind.Array ? type.EnumerateArray().Select(t => t.GetString()).ToList() : [type.GetString()];
            if (value.ValueKind == JsonValueKind.Null && !types.Contains("null"))
            {
                if (required.Contains(name))
                    throw new ToolError(ErrorCode.InvalidArgument, $"parameter '{name}' must be {Describe(types)}, not null.");
                arguments.Remove(name);
                continue;
            }
            if (types.Any(t => Matches(value, t))) continue;
            var detail = types.Contains("integer") && value.ValueKind == JsonValueKind.Number
                ? $"a whole number from {int.MinValue} to {int.MaxValue}, not {value.GetRawText()}"
                : $"{Describe(types)}, not {Kind(value)}";
            throw new ToolError(ErrorCode.InvalidArgument, $"parameter '{name}' must be {detail}.");
        }
    }

    /// <summary>
    /// A file system exception raised by System.IO for a path taken from the arguments (empty, too long, malformed,
    /// missing, denied) as a tool error; null for anything else, which stays an internal error.
    /// </summary>
    public static ToolError? FileSystemError(Exception ex)
    {
        if (ex is not (ArgumentException or NotSupportedException or IOException or UnauthorizedAccessException) || !ThrownBySystemIO(ex)) return null;
        var message = ex.Message.Length > 300 ? ex.Message[..300] + "..." : ex.Message;
        return ex switch
        {
            PathTooLongException => new ToolError(ErrorCode.InvalidArgument, "a path is too long.", "Pass a shorter path."),
            ArgumentException or NotSupportedException => new ToolError(ErrorCode.InvalidArgument, $"invalid path: {message}", "Pass an absolute path without invalid characters."),
            FileNotFoundException or DirectoryNotFoundException => new ToolError(ErrorCode.NotFound, message),
            _ => new ToolError(ErrorCode.IoError, message),
        };
    }

    /// <summary>Whether the exception comes from System.IO before it passes through this server's code.</summary>
    private static bool ThrownBySystemIO(Exception ex)
    {
        foreach (var frame in new System.Diagnostics.StackTrace(ex, false).GetFrames())
        {
            var ns = frame.GetMethod()?.DeclaringType?.Namespace;
            if (ns == null) continue;
            if (ns.StartsWith("NetDecompilerMcp", StringComparison.Ordinal)) return false;
            if (ns == "System.IO" || ns.StartsWith("System.IO.", StringComparison.Ordinal)) return true;
        }
        return false;
    }

    private static bool Matches(JsonElement value, string? type) => type switch
    {
        "string" => value.ValueKind == JsonValueKind.String,
        "integer" => value.ValueKind == JsonValueKind.Number && value.TryGetInt32(out _),
        "number" => value.ValueKind == JsonValueKind.Number,
        "boolean" => value.ValueKind is JsonValueKind.True or JsonValueKind.False,
        "array" => value.ValueKind == JsonValueKind.Array,
        "object" => value.ValueKind == JsonValueKind.Object,
        "null" => value.ValueKind == JsonValueKind.Null,
        _ => true,
    };

    private static string Describe(List<string?> types) =>
        string.Join(" or ", types.Where(t => t != "null").Select(t => t switch
        {
            "string" => "a string",
            "integer" => "a whole number",
            "number" => "a number",
            "boolean" => "true or false",
            "array" => "an array",
            "object" => "an object",
            _ => t,
        }));

    private static string Kind(JsonElement value) => value.ValueKind switch
    {
        JsonValueKind.String => "a string",
        JsonValueKind.Number => "a number",
        JsonValueKind.True or JsonValueKind.False => "a boolean",
        JsonValueKind.Array => "an array",
        JsonValueKind.Object => "an object",
        _ => "null",
    };
}
