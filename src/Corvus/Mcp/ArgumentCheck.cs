using System.Text.Json;
using Corvus.Core;

namespace Corvus.Mcp;

/// <summary>
/// Checks tool call arguments against the tool's input schema before they are bound to the method's parameters, so a
/// wrong JSON type is an invalid_argument error that names the parameter instead of a serializer exception.
/// </summary>
public static class ArgumentCheck
{
    /// <summary>
    /// Throws <see cref="ToolError"/> for an argument name the schema does not declare (with the closest declared names),
    /// an argument of the wrong JSON type, or a string outside its parameter's "enum" (and the <see cref="ParameterDomains"/>
    /// aliases of <paramref name="tool"/>). A null for an optional parameter that does not take null is removed, so the
    /// parameter's default applies (some clients send null for "not given").
    /// Integer parameters are all <see cref="int"/>, so integers outside its range are rejected here too.
    /// </summary>
    public static void Apply(JsonElement inputSchema, IDictionary<string, JsonElement>? arguments, string? tool = null)
    {
        if (arguments == null || arguments.Count == 0) return;
        var properties = inputSchema.TryGetProperty("properties", out var p) && p.ValueKind == JsonValueKind.Object ? p : default;
        var declared = properties.ValueKind == JsonValueKind.Object ? properties.EnumerateObject().Select(e => e.Name).ToList() : [];
        foreach (var name in arguments.Keys)
            if (!declared.Contains(name, StringComparer.Ordinal))
                throw UnknownParameter(name, declared);
        var required = Required(inputSchema);
        foreach (var (name, value) in arguments.ToList())
        {
            if (!properties.TryGetProperty(name, out var property) || !property.TryGetProperty("type", out var type)) continue;
            var types = type.ValueKind == JsonValueKind.Array ? type.EnumerateArray().Select(t => t.GetString()).ToList() : [type.GetString()];
            if (value.ValueKind == JsonValueKind.Null && !types.Contains("null"))
            {
                if (required.Contains(name))
                    throw new ToolError(ErrorCode.InvalidArgument, $"parameter '{name}' must be {Describe(types)}, not null.", PassHint(name, property, tool))
                    {
                        Details = new { parameter = name },
                    };
                arguments.Remove(name);
                continue;
            }
            if (types.Any(t => Matches(value, t)))
            {
                if (value.ValueKind == JsonValueKind.String && property.TryGetProperty("enum", out var allowed) && allowed.ValueKind == JsonValueKind.Array)
                    CheckValue(tool, name, value.GetString()!, allowed);
                if (name == "limit" && value.ValueKind == JsonValueKind.Number && value.TryGetInt32(out var limit) && limit < 1 && IsNativeTool(tool))
                    throw new ToolError(ErrorCode.InvalidArgument, $"parameter 'limit' must be at least 1, not {limit}.", "Pass limit=1 or more, or omit it for the default.")
                    {
                        Details = new { parameter = name, value = limit },
                    };
                continue;
            }
            var detail = types.Contains("integer") && value.ValueKind == JsonValueKind.Number
                ? $"a whole number from {int.MinValue} to {int.MaxValue}, not {value.GetRawText()}"
                : $"{Describe(types)}, not {Kind(value)}";
            throw new ToolError(ErrorCode.InvalidArgument, $"parameter '{name}' must be {detail}.", PassHint(name, property, tool))
            {
                Details = new { parameter = name },
            };
        }
    }

    /// <summary>
    /// Throws <see cref="MissingParameter"/> for the first required parameter the call does not pass. Runs after
    /// <see cref="Apply"/>, so a misspelt name is reported as unknown (with the intended name) rather than as missing.
    /// </summary>
    public static void RequireAll(JsonElement inputSchema, IDictionary<string, JsonElement>? arguments, string? tool = null)
    {
        foreach (var name in Required(inputSchema))
            if (arguments == null || !arguments.ContainsKey(name))
                throw MissingParameter(inputSchema, name, tool);
    }

    private static List<string> Required(JsonElement inputSchema) =>
        inputSchema.TryGetProperty("required", out var r) && r.ValueKind == JsonValueKind.Array
            ? r.EnumerateArray().Where(e => e.ValueKind == JsonValueKind.String).Select(e => e.GetString()!).ToList() : [];

    /// <summary>The error for a required parameter the call did not pass; Next names its type or values and range.</summary>
    public static ToolError MissingParameter(JsonElement inputSchema, string name, string? tool) =>
        new(ErrorCode.InvalidArgument, $"missing required parameter '{name}'.",
            PassHint(name, inputSchema.ValueKind == JsonValueKind.Object && inputSchema.TryGetProperty("properties", out var p) && p.ValueKind == JsonValueKind.Object && p.TryGetProperty(name, out var property) ? property : default, tool))
        {
            Details = new { parameter = name },
        };

    /// <summary>"pass name: a string; `corvus describe tool` ...": what the parameter takes and where every parameter is listed.</summary>
    private static string PassHint(string name, JsonElement property, string? tool)
    {
        var expected = Expected(property);
        return $"pass {name}{(expected.Length > 0 ? ": " + expected : "")}; " +
               (tool != null ? $"`corvus describe {tool}` or the tool's input schema lists every parameter" : "the tool's input schema lists every parameter");
    }

    /// <summary>A parameter's listed values, or its type and range ("a whole number from 1 to 500"); "" when the schema says neither.</summary>
    private static string Expected(JsonElement property)
    {
        if (property.ValueKind != JsonValueKind.Object) return "";
        if (property.TryGetProperty("enum", out var values) && values.ValueKind == JsonValueKind.Array)
        {
            var listed = values.EnumerateArray().Where(v => v.ValueKind == JsonValueKind.String).Select(v => v.GetString()!).ToList();
            if (listed.Count > 0) return "one of " + string.Join(", ", listed.Count > 12 ? [.. listed.Take(12), "..."] : listed);
        }
        if (!property.TryGetProperty("type", out var type)) return "";
        var types = type.ValueKind == JsonValueKind.Array ? type.EnumerateArray().Select(t => t.GetString()).ToList() : [type.GetString()];
        string? min = property.TryGetProperty("minimum", out var lo) ? lo.GetRawText() : null;
        string? max = property.TryGetProperty("maximum", out var hi) ? hi.GetRawText() : null;
        return Describe(types) + (min != null && max != null ? $" from {min} to {max}" : min != null ? $", at least {min}" : max != null ? $", at most {max}" : "");
    }

    /// <summary>Native tools (the native, native-edit and engine families, and tools named *native*), whose paged lists reject a limit below 1.</summary>
    public static bool IsNativeTool(string? tool) =>
        tool != null && (Toolsets.FamilyOf(tool) is "native" or "native-edit" or "engine" || tool.Contains("native", StringComparison.Ordinal));

    /// <summary>Accepts a listed value or alias (any case, trimmed) and the empty string, which the tool reads as its default.</summary>
    private static void CheckValue(string? tool, string name, string value, JsonElement allowed)
    {
        var text = value.Trim();
        if (text.Length == 0) return;
        var values = allowed.EnumerateArray().Where(e => e.ValueKind == JsonValueKind.String).Select(e => e.GetString()!).ToList();
        if (values.Concat(ParameterDomains.Find(tool, name)?.Aliases ?? []).Any(v => v.Equals(text, StringComparison.OrdinalIgnoreCase))) return;
        var suggestions = Suggest(text, values);
        var shown = Format.EscapeInvisible(text.Length > 80 ? text[..80] + "..." : text);
        var message = $"parameter '{name}' must be one of {string.Join(", ", values)}, not '{shown}'."
                      + (suggestions.Count > 0 ? $" Did you mean {string.Join(" or ", suggestions.Select(s => $"'{s}'"))}?" : "");
        throw new ToolError(ErrorCode.InvalidArgument, message, $"Pass one of: {string.Join(", ", values)}.")
        {
            Details = new { parameter = name, value = shown, allowed = values, suggestions },
        };
    }

    /// <summary>The error for an argument name the tool does not declare: the closest declared names, or all of them.</summary>
    public static ToolError UnknownParameter(string name, IReadOnlyList<string> declared)
    {
        var suggestions = Suggest(name, declared);
        var shown = Format.EscapeInvisible(name.Length > 80 ? name[..80] + "..." : name);
        var message = declared.Count == 0
            ? $"unknown parameter '{shown}': this tool takes no parameters."
            : suggestions.Count > 0
                ? $"unknown parameter '{shown}'. Did you mean {string.Join(" or ", suggestions.Select(s => $"'{s}'"))}?"
                : $"unknown parameter '{shown}'.";
        var next = declared.Count == 0 ? "Call the tool without arguments." : $"Parameters: {string.Join(", ", declared)}.";
        return new ToolError(ErrorCode.InvalidArgument, message, next)
        {
            Details = new { parameter = name, suggestions, parameters = declared },
        };
    }

    /// <summary>
    /// Declared names close to <paramref name="name"/>, closest first (at most three): same name ignoring case and
    /// separators, an edit distance within a third of the length (at least 2), or one name containing the other.
    /// </summary>
    public static List<string> Suggest(string name, IReadOnlyList<string> declared)
    {
        var key = Normalize(name);
        if (key.Length == 0) return [];
        var scored = new List<(string Name, int Score)>();
        foreach (var candidate in declared)
        {
            var other = Normalize(candidate);
            var distance = Distance(key, other);
            var limit = Math.Max(2, Math.Min(key.Length, other.Length) / 3);
            if (distance <= limit) scored.Add((candidate, distance));
            else if (Math.Min(key.Length, other.Length) >= 3 && (other.Contains(key) || key.Contains(other)))
                scored.Add((candidate, limit + Math.Abs(key.Length - other.Length)));
        }
        return scored.OrderBy(s => s.Score).ThenBy(s => s.Name, StringComparer.Ordinal).Take(3).Select(s => s.Name).ToList();
    }

    private static string Normalize(string name) =>
        new(name.Where(char.IsLetterOrDigit).Select(char.ToLowerInvariant).ToArray());

    /// <summary>Optimal string alignment distance (insertions, deletions, substitutions, adjacent transpositions).</summary>
    private static int Distance(string a, string b)
    {
        if (a.Length > 200 || b.Length > 200) return int.MaxValue;
        var d = new int[a.Length + 1, b.Length + 1];
        for (var i = 0; i <= a.Length; i++) d[i, 0] = i;
        for (var j = 0; j <= b.Length; j++) d[0, j] = j;
        for (var i = 1; i <= a.Length; i++)
            for (var j = 1; j <= b.Length; j++)
            {
                var cost = a[i - 1] == b[j - 1] ? 0 : 1;
                d[i, j] = Math.Min(Math.Min(d[i - 1, j] + 1, d[i, j - 1] + 1), d[i - 1, j - 1] + cost);
                if (i > 1 && j > 1 && a[i - 1] == b[j - 2] && a[i - 2] == b[j - 1])
                    d[i, j] = Math.Min(d[i, j], d[i - 2, j - 2] + 1);
            }
        return d[a.Length, b.Length];
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
            if (ns.StartsWith("Corvus", StringComparison.Ordinal)) return false;
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
