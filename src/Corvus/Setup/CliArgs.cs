using System.Globalization;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Corvus.Core;

namespace Corvus.Setup;

/// <summary>A tool CLI usage error: exit code 2.</summary>
internal sealed class UsageException(string message) : Exception(message);

/// <summary>The tool CLI's command line: positionals, tool arguments, JSON arguments, output flags and server options.</summary>
internal sealed partial class CliArgs
{
    public List<string> Positionals { get; } = [];
    public List<(string Key, string Value, bool Json)> Assignments { get; } = [];
    public List<string> ServerArgs { get; } = [];
    public string? ArgsJson { get; private set; }
    public string? ArgsFile { get; private set; }
    public bool Json { get; private set; }
    public bool Structured { get; private set; }
    public bool StopOnError { get; private set; }
    public string? BatchFile { get; private set; }
    public string? TimeLimit { get; private set; }
    public string? Rules { get; private set; }
    public List<string> Limits { get; } = [];
    public bool Recurse { get; private set; }
    public string? FailOn { get; private set; }
    public bool AllowIncomplete { get; private set; }
    public string? Extract { get; private set; }

    public static CliArgs Parse(IReadOnlyList<string> tokens)
    {
        var a = new CliArgs();
        for (int i = 0; i < tokens.Count; i++)
        {
            var t = tokens[i];
            string Next() => i + 1 < tokens.Count ? tokens[++i] : throw new UsageException($"{t} needs a value.");
            switch (t)
            {
                // --json followed by an object is the arguments; alone it selects JSON output.
                case "--json" when i + 1 < tokens.Count && tokens[i + 1].TrimStart().StartsWith('{'): a.ArgsJson = Next(); continue;
                case "--json": a.Json = true; continue;
                case "--args": a.ArgsJson = Next(); continue;
                case "--args-file": a.ArgsFile = Next(); continue;
                case "--structured": a.Structured = true; continue;
                case "--stop-on-error": a.StopOnError = true; continue;
                case "--file": a.BatchFile = Next(); continue;
                case "--time-limit": a.TimeLimit = Next(); continue;
                case "--rules": a.Rules = Next(); continue;
                case "--limit": a.Limits.Add(Next()); continue;
                case "--recurse": a.Recurse = true; continue;
                case "--fail-on": a.FailOn = Next(); continue;
                case "--allow-incomplete": a.AllowIncomplete = true; continue;
                case "--extract": a.Extract = Next(); continue;
            }
            if (t.StartsWith("--", StringComparison.Ordinal))
            {
                a.ServerArgs.Add(t);
                if (Core.ServerOptions.ValueOptions.Contains(t)) a.ServerArgs.Add(Next());
            }
            else if (t.Length > 1 && t[0] == '-') throw new UsageException($"Unknown option {t}.");
            else if (Assignment().Match(t) is { Success: true } m) a.Assignments.Add((m.Groups[1].Value, t[m.Length..], m.Groups[2].Value == ":="));
            else a.Positionals.Add(t);
        }
        return a;
    }

    /// <summary>Server options for a CLI session: no file watching, whole results, warnings only on stderr.</summary>
    // A one-shot session builds indexes only on demand: a background pass would compete with the call and be discarded.
    public ServerOptions Server(bool oneShot = false)
    {
        Core.ServerOptions options;
        try { options = Core.ServerOptions.Parse([.. ServerArgs]); }
        catch (Exception ex) when (ex is ArgumentException or FormatException or OverflowException) { throw new UsageException(ex.Message); }
        options.WatchFiles = false;
        if (oneShot) options.BackgroundIndexing = false;
        if (!Has("--max-output")) options.MaxOutputChars = int.MaxValue / 4;
        if (!Has("--log-level") && Environment.GetEnvironmentVariable(Core.ServerOptions.LogLevelVariable) is not { Length: > 0 })
            options.LogLevel = Microsoft.Extensions.Logging.LogLevel.Warning;
        return options;
    }

    private bool Has(string option) => ServerArgs.Contains(option, StringComparer.OrdinalIgnoreCase);

    /// <summary>The call's arguments: the JSON object, then each assignment coerced to its schema type; unknown names pass through.</summary>
    public Dictionary<string, object?> ToolArguments(JsonNode? inputSchema, TextReader stdin)
    {
        var result = new Dictionary<string, object?>(StringComparer.Ordinal);
        var json = ArgsFile != null ? ReadSource(ArgsFile, stdin) : ArgsJson;
        if (json != null)
        {
            JsonNode? parsed;
            try { parsed = JsonNode.Parse(json); }
            catch (JsonException ex) { throw new UsageException($"The arguments are not valid JSON: {ex.Message}"); }
            if (parsed is not JsonObject obj) throw new UsageException("The arguments must be a JSON object.");
            foreach (var (key, value) in obj) result[key] = Element(value);
        }
        var properties = inputSchema?["properties"] as JsonObject;
        foreach (var (key, raw, isJson) in Assignments)
        {
            var value = raw.StartsWith('@') && !isJson ? ReadSource(raw[1..], stdin, key) : raw;
            result[key] = isJson ? Element(ParseJson(key, value)) : Element(Coerce(key, value, properties?[key]));
        }
        return result;
    }

    private static string ReadSource(string path, TextReader stdin, string? key = null)
    {
        if (path == "-") return stdin.ReadToEnd();
        try { return File.ReadAllText(path); }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException)
        {
            // Values such as Android resource references (@xml/config) start with @ too.
            var text = key == null ? "" : $" For text that starts with @, pass it as JSON: {key}:='\"@{path}\"'.";
            throw new UsageException($"Cannot read {path}: {ex.Message}{text}");
        }
    }

    private static JsonElement? Element(JsonNode? node) => node is null ? null : JsonSerializer.SerializeToElement(node);

    private static JsonNode? ParseJson(string key, string text)
    {
        try { return JsonNode.Parse(text); }
        catch (JsonException ex) { throw new UsageException($"{key}:= takes JSON: {ex.Message}"); }
    }

    /// <summary>A text value as the parameter's schema type: integer, number, boolean, array (JSON or comma-separated), object or string.</summary>
    public static JsonNode? Coerce(string key, string text, JsonNode? schema)
    {
        var types = Types(schema);
        if (types.Count == 0 || types.Contains("string")) return JsonValue.Create(text);
        if (text == "null" && types.Contains("null")) return null;
        if (types.Contains("integer"))
        {
            var hex = text.StartsWith("0x", StringComparison.OrdinalIgnoreCase);
            if (long.TryParse(hex ? text[2..] : text, hex ? NumberStyles.AllowHexSpecifier : NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out var n))
                return JsonValue.Create(n);
            throw new UsageException($"{key} takes an integer, not '{text}'.");
        }
        if (types.Contains("number"))
            return double.TryParse(text, NumberStyles.Float, CultureInfo.InvariantCulture, out var d) ? JsonValue.Create(d)
                : throw new UsageException($"{key} takes a number, not '{text}'.");
        if (types.Contains("boolean"))
            return text.ToLowerInvariant() switch
            {
                "true" or "1" or "yes" or "on" => JsonValue.Create(true),
                "false" or "0" or "no" or "off" => JsonValue.Create(false),
                _ => throw new UsageException($"{key} takes true or false, not '{text}'."),
            };
        if (types.Contains("array"))
        {
            if (text.TrimStart().StartsWith('[')) return ParseJson(key, text);
            var items = schema?["items"];
            return new JsonArray([.. text.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries).Select(s => Coerce(key, s, items))]);
        }
        if (types.Contains("object")) return ParseJson(key, text);
        return JsonValue.Create(text);
    }

    /// <summary>The schema's type names ("type" as a string or an array).</summary>
    public static List<string> Types(JsonNode? schema) => schema?["type"] switch
    {
        JsonValue v when v.TryGetValue<string>(out var s) => [s],
        JsonArray arr => [.. arr.Select(n => n?.GetValue<string>()).OfType<string>()],
        _ => [],
    };

    [GeneratedRegex(@"^([A-Za-z_][A-Za-z0-9_]*)(:=|=)")]
    private static partial Regex Assignment();
}
