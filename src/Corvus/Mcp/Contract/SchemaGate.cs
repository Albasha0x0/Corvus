using System.Text;
using System.Text.Json.Nodes;

namespace Corvus.Mcp;

/// <summary>
/// The strictest schema subset model gateways accept (Anthropic-compatible gateways, OpenAI strict tools, Gemini function
/// declarations): one unsupported keyword in one tool rejects the whole request, so every tool must stay inside it.
/// Input schemas: no references or combinators anywhere, one declared type per schema, arrays with typed items, enums typed
/// and without null, nesting at most <see cref="MaxDepth"/>, at most <see cref="MaxInputBytes"/>. Output schemas: no
/// references or combinators, no type unions, the same depth.
/// </summary>
public static class SchemaGate
{
    public const int MaxDepth = 10, MaxInputBytes = 13_312;

    private static readonly string[] Forbidden =
        ["$ref", "$defs", "definitions", "anyOf", "oneOf", "allOf", "not", "if", "then", "else", "const", "patternProperties", "dependentSchemas", "$schema"];

    private static readonly HashSet<string> Types = ["object", "array", "string", "integer", "number", "boolean"];

    public sealed record Problem(string Tool, string Path, string Rule)
    {
        public override string ToString() => $"{Tool}{(Path.Length > 0 ? Path : "/")}: {Rule}";
    }

    /// <summary>The problems of each tools/list entry (name, inputSchema, outputSchema); empty when every tool passes.</summary>
    public static List<Problem> Check(IEnumerable<JsonNode?> tools)
    {
        var problems = new List<Problem>();
        foreach (var tool in tools)
        {
            var name = (string?)tool?["name"] ?? "?";
            if (tool?["inputSchema"] is JsonObject input)
            {
                if (Encoding.UTF8.GetByteCount(input.ToJsonString()) is var bytes && bytes > MaxInputBytes)
                    problems.Add(new(name, "", $"input schema is {bytes} bytes, over {MaxInputBytes}"));
                Walk(input, "", 1, strict: true, name, problems);
            }
            else problems.Add(new(name, "", "no input schema object"));
            if (tool?["outputSchema"] is JsonObject output) Walk(output, "#output", 1, strict: false, name, problems);
        }
        return problems;
    }

    private static void Walk(JsonObject schema, string path, int depth, bool strict, string tool, List<Problem> problems)
    {
        foreach (var keyword in Forbidden)
            if (schema.ContainsKey(keyword)) problems.Add(new(tool, path, $"keyword {keyword}"));
        if (depth > MaxDepth) problems.Add(new(tool, path, $"nested deeper than {MaxDepth}"));
        var type = schema["type"];
        if (type is JsonArray) problems.Add(new(tool, path, "type is a union"));
        else if (strict && (type is not JsonValue v || !Types.Contains((string?)v ?? "")))
            problems.Add(new(tool, path, "no single declared type"));
        if (strict && schema["enum"] is JsonArray values && values.Any(e => e is null)) problems.Add(new(tool, path, "enum contains null"));
        if (strict && (string?)(type as JsonValue) == "array" && schema["items"] is not JsonObject) problems.Add(new(tool, path, "array without items"));

        if (schema["properties"] is JsonObject properties)
            foreach (var (name, child) in properties)
                if (child is JsonObject c) Walk(c, $"{path}/{name}", depth + 1, strict, tool, problems);
        foreach (var key in new[] { "items", "additionalProperties" })
            if (schema[key] is JsonObject child) Walk(child, $"{path}/{key}", depth + 1, strict, tool, problems);
    }
}
