using System.Text.Json;
using System.Text.Json.Nodes;
using ModelContextProtocol.Server;

namespace Corvus.Mcp;

public static partial class ToolOutput
{
    /// <summary>
    /// Output schemas as <see cref="Finish"/> sends records: list schemas get the list envelope instead of truncated, every
    /// schema the optional notices, warnings, coverage and resultId, code and bytes tools their page fields; nullable
    /// properties are optional (nulls are omitted) and timing fields are gone (they move to _meta).
    /// </summary>
    public static void ApplyEnvelope(IEnumerable<McpServerTool> tools)
    {
        foreach (var tool in tools)
            if (tool.ProtocolTool.OutputSchema is { } schema && JsonNode.Parse(schema.GetRawText()) is JsonObject root)
            {
                Envelope(root, ToolContract.Of(tool.ProtocolTool.Name).Output, tool.ProtocolTool.Name);
                tool.ProtocolTool.OutputSchema = JsonSerializer.SerializeToElement(root);
            }
    }

    /// <summary>
    /// List records whose rows are not yet named items (families rename them); the first non-empty array holds the page.
    /// </summary>
    internal static readonly IReadOnlyDictionary<string, string[]> RowArrays = new Dictionary<string, string[]>(StringComparer.Ordinal)
    {
        ["get_android_device_info"] = ["properties"],
        ["compare_folders"] = ["entries"],
    };

    internal static void Envelope(JsonObject root, OutputClass output, string? tool = null)
    {
        OptionalNullables(root);
        if (root["properties"] is not JsonObject properties) return;
        var required = root["required"] as JsonArray;
        void Remove(string name)
        {
            properties.Remove(name);
            if (required?.FirstOrDefault(r => r?.GetValue<string>() == name) is { } r) required.Remove(r);
        }
        void Add(string name, JsonNode schema)
        {
            if (!properties.ContainsKey(name)) properties[name] = schema;
        }
        foreach (var f in TimingFields) Remove(f);
        if (IsListSchema(properties, tool))
        {
            Remove("truncated");
            Add("limit", Type("integer"));
            Add("totalExact", Type("boolean"));
            Add("hasMore", Type("boolean"));
            if (properties["offset"] is JsonObject o && Is(o, "integer")) Add("nextOffset", Type("integer"));
        }
        else if (output is OutputClass.Code or OutputClass.Bytes)
        {
            Add("code", Type("string"));
            Add("offset", Type("integer"));
            Add("nextOffset", Type("integer"));
            Add("totalChars", Type("integer"));
        }
        Add("notices", Strings());
        Add("warnings", Strings());
        Add("coverage", Type("object"));
        Add("resultId", Type("string"));
    }

    /// <summary>A total beside "items" or the tool's row arrays (as <see cref="RowsKey"/> reads records).</summary>
    internal static bool IsListSchema(JsonObject properties, string? tool) =>
        properties["total"] is JsonObject t && Is(t, "integer")
        && (tool != null && RowArrays.TryGetValue(tool, out var named) ? named : ["items"]).Any(k => properties[k] is JsonObject a && Is(a, "array"));

    private static bool Is(JsonObject schema, string type) => schema["type"] switch
    {
        JsonValue v => v.GetValue<string>() == type,
        JsonArray a => a.Any(e => e?.GetValue<string>() == type),
        _ => false,
    };

    private static JsonObject Type(string type) => new() { ["type"] = type };

    private static JsonObject Strings() => new() { ["type"] = "array", ["items"] = Type("string") };

    /// <summary>Drops nullable properties from "required" at every level: a null is sent as an omitted member.</summary>
    private static void OptionalNullables(JsonNode? node)
    {
        switch (node)
        {
            case JsonObject o:
                if (o["properties"] is JsonObject props && o["required"] is JsonArray required)
                {
                    foreach (var r in required.Where(r => props[r!.GetValue<string>()] is JsonObject p && Nullable(p)).ToList()) required.Remove(r);
                    if (required.Count == 0) o.Remove("required");
                }
                foreach (var (_, child) in o) OptionalNullables(child);
                break;
            case JsonArray a:
                foreach (var child in a) OptionalNullables(child);
                break;
        }
    }

    private static bool Nullable(JsonObject schema) =>
        schema["type"] is JsonArray a && a.Any(e => e?.GetValue<string>() == "null")
        || schema["type"] is JsonValue v && v.GetValue<string>() == "null"
        || (schema["anyOf"] ?? schema["oneOf"]) is JsonArray options && options.Any(e => e is JsonObject x && Nullable(x));
}
