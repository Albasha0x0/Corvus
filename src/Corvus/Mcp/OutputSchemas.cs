using System.Text.Json;
using System.Text.Json.Nodes;

namespace Corvus.Mcp;

/// <summary>
/// The output-schema policy (SC-11): what tools/list sends is <see cref="Compact"/>, the record's fields and their types (no
/// descriptions, titles or required lists, objects below <see cref="MaxDepth"/> left open, the shared optional envelope
/// fields left to their one declaration in docs/schemas). docs/schemas carries the <see cref="Described"/> form, the full
/// promise that tests validate results against. Both make a nullable property optional, since results are written
/// without nulls (<see cref="Catalog.ToolSerializerOptions"/>).
/// </summary>
public static class OutputSchemas
{
    /// <summary>Object nesting kept in tools/list: the root and its rows.</summary>
    public const int MaxDepth = 2;

    /// <summary>
    /// Optional fields every record may carry (ToolOutput.Envelope), declared once in docs/schemas/envelope.json instead of
    /// in each compact schema; a record that has them still validates, since schemas allow further properties.
    /// </summary>
    public static readonly IReadOnlyList<string> SharedEnvelope = ["notices", "warnings", "coverage", "resultId"];

    private static readonly string[] Annotations = ["description", "title"];

    public static JsonElement Compact(JsonElement schema) => Transform(schema, strip: true, MaxDepth);

    public static JsonElement Described(JsonElement schema) => Transform(schema, strip: false, int.MaxValue);

    private static JsonElement Transform(JsonElement schema, bool strip, int maxDepth)
    {
        var original = JsonNode.Parse(schema.GetRawText())!;
        var root = original.DeepClone();
        Visit(root, original, strip, maxDepth, IsObject(root) ? 1 : 0);
        if (strip && root["properties"] is JsonObject properties)
            foreach (var name in SharedEnvelope)
                if (root["required"] is not JsonArray required || required.All(r => (string?)r != name)) properties.Remove(name);
        if (strip && root is JsonObject top) top.Remove("required");
        DropDanglingReferences(root, root);
        if (strip)
        {
            InlineReferences(root, root, 0);
            // A row copied in for a $ref lands at the reference's depth, which may be below the cap.
            Visit(root, root, strip, maxDepth, IsObject(root) ? 1 : 0);
        }
        return JsonSerializer.SerializeToElement(root);
    }

    /// <summary>
    /// Replaces each local $ref (the SDK's pointer to a row type it already wrote) with a copy of its target: gateways that
    /// check output schemas reject $ref (SchemaGate). A reference cycle ends in an open object.
    /// </summary>
    private static void InlineReferences(JsonNode? node, JsonNode root, int hops)
    {
        switch (node)
        {
            case JsonObject o:
                if (o["$ref"] is JsonValue r)
                {
                    o.Remove("$ref");
                    if (hops < 8 && Resolve(root, (string?)r) is JsonObject target)
                    {
                        var copy = target.DeepClone().AsObject();
                        InlineReferences(copy, root, hops + 1);
                        foreach (var (key, value) in copy.ToList())
                            if (!o.ContainsKey(key)) { copy.Remove(key); o[key] = value; }
                    }
                    else if (!o.ContainsKey("type")) o["type"] = "object";
                }
                foreach (var (_, child) in o.ToList()) InlineReferences(child, root, hops);
                break;
            case JsonArray a:
                foreach (var child in a) InlineReferences(child, root, hops);
                break;
        }
    }

    /// <summary>
    /// Rewrites <paramref name="node"/> in place. <paramref name="level"/> counts the object schemas down to it, itself included;
    /// nullability is read from <paramref name="original"/>, so a $ref keeps its target's.
    /// </summary>
    private static void Visit(JsonNode? node, JsonNode original, bool strip, int maxDepth, int level)
    {
        if (node is not JsonObject o) return;
        if (strip)
            foreach (var key in Annotations) o.Remove(key);
        if (o["properties"] is JsonObject properties)
        {
            var required = o["required"] as JsonArray;
            foreach (var (name, child) in properties.ToList())
            {
                if (child is not JsonObject c) continue;
                if (IsNullable(c, original))
                {
                    WithoutNull(c);
                    if (required != null) Remove(required, name);
                }
            }
            if (required is { Count: 0 } || (strip && level > 1)) o.Remove("required"); // the root's goes after the envelope step reads it
        }
        foreach (var (key, child) in o.ToList())
        {
            switch (key)
            {
                case "properties" or "$defs" when child is JsonObject map:
                    foreach (var (name, sub) in map.ToList())
                        if (Below(sub)) map[name] = Open(sub!);
                        else Visit(sub, original, strip, maxDepth, Level(sub));
                    break;
                case "items" or "additionalProperties" when child is JsonObject:
                    if (Below(child)) o[key] = Open(child);
                    else Visit(child, original, strip, maxDepth, Level(child));
                    break;
                case "anyOf" or "oneOf" or "allOf" when child is JsonArray options:
                    foreach (var option in options) Visit(option, original, strip, maxDepth, level);
                    break;
            }
        }

        int Level(JsonNode? child) => IsObject(child) ? level + 1 : level;
        bool Below(JsonNode? child) => IsObject(child) && level + 1 > maxDepth;
    }

    private static bool IsObject(JsonNode? schema) => schema is JsonObject o && (o["properties"] is not null || o["type"] switch
    {
        JsonValue t => (string?)t == "object",
        JsonArray types => types.Any(t => (string?)t == "object"),
        _ => false,
    });

    /// <summary>An object below the depth cap: any object, nullable if it was.</summary>
    private static JsonObject Open(JsonNode schema) => new() { ["type"] = schema["type"]?.DeepClone() ?? "object" };

    private static bool IsNullable(JsonObject schema, JsonNode root, int hops = 0)
    {
        if (schema["type"] is JsonArray types && types.Any(t => (string?)t == "null")) return true;
        if (schema["enum"] is JsonArray values && values.Any(v => v is null)) return true;
        if (schema["anyOf"] is JsonArray options && options.Any(x => x is JsonObject a && (string?)a["type"] == "null")) return true;
        return hops < 8 && schema["$ref"] is JsonValue r && Resolve(root, (string?)r) is JsonObject target && IsNullable(target, root, hops + 1);
    }

    private static void WithoutNull(JsonObject schema)
    {
        if (schema["type"] is JsonArray types)
        {
            var kept = types.Where(t => (string?)t != "null").Select(t => (string)t!).ToList();
            schema["type"] = kept.Count == 1 ? JsonValue.Create(kept[0]) : new JsonArray([.. kept.Select(k => (JsonNode)JsonValue.Create(k)!)]);
        }
        if (schema["enum"] is JsonArray values)
            for (int i = values.Count - 1; i >= 0; i--)
                if (values[i] is null) values.RemoveAt(i);
        if (schema["anyOf"] is JsonArray options)
        {
            for (int i = options.Count - 1; i >= 0; i--)
                if (options[i] is JsonObject a && (string?)a["type"] == "null") options.RemoveAt(i);
            if (options.Count == 1 && options[0] is JsonObject only)
            {
                schema.Remove("anyOf");
                foreach (var (k, v) in only.ToList()) { only.Remove(k); schema[k] = v; }
            }
        }
    }

    private static void Remove(JsonArray names, string name)
    {
        for (int i = names.Count - 1; i >= 0; i--)
            if ((string?)names[i] == name) names.RemoveAt(i);
    }

    /// <summary>A $ref into an object the depth cap opened has nothing to point at: it accepts any value.</summary>
    private static void DropDanglingReferences(JsonNode? node, JsonNode root)
    {
        switch (node)
        {
            case JsonObject o:
                if (o["$ref"] is JsonValue r && Resolve(root, (string?)r) is null)
                {
                    o.Remove("$ref");
                    o.Remove("items");
                }
                foreach (var (_, child) in o.ToList()) DropDanglingReferences(child, root);
                // An empty items schema accepts any value, as no items keyword does.
                if (o["items"] is JsonObject { Count: 0 }) o.Remove("items");
                break;
            case JsonArray a:
                foreach (var child in a) DropDanglingReferences(child, root);
                break;
        }
    }

    /// <summary>A local JSON pointer ("#", "#/properties/a/items").</summary>
    internal static JsonNode? Resolve(JsonNode root, string? reference)
    {
        if (reference is null || !reference.StartsWith('#')) return null;
        JsonNode? current = root;
        foreach (var raw in reference[1..].Split('/', StringSplitOptions.RemoveEmptyEntries))
        {
            var part = raw.Replace("~1", "/").Replace("~0", "~");
            current = current switch
            {
                JsonObject o when o.TryGetPropertyValue(part, out var next) => next,
                JsonArray a when int.TryParse(part, out var i) && i < a.Count => a[i],
                _ => null,
            };
            if (current is null) return null;
        }
        return current;
    }
}
