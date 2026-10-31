using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization.Metadata;
using Corvus.Core;

namespace Corvus.Mcp;

/// <summary>Output schemas: tools/list sends the <see cref="Compact"/> form, docs/schemas the <see cref="Described"/> form tests validate against.</summary>
// Both make nullable properties optional, since results are written without nulls.
public static class OutputSchemas
{
    /// <summary>Object nesting kept in tools/list: the root and its rows.</summary>
    public const int MaxDepth = 2;

    /// <summary>Optional fields every record may carry, declared once in docs/schemas/envelope.json; schemas allow further properties.</summary>
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

    /// <summary>Replaces each local $ref with a copy of its target; a reference cycle ends in an open object.</summary>
    // Gateways that check output schemas reject $ref (SchemaGate).
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

    /// <summary>Rewrites <paramref name="node"/> in place; <paramref name="level"/> counts object schemas down to it, and nullability comes from <paramref name="original"/>.</summary>
    private static void Visit(JsonNode? node, JsonNode original, bool strip, int maxDepth, int level)
    {
        if (node is not JsonObject o) return;
        if (strip)
            foreach (var key in Annotations) o.Remove(key);
        if (o["properties"] is JsonObject properties)
        {
            // A change row's rule id is declared in docs/schemas only; rows allow further properties.
            if (strip && properties.ContainsKey("kind") && properties.ContainsKey("key") && properties.ContainsKey("fields")) properties.Remove("rule");
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
            // The root's list goes after the envelope step reads it.
            if (required is { Count: 0 } || (strip && level > 1)) o.Remove("required");
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

    /// <summary>
    /// Gives each array of <paramref name="schema"/> without an item schema the
    /// one of its element type in <paramref name="type"/>: an open object for
    /// object rows, a converter's own schema for a converted type; other arrays
    /// are left as they are.
    /// </summary>
    public static void TypeItems(JsonNode? schema, Type type, JsonSerializerOptions options) => TypeItems(schema, type, options, 0);

    private static void TypeItems(JsonNode? schema, Type type, JsonSerializerOptions options, int depth)
    {
        // A $ref points at a place this walk reaches by its own path.
        if (schema is not JsonObject o || o.ContainsKey("$ref") || depth > 16) return;
        type = Nullable.GetUnderlyingType(type) ?? type;
        if (o["anyOf"] is JsonArray choices)
            foreach (var choice in choices) TypeItems(choice, type, options, depth + 1);
        var info = options.GetTypeInfo(type);
        switch (info.Kind)
        {
            case JsonTypeInfoKind.Object when o["properties"] is JsonObject properties:
                foreach (var property in info.Properties)
                    TypeItems(properties[property.Name], property.PropertyType, options, depth + 1);
                break;
            case JsonTypeInfoKind.Enumerable when info.ElementType is { } element:
                if (o["items"] is JsonObject { Count: > 0 } items) TypeItems(items, element, options, depth + 1);
                else if (ItemSchema(element, options) is { } derived) o["items"] = derived;
                break;
            case JsonTypeInfoKind.Dictionary when info.ElementType is { } value:
                TypeItems(o["additionalProperties"], value, options, depth + 1);
                break;
        }
    }

    private static JsonNode? ItemSchema(Type element, JsonSerializerOptions options) =>
        element == typeof(object) ? new JsonObject { ["type"] = "object" }
        : options.GetTypeInfo(element).Converter is IJsonSchemaSource source ? source.Schema(options)
        : null;

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
