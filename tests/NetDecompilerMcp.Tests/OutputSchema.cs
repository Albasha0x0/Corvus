using System.Text.Json;

namespace NetDecompilerMcp.Tests;

/// <summary>Minimal JSON Schema validator for SDK-generated output schemas; unsupported keywords are ignored.</summary>
public static class OutputSchema
{
    /// <summary>The schema violations of <paramref name="value"/>, as "path: problem" lines (empty when it conforms).</summary>
    public static List<string> Validate(JsonElement schema, JsonElement value) => Validate(schema, schema, value);

    /// <summary>Validates against <paramref name="schema"/>, a part of <paramref name="root"/> (which its references resolve in).</summary>
    public static List<string> Validate(JsonElement root, JsonElement schema, JsonElement value)
    {
        var errors = new List<string>();
        Check(root, schema, value, "data", errors, 0);
        return errors;
    }

    private static void Check(JsonElement root, JsonElement schema, JsonElement value, string path, List<string> errors, int depth)
    {
        if (depth > 64 || schema.ValueKind != JsonValueKind.Object) return;
        if (schema.TryGetProperty("$ref", out var reference) && reference.GetString() is { } r)
        {
            if (Resolve(root, r) is { } target) Check(root, target, value, path, errors, depth + 1);
            return;
        }
        foreach (var keyword in new[] { "anyOf", "oneOf" })
        {
            if (!schema.TryGetProperty(keyword, out var options)) continue;
            if (!options.EnumerateArray().Any(o => { var e = new List<string>(); Check(root, o, value, path, e, depth + 1); return e.Count == 0; }))
                errors.Add($"{path}: matches none of the {keyword} options");
            return;
        }

        if (schema.TryGetProperty("type", out var type))
        {
            var allowed = type.ValueKind == JsonValueKind.Array ? type.EnumerateArray().Select(t => t.GetString()).ToList() : [type.GetString()];
            if (!allowed.Any(t => Is(value, t)))
            {
                errors.Add($"{path}: {value.ValueKind} is not {string.Join(" or ", allowed)}");
                return;
            }
        }
        if (value.ValueKind == JsonValueKind.Object)
        {
            if (schema.TryGetProperty("required", out var required))
                foreach (var name in required.EnumerateArray().Select(n => n.GetString()!))
                    if (!value.TryGetProperty(name, out _)) errors.Add($"{path}: missing required property '{name}'");
            if (schema.TryGetProperty("properties", out var properties))
                foreach (var p in properties.EnumerateObject())
                    if (value.TryGetProperty(p.Name, out var child)) Check(root, p.Value, child, $"{path}/{p.Name}", errors, depth + 1);
        }
        else if (value.ValueKind == JsonValueKind.Array && schema.TryGetProperty("items", out var items))
        {
            int i = 0;
            foreach (var item in value.EnumerateArray()) Check(root, items, item, $"{path}/{i++}", errors, depth + 1);
        }
    }

    private static bool Is(JsonElement value, string? type) => type switch
    {
        "null" => value.ValueKind == JsonValueKind.Null,
        "object" => value.ValueKind == JsonValueKind.Object,
        "array" => value.ValueKind == JsonValueKind.Array,
        "string" => value.ValueKind == JsonValueKind.String,
        "boolean" => value.ValueKind is JsonValueKind.True or JsonValueKind.False,
        "integer" => value.ValueKind == JsonValueKind.Number && value.TryGetInt64(out _),
        "number" => value.ValueKind == JsonValueKind.Number,
        _ => true,
    };

    /// <summary>A local reference: "#", "#/$defs/X", "#/properties/a/items" (JSON pointer).</summary>
    internal static JsonElement? Resolve(JsonElement root, string reference)
    {
        if (!reference.StartsWith('#')) return null;
        var current = root;
        foreach (var raw in reference[1..].Split('/', StringSplitOptions.RemoveEmptyEntries))
        {
            var part = raw.Replace("~1", "/").Replace("~0", "~");
            if (current.ValueKind == JsonValueKind.Object && current.TryGetProperty(part, out var next)) current = next;
            else if (current.ValueKind == JsonValueKind.Array && int.TryParse(part, out var index) && index < current.GetArrayLength()) current = current[index];
            else return null;
        }
        return current;
    }
}
