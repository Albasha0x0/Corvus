using System.Text.Json;
using System.Text.Json.Nodes;

namespace Corvus.Mcp;

/// <summary>
/// Structured content for tools that keep their readable text as the text block. Such a tool is declared with
/// UseStructuredContent and OutputSchemaType (the record), returns its text, and hands the record to
/// <see cref="With"/>; the call filter puts the record in structuredContent. Called directly (tests), the tool returns the
/// same text and the record is dropped.
/// </summary>
public static class StructuredOutput
{
    /// <summary>The record of the call in progress.</summary>
    public sealed class Collector
    {
        public object? Value { get; internal set; }
    }

    private static readonly AsyncLocal<Collector?> Current = new();

    /// <summary>Starts collecting for one tool call; the collector flows into the tool's tasks.</summary>
    public static Collector Begin() => Current.Value = new Collector();

    /// <summary>Records <paramref name="structured"/> as the call's structured content and returns <paramref name="text"/>.</summary>
    public static string With(string text, object structured)
    {
        if (Current.Value is { } c) c.Value = structured;
        return text;
    }

    /// <summary>
    /// The record as JSON, at most <paramref name="maxChars"/> long: past that, the top-level "items" array (else the largest
    /// top-level array) is cut from the end and "truncated" set, so the result stays within the response limit and still
    /// matches the output schema. Callers page on with offset = offset + the number of items received.
    /// </summary>
    public static JsonElement Serialize(object value, int maxChars)
    {
        var node = JsonSerializer.SerializeToNode(value, value.GetType(), Catalog.ToolSerializerOptions)!;
        if (node is JsonObject o && o.ToJsonString(Catalog.ToolSerializerOptions).Length > maxChars)
        {
            var array = o["items"] as JsonArray
                        ?? o.Select(p => p.Value).OfType<JsonArray>().OrderByDescending(a => a.ToJsonString().Length).FirstOrDefault();
            int length;
            while (array is { Count: > 0 } && (length = o.ToJsonString(Catalog.ToolSerializerOptions).Length) > maxChars)
            {
                // In proportion to the excess, and at least one item.
                int keep = Math.Min(array.Count - 1, (int)(array.Count * 0.9 * maxChars / length));
                while (array.Count > keep) array.RemoveAt(array.Count - 1);
                if (o.ContainsKey("truncated")) o["truncated"] = true;
            }
        }
        return JsonSerializer.SerializeToElement(node, Catalog.ToolSerializerOptions);
    }
}
