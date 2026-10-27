using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Corvus.Core;

/// <summary>Value-free shapes of captured messages: JSON keys, event stream and NDJSON groups, GraphQL operations.</summary>
public static partial class MessageShapes
{
    private const int MaxDepth = 4, MaxKeys = 24;

    /// <summary>The sorted key shape of a JSON value; id-like keys become {n} or {id}, a scalar is its type.</summary>
    public static string Of(JsonElement e) => e.ValueKind switch
    {
        JsonValueKind.Object or JsonValueKind.Array => Nested(e, 0),
        JsonValueKind.String => "string",
        JsonValueKind.Number => "number",
        JsonValueKind.True or JsonValueKind.False => "bool",
        _ => "null",
    };

    private static string Nested(JsonElement e, int depth)
    {
        if (e.ValueKind == JsonValueKind.Array)
        {
            var first = e.EnumerateArray().FirstOrDefault();
            return first.ValueKind is JsonValueKind.Object or JsonValueKind.Array ? "[" + (depth >= MaxDepth ? "…" : Nested(first, depth + 1)) + "]" : "[]";
        }
        if (e.ValueKind != JsonValueKind.Object) return "";
        if (depth >= MaxDepth) return "{…}";
        var keys = new SortedDictionary<string, string>(StringComparer.Ordinal);
        foreach (var p in e.EnumerateObject())
        {
            var key = Key(p.Name);
            if (!keys.ContainsKey(key)) keys[key] = p.Value.ValueKind is JsonValueKind.Object or JsonValueKind.Array ? Nested(p.Value, depth + 1) : "";
        }
        var parts = keys.Take(MaxKeys).Select(k => k.Key + k.Value);
        return "{" + string.Join(",", parts) + (keys.Count > MaxKeys ? ",…" : "") + "}";
    }

    private static string Key(string name) =>
        name.Length > 0 && name.All(char.IsAsciiDigit) ? "{n}" : IdLike().IsMatch(name) ? "{id}" : name.Length > 64 ? name[..61] + "..." : name;

    // GUIDs and long hex or base64url tokens, as endpoint templates treat path segments.
    [GeneratedRegex("^([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}|[0-9a-fA-F]{16,}|[A-Za-z0-9_-]{24,})$")]
    private static partial Regex IdLike();

    /// <summary>The shape of JSON text, or null when it is not JSON.</summary>
    public static string? OfText(string text)
    {
        try
        {
            using var doc = JsonDocument.Parse(text, new JsonDocumentOptions { MaxDepth = 64 });
            return Of(doc.RootElement);
        }
        catch (JsonException) { return null; }
    }

    /// <summary>Event stream or NDJSON messages grouped by shape, most frequent first; null for other types.</summary>
    public static (string Format, int Messages, List<(string Shape, int Count)> Groups)? Stream(string? mime, string text)
    {
        var type = (mime ?? "").Split(';')[0].Trim().ToLowerInvariant();
        var counts = new Dictionary<string, int>(StringComparer.Ordinal);
        int messages = 0;
        void Add(string shape) { counts[shape] = counts.GetValueOrDefault(shape) + 1; messages++; }
        string format;
        if (type == "text/event-stream")
        {
            format = "SSE";
            foreach (var block in text.Replace("\r\n", "\n").Split("\n\n", StringSplitOptions.RemoveEmptyEntries))
            {
                string name = "message";
                var data = new StringBuilder();
                bool any = false;
                foreach (var line in block.Split('\n'))
                {
                    if (line.StartsWith("event:", StringComparison.Ordinal)) name = line[6..].Trim();
                    else if (line.StartsWith("data:", StringComparison.Ordinal))
                    {
                        if (any) data.Append('\n');
                        data.Append(line.AsSpan(5).TrimStart(' '));
                        any = true;
                    }
                }
                if (any) Add(name + " " + (OfText(data.ToString()) ?? "text"));
            }
        }
        else if (type is "application/x-ndjson" or "application/jsonl" or "application/x-jsonlines" or "application/json-seq")
        {
            format = "NDJSON";
            foreach (var line in text.Split('\n'))
            {
                var trimmed = line.Trim().Trim('\u001e');
                if (trimmed.Length > 0) Add(OfText(trimmed) ?? "text");
            }
        }
        else return null;
        return (format, messages, [.. counts.OrderByDescending(c => c.Value).ThenBy(c => c.Key, StringComparer.Ordinal).Select(c => (c.Key, c.Value))]);
    }

    /// <summary>The GraphQL operations a request names, from its body or GET parameters.</summary>
    public static List<string> GraphQl(string url, string? body)
    {
        var found = new List<string>();
        if (body is { Length: > 0 } && body.TrimStart() is ['{' or '[', ..])
        {
            try
            {
                using var doc = JsonDocument.Parse(body, new JsonDocumentOptions { MaxDepth = 64 });
                var root = doc.RootElement;
                foreach (var op in root.ValueKind == JsonValueKind.Array ? root.EnumerateArray().Take(100) : [root])
                    if (Operation(op) is { } o) found.Add(o);
            }
            catch (JsonException) { }
        }
        if (found.Count == 0 && Uri.TryCreate(url, UriKind.Absolute, out var uri) && uri.Query.Length > 1)
        {
            string? query = null, name = null;
            foreach (var pair in uri.Query[1..].Split('&'))
            {
                var kv = pair.Split('=', 2);
                if (kv.Length != 2) continue;
                var value = Uri.UnescapeDataString(kv[1].Replace('+', ' '));
                if (kv[0] == "query") query = value;
                else if (kv[0] == "operationName") name = value;
            }
            if (query != null || (name != null && uri.AbsolutePath.Contains("graphql", StringComparison.OrdinalIgnoreCase)))
                found.Add(Describe(query, name));
        }
        return found;

        static string? Operation(JsonElement op)
        {
            if (op.ValueKind != JsonValueKind.Object) return null;
            string? query = op.TryGetProperty("query", out var q) && q.ValueKind == JsonValueKind.String ? q.GetString() : null;
            string? name = op.TryGetProperty("operationName", out var n) && n.ValueKind == JsonValueKind.String ? n.GetString() : null;
            bool persisted = op.TryGetProperty("extensions", out var x) && x.ValueKind == JsonValueKind.Object && x.TryGetProperty("persistedQuery", out _);
            if (query == null && name == null && !persisted) return null;
            return Describe(query, name) + (persisted && query == null ? " (persisted)" : "");
        }
    }

    private static string Describe(string? query, string? name)
    {
        var m = query != null ? OperationHead().Match(query) : null;
        var keyword = m is { Success: true } ? m.Groups[1].Value : "query";
        var named = name ?? (m is { Success: true, Groups: [_, _, { Success: true } g] } ? g.Value : null);
        return $"{keyword} {named ?? "(anonymous)"}";
    }

    // The keyword opens the document after comments; a shorthand "{ ... }" is an anonymous query.
    [GeneratedRegex(@"^\s*(?:#[^\n]*\n\s*)*(query|mutation|subscription)\b\s*([_A-Za-z][_0-9A-Za-z]*)?", RegexOptions.CultureInvariant)]
    private static partial Regex OperationHead();
}
