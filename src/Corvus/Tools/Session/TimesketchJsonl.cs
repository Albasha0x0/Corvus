using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Corvus.Tools;

/// <summary>Timesketch events (JSONL) projected from the UTC timestamps in a kept result's items.</summary>
internal static class TimesketchJsonl
{
    /// <summary>The JSONL lines and what was counted: items scanned, events written, time values skipped.</summary>
    internal sealed record Projection(string Lines, int Items, int Events, int Skipped);

    private static readonly Regex Stamp = new(@"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d{1,7})?(?<z>Z|[+-]\d\d:\d\d)?$",
        RegexOptions.CultureInvariant | RegexOptions.NonBacktracking);

    private static readonly string[] Labels = ["name", "path", "file", "entry", "title", "id"];
    private static readonly HashSet<string> Reserved = new(["message", "datetime", "timestamp", "timestamp_desc", "data_type"], StringComparer.Ordinal);

    /// <summary>Returns one event per zoned timestamp; counts others as skipped. Throws JsonException on bad JSON.</summary>
    internal static Projection From(string tool, string record)
    {
        using var doc = JsonDocument.Parse(record);
        var sb = new StringBuilder();
        int items = 0, events = 0, skipped = 0;
        foreach (var item in ReadResultView.Items(doc.RootElement))
        {
            items++;
            var found = new List<(string Path, DateTimeOffset At)>();
            Walk(item, "", found, ref skipped);
            if (found.Count == 0) continue;
            var label = Label(item) ?? $"item {items}";
            foreach (var (path, at) in found)
            {
                var line = new Dictionary<string, object?>
                {
                    ["message"] = $"{path}: {label}",
                    ["datetime"] = at.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss.ffffff'+00:00'", CultureInfo.InvariantCulture),
                    ["timestamp_desc"] = path,
                    ["data_type"] = "corvus:" + tool,
                };
                if (item.ValueKind == JsonValueKind.Object)
                    foreach (var p in item.EnumerateObject())
                        if (!Reserved.Contains(p.Name) && (p.Value.ValueKind is JsonValueKind.String or JsonValueKind.Number or JsonValueKind.True or JsonValueKind.False) && !Stamp.IsMatch(p.Value.ToString()))
                            line[p.Name] = p.Value.Clone();
                sb.Append(JsonSerializer.Serialize(line)).Append('\n');
                events++;
            }
        }
        return new Projection(sb.ToString(), items, events, skipped);
    }

    private static string? Label(JsonElement item)
    {
        if (item.ValueKind != JsonValueKind.Object) return null;
        foreach (var key in Labels)
            if (item.TryGetProperty(key, out var v) && v.ValueKind == JsonValueKind.String && v.GetString() is { Length: > 0 } s) return s;
        return null;
    }

    private static void Walk(JsonElement e, string path, List<(string, DateTimeOffset)> found, ref int skipped)
    {
        switch (e.ValueKind)
        {
            case JsonValueKind.Object:
                foreach (var p in e.EnumerateObject()) Walk(p.Value, path.Length == 0 ? p.Name : path + "." + p.Name, found, ref skipped);
                break;
            case JsonValueKind.Array:
                foreach (var v in e.EnumerateArray()) Walk(v, path, found, ref skipped);
                break;
            case JsonValueKind.String when Stamp.Match(e.GetString()!) is { Success: true } m:
                var s = e.GetString()!;
                // Seconds before the epoch (UTC) are refused, not clamped.
                if (m.Groups["z"].Success && DateTimeOffset.TryParse(s, CultureInfo.InvariantCulture, DateTimeStyles.None, out var at) && at.ToUnixTimeSeconds() >= 0)
                    found.Add((path.Length == 0 ? "time" : path, at));
                else skipped++;
                break;
        }
    }
}
