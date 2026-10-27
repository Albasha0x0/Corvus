using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Corvus.Core;

namespace Corvus.Mcp;

/// <summary>Readable text of a record for tools without a renderer: key: value lines, object arrays as columns; file values escaped, one line each.</summary>
internal static class RecordText
{
    private const int MaxColumn = 40, MaxColumns = 12, InlineList = 160;

    /// <summary>Envelope fields that the list header and footer already say.</summary>
    private static readonly HashSet<string> Envelope = ["offset", "limit", "total", "totalExact", "hasMore", "nextOffset", "truncated"];

    public static string Render(JsonObject record, (int Offset, int Shown, int Total, bool Truncated, int Count)? list) => Render(record, "items", list);

    /// <param name="rows">The list's rows array.</param>
    public static string Render(JsonObject record, string rows, (int Offset, int Shown, int Total, bool Truncated, int Count)? list)
    {
        var sb = new StringBuilder();
        foreach (var (key, value) in record)
        {
            if (value is null || list != null && (key == rows || Envelope.Contains(key))) continue;
            Member(sb, key, value, 0);
        }
        if (list is { } l)
        {
            bool exact = !(l.Truncated && l.Offset + l.Count >= l.Total);
            sb.Append($"{(exact ? "" : "≥")}{l.Total} {OutputPager.Noun(l.Total, "row")}")
              .Append(l.Shown == 0 ? (l.Offset > 0 ? $" (none from offset {l.Offset})" : "") : $" (showing {l.Offset + 1}-{l.Offset + l.Shown})").Append(":\n");
            if (record[rows] is JsonArray items) Table(sb, items, 1);
            bool more = l.Offset + l.Shown < l.Total || !exact && l.Shown == l.Count && l.Shown > 0;
            sb.Append(more ? OutputPager.More(l.Offset + l.Shown) : OutputPager.End(l.Total, "row")).Append('\n');
        }
        return sb.ToString();
    }

    private static void Member(StringBuilder sb, string key, JsonNode value, int depth)
    {
        var pad = new string(' ', depth * 2);
        switch (value)
        {
            case JsonObject o when o.Count == 0:
                return;
            case JsonObject o:
                sb.Append(pad).Append(key).Append(":\n");
                foreach (var (k, v) in o)
                    if (v is not null) Member(sb, k, v, depth + 1);
                return;
            case JsonArray { Count: 0 }:
                return;
            case JsonArray a when a.All(e => e is JsonValue):
                var parts = a.Select(e => Cell(e!)).ToList();
                if (parts.Sum(p => p.Length + 2) <= InlineList) sb.Append(pad).Append(key).Append(": ").Append(string.Join(", ", parts)).Append('\n');
                else
                {
                    sb.Append(pad).Append(key).Append($" ({a.Count}):\n");
                    foreach (var p in parts) sb.Append(pad).Append("  ").Append(p).Append('\n');
                }
                return;
            case JsonArray a:
                sb.Append(pad).Append(key).Append($" ({a.Count}):\n");
                Table(sb, a, depth + 1);
                return;
            default:
                sb.Append(pad).Append(key).Append(": ").Append(Cell(value)).Append('\n');
                return;
        }
    }

    /// <summary>Rows as aligned columns under a header; scalar columns in first-seen order, nested values folded into one cell.</summary>
    private static void Table(StringBuilder sb, JsonArray rows, int depth)
    {
        var pad = new string(' ', depth * 2);
        if (rows.Any(r => r is not JsonObject))
        {
            foreach (var r in rows) sb.Append(pad).Append(r is null ? "" : Cell(r)).Append('\n');
            return;
        }
        var columns = new List<string>();
        bool more = false;
        foreach (var r in rows.Cast<JsonObject>())
            foreach (var (k, v) in r)
                if (v is not null && !columns.Contains(k))
                {
                    if (columns.Count < MaxColumns) columns.Add(k);
                    else more = true;
                }
        // Fields past the last column go into one key=value cell, so the text keeps every field of the record.
        var cells = rows.Cast<JsonObject>().Select(r => columns.Select(c => r[c] is { } v ? Cell(v) : "")
            .Concat(more ? [string.Join("; ", r.Where(p => p.Value is not null && !columns.Contains(p.Key)).Select(p => $"{p.Key}={Cell(p.Value!)}"))] : []).ToList()).ToList();
        if (more) columns.Add("more");
        // Columns empty in every row are left out.
        var used = Enumerable.Range(0, columns.Count).Where(i => cells.Any(row => row[i].Length > 0)).ToList();
        var widths = used.Select(i => Math.Min(MaxColumn, Math.Max(columns[i].Length, cells.Max(row => row[i].Length)))).ToList();
        void Line(IReadOnlyList<string> values)
        {
            var line = new StringBuilder(pad);
            for (int j = 0; j < used.Count; j++)
            {
                var v = values[used[j]];
                line.Append(v);
                if (j < used.Count - 1) line.Append(' ', Math.Max(1, widths[j] - v.Length + 2));
            }
            sb.Append(line.ToString().TrimEnd()).Append('\n');
        }
        Line(columns);
        foreach (var row in cells) Line(row);
    }

    /// <summary>One value on one line: strings as they are (markers escaped, line breaks as \n), objects as k=v pairs.</summary>
    private static string Cell(JsonNode value) => value switch
    {
        JsonObject o => string.Join("; ", o.Where(p => p.Value is not null && p.Value is not JsonArray { Count: 0 }).Select(p => $"{p.Key}={Cell(p.Value!)}")),
        JsonArray a => "[" + string.Join(", ", a.Select(e => e is null ? "" : Cell(e))) + "]",
        JsonValue v => v.GetValueKind() switch
        {
            JsonValueKind.String => Format.EscapeMarkers(v.GetValue<string>()).Replace("\r", "\\r").Replace("\n", "\\n"),
            JsonValueKind.True => "true",
            JsonValueKind.False => "false",
            JsonValueKind.Number => v.ToJsonString(),
            _ => v.ToJsonString(),
        },
        _ => "",
    };
}
