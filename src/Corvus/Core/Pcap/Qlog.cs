using System.Globalization;
using System.Text;
using System.Text.Json;

namespace Corvus.Core.Pcap;

/// <summary>A qlog file in JSON or JSON-SEQ form; malformed input throws <see cref="InvalidDataException"/>.</summary>
internal sealed class Qlog
{
    private const int MaxSummary = 240;
    private const long MaxFile = 1L << 30;

    /// <summary>An event: its trace's index, time in milliseconds as logged, name (category:event) and data as compact JSON.</summary>
    public sealed record Event(int Trace, double? Time, string Name, string Data);

    /// <summary>A trace: its vantage point, title, original destination connection id and its events' counts.</summary>
    public sealed class Trace
    {
        public string Vantage = "unknown";
        public string? Title, Odcid;
        public long Events;
        public double? First, Last;
        public readonly Dictionary<string, long> Counts = new(StringComparer.Ordinal);
        public readonly Dictionary<string, long> PacketsSent = new(StringComparer.Ordinal), PacketsReceived = new(StringComparer.Ordinal);
        public readonly List<string> Closes = [];
        public long Dropped;
        internal string[]? Fields;
    }

    public string Format { get; private set; } = "JSON";
    public string Version { get; private set; } = "unknown";
    public List<Trace> Traces { get; } = [];
    public long Events => Traces.Sum(t => t.Events);

    /// <summary>True when the head is a JSON or JSON-SEQ document that names a qlog version or format.</summary>
    public static bool Looks(ReadOnlySpan<byte> head)
    {
        int at = 0;
        if (head.StartsWith("﻿"u8)) at = 3;
        while (at < head.Length && head[at] is (byte)' ' or (byte)'\t' or (byte)'\r' or (byte)'\n' or 0x1E) at++;
        if (at >= head.Length || head[at] != '{') return false;
        var text = head[at..Math.Min(head.Length, at + 4096)];
        return text.IndexOf("\"qlog_version\""u8) >= 0 || text.IndexOf("\"qlog_format\""u8) >= 0 || text.IndexOf("\"file_schema\":\"urn:ietf:params:qlog"u8) >= 0;
    }

    /// <summary>Reads the file; <paramref name="visit"/> receives each event in file order.</summary>
    public static Qlog Read(Stream s, Action<Event> visit, CancellationToken ct)
    {
        var q = new Qlog();
        var options = new JsonDocumentOptions { MaxDepth = 256, AllowTrailingCommas = true };
        // JsonDocument needs the whole document; 1 GiB bounds it.
        if (s.CanSeek && s.Length > MaxFile) throw new InvalidDataException($"over {MaxFile:N0} bytes");
        var bytes = new MemoryStream();
        s.CopyTo(bytes);
        var all = bytes.GetBuffer().AsMemory(0, (int)bytes.Length);
        int start = 0;
        var span = all.Span;
        if (span.StartsWith("﻿"u8)) start = 3;
        while (start < span.Length && span[start] is (byte)' ' or (byte)'\t' or (byte)'\r' or (byte)'\n') start++;
        try
        {
            if (start < span.Length && span[start] == 0x1E)
            {
                q.Format = "JSON-SEQ";
                var trace = new Trace();
                q.Traces.Add(trace);
                bool header = true;
                int at = start;
                while (at < span.Length)
                {
                    ct.ThrowIfCancellationRequested();
                    int end = span[(at + 1)..].IndexOf((byte)0x1E);
                    end = end < 0 ? span.Length : at + 1 + end;
                    var record = all[(at + 1)..end];
                    at = end;
                    if (record.Span.Trim(" \t\r\n"u8).IsEmpty) continue;
                    using var doc = JsonDocument.Parse(record, options);
                    if (header)
                    {
                        header = false;
                        q.Header(doc.RootElement);
                        if (doc.RootElement.TryGetProperty("trace", out var t) && t.ValueKind == JsonValueKind.Object) Describe(trace, t);
                        continue;
                    }
                    q.Add(0, trace, doc.RootElement, visit);
                }
                return q;
            }
            using var whole = JsonDocument.Parse(all[start..], options);
            var root = whole.RootElement;
            if (root.ValueKind != JsonValueKind.Object) throw new InvalidDataException("the document is not a JSON object");
            q.Header(root);
            if (root.TryGetProperty("traces", out var traces) && traces.ValueKind == JsonValueKind.Array)
                foreach (var t in traces.EnumerateArray())
                {
                    if (t.ValueKind != JsonValueKind.Object) continue;
                    var trace = new Trace();
                    Describe(trace, t);
                    int index = q.Traces.Count;
                    q.Traces.Add(trace);
                    if (t.TryGetProperty("events", out var events) && events.ValueKind == JsonValueKind.Array)
                        foreach (var e in events.EnumerateArray())
                        {
                            ct.ThrowIfCancellationRequested();
                            q.Add(index, trace, e, visit);
                        }
                }
            return q;
        }
        catch (JsonException ex) { throw new InvalidDataException($"not valid JSON: {ex.Message}", ex); }
    }

    private void Header(JsonElement root)
    {
        if (root.ValueKind != JsonValueKind.Object) return;
        if (Text(root, "qlog_version") is { } v) Version = v;
        else if (Text(root, "file_schema") is { } schema) Version = schema;
        if (Text(root, "qlog_format") is { } f && Format != "JSON-SEQ") Format = f;
    }

    private static void Describe(Trace trace, JsonElement t)
    {
        trace.Title = Text(t, "title");
        if (t.TryGetProperty("vantage_point", out var vp) && vp.ValueKind == JsonValueKind.Object) trace.Vantage = Text(vp, "type") ?? "unknown";
        if (t.TryGetProperty("common_fields", out var common) && common.ValueKind == JsonValueKind.Object)
            trace.Odcid = Text(common, "ODCID") ?? Text(common, "group_id");
        if (t.TryGetProperty("event_fields", out var fields) && fields.ValueKind == JsonValueKind.Array)
            trace.Fields = [.. fields.EnumerateArray().Select(f => f.ValueKind == JsonValueKind.String ? f.GetString() ?? "" : "")];
    }

    private void Add(int index, Trace trace, JsonElement e, Action<Event> visit)
    {
        string name;
        double? time = null;
        JsonElement data = default;
        if (e.ValueKind == JsonValueKind.Object)
        {
            name = Text(e, "name") ?? (Text(e, "category") is { } c && Text(e, "event") is { } ev ? $"{c}:{ev}" : "unknown");
            if (e.TryGetProperty("time", out var t) && t.ValueKind == JsonValueKind.Number) time = t.GetDouble();
            else if (e.TryGetProperty("relative_time", out var r) && r.ValueKind == JsonValueKind.Number) time = r.GetDouble();
            e.TryGetProperty("data", out data);
        }
        else if (e.ValueKind == JsonValueKind.Array && trace.Fields is { } fields)
        {
            string? category = null, ev = null;
            int i = 0;
            foreach (var value in e.EnumerateArray())
            {
                if (i >= fields.Length) break;
                switch (fields[i++])
                {
                    case "time" or "relative_time" or "delta_time" when value.ValueKind == JsonValueKind.Number: time = value.GetDouble(); break;
                    case "time" or "relative_time" or "delta_time" when value.ValueKind == JsonValueKind.String:
                        if (double.TryParse(value.GetString(), NumberStyles.Float, CultureInfo.InvariantCulture, out var parsed)) time = parsed;
                        break;
                    case "category": category = value.GetString(); break;
                    case "event" or "event_type": ev = value.GetString(); break;
                    case "data": data = value; break;
                }
            }
            name = category != null && ev != null ? $"{category}:{ev}" : ev ?? "unknown";
        }
        else return;
        trace.Events++;
        trace.Counts[name] = trace.Counts.GetValueOrDefault(name) + 1;
        if (time is double tm)
        {
            trace.First = trace.First is double f ? Math.Min(f, tm) : tm;
            trace.Last = trace.Last is double l ? Math.Max(l, tm) : tm;
        }
        bool hasData = data.ValueKind == JsonValueKind.Object;
        switch (name)
        {
            case "transport:packet_sent" or "quic:packet_sent" when hasData: Count(trace.PacketsSent, data); break;
            case "transport:packet_received" or "quic:packet_received" when hasData: Count(trace.PacketsReceived, data); break;
            case "transport:packet_dropped" or "quic:packet_dropped": trace.Dropped++; break;
            case "connectivity:connection_closed" or "quic:connection_closed" or "transport:connection_closed" when hasData && trace.Closes.Count < 20:
                trace.Closes.Add(Close(data));
                break;
        }
        visit(new Event(index, time, name, data.ValueKind == JsonValueKind.Undefined ? "" : Compact(data)));
    }

    private static void Count(Dictionary<string, long> counts, JsonElement data)
    {
        string type = data.TryGetProperty("header", out var h) && h.ValueKind == JsonValueKind.Object ? Text(h, "packet_type") ?? "unknown" : Text(data, "packet_type") ?? "unknown";
        counts[type] = counts.GetValueOrDefault(type) + 1;
    }

    // A close as text: owner, error code (transport or application) and reason.
    private static string Close(JsonElement d)
    {
        var parts = new List<string>();
        if (Text(d, "owner") is { } owner) parts.Add(owner);
        foreach (var key in new[] { "connection_code", "application_code", "error_code", "internal_code" })
            if (d.TryGetProperty(key, out var v) && v.ValueKind is JsonValueKind.String or JsonValueKind.Number) parts.Add($"{key}={v}");
        if (Text(d, "reason") is { Length: > 0 } reason) parts.Add($"reason \"{reason}\"");
        if (Text(d, "trigger") is { } trigger) parts.Add($"trigger {trigger}");
        return parts.Count == 0 ? "closed" : string.Join(", ", parts);
    }

    private static string? Text(JsonElement e, string name) =>
        e.ValueKind == JsonValueKind.Object && e.TryGetProperty(name, out var v) ? v.ValueKind switch
        {
            JsonValueKind.String => v.GetString(),
            JsonValueKind.Number => v.GetRawText(),
            _ => null,
        } : null;

    /// <summary>Compact JSON of an event's data, cut at <see cref="MaxSummary"/> characters.</summary>
    private static string Compact(JsonElement data)
    {
        var raw = data.GetRawText();
        var sb = new StringBuilder(Math.Min(raw.Length, MaxSummary + 1));
        bool quoted = false, escaped = false;
        foreach (char ch in raw)
        {
            if (sb.Length > MaxSummary) break;
            if (quoted)
            {
                sb.Append(ch);
                if (escaped) escaped = false;
                else if (ch == '\\') escaped = true;
                else if (ch == '"') quoted = false;
            }
            else if (ch == '"') { quoted = true; sb.Append(ch); }
            else if (!char.IsWhiteSpace(ch)) sb.Append(ch);
        }
        return sb.Length > MaxSummary ? sb.ToString(0, MaxSummary) + "..." : sb.ToString();
    }
}
