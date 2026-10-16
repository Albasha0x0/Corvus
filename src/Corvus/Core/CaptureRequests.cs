using System.Globalization;
using System.Text;
using System.Text.Json;

namespace Corvus.Core;

/// <summary>A WebSocket message of a captured exchange: direction, text (binary as base64) and whether it was binary.</summary>
public sealed record CapturedMessage(bool Sent, string Data, bool Binary);

/// <summary>
/// The request side of one captured exchange, in capture order: headers and cookies (names and values; callers show values
/// only when asked), request body, response type and size, timing, and WebSocket messages. Texts are kept up to
/// <see cref="CaptureRequests.MaxText"/> characters, for GraphQL operations and message shapes.
/// </summary>
public sealed record CapturedRequest(int Index, string Method, string Url, int Status)
{
    public string? HttpVersion { get; init; }
    public IReadOnlyList<KeyValuePair<string, string>> Headers { get; init; } = [];
    public IReadOnlyList<KeyValuePair<string, string>> Cookies { get; init; } = [];
    public string? BodyType { get; init; }
    public long BodySize { get; init; }
    public string? BodyText { get; init; }
    public string? ResponseType { get; init; }
    public long ResponseSize { get; init; }
    /// <summary>The response body as text when it is JSON, an event stream or NDJSON; null otherwise.</summary>
    public string? ResponseText { get; init; }
    public double? TimeMs { get; init; }
    public string? Started { get; init; }
    public IReadOnlyList<CapturedMessage>? Messages { get; init; }
}

/// <summary>The request side of HAR entries and mitmproxy flows (<see cref="Captures"/> reads the files as streams).</summary>
public static class CaptureRequests
{
    /// <summary>Longest body or response text kept per exchange.</summary>
    public const int MaxText = 1 << 20;

    /// <summary>Longest WebSocket message text kept, and messages kept per exchange.</summary>
    private const int MaxMessageText = 64 * 1024, MaxMessages = 10_000;

    /// <summary>
    /// The requests of a HAR, mitmproxy flow or .saz file, streamed in capture order; the capture's kind, or null when the
    /// file is none of these. Without <paramref name="texts"/> bodies, response texts and messages are not kept.
    /// </summary>
    public static string? Read(Stream s, Action<CapturedRequest> request, List<string> notes, bool texts, CancellationToken ct)
    {
        var head = new byte[4096];
        head = head[..s.ReadAtLeast(head, head.Length, throwOnEndOfStream: false)];
        s.Position = 0;
        if (Captures.LooksLikeHar(head)) return ReadHar(s, request, AnalysisLimits.Default.MaxItemBytes, texts, ct) ? Captures.HarKind : null;
        if (Captures.LooksLikeFlows(s))
        {
            ReadFlows(s, request, notes, AnalysisLimits.Default.MaxItemBytes, texts, ct);
            return Captures.FlowKind;
        }
        if (Saz.Looks(s))
        {
            Saz.ReadRequests(s, request, ct);
            return Saz.Kind;
        }
        return null;
    }

    /// <summary>Streams a HAR file's entries as requests; false when there is no log.entries array.</summary>
    public static bool ReadHar(Stream stream, Action<CapturedRequest> request, long maxEntryBytes, bool texts, CancellationToken ct)
    {
        int index = 0;
        return Captures.ReadHarEntries(stream, e => request(FromHar(e, index++, texts)), maxEntryBytes, ct);
    }

    /// <summary>Streams a mitmproxy flow file's HTTP flows as requests.</summary>
    public static void ReadFlows(Stream stream, Action<CapturedRequest> request, List<string> notes, long maxFlowBytes, bool texts, CancellationToken ct)
    {
        int index = 0;
        Captures.ReadFlowObjects(stream, flow =>
        {
            if (FromFlow(flow, index, texts) is not { } r) return false;
            index++;
            request(r);
            return true;
        }, notes, maxFlowBytes, ct);
    }

    internal static CapturedRequest FromHar(JsonElement e, int index, bool texts = true)
    {
        var rq = Member(e, "request");
        var rs = Member(e, "response");
        var headers = Pairs(rq, "headers");
        var cookies = Pairs(rq, "cookies");
        if (cookies.Count == 0) cookies = CookieHeader(headers);
        var post = Member(rq, "postData");
        var content = Member(rs, "content");
        string? bodyText = texts ? Str(post, "text") : null;
        string? responseType = Str(content, "mimeType");
        return new CapturedRequest(index, Str(rq, "method") ?? "?", Str(rq, "url") ?? "", Int(rs, "status"))
        {
            HttpVersion = Str(rq, "httpVersion"),
            Headers = headers,
            Cookies = cookies,
            BodyType = Str(post, "mimeType"),
            BodySize = Long(rq, "bodySize") is > 0 and var b ? b : Encoding.UTF8.GetByteCount(bodyText ?? ""),
            BodyText = Clip(bodyText),
            ResponseType = responseType,
            ResponseSize = Long(content, "size") is > 0 and var size ? size : Math.Max(0, Long(rs, "bodySize")),
            ResponseText = texts && Texty(responseType) ? Clip(HarText(content)) : null,
            TimeMs = e.ValueKind == JsonValueKind.Object && e.TryGetProperty("time", out var t) && t.TryGetDouble(out var ms) && ms >= 0 ? ms : null,
            Started = Str(e, "startedDateTime"),
            Messages = HarMessages(e, texts),
        };
    }

    /// <summary>The response text of a HAR content object: plain, or base64 decoded as UTF-8.</summary>
    private static string? HarText(JsonElement content)
    {
        if (Str(content, "text") is not { } text) return null;
        if (Str(content, "encoding") is not { } enc || !enc.Equals("base64", StringComparison.OrdinalIgnoreCase)) return text;
        try { return Encoding.UTF8.GetString(Convert.FromBase64String(text)); }
        catch (FormatException) { return null; }
    }

    /// <summary>Chrome's _webSocketMessages: type send / receive, opcode 1 (text) or 2 (binary, base64 data).</summary>
    private static List<CapturedMessage>? HarMessages(JsonElement e, bool texts)
    {
        if (e.ValueKind != JsonValueKind.Object || !e.TryGetProperty("_webSocketMessages", out var list) || list.ValueKind != JsonValueKind.Array) return null;
        var messages = new List<CapturedMessage>();
        foreach (var m in list.EnumerateArray())
        {
            if (messages.Count >= MaxMessages) break;
            var data = texts ? Str(m, "data") ?? "" : "";
            messages.Add(new CapturedMessage(Str(m, "type") == "send", data.Length > MaxMessageText ? data[..MaxMessageText] : data, Long(m, "opcode") == 2));
        }
        return messages;
    }

    internal static CapturedRequest? FromFlow(object? flow, int index, bool texts = true)
    {
        if (Captures.Flow(flow) is not { } r || flow is not Dictionary<string, object?> f || f.GetValueOrDefault("request") is not Dictionary<string, object?> rq) return null;
        var rs = f.GetValueOrDefault("response") as Dictionary<string, object?>;
        var headers = FlowPairs(rq.GetValueOrDefault("headers"));
        var body = Bytes(rq.GetValueOrDefault("content"));
        var response = Bytes(rs?.GetValueOrDefault("content"));
        var responseType = FlowPairs(rs?.GetValueOrDefault("headers")).FirstOrDefault(h => h.Key.Equals("content-type", StringComparison.OrdinalIgnoreCase)).Value;
        double? start = Number(rq.GetValueOrDefault("timestamp_start")), end = Number(rs?.GetValueOrDefault("timestamp_end"));
        List<CapturedMessage>? messages = null;
        if (f.GetValueOrDefault("websocket") is Dictionary<string, object?> ws && ws.GetValueOrDefault("messages") is List<object?> list)
        {
            // mitmproxy 7+: [opcode, from_client, content, timestamp]
            messages = [];
            foreach (var m in list.Take(MaxMessages))
                if (m is List<object?> { Count: >= 3 } fields)
                {
                    bool binary = fields[0] is long op && op == 2;
                    var data = Bytes(fields[2]) ?? [];
                    var text = binary ? Convert.ToBase64String(data.AsSpan(0, Math.Min(data.Length, MaxMessageText))) : Encoding.UTF8.GetString(data.AsSpan(0, Math.Min(data.Length, MaxMessageText)));
                    messages.Add(new CapturedMessage(fields[1] is true, text, binary));
                }
        }
        return new CapturedRequest(index, r.Method, r.Url, r.Status)
        {
            HttpVersion = Text(rq.GetValueOrDefault("http_version")),
            Headers = headers,
            Cookies = CookieHeader(headers),
            BodyType = headers.FirstOrDefault(h => h.Key.Equals("content-type", StringComparison.OrdinalIgnoreCase)).Value,
            BodySize = body?.Length ?? 0,
            BodyText = texts && body is { Length: > 0 } ? Clip(Encoding.UTF8.GetString(body.AsSpan(0, Math.Min(body.Length, MaxText)))) : null,
            ResponseType = responseType,
            ResponseSize = response?.Length ?? 0,
            ResponseText = texts && response is { Length: > 0 } && Texty(responseType) ? Encoding.UTF8.GetString(response.AsSpan(0, Math.Min(response.Length, MaxText))) : null,
            TimeMs = start != null && end != null && end >= start ? (end - start) * 1000 : null,
            Started = start != null ? DateTimeOffset.FromUnixTimeMilliseconds((long)(start.Value * 1000)).UtcDateTime.ToString("o", CultureInfo.InvariantCulture) : null,
            Messages = messages,
        };

        static byte[]? Bytes(object? v) => v switch { byte[] b => b, string s => Encoding.UTF8.GetBytes(s), _ => null };
        static double? Number(object? v) => v switch { double d => d, long l => l, _ => null };
        static string? Text(object? v) => v switch { byte[] b => Encoding.UTF8.GetString(b), string s => s, _ => null };
        static List<KeyValuePair<string, string>> FlowPairs(object? headers) =>
            headers is List<object?> list
                ? [.. list.OfType<List<object?>>().Where(p => p.Count == 2).Select(p => new KeyValuePair<string, string>(Text(p[0]) ?? "", Text(p[1]) ?? ""))]
                : [];
    }

    /// <summary>Name=value pairs of every Cookie header.</summary>
    internal static List<KeyValuePair<string, string>> CookieHeader(IEnumerable<KeyValuePair<string, string>> headers) =>
    [
        .. headers.Where(h => h.Key.Equals("cookie", StringComparison.OrdinalIgnoreCase))
            .SelectMany(h => h.Value.Split(';', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries))
            .Select(c => c.Split('=', 2) is [var n, var v] ? new KeyValuePair<string, string>(n.Trim(), v) : new KeyValuePair<string, string>(c, "")),
    ];

    /// <summary>JSON, an event stream or NDJSON / JSON lines: response types whose text is kept for shapes.</summary>
    internal static bool Texty(string? mime)
    {
        var m = (mime ?? "").Split(';')[0].Trim().ToLowerInvariant();
        return m.EndsWith("json", StringComparison.Ordinal) || m.EndsWith("+json", StringComparison.Ordinal) || m is "text/event-stream" or "application/x-ndjson"
            or "application/jsonl" or "application/x-jsonlines" or "application/json-seq";
    }

    private static string? Clip(string? text) => text is { Length: > MaxText } ? text[..MaxText] : text;

    private static JsonElement Member(JsonElement e, string name) =>
        e.ValueKind == JsonValueKind.Object && e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.Object ? v : default;

    private static string? Str(JsonElement e, string name)
    {
        if (e.ValueKind != JsonValueKind.Object || !e.TryGetProperty(name, out var v) || v.ValueKind != JsonValueKind.String) return null;
        try { return v.GetString(); }
        catch (InvalidOperationException) { return null; } // invalid UTF-8 in the string
    }

    private static long Long(JsonElement e, string name) =>
        e.ValueKind == JsonValueKind.Object && e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.Number && v.TryGetInt64(out var l) ? l : 0;

    private static int Int(JsonElement e, string name) => (int)Math.Clamp(Long(e, name), 0, int.MaxValue);

    private static List<KeyValuePair<string, string>> Pairs(JsonElement e, string name)
    {
        var list = new List<KeyValuePair<string, string>>();
        if (e.ValueKind != JsonValueKind.Object || !e.TryGetProperty(name, out var a) || a.ValueKind != JsonValueKind.Array) return list;
        foreach (var p in a.EnumerateArray())
            if (Str(p, "name") is { } n) list.Add(new(n, Str(p, "value") ?? ""));
        return list;
    }
}
