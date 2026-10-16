using System.Globalization;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Corvus.Core;

/// <summary>One captured HTTP exchange: what was asked, what came back, and the response body as sent (still content-encoded).</summary>
public sealed record CapturedResponse(string Method, string Url, int Status, string? MimeType, string? ContentEncoding, byte[]? Body, string? Problem);

/// <summary>
/// Traffic captures as containers of responses: HAR (browser and proxy exports, JSON) and mitmproxy flow files (tnetstrings).
/// Each response body becomes a file named after its URL (host/path, the query folded into a short hash), decoded by its
/// Content-Encoding (gzip, deflate, br, zstd) within the size limits. Nothing is fetched or replayed.
/// </summary>
public static class Captures
{
    public const string HarKind = "HAR capture (HTTP responses)";
    public const string FlowKind = "mitmproxy flows (HTTP responses)";

    /// <summary>JSON text whose root object has a "log" member near the start.</summary>
    public static bool LooksLikeHar(ReadOnlySpan<byte> b)
    {
        if (b.StartsWith((ReadOnlySpan<byte>)[0xEF, 0xBB, 0xBF])) b = b[3..];
        int i = 0;
        while (i < b.Length && b[i] is (byte)' ' or (byte)'\t' or (byte)'\r' or (byte)'\n') i++;
        return i < b.Length && b[i] == '{' && b[i..Math.Min(b.Length, i + 4096)].IndexOf("\"log\""u8) >= 0;
    }

    /// <summary>A tnetstring dictionary at the start ("&lt;length&gt;:&lt;data&gt;}").</summary>
    public static bool LooksLikeFlows(ReadOnlySpan<byte> b) =>
        FirstFlowEnd(b) is { } end && end < b.Length && b[(int)end] == '}';

    /// <summary>A tnetstring dictionary at the start of a seekable stream, its type byte read where its length prefix says.</summary>
    public static bool LooksLikeFlows(Stream s)
    {
        Span<byte> head = stackalloc byte[11];
        s.Position = 0;
        if (FirstFlowEnd(head[..s.ReadAtLeast(head, head.Length, throwOnEndOfStream: false)]) is not { } end || end >= s.Length) return false;
        s.Position = end;
        bool flows = s.ReadByte() == '}';
        s.Position = 0;
        return flows;
    }

    /// <summary>Where the type byte of the tnetstring at the start of <paramref name="b"/> is, from its length prefix.</summary>
    private static long? FirstFlowEnd(ReadOnlySpan<byte> b)
    {
        int colon = b[..Math.Min(b.Length, 11)].IndexOf((byte)':');
        if (colon <= 0) return null;
        foreach (var c in b[..colon]) if (!char.IsAsciiDigit((char)c)) return null;
        return long.TryParse(Encoding.ASCII.GetString(b[..colon]), NumberStyles.None, CultureInfo.InvariantCulture, out long length) ? colon + 1 + length : null;
    }

    /// <summary>The responses of a HAR file; null when the JSON has no log.entries array (another JSON document).</summary>
    public static List<CapturedResponse>? ReadHar(byte[] data)
    {
        var result = new List<CapturedResponse>();
        using var s = new MemoryStream(data, writable: false);
        return ReadHar(s, result.Add, AnalysisLimits.Default.MaxItemBytes, default) ? result : null;
    }

    /// <summary>
    /// Streams a HAR file: each element of log.entries is parsed on its own and handed to <paramref name="response"/>, so memory
    /// holds one entry (at most <paramref name="maxEntryBytes"/> of JSON) rather than the document. False when there is no
    /// log.entries array. Without <paramref name="bodies"/> the response bodies are not decoded (Body null).
    /// </summary>
    public static bool ReadHar(Stream stream, Action<CapturedResponse> response, long maxEntryBytes, CancellationToken ct, bool bodies = true) =>
        ReadHarEntries(stream, e => response(Response(e, bodies)), maxEntryBytes, ct);

    /// <summary>Streams the elements of log.entries, each parsed on its own; false when there is no log.entries array.</summary>
    internal static bool ReadHarEntries(Stream stream, Action<JsonElement> entry, long maxEntryBytes, CancellationToken ct)
    {
        var buffer = new byte[1 << 16];
        int length = 0;
        bool final = false, sawEntries = false, inLog = false, inEntries = false;
        bool rootIsLog = false, logIsEntries = false;
        var state = new JsonReaderState(new JsonReaderOptions { MaxDepth = 64 });
        long offset = 0;
        try
        {
            while (true)
            {
                ct.ThrowIfCancellationRequested();
                int read = stream.Read(buffer, length, buffer.Length - length);
                if (read == 0) final = true;
                length += read;
                if (offset == 0 && length >= 3 && buffer.AsSpan(0, 3).SequenceEqual((ReadOnlySpan<byte>)[0xEF, 0xBB, 0xBF]))
                {
                    Array.Copy(buffer, 3, buffer, 0, length -= 3);
                    offset = 3;
                }
                var reader = new Utf8JsonReader(buffer.AsSpan(0, length), final, state);
                long consumed = 0;
                var resume = state;
                while (true)
                {
                    var before = reader.CurrentState;
                    long at = reader.BytesConsumed;
                    if (!reader.Read()) { consumed = at; resume = before; break; }
                    int depth = reader.CurrentDepth;
                    switch (reader.TokenType)
                    {
                        case JsonTokenType.PropertyName when depth == 1:
                            rootIsLog = reader.ValueTextEquals("log"u8);
                            break;
                        case JsonTokenType.PropertyName when depth == 2 && inLog:
                            logIsEntries = reader.ValueTextEquals("entries"u8);
                            break;
                        case JsonTokenType.StartObject when depth == 1 && rootIsLog:
                            inLog = true;
                            break;
                        case JsonTokenType.EndObject when depth == 1 && inLog:
                            inLog = false;
                            break;
                        case JsonTokenType.StartArray when depth == 2 && inLog && logIsEntries:
                            inEntries = sawEntries = true;
                            break;
                        case JsonTokenType.EndArray when depth == 2 && inEntries:
                            inEntries = false;
                            break;
                        case JsonTokenType.StartObject when depth == 3 && inEntries:
                            var probe = reader;
                            if (!probe.TrySkip()) { consumed = at; resume = before; goto refill; }
                            using (var document = JsonDocument.ParseValue(ref reader)) entry(document.RootElement);
                            break;
                        case JsonTokenType.StartArray or JsonTokenType.String or JsonTokenType.Number or JsonTokenType.True or JsonTokenType.False or JsonTokenType.Null
                            when depth == 0:
                            return false; // the root is not an object
                    }
                }
                refill:
                if (final) break;
                offset += consumed;
                state = resume;
                Array.Copy(buffer, consumed, buffer, 0, length - consumed);
                length -= (int)consumed;
                if (length == buffer.Length)
                {
                    if (buffer.Length >= maxEntryBytes)
                        throw new ToolError(ErrorCode.LimitExceeded, $"A HAR entry at byte {offset:N0} is larger than {maxEntryBytes:N0} bytes.");
                    Array.Resize(ref buffer, (int)Math.Min(Math.Min((long)buffer.Length * 2, maxEntryBytes), Array.MaxLength));
                }
            }
        }
        catch (JsonException ex) { throw new ToolError(ErrorCode.MalformedInput, $"Damaged HAR file: {ex.Message}"); }
        return sawEntries;
    }

    private static CapturedResponse Response(JsonElement e, bool bodies)
    {
        var request = e.TryGetProperty("request", out var rq) && rq.ValueKind == JsonValueKind.Object ? rq : default;
        var response = e.TryGetProperty("response", out var rs) && rs.ValueKind == JsonValueKind.Object ? rs : default;
        string method = Str(request, "method") ?? "?", url = Str(request, "url") ?? "";
        int status = response.ValueKind == JsonValueKind.Object && response.TryGetProperty("status", out var st) && st.TryGetInt32(out var s) ? s : 0;
        string? encoding = HarHeader(response, "content-encoding");
        byte[]? body = null;
        string? mime = null, problem = null;
        if (response.ValueKind == JsonValueKind.Object && response.TryGetProperty("content", out var content) && content.ValueKind == JsonValueKind.Object)
        {
            mime = Str(content, "mimeType");
            if (bodies && Str(content, "text") is { } text)
            {
                if (Str(content, "encoding") is { } enc && enc.Equals("base64", StringComparison.OrdinalIgnoreCase))
                {
                    try { body = Convert.FromBase64String(text); }
                    catch (FormatException) { problem = "invalid base64 body"; }
                }
                else
                {
                    body = Encoding.UTF8.GetBytes(text);
                    encoding = null; // HAR text is the decoded body
                }
            }
        }
        return new CapturedResponse(method, url, status, mime, encoding, body, problem);

        static string? Str(JsonElement e, string name)
        {
            if (e.ValueKind != JsonValueKind.Object || !e.TryGetProperty(name, out var v) || v.ValueKind != JsonValueKind.String) return null;
            try { return v.GetString(); }
            catch (InvalidOperationException) { return null; } // invalid UTF-8 in the string
        }

        static string? HarHeader(JsonElement response, string name)
        {
            if (response.ValueKind != JsonValueKind.Object || !response.TryGetProperty("headers", out var headers) || headers.ValueKind != JsonValueKind.Array) return null;
            foreach (var h in headers.EnumerateArray())
                if (Str(h, "name") is { } n && n.Equals(name, StringComparison.OrdinalIgnoreCase)) return Str(h, "value");
            return null;
        }
    }

    public static List<CapturedResponse> ReadFlows(byte[] data, List<string> notes, CancellationToken ct)
    {
        var result = new List<CapturedResponse>();
        ReadFlows(new MemoryStream(data, writable: false), result.Add, notes, long.MaxValue, ct);
        return result;
    }

    /// <summary>
    /// Streams a mitmproxy flow file: each top-level flow is read and parsed on its own, so memory holds one flow (at most
    /// <paramref name="maxFlowBytes"/>) rather than the file. HTTP flows go to <paramref name="response"/>.
    /// </summary>
    public static void ReadFlows(Stream stream, Action<CapturedResponse> response, List<string> notes, long maxFlowBytes, CancellationToken ct) =>
        ReadFlowObjects(stream, flow =>
        {
            if (Flow(flow) is not { } r) return false;
            response(r);
            return true;
        }, notes, maxFlowBytes, ct);

    /// <summary>Streams the top-level flows of a mitmproxy flow file as tnetstring values; <paramref name="flow"/> says whether it took the flow (an HTTP one).</summary>
    internal static void ReadFlowObjects(Stream stream, Func<object?, bool> flow, List<string> notes, long maxFlowBytes, CancellationToken ct)
    {
        long length = stream.Length;
        // flows are read through a window, so small ones cost no seek each
        var window = new byte[(int)Math.Min(1 << 20, Math.Max(length, 1))];
        long start = 0;
        int filled = 0;
        ReadOnlySpan<byte> At(long at, int count)
        {
            if (at < start || at + count > start + filled)
            {
                stream.Position = start = at;
                filled = stream.ReadAtLeast(window, (int)Math.Min(window.Length, length - at), throwOnEndOfStream: false);
            }
            return window.AsSpan((int)(at - start), (int)Math.Min(count, start + filled - at));
        }
        int read = 0, other = 0;
        for (long at = 0; at < length;)
        {
            ct.ThrowIfCancellationRequested();
            // a length past the file is left to the parser, which says so; one that fits but is too large stops the read
            long size = FirstFlowEnd(At(at, 11)) is { } end && end < length - at ? end + 1 : length - at;
            if (size > maxFlowBytes)
            {
                notes.Add($"A flow at byte {at:N0} is larger than {maxFlowBytes:N0} bytes; {read} flow(s) read before it.");
                break;
            }
            byte[] buffer;
            if (size <= window.Length) buffer = At(at, (int)size).ToArray();
            else
            {
                buffer = new byte[size];
                stream.Position = at;
                stream.ReadExactly(buffer);
            }
            int p = 0;
            object? value;
            try { value = TNetString.Read(buffer, ref p, 0); }
            catch (FormatException ex)
            {
                notes.Add($"Flow file damaged at byte {at + p}: {ex.Message}; {read} flow(s) read before it.");
                break;
            }
            at += p;
            if (flow(value)) read++;
            else other++;
        }
        if (other > 0) notes.Add($"{other} flow(s) that are not HTTP (WebSocket, TCP, DNS) or have no request skipped.");
    }

    /// <summary>An HTTP flow's request and response; null for another kind of flow or one without a request.</summary>
    internal static CapturedResponse? Flow(object? flow)
    {
        if (flow is not Dictionary<string, object?> f) return null;
        if (Text(f.GetValueOrDefault("type")) is { } type && type != "http") return null;
        if (f.GetValueOrDefault("request") is not Dictionary<string, object?> request) return null;
        var response = f.GetValueOrDefault("response") as Dictionary<string, object?>;
        string scheme = Text(request.GetValueOrDefault("scheme")) ?? "http", host = Text(request.GetValueOrDefault("host")) ?? "",
            path = Text(request.GetValueOrDefault("path")) ?? "/";
        long port = request.GetValueOrDefault("port") is long p ? p : 0;
        bool defaultPort = port == 0 || (scheme == "https" && port == 443) || (scheme == "http" && port == 80);
        var url = path.StartsWith("http", StringComparison.OrdinalIgnoreCase) ? path : $"{scheme}://{host}{(defaultPort ? "" : $":{port}")}{path}";
        var headers = response?.GetValueOrDefault("headers") as List<object?>;
        return new CapturedResponse(Text(request.GetValueOrDefault("method")) ?? "?", url,
            response?.GetValueOrDefault("status_code") is long code ? (int)code : 0, Header(headers, "content-type"), Header(headers, "content-encoding"),
            response?.GetValueOrDefault("content") as byte[] ?? (response?.GetValueOrDefault("content") is string sc ? Encoding.UTF8.GetBytes(sc) : null), null);

        static string? Text(object? v) => v switch { byte[] b => Encoding.UTF8.GetString(b), string s => s, _ => null };

        static string? Header(List<object?>? headers, string name)
        {
            foreach (var h in headers ?? [])
                if (h is List<object?> { Count: 2 } pair && Text(pair[0]) is { } n && n.Equals(name, StringComparison.OrdinalIgnoreCase)) return Text(pair[1]);
            return null;
        }
    }

    /// <summary>The capture as a container; null for JSON that is not HAR.</summary>
    public static ContainerContents? Open(byte[] data, bool flows, bool allFiles, AnalysisLimits limits, CancellationToken ct)
    {
        if (!flows) return OpenHar(new MemoryStream(data, writable: false), allFiles, limits, ct);
        var collector = new Collector(true, allFiles, limits, ct);
        foreach (var r in ReadFlows(data, collector.Notes, ct)) collector.Add(r);
        return collector.Contents();
    }

    /// <summary>A mitmproxy flow file read from a seekable stream as a container (one flow in memory at a time).</summary>
    public static ContainerContents OpenFlows(Stream stream, bool allFiles, AnalysisLimits limits, CancellationToken ct)
    {
        var collector = new Collector(true, allFiles, limits, ct);
        ReadFlows(stream, collector.Add, collector.Notes, limits.MaxItemBytes, ct);
        return collector.Contents();
    }

    /// <summary>A HAR file read from a stream as a container (one entry in memory at a time); null for JSON that is not HAR.</summary>
    public static ContainerContents? OpenHar(Stream stream, bool allFiles, AnalysisLimits limits, CancellationToken ct)
    {
        var collector = new Collector(false, allFiles, limits, ct);
        return ReadHar(stream, collector.Add, Math.Min(limits.MaxItemBytes * 2, Array.MaxLength), ct) ? collector.Contents() : null;
    }

    /// <summary>Responses turned into entries and, for the interesting ones (all with allFiles), extracted bodies.</summary>
    private sealed class Collector(bool flows, bool allFiles, AnalysisLimits limits, CancellationToken ct)
    {
        public List<string> Notes { get; } = [];
        private readonly List<ContainerEntry> _entries = [];
        private readonly List<ExtractedItem> _items = [];
        private long _total;
        private int _responses, _empty;
        private bool _stopped;

        /// <summary>Responses listed as entries; past this the capture is still read and counted.</summary>
        private const int MaxEntries = 200_000;

        public void Add(CapturedResponse r)
        {
            ct.ThrowIfCancellationRequested();
            _responses++;
            if (_stopped) return;
            var path = PathOf(r);
            var detail = new StringBuilder($"{r.Method} {r.Status}");
            if (r.MimeType != null) detail.Append(' ').Append(r.MimeType.Split(';')[0].Trim());
            byte[]? body = r.Body;
            if (body != null && r.ContentEncoding is { Length: > 0 } enc && !enc.Equals("identity", StringComparison.OrdinalIgnoreCase))
            {
                var decoded = Decode(body, enc, limits.MaxItemBytes);
                if (decoded != null) { body = decoded; detail.Append($", {enc} decoded"); }
                else detail.Append($", {enc} body not decoded");
            }
            if (r.Problem != null) detail.Append(", ").Append(r.Problem);
            if (body == null || body.Length == 0) { _empty++; detail.Append(", no body"); }
            if (_entries.Count < MaxEntries) _entries.Add(new ContainerEntry(path, body?.Length ?? 0, $"{detail}; {Clip(r.Url)}"));
            if (body is not { Length: > 0 } || !(allFiles || Containers.IsInteresting(path))) return;
            if (_items.Count >= limits.MaxItems || body.Length > limits.MaxItemBytes || (_total += body.Length) > limits.MaxTotalBytes)
            {
                Notes.Add("Stopped: the extraction limit was reached.");
                _stopped = true;
                return;
            }
            _items.Add(new ExtractedItem(path, body, $"{(flows ? "flow" : "HAR")} response {r.Method} {Clip(r.Url)}"));
        }

        public ContainerContents Contents()
        {
            Notes.Insert(0, $"{_responses} response(s), {_responses - _empty} with a body; files are named host/path, the query folded into a short hash.");
            if (_responses > MaxEntries) Notes.Insert(1, $"The first {MaxEntries:N0} responses are listed.");
            return new ContainerContents(flows ? FlowKind : HarKind, _items, Notes) { Entries = _entries };
        }
    }

    private static string Clip(string url) => url.Length > 200 ? url[..197] + "..." : url;

    /// <summary>The body decoded by its Content-Encoding (the last coding applied is undone first); null when it cannot be.</summary>
    internal static byte[]? Decode(byte[] body, string encodings, long maxBytes)
    {
        byte[]? current = body;
        foreach (var coding in encodings.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries).Reverse())
        {
            if (current == null) return null;
            current = coding.ToLowerInvariant() switch
            {
                "gzip" or "x-gzip" => Blob.TryDecompress(current, "gzip", maxBytes),
                "deflate" => Blob.TryDecompress(current, current.Length > 1 && current[0] == 0x78 ? "zlib" : "deflate", maxBytes),
                "br" => Brotli(current, maxBytes),
                "zstd" => Zstd(current, maxBytes),
                "identity" => current,
                _ => null,
            };
        }
        return current;

        static byte[]? Brotli(byte[] data, long max)
        {
            try
            {
                using var s = new BrotliStream(new MemoryStream(data, writable: false), CompressionMode.Decompress);
                return Blob.ReadBounded(s, max);
            }
            catch (Exception ex) when (ex is InvalidDataException or IOException or InvalidOperationException) { return null; }
        }

        static byte[]? Zstd(byte[] data, long max)
        {
            try
            {
                using var s = new ZstdSharp.DecompressionStream(new MemoryStream(data, writable: false));
                return Blob.ReadBounded(s, max);
            }
            catch (Exception ex) when (ex is ZstdSharp.ZstdException or IOException) { return null; }
        }
    }

    /// <summary>
    /// "host[_port]/path segments", each segment unescaped and made a safe file name; a trailing '/' becomes "index", a query
    /// adds "_q&lt;hash&gt;" before the extension, and a missing extension comes from the MIME type.
    /// </summary>
    internal static string PathOf(CapturedResponse r)
    {
        if (!Uri.TryCreate(r.Url, UriKind.Absolute, out var uri) || uri.Scheme == "data")
            return Safe(r.Url.StartsWith("data:", StringComparison.OrdinalIgnoreCase) ? "data-url" : "unknown") + "/" + Hash(r.Url) + Extension(r.MimeType);
        var parts = new List<string> { Safe(uri.IsDefaultPort || uri.Port < 0 ? uri.Host : $"{uri.Host}_{uri.Port}") };
        if (uri.Scheme is not ("http" or "https")) parts.Insert(0, Safe(uri.Scheme));
        foreach (var segment in uri.AbsolutePath.Split('/', StringSplitOptions.RemoveEmptyEntries).Take(32))
            parts.Add(Safe(Uri.UnescapeDataString(segment)));
        string file = uri.AbsolutePath.EndsWith('/') || parts.Count == 1 ? "index" : parts[^1];
        if (!(uri.AbsolutePath.EndsWith('/') || parts.Count == 1)) parts.RemoveAt(parts.Count - 1);
        string ext = Path.GetExtension(file);
        string stem = ext.Length > 0 && ext.Length <= 8 ? file[..^ext.Length] : file;
        if (ext.Length is 0 or > 8) { ext = Extension(r.MimeType); stem = file; }
        if (uri.Query.Length > 1) stem += "_q" + Hash(uri.Query);
        parts.Add(stem + ext);
        return string.Join('/', parts);
    }

    private static string Hash(string text) => Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(text)))[..8];

    /// <summary>Unsafe characters become '_'; "." and ".." become "_." and "_..", so no segment climbs.</summary>
    private static string Safe(string segment)
    {
        var sb = new StringBuilder(Math.Min(segment.Length, 100));
        foreach (var c in segment.Length > 100 ? segment[..100] : segment)
            sb.Append(c < 0x20 || c is '/' or '\\' or ':' or '*' or '?' or '"' or '<' or '>' or '|' ? '_' : c);
        var s = sb.ToString().Trim();
        return s.Length == 0 ? "_" : s is "." or ".." ? "_" + s : s;
    }

    private static string Extension(string? mime) => (mime ?? "").Split(';')[0].Trim().ToLowerInvariant() switch
    {
        "text/html" => ".html",
        "application/json" or "text/json" => ".json",
        "text/javascript" or "application/javascript" or "application/x-javascript" => ".js",
        "text/css" => ".css",
        "text/plain" => ".txt",
        "application/xml" or "text/xml" => ".xml",
        "image/png" => ".png",
        "image/jpeg" => ".jpg",
        "image/gif" => ".gif",
        "image/svg+xml" => ".svg",
        "image/webp" => ".webp",
        "application/wasm" => ".wasm",
        "application/zip" => ".zip",
        _ => ".bin",
    };
}

/// <summary>tnetstrings as mitmproxy writes them: "&lt;length&gt;:&lt;data&gt;&lt;type&gt;" with , ; # ^ ! ~ } ] types.</summary>
internal static class TNetString
{
    private const int MaxDepth = 64;

    /// <summary>byte[] (','), string (';'), long, double, bool, null, Dictionary&lt;string, object?&gt; or List&lt;object?&gt;.</summary>
    public static object? Read(byte[] data, ref int at, int depth)
    {
        if (depth > MaxDepth) throw new FormatException("nesting too deep");
        int colon = Array.IndexOf(data, (byte)':', at, Math.Min(11, data.Length - at));
        if (colon <= at) throw new FormatException("no length prefix");
        if (!int.TryParse(Encoding.ASCII.GetString(data, at, colon - at), NumberStyles.None, CultureInfo.InvariantCulture, out int length)
            || length > data.Length - colon - 2) throw new FormatException("bad length");
        int start = colon + 1, end = start + length;
        byte type = data[end];
        at = end + 1;
        var body = data.AsSpan(start, length);
        switch ((char)type)
        {
            case ',': return body.ToArray();
            case ';': return Encoding.UTF8.GetString(body);
            case '#': return long.TryParse(body, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out var l) ? l : throw new FormatException("bad integer");
            case '^': return double.TryParse(body, NumberStyles.Float, CultureInfo.InvariantCulture, out var d) ? d : throw new FormatException("bad float");
            case '!': return body.SequenceEqual("true"u8);
            case '~': return null;
            case '}':
            {
                var dict = new Dictionary<string, object?>(StringComparer.Ordinal);
                for (int p = start; p < end;)
                {
                    var key = Read(data, ref p, depth + 1);
                    if (p >= end) throw new FormatException("dictionary key without a value");
                    var value = Read(data, ref p, depth + 1);
                    if (p > end) throw new FormatException("value past the dictionary");
                    dict[key switch { byte[] b => Encoding.UTF8.GetString(b), string s => s, _ => Convert.ToString(key, CultureInfo.InvariantCulture) ?? "" }] = value;
                }
                return dict;
            }
            case ']':
            {
                var list = new List<object?>();
                for (int p = start; p < end;)
                {
                    list.Add(Read(data, ref p, depth + 1));
                    if (p > end) throw new FormatException("item past the list");
                }
                return list;
            }
            default: throw new FormatException($"unknown type '{(char)type}'");
        }
    }
}
