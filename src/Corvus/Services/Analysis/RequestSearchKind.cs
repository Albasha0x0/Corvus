using System.Globalization;
using System.Text;
using Corvus.Core;

namespace Corvus.Services.Analysis;

/// <summary>search_container kind=request: each request of a HAR, mitmproxy or .saz capture, streamed; values only with values=true.</summary>
internal sealed class RequestSearchKind : IContainerSearchKind
{
    public IReadOnlyList<string> Kinds => ["request"];

    public IEnumerable<ContainerMatch> Search(ContainerScope scope, string kind, Func<string, bool> matches, CancellationToken ct) => [];

    public UnpackService.ContainerSearch SearchFile(string path, string query, int offset, int limit, ContainerSearchArgs args, CancellationToken ct)
    {
        var source = InputFiles.RequireRegularFile(path, "capture file");
        if (!File.Exists(source)) throw Targets.FileNotFound(source);
        var matches = SearchService.CreateMatcher(query, regex: false);
        var notes = new List<string>();
        var page = new List<ContainerMatch>();
        int total = 0, read = 0;
        var responses = new List<GatewayResponse>();
        var connects = new List<ConnectCall>();
        int jsonResponses = 0, clipped = 0, otherText = 0;
        string? kind;
        using (var s = new FileStream(source, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 1 << 16))
            kind = CaptureRequests.Read(s, r =>
            {
                ct.ThrowIfCancellationRequested();
                read++;
                if (Uri.TryCreate(r.Url, UriKind.Absolute, out var uri) && uri.Port > 0)
                    connects.Add(new(r.Index + 1, uri.Host, uri.Port));
                if (r.ResponseText != null)
                {
                    if (r.ResponseType?.Contains("json", StringComparison.OrdinalIgnoreCase) != true) otherText++;
                    else if (r.ResponseClipped) clipped++;
                    else if (jsonResponses++ < MaxFlowResponses) responses.Add(new(r.Index + 1, r.Url, Encoding.UTF8.GetBytes(r.ResponseText)));
                }
                var row = Row(r, args.Values);
                if (!(matches(row.Name) || matches(row.Path) || (row.Detail != null && matches(row.Detail)))) return;
                if (total++ >= offset && page.Count < limit) page.Add(row);
            }, notes, texts: true, ct);
        if (kind == null)
            throw new ToolError(ErrorCode.Unsupported, $"{Path.GetFileName(source)} is not a HAR, mitmproxy or .saz capture.",
                "kind=request reads HAR, mitmproxy flows and .saz; kind=packet reads pcap and pcapng");
        notes.AddRange(Flow(responses, connects, jsonResponses, clipped, otherText));
        notes.Insert(0, $"{read:N0} request(s), {total:N0} match; " +
                        (args.Values ? "values shown." : "header, cookie and query values hidden (values=true shows them)."));
        return new UnpackService.ContainerSearch(source, kind, read, page, offset, total, notes);
    }

    private const int MaxFlowResponses = 1000, MaxFlowNotes = 10, MaxFramingBytes = 16 << 20;

    /// <summary>
    /// Joins each JSON response's host and port pair to a later request; names the rest
    /// and reports every bound.
    /// </summary>
    internal static List<string> Flow(List<GatewayResponse> responses, List<ConnectCall> connects, int jsonResponses, int clipped = 0, int otherText = 0)
    {
        var notes = new List<string>();
        if (jsonResponses + clipped + otherText == 0) return notes;
        var report = ConnectionFlow.Join(responses, connects);
        var joined = report.Joins.Select(j => $"#{j.ResponseSequence} {j.SourceHostField}, {j.SourcePortField} -> request #{j.ConnectSequence} {j.Host}:{j.Port}").ToList();
        var unjoined = report.Unresolved.Where(u => u.Side == "response" && u.Reason != ConnectionFlow.NoPairReason).Select(u => $"#{u.Sequence} not joined: {u.Reason}").ToList();
        var head = $"connection flow: {report.Joins.Count:N0} join(s) from {responses.Count:N0} of {jsonResponses:N0} JSON response(s), {connects.Count:N0} request URL(s) indexed";
        if (jsonResponses > responses.Count)
            head += $" (partial: the first {MaxFlowResponses:N0} were read; save a capture of the later entries and search it)";
        notes.Add(head + (joined.Count + unjoined.Count > 0 ? ":" : "; no response names a host and port."));
        notes.AddRange(joined.Take(MaxFlowNotes));
        if (joined.Count > MaxFlowNotes) notes.Add($"+{joined.Count - MaxFlowNotes:N0} more join(s)");
        notes.AddRange(unjoined.Take(MaxFlowNotes));
        if (unjoined.Count > MaxFlowNotes) notes.Add($"+{unjoined.Count - MaxFlowNotes:N0} more not joined");
        if (clipped > 0) notes.Add($"connection flow: {clipped:N0} JSON response(s) clipped at {CaptureRequests.MaxText:N0} were not read (unknown)");
        if (otherText > 0) notes.Add($"connection flow: {otherText:N0} response(s) not typed as JSON were not scanned (unknown)");
        return notes;
    }

    /// <summary>One request: its host, its URL template (the URL with values=true), and its facts in Detail.</summary>
    internal static ContainerMatch Row(CapturedRequest r, bool values)
    {
        var (host, template) = EndpointSearchKind.Template(r.Method, r.Url);
        if (Uri.TryCreate(r.Url, UriKind.Absolute, out var uri)) host = uri.Host;
        var d = new List<string> { $"#{r.Index + 1}", r.Status != 0 ? $"status {r.Status}" : "no response" };
        if (r.HttpVersion is { Length: > 0 } version) d.Add(version);
        if (r.TimeMs is { } ms) d.Add($"{ms.ToString("0", CultureInfo.InvariantCulture)} ms");
        var headers = r.Headers.Where(h => !h.Key.Equals("cookie", StringComparison.OrdinalIgnoreCase)).ToList();
        if (headers.Count > 0) d.Add("request headers: " + Names(headers, values, ": "));
        if (r.Cookies.Count > 0) d.Add("cookies: " + Names(r.Cookies, values, "="));
        if (r.BodySize > 0 || r.BodyType != null) d.Add($"body {Type(r.BodyType)} {r.BodySize:N0} B");
        var operations = MessageShapes.GraphQl(r.Url, r.BodyText);
        if (operations.Count > 0) d.Add("GraphQL " + string.Join(", ", operations.Take(10)) + (operations.Count > 10 ? $", +{operations.Count - 10}" : ""));
        if (r.ResponseSize > 0 || r.ResponseType != null) d.Add($"response {Type(r.ResponseType)} {r.ResponseSize:N0} B");
        if (r.ResponseText != null && MessageShapes.Stream(r.ResponseType, r.ResponseText) is { } stream)
            d.Add($"{stream.Format} {stream.Messages:N0} message(s): {Groups(stream.Groups)}");
        if (r.Messages is { } messages) d.Add(WebSocket(messages, values));
        return new ContainerMatch(host, values ? $"{r.Method} {r.Url}" : template, "request") { Detail = string.Join("; ", d) };
    }

    /// <summary>Distinct names in first-seen order, or name and value pairs (values clipped) when asked.</summary>
    private static string Names(IEnumerable<KeyValuePair<string, string>> pairs, bool values, string separator)
    {
        if (values) return string.Join(", ", pairs.Select(p => p.Key + separator + Clip(p.Value, 200)));
        return string.Join(", ", pairs.Select(p => p.Key).Distinct(StringComparer.OrdinalIgnoreCase));
    }

    private static string Type(string? mime) => mime is { Length: > 0 } ? mime.Split(';')[0].Trim() : "(no type)";

    private static string Groups(List<(string Shape, int Count)> groups) =>
        string.Join(", ", groups.Take(6).Select(g => $"{g.Shape} x{g.Count}")) + (groups.Count > 6 ? $", +{groups.Count - 6} shape(s)" : "");

    /// <summary>Counts by direction and the message shapes (JSON keys, else text or binary); with values the first messages clipped.</summary>
    private static string WebSocket(IReadOnlyList<CapturedMessage> messages, bool values)
    {
        int sent = messages.Count(m => m.Sent);
        var shapes = messages.GroupBy(m => (m.Sent ? "sent " : "received ") + (m.Binary ? "binary" : MessageShapes.OfText(m.Data) ?? "text"))
            .Select(g => (g.Key, g.Count())).OrderByDescending(g => g.Item2).ThenBy(g => g.Key, StringComparer.Ordinal).ToList();
        var sb = new StringBuilder($"WebSocket {messages.Count:N0} message(s), {sent:N0} sent, {messages.Count - sent:N0} received");
        if (shapes.Count > 0) sb.Append(": ").Append(Groups(shapes));
        if (values && messages.Count > 0)
            sb.Append("; first: ").Append(string.Join(" | ", messages.Take(3).Select(m => (m.Sent ? "> " : "< ") + Clip(m.Data, 120))));
        sb.Append(Framing(messages, sent: true)).Append(Framing(messages, sent: false));
        return sb.ToString();
    }

    /// <summary>
    /// The length-prefix framing of one direction's binary messages, as a "; framing" clause;
    /// empty without binary messages, unknown when a message is clipped or not base64, and
    /// partial when the message or byte bound stopped the read.
    /// </summary>
    internal static string Framing(IReadOnlyList<CapturedMessage> messages, bool sent)
    {
        var binary = messages.Where(m => m.Sent == sent && m.Binary).ToList();
        if (binary.Count == 0) return "";
        var side = sent ? "sent" : "received";
        var chunks = new List<RecordedChunk>();
        long total = 0;
        bool capped = messages.Count >= CaptureRequests.MaxMessages;
        foreach (var m in binary)
        {
            if (m.Clipped) return $"; framing {side}: unknown, a message is clipped at {CaptureRequests.MaxMessageText:N0}";
            if (total + m.Data.Length * 3L / 4 > MaxFramingBytes) { capped = true; break; }
            var bytes = new byte[m.Data.Length];
            if (!Convert.TryFromBase64String(m.Data, bytes, out int n)) return $"; framing {side}: unknown, a message is not base64";
            total += n;
            chunks.Add(new RecordedChunk(!sent, bytes[..n]));
        }
        var limit = capped
            ? $" (partial: {chunks.Count:N0} of {binary.Count:N0} messages read, bounds {CaptureRequests.MaxMessages:N0} messages and {MaxFramingBytes >> 20:N0} MiB; save a capture of the later messages and search it)"
            : "";
        return FrameInference.Infer(chunks, !sent) is { } layout
            ? $"; framing {side}: {layout.Describe()}, {layout.Frames:N0} frame(s) in {chunks.Count:N0} message(s){limit}"
            : $"; framing {side}: no length prefix explains {chunks.Count:N0} binary message(s){limit}";
    }

    private static string Clip(string s, int max) => s.Length > max ? s[..(max - 1)] + "…" : s;
}
