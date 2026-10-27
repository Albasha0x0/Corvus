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
        string? kind;
        using (var s = new FileStream(source, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 1 << 16))
            kind = CaptureRequests.Read(s, r =>
            {
                ct.ThrowIfCancellationRequested();
                read++;
                var row = Row(r, args.Values);
                if (!(matches(row.Name) || matches(row.Path) || (row.Detail != null && matches(row.Detail)))) return;
                if (total++ >= offset && page.Count < limit) page.Add(row);
            }, notes, texts: true, ct);
        if (kind == null)
            throw new ToolError(ErrorCode.Unsupported, $"{Path.GetFileName(source)} is not a HAR, mitmproxy or .saz capture.",
                "kind=request reads HAR, mitmproxy flows and .saz; kind=packet reads pcap and pcapng");
        notes.Insert(0, $"{read:N0} request(s), {total:N0} match; " +
                        (args.Values ? "values shown." : "header, cookie and query values hidden (values=true shows them)."));
        return new UnpackService.ContainerSearch(source, kind, read, page, offset, total, notes);
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
        return sb.ToString();
    }

    private static string Clip(string s, int max) => s.Length > max ? s[..(max - 1)] + "…" : s;
}
