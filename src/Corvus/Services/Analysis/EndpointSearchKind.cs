using System.Text.RegularExpressions;
using Corvus.Core;
using Corvus.Core.Pcap;
using Corvus.Services.Analysis.Endpoints;

namespace Corvus.Services.Analysis;

/// <summary>search_container kind=endpoint: request templates of a capture (values never shown), endpoints named in code, or both joined.</summary>
// Captures: HAR, mitmproxy, Fiddler .saz, pcap, pcapng; numeric and id path segments fold to {n} and {id}.
internal sealed partial class EndpointSearchKind : IContainerSearchKind
{
    public IReadOnlyList<string> Kinds => ["endpoint"];

    public IEnumerable<ContainerMatch> Search(ContainerScope scope, string kind, Func<string, bool> matches, CancellationToken ct)
    {
        var captured = CaptureRows(scope.Source, ct);
        List<ContainerMatch> rows;
        if (captured != null)
        {
            rows = [.. captured.Select(r => r with { Seen = "capture" })];
            scope.Tally.Files = 1;
        }
        else
        {
            var code = ApiSurface.CodeItems(scope.Source, scope.Items, AnalysisLimits.Default, ct);
            scope.Tally.Files = code.Count;
            scope.Tally.Note = "Code searched: " + (code.Count == 0 ? "none" : string.Join(", ", code.GroupBy(c => c.Kind).Select(g => $"{g.Count()} {g.Key}"))) + ".";
            var surface = ApiSurface.Read(code, ct);
            rows = [.. surface.Endpoints.Select(e => new ContainerMatch(e.File, e.Text, "endpoint")
            {
                Detail = e.Client + (e.Base != null ? $", base {e.Base}" : ""), Member = e.Member, Location = e.Location, Seen = "code",
            })];
            if (scope.Capture != null)
                rows = Join(rows, CaptureRows(scope.Capture, ct)
                    ?? throw new ToolError(ErrorCode.InvalidArgument, $"{scope.Capture} is not a HAR, mitmproxy, .saz or pcap capture.", "pass a capture file as capture"));
        }
        foreach (var row in rows)
            if (matches(row.Name) || matches(row.Path) || (row.Member != null && matches(row.Member)) || (row.Detail != null && matches(row.Detail)))
                yield return row;
    }

    /// <summary>Code rows, marked code+capture where a captured request matches their template, then unexplained captured templates.</summary>
    private static List<ContainerMatch> Join(List<ContainerMatch> code, List<ContainerMatch> captured)
    {
        var http = captured.Where(c => !c.Name.StartsWith("tls://", StringComparison.Ordinal) && !c.Name.StartsWith("dns://", StringComparison.Ordinal)
                                       && !c.Name.StartsWith("CONNECT ", StringComparison.Ordinal)).ToList();
        var hosts = captured.Where(c => !http.Contains(c)).Select(c => c.Path.ToLowerInvariant()).ToHashSet(StringComparer.Ordinal);
        var explained = new HashSet<ContainerMatch>();
        var joined = new List<ContainerMatch>();
        foreach (var row in code)
        {
            var seen = http.Where(c => EndpointTemplates.Matches(row.Name, c.Name)).ToList();
            explained.UnionWith(seen);
            if (seen.Count > 0)
                joined.Add(row with { Seen = "code+capture", Detail = row.Detail + "; captured as " + string.Join(", ", seen.Take(4).Select(s => $"{s.Name} ({s.Detail})")) + (seen.Count > 4 ? ", ..." : "") });
            else if (EndpointTemplates.Key(row.Name).Host is { } host && hosts.Contains(host))
                joined.Add(row with { Detail = row.Detail + "; host contacted in the capture, this path not" });
            else joined.Add(row);
        }
        joined.AddRange(captured.Where(c => !explained.Contains(c)).Select(c => c with { Seen = "capture" }));
        return joined;
    }

    /// <summary>A capture's request templates, streamed, ranked and paged, or compared with a second capture; null when not a capture.</summary>
    public UnpackService.ContainerSearch? SearchFile(string path, string query, int offset, int limit, ContainerSearchArgs args, CancellationToken ct)
    {
        string full;
        try { full = Path.GetFullPath(path); }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException) { return null; }
        var read = Capture(full, shapes: args.Capture != null, ct);
        if (read == null) return null;
        var matches = SearchService.CreateMatcher(query, regex: false);
        if (args.Capture != null)
        {
            var other = Capture(args.Capture, shapes: true, ct)
                ?? throw new ToolError(ErrorCode.InvalidArgument, $"{args.Capture} is not a HAR, mitmproxy, .saz or pcap capture.", "pass a second capture as capture to compare the two");
            var diff = Diff(read.Value.Facts, other.Facts).Where(r => Matches(r, matches)).ToList();
            var notes = new List<string>
            {
                $"{full} ({read.Value.Requests:N0} request(s)) compared with {args.Capture} ({other.Requests:N0}): " +
                string.Join(", ", new[] { "added", "removed", "changed", "same" }.Select(state => $"{diff.Count(r => r.Seen == state)} {state}")) +
                "; changed compares statuses, header names, response types, message shapes and GraphQL operations.",
            };
            notes.AddRange(read.Value.Notes);
            notes.AddRange(other.Notes);
            return new UnpackService.ContainerSearch(full, read.Value.Kind, read.Value.Requests + other.Requests, diff.Skip(offset).Take(limit).ToList(), offset, diff.Count, notes);
        }
        var rows = Rows(read.Value.Facts).Where(r => Matches(r, matches)).Select(r => r with { Seen = "capture" }).ToList();
        return UnpackService.Ranked(full, read.Value.Kind, read.Value.Requests, rows, query, offset, limit, read.Value.Notes);
    }

    private static bool Matches(ContainerMatch row, Func<string, bool> matches) =>
        matches(row.Name) || matches(row.Path) || (row.Member != null && matches(row.Member)) || (row.Detail != null && matches(row.Detail));

    private static List<ContainerMatch>? CaptureRows(string path, CancellationToken ct) => Capture(path, shapes: false, ct) is { } c ? Rows(c.Facts) : null;

    /// <summary>What a capture shows of one request template: its requests and statuses, and with shapes what is compared between captures.</summary>
    internal sealed class TemplateFacts
    {
        public int Count;
        public readonly SortedSet<int> Statuses = [];
        public readonly SortedSet<string> Headers = new(StringComparer.Ordinal), Types = new(StringComparer.Ordinal),
            Shapes = new(StringComparer.Ordinal), Operations = new(StringComparer.Ordinal);
        /// <summary>A pcap row's own detail (ClientHello and DNS counts).</summary>
        public string? Detail;
    }

    /// <summary>Distinct shapes kept per template; past this a template's shapes are not compared further.</summary>
    private const int MaxShapes = 16;

    /// <summary>A streamed capture's request templates, kind, request count and notes; null when not a capture.</summary>
    // With shapes, each template also gathers header names, response types, message shapes and GraphQL operations.
    private static (Dictionary<(string Host, string Text), TemplateFacts> Facts, string Kind, int Requests, List<string> Notes)? Capture(string path, bool shapes,
        CancellationToken ct)
    {
        var notes = new List<string>();
        var templates = new Dictionary<(string Host, string Text), TemplateFacts>();
        int requests = 0;
        void Add(CapturedRequest r)
        {
            ct.ThrowIfCancellationRequested();
            requests++;
            var key = r.Method == "CONNECT" ? (Host: r.Url, Text: $"CONNECT {r.Url}") : Template(r.Method, r.Url);
            if (!templates.TryGetValue(key, out var facts)) templates[key] = facts = new TemplateFacts();
            facts.Count++;
            if (r.Status != 0) facts.Statuses.Add(r.Status);
            if (!shapes) return;
            foreach (var h in r.Headers)
                if (!h.Key.StartsWith(':') && !h.Key.Equals("cookie", StringComparison.OrdinalIgnoreCase)) facts.Headers.Add(h.Key.ToLowerInvariant());
            if (r.ResponseType is { Length: > 0 } type) facts.Types.Add(type.Split(';')[0].Trim().ToLowerInvariant());
            foreach (var op in MessageShapes.GraphQl(r.Url, r.BodyText)) facts.Operations.Add(op);
            if (facts.Shapes.Count >= MaxShapes) return;
            if (r.ResponseText != null)
            {
                if (MessageShapes.Stream(r.ResponseType, r.ResponseText) is { } stream)
                    foreach (var g in stream.Groups) facts.Shapes.Add($"{stream.Format} {g.Shape}");
                else if (MessageShapes.OfText(r.ResponseText) is { } shape) facts.Shapes.Add(shape);
            }
            foreach (var m in r.Messages ?? [])
                if (!m.Binary && facts.Shapes.Count < MaxShapes) facts.Shapes.Add((m.Sent ? "WebSocket sent " : "WebSocket received ") + (MessageShapes.OfText(m.Data) ?? "text"));
        }
        string kind;
        try
        {
            if (!File.Exists(path)) return null;
            using var s = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 1 << 16);
            var head = new byte[4];
            head = head[..s.ReadAtLeast(head, head.Length, throwOnEndOfStream: false)];
            s.Position = 0;
            if (head.Length >= 4 && PcapReader.Looks(head))
            {
                var capture = CaptureAnalysis.Read(s, ct);
                foreach (var row in CaptureRows(capture)) templates[(row.Path, row.Name)] = new TemplateFacts { Count = 1, Detail = row.Detail };
                return (templates, "packet capture", (int)Math.Min(capture.Packets, int.MaxValue), notes);
            }
            if (CaptureRequests.Read(s, Add, notes, texts: shapes, ct) is not { } k) return null;
            kind = k;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return null; }
        // Ordinal by host, then template; a pcap keeps its reader's order.
        var ordered = templates.OrderBy(t => t.Key.Host, StringComparer.Ordinal).ThenBy(t => t.Key.Text, StringComparer.Ordinal).ToDictionary();
        return (ordered, kind, requests, notes);
    }

    private static List<ContainerMatch> Rows(Dictionary<(string Host, string Text), TemplateFacts> templates) =>
        [.. templates.Select(t => new ContainerMatch(t.Key.Host, t.Key.Text, "endpoint") { Detail = Describe(t.Value) })];

    private static string Describe(TemplateFacts f) =>
        f.Detail ?? $"{f.Count} request(s)" + (f.Statuses.Count > 0 ? $", status {string.Join(", ", f.Statuses)}" : "");

    /// <summary>Two captures' templates as added, removed, changed (each difference named) and same rows, in that order.</summary>
    internal static List<ContainerMatch> Diff(Dictionary<(string Host, string Text), TemplateFacts> before, Dictionary<(string Host, string Text), TemplateFacts> after)
    {
        var added = new List<ContainerMatch>();
        var removed = new List<ContainerMatch>();
        var changed = new List<ContainerMatch>();
        var same = new List<ContainerMatch>();
        foreach (var (key, f) in after)
            if (!before.ContainsKey(key)) added.Add(new ContainerMatch(key.Host, key.Text, "endpoint") { Seen = "added", Detail = Describe(f) });
        foreach (var (key, b) in before)
        {
            if (!after.TryGetValue(key, out var a))
            {
                removed.Add(new ContainerMatch(key.Host, key.Text, "endpoint") { Seen = "removed", Detail = Describe(b) });
                continue;
            }
            var differences = new List<string>();
            if (!b.Statuses.SetEquals(a.Statuses)) differences.Add($"status {string.Join(", ", b.Statuses)} -> {string.Join(", ", a.Statuses)}");
            Delta("request headers", b.Headers, a.Headers, differences);
            Delta("response types", b.Types, a.Types, differences);
            Delta("shapes", b.Shapes, a.Shapes, differences);
            Delta("GraphQL", b.Operations, a.Operations, differences);
            var detail = $"{b.Count} -> {a.Count} request(s)";
            if (differences.Count > 0) changed.Add(new ContainerMatch(key.Host, key.Text, "endpoint") { Seen = "changed", Detail = detail + "; " + string.Join("; ", differences) });
            else same.Add(new ContainerMatch(key.Host, key.Text, "endpoint") { Seen = "same", Detail = detail });
        }
        return [.. added, .. removed, .. changed, .. same];

        static void Delta(string what, SortedSet<string> before, SortedSet<string> after, List<string> into)
        {
            var plus = after.Except(before).ToList();
            var minus = before.Except(after).ToList();
            if (plus.Count + minus.Count == 0) return;
            into.Add($"{what} " + string.Join(", ", plus.Take(8).Select(x => "+" + x).Concat(minus.Take(8).Select(x => "-" + x)))
                     + (plus.Count + minus.Count > 16 ? ", ..." : ""));
        }
    }

    /// <summary>A pcap / pcapng capture's endpoints: HTTP request templates, then tls:// ClientHello server names, then dns:// names.</summary>
    private static List<ContainerMatch> CaptureRows(CaptureAnalysis c) =>
    [
        .. PcapFileView.Requests(c).Select(r => new ContainerMatch(r.Host, r.Template, "endpoint") { Detail = $"{r.Count} request(s)" }),
        .. c.ServerNames().Select(t => new ContainerMatch(t.ServerName, $"tls://{t.ServerName}", "endpoint")
        {
            Detail = $"{t.Hellos} ClientHello(s)" + (t.Alpn.Count > 0 ? $", ALPN {string.Join(", ", t.Alpn)}" : "") + (t.Ja4.Count > 0 ? $", JA4 {string.Join(", ", t.Ja4)}" : ""),
        }),
        .. c.DnsNames().Select(d => new ContainerMatch(d.Name, $"dns://{d.Name}", "endpoint")
        {
            Detail = $"{d.Queries} query(ies)" + (d.Answers.Count > 0 ? $", {string.Join(", ", d.Answers.Take(4))}" : ""),
        }),
    ];

    internal static (string Host, string Text) Template(string method, string url)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri)) return ("", $"{method} {url}");
        var segments = uri.AbsolutePath.Split('/').Select(s => s.Length == 0 ? s : Numeric().IsMatch(s) ? "{n}" : Id().IsMatch(s) ? "{id}" : s);
        var names = uri.Query.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries).Select(p => p.Split('=')[0]).Distinct().Order(StringComparer.Ordinal);
        var query = string.Join("&", names.Select(n => n + "=…"));
        return (uri.Host, $"{method} {uri.Scheme}://{uri.Authority}{string.Join("/", segments)}{(query.Length > 0 ? "?" + query : "")}");
    }

    [GeneratedRegex("^[0-9]+$")]
    private static partial Regex Numeric();

    // GUIDs and long hex or base64url tokens.
    [GeneratedRegex("^([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}|[0-9a-fA-F]{16,}|[A-Za-z0-9_-]{24,})$")]
    private static partial Regex Id();
}
