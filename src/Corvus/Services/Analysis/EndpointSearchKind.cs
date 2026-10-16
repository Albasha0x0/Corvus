using System.Text.RegularExpressions;
using Corvus.Core;
using Corvus.Core.Pcap;
using Corvus.Services.Analysis.Endpoints;

namespace Corvus.Services.Analysis;

/// <summary>
/// search_container kind=endpoint. On a HAR, mitmproxy, Fiddler .saz or pcap / pcapng capture: each request template once
/// (method, host, path with numeric and id segments as {n} / {id}, query names), with its request count and statuses; values
/// are never shown. On code (an APK, DEX, .NET assembly, iOS app or any container of them): the endpoints the code names
/// (<see cref="ApiSurface"/>), each with its client, method and location. With a capture beside code, both are joined:
/// every row says whether it was seen in code, in the capture, or both.
/// </summary>
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

    /// <summary>
    /// Code rows marked code+capture where a captured request is an instance of their template (its detail names the
    /// requests), then the captured templates no code row explains, marked capture.
    /// </summary>
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

    /// <summary>The endpoint rows of a capture file, or null when the file is not a capture.</summary>
    /// <summary>
    /// A capture file searched on its own, streamed at any size: its request templates ranked and paged; null when the file is
    /// not a capture (code goes through the container's files).
    /// </summary>
    public UnpackService.ContainerSearch? SearchFile(string path, string query, int offset, int limit, CancellationToken ct)
    {
        string full;
        try { full = Path.GetFullPath(path); }
        catch (Exception ex) when (ex is ArgumentException or NotSupportedException or PathTooLongException) { return null; }
        var read = Capture(full, ct);
        if (read == null) return null;
        var matches = SearchService.CreateMatcher(query, regex: false);
        var rows = read.Value.Rows.Where(r => Matches(r, matches)).Select(r => r with { Seen = "capture" }).ToList();
        return UnpackService.Ranked(full, read.Value.Kind, read.Value.Requests, rows, query, offset, limit, read.Value.Notes);
    }

    private static bool Matches(ContainerMatch row, Func<string, bool> matches) =>
        matches(row.Name) || matches(row.Path) || (row.Member != null && matches(row.Member)) || (row.Detail != null && matches(row.Detail));

    private static List<ContainerMatch>? CaptureRows(string path, CancellationToken ct) => Capture(path, ct)?.Rows;

    /// <summary>
    /// The endpoint rows of a capture file read as a stream (pcap / pcapng, HAR and mitmproxy flows one entry at a time, a .saz
    /// by its session heads), with the capture's kind, the requests read and the reader's notes; null when the file is not a capture.
    /// </summary>
    private static (List<ContainerMatch> Rows, string Kind, int Requests, List<string> Notes)? Capture(string path, CancellationToken ct)
    {
        var notes = new List<string>();
        var templates = new Dictionary<(string Host, string Text), (int Count, SortedSet<int> Statuses)>();
        int requests = 0;
        void Add(CapturedResponse r)
        {
            ct.ThrowIfCancellationRequested();
            requests++;
            var key = r.Method == "CONNECT" ? (Host: r.Url, Text: $"CONNECT {r.Url}") : Template(r.Method, r.Url);
            var (count, statuses) = templates.GetValueOrDefault(key, (0, []));
            if (r.Status != 0) statuses.Add(r.Status);
            templates[key] = (count + 1, statuses);
        }
        string kind;
        try
        {
            if (!File.Exists(path)) return null;
            using var s = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete, 1 << 16);
            var head = new byte[4096];
            head = head[..s.ReadAtLeast(head, head.Length, throwOnEndOfStream: false)];
            s.Position = 0;
            if (head.Length >= 4 && PcapReader.Looks(head))
            {
                var capture = CaptureAnalysis.Read(s, ct);
                return (CaptureRows(capture), "packet capture", (int)Math.Min(capture.Packets, int.MaxValue), notes);
            }
            if (Captures.LooksLikeHar(head))
            {
                if (!Captures.ReadHar(s, Add, AnalysisLimits.Default.MaxItemBytes, ct, bodies: false)) return null;
                kind = Captures.HarKind;
            }
            else if (Captures.LooksLikeFlows(s))
            {
                Captures.ReadFlows(s, Add, notes, AnalysisLimits.Default.MaxItemBytes, ct);
                kind = Captures.FlowKind;
            }
            else if (Saz.Looks(s))
            {
                foreach (var r in Saz.Read(s, ct)) Add(r);
                kind = Saz.Kind;
            }
            else return null;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return null; }
        var rows = new List<ContainerMatch>();
        foreach (var ((host, text), (count, statuses)) in templates.OrderBy(t => t.Key.Host, StringComparer.Ordinal).ThenBy(t => t.Key.Text, StringComparer.Ordinal))
            rows.Add(new ContainerMatch(host, text, "endpoint") { Detail = $"{count} request(s)" + (statuses.Count > 0 ? $", status {string.Join(", ", statuses)}" : "") });
        return (rows, kind, requests, notes);
    }

    /// <summary>A pcap / pcapng capture's endpoints: HTTP request templates, then tls:// ClientHello server names, then dns:// names.</summary>
    private static List<ContainerMatch> CaptureRows(CaptureAnalysis c) =>
    [
        .. PcapFileView.Requests(c).Select(r => new ContainerMatch(r.Host, r.Template, "endpoint") { Detail = $"{r.Count} request(s)" }),
        .. c.ServerNames().Select(t => new ContainerMatch(t.ServerName, $"tls://{t.ServerName}", "endpoint")
        {
            Detail = $"{t.Hellos} ClientHello(s)" + (t.Alpn.Count > 0 ? $", ALPN {string.Join(", ", t.Alpn)}" : ""),
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

    // GUIDs and long hex or base64url tokens
    [GeneratedRegex("^([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}|[0-9a-fA-F]{16,}|[A-Za-z0-9_-]{24,})$")]
    private static partial Regex Id();
}
