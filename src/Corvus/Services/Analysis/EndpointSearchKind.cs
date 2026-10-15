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
        if (captured != null) rows = [.. captured.Select(r => r with { Seen = "capture" })];
        else
        {
            var surface = ApiSurface.Read(ApiSurface.CodeItems(scope.Source, scope.Items, AnalysisLimits.Default, ct), ct);
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
    private static List<ContainerMatch>? CaptureRows(string path, CancellationToken ct)
    {
        byte[] data;
        try
        {
            if (!File.Exists(path)) return null;
            using (var s = File.OpenRead(path))
            {
                var magic = new byte[4];
                if (s.ReadAtLeast(magic, 4, throwOnEndOfStream: false) == 4 && PcapReader.Looks(magic))
                {
                    s.Position = 0;
                    return CaptureRows(CaptureAnalysis.Read(s, ct)); // streamed: no size limit
                }
            }
            if (new FileInfo(path).Length > AnalysisLimits.Default.MaxItemBytes) return null;
            data = File.ReadAllBytes(path);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { return null; }
        List<CapturedResponse>? requests = Captures.LooksLikeHar(data) ? Captures.ReadHar(data)
            : Captures.LooksLikeFlows(data) ? Captures.ReadFlows(data, [], ct) : Saz.Looks(data) ? Saz.Read(data, ct) : null;
        if (requests == null) return null;
        var groups = requests.GroupBy(r => r.Method == "CONNECT" ? (Host: r.Url, Text: $"CONNECT {r.Url}") : Template(r.Method, r.Url)).OrderBy(g => g.Key.Host, StringComparer.Ordinal).ThenBy(g => g.Key.Text, StringComparer.Ordinal);
        var rows = new List<ContainerMatch>();
        foreach (var g in groups)
        {
            ct.ThrowIfCancellationRequested();
            var statuses = string.Join(", ", g.Select(r => r.Status).Where(s => s != 0).Distinct().Order());
            rows.Add(new ContainerMatch(g.Key.Host, g.Key.Text, "endpoint") { Detail = $"{g.Count()} request(s)" + (statuses.Length > 0 ? $", status {statuses}" : "") });
        }
        return rows;
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
