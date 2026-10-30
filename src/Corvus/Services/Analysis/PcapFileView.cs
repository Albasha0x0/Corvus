using Corvus.Core.Pcap;

namespace Corvus.Services.Analysis;

/// <summary>view=pcap: one streaming pass over a capture: protocols, largest flows, DNS, TLS server names, HTTP templates, patterns.</summary>
internal sealed class PcapFileView : IFileSummaryView
{
    private const int MaxListed = 100;

    /// <summary>An HTTP request template (query values dropped, ids as {n} / {id}) and how often it was sent.</summary>
    public sealed record Request(string Host, string Template, int Count);

    public sealed record Facts(string Format, IReadOnlyList<string> LinkTypes, int Interfaces, long Packets, long CapturedBytes, DateTime? First, DateTime? Last,
        IReadOnlyDictionary<string, long> Protocols, int FlowCount, IReadOnlyList<CaptureFlow> Flows, IReadOnlyList<CaptureDnsName> Dns,
        IReadOnlyList<CaptureTlsName> Tls, IReadOnlyList<Request> Http, IReadOnlyList<string> Notes)
    {
        /// <summary>DNS names that look like carried data, connections at a regular interval.</summary>
        public IReadOnlyList<string> Noteworthy { get; init; } = [];
    }

    public string Name => "pcap";

    public FileView? Inspect(FileInput file, CancellationToken ct)
    {
        if (!PcapReader.Looks(file.Head)) return null;
        CaptureAnalysis c;
        using (var s = file.OpenRead()) c = CaptureAnalysis.Read(s, ct);
        var dns = c.DnsNames().ToList();
        var tls = c.ServerNames().ToList();
        var http = Requests(c).ToList();
        var notes = new List<string>(c.Issues);
        notes.AddRange(c.Notes);
        if (c.FlowCount > MaxListed) notes.Add($"flows: the {MaxListed} largest of {c.FlowCount:N0} by bytes");
        if (dns.Count > MaxListed) notes.Add($"DNS names: the first {MaxListed} of {dns.Count:N0}");
        if (tls.Count > MaxListed) notes.Add($"TLS server names: the first {MaxListed} of {tls.Count:N0}");
        if (http.Count > MaxListed) notes.Add($"HTTP requests: the first {MaxListed} of {http.Count:N0}; search_container kind=endpoint lists them all");
        notes.Add("Only a ClientHello is joined across segments; HTTP request lines come from the segment that starts them; unpack_container reassembles TCP, exports HTTP objects and decrypts TLS with a key log.");
        var facts = new Facts(c.Format, [.. c.LinkTypes.Select(PacketDecoder.LinkTypeName)], c.Interfaces, c.Packets, c.Bytes, c.First, c.Last, c.Protocols,
            c.FlowCount, [.. c.Flows().OrderByDescending(f => f.Bytes).Take(MaxListed)], [.. dns.Take(MaxListed)], [.. tls.Take(MaxListed)], [.. http.Take(MaxListed)], notes)
        {
            Noteworthy = CapturePatterns.Find(c),
        };

        var span = c.First is { } first && c.Last is { } last ? $" over {(last - first).TotalSeconds:0.#} s" : "";
        var highlights = new List<string>
        {
            $"{c.Format} capture ({string.Join(", ", facts.LinkTypes)}): {c.Packets:N0} packets, {c.FlowCount:N0} TCP/UDP flows{span}.",
        };
        if (tls.Count > 0) highlights.Add($"TLS server names: {List(tls.Select(t => t.ServerName), tls.Count)}.");
        if (http.Count > 0) highlights.Add($"HTTP requests: {List(http.Select(r => r.Template), http.Count)}.");
        if (dns.Count > 0) highlights.Add($"DNS names: {List(dns.Select(d => d.Name), dns.Count)}.");
        highlights.AddRange(facts.Noteworthy.Select(n => $"Worth reviewing: {n}."));
        if (c.Issues.Count > 0) highlights.Add($"Capture structure issue: {c.Issues[0]}.");
        return new FileView(facts, highlights)
        {
            Findings = [.. facts.Noteworthy.Select(n => new Finding(FindingLevel.Review, "capture/pattern", "capture", n, null, "capture"))],
            Indicators = Indicators(dns, tls),
        };
    }

    private static List<IndicatorHit> Indicators(List<CaptureDnsName> dns, List<CaptureTlsName> tls)
    {
        var hits = new List<IndicatorHit>();
        foreach (var d in dns.Take(IndicatorList.MaxPerReader))
            if (IndicatorList.Domain(d.Name) is { Length: > 0 } name) hits.Add(new IndicatorHit(IndicatorList.HostType(name), name, "pcap", "DNS query"));
        foreach (var t in tls.Take(IndicatorList.MaxPerReader))
        {
            if (IndicatorList.Domain(t.ServerName) is { Length: > 0 } name) hits.Add(new IndicatorHit(IndicatorList.HostType(name), name, "pcap", "TLS server name"));
            hits.AddRange(t.Ja3.Select(j => new IndicatorHit("ja3", j, "pcap", $"ClientHello to {t.ServerName}")));
            hits.AddRange(t.Ja4.Select(j => new IndicatorHit("ja4", j, "pcap", $"ClientHello to {t.ServerName}")));
        }
        return hits;
    }

    /// <summary>Requests grouped by endpoint template, as search_container kind=endpoint shows them.</summary>
    internal static IEnumerable<Request> Requests(CaptureAnalysis c) => c.Requests()
        .Select(r => (r.Count, Key: Template(r)))
        .GroupBy(r => r.Key).OrderBy(g => g.Key.Host, StringComparer.Ordinal).ThenBy(g => g.Key.Text, StringComparer.Ordinal)
        .Select(g => new Request(g.Key.Host, g.Key.Text, g.Sum(r => r.Count)));

    private static (string Host, string Text) Template(CaptureHttpRequest r)
    {
        if (r.Method == "CONNECT") return (r.Target, $"CONNECT {r.Target}");
        if (r.Target.StartsWith("http://", StringComparison.OrdinalIgnoreCase)) return EndpointSearchKind.Template(r.Method, r.Target);
        if (r.Host.Length == 0 || !r.Target.StartsWith('/')) return ("", $"{r.Method} {r.Target.Split('?')[0]}");
        return EndpointSearchKind.Template(r.Method, $"http://{r.Host}{r.Target}");
    }

    private static string List(IEnumerable<string> items, int count) => string.Join(", ", items.Take(5)) + (count > 5 ? $" (+{count - 5})" : "");
}
