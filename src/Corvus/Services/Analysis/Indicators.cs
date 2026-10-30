namespace Corvus.Services.Analysis;

/// <summary>An observable a reader found: its type, value, the reader's name and where in the file it sits.</summary>
public sealed record IndicatorHit(string Type, string Value, string Source, string? Location);

/// <summary>A deduplicated indicator: every reader that found it and the first location.</summary>
public sealed record Indicator(string Type, string Value, IReadOnlyList<string> Sources, string FirstLocation);

/// <summary>view=indicators: the observables of every view and assembly of the file, one row per type and value.</summary>
public sealed record IndicatorFacts(int Total, IReadOnlyDictionary<string, int> ByType, IReadOnlyList<Indicator> Indicators, IReadOnlyList<string> Notes);

/// <summary>Collects and merges the observables that views and assemblies read.</summary>
public static class IndicatorList
{
    /// <summary>Hits kept per reader; a reader past it is counted in a note.</summary>
    public const int MaxPerReader = 5_000;

    /// <summary>Types written for network values, TLS client fingerprints and certificate names.</summary>
    public static readonly IReadOnlyList<string> Types = ["url", "domain", "ipv4", "ipv6", "email", "ja3", "ja4", "signer", "issuer"];

    private static readonly HashSet<string> NetworkTypes = new(StringComparer.Ordinal) { "url", "domain", "ipv4", "ipv6", "email" };

    /// <summary>The network values of field texts, each with its field's location; empty for none.</summary>
    public static List<IndicatorHit> FromText(string source, IEnumerable<(string Text, string Location)> fields, CancellationToken ct) =>
        [.. Values.FromFields(fields, out _, ct).Where(v => NetworkTypes.Contains(v.Type))
            .Select(v => new IndicatorHit(v.Type, v.Value, source, v.Locations.FirstOrDefault()))];

    // Shorter runs are mostly identifiers and padding.
    private const int MinStringChars = 8, MaxStringChars = 2_048, MaxImageBytes = 256 << 20;

    /// <summary>The network values of the printable ASCII and UTF-16 runs of a native image, each with its file offset; empty for none.</summary>
    public static List<IndicatorHit> FromImageStrings(string source, byte[] image, CancellationToken ct)
    {
        var fields = new List<(string, string)>();
        void Scan(int step, string encoding)
        {
            var run = new System.Text.StringBuilder();
            int start = 0;
            for (int i = 0; i + step <= Math.Min(image.Length, MaxImageBytes) && fields.Count < MaxPerReader; i += step)
            {
                if ((i & 0xFFFFF) == 0) ct.ThrowIfCancellationRequested();
                bool text = image[i] is >= 0x20 and < 0x7F && (step == 1 || image[i + 1] == 0);
                if (text)
                {
                    if (run.Length == 0) start = i;
                    if (run.Length < MaxStringChars) run.Append((char)image[i]);
                    continue;
                }
                Flush();
            }
            Flush();
            void Flush()
            {
                if (run.Length >= MinStringChars && run.ToString() is var t && (t.Contains("://") || t.Contains('@') || t.Contains('.')))
                    fields.Add((t, $"{encoding} string at 0x{start:x}"));
                run.Clear();
            }
        }
        Scan(1, "ASCII");
        Scan(2, "UTF-16");
        return FromText(source, fields, ct);
    }

    /// <summary>The signer and issuer names and the OCSP, CRL and CA issuer URLs of certificates; self-issued certificates give no issuer.</summary>
    public static List<IndicatorHit> FromCertificates(string source, IEnumerable<Core.CertificateEntry> certificates, CancellationToken ct)
    {
        var hits = new List<IndicatorHit>();
        var urls = new List<(string, string)>();
        foreach (var c in certificates)
        {
            ct.ThrowIfCancellationRequested();
            if (c.Ca != true) hits.Add(new IndicatorHit("signer", c.Subject, source, $"certificate #{c.Index}"));
            if (!c.SelfIssued) hits.Add(new IndicatorHit("issuer", c.Issuer, source, $"certificate #{c.Index}"));
            foreach (var u in c.Urls)
            {
                int space = u.IndexOf(' ');
                urls.Add((space < 0 ? u : u[(space + 1)..], $"{(space < 0 ? "URL" : u[..space] + " URL")} of certificate #{c.Index}"));
            }
        }
        hits.AddRange(FromText(source, urls, ct));
        return hits;
    }

    /// <summary>A domain name as read from a capture or document: trimmed, lower case, trailing dot dropped; empty for none.</summary>
    public static string Domain(string name) => name.Trim().TrimEnd('.').ToLowerInvariant();

    /// <summary>The indicator type of a host name: ipv4 or ipv6 for an address literal, else domain.</summary>
    public static string HostType(string host) =>
        System.Net.IPAddress.TryParse(host, out var ip) ? ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 ? "ipv6" : "ipv4" : "domain";

    /// <summary>The hits of the file's assemblies and views merged by type and value; sources and first location keep reading order.</summary>
    public static IndicatorFacts Of(InspectionService.FileSummary summary)
    {
        var rows = new Dictionary<(string Type, string Value), (List<string> Sources, string Location)>();
        var notes = new List<string>();
        void Add(string type, string value, string source, string? location)
        {
            var key = (type, value);
            var where = location == null ? source : $"{source}: {location}";
            if (!rows.TryGetValue(key, out var row)) rows[key] = row = ([], where);
            if (!row.Sources.Contains(source)) row.Sources.Add(source);
        }
        foreach (var a in summary.Assemblies)
        {
            foreach (var v in a.NetworkValues ?? a.Values.Top.Where(v => NetworkTypes.Contains(v.Type)))
                Add(v.Type, v.Value, a.Path, v.Locations.FirstOrDefault());
            if (a.NetworkValues == null && a.Values.Total > a.Values.Top.Count)
                notes.Add($"{a.Path}: {a.Values.Top.Count} of {a.Values.Total} extracted values listed; extract_strings lists all.");
        }
        foreach (var h in summary.Views.OrderBy(v => v.Key, StringComparer.Ordinal).SelectMany(v => v.Value.Indicators))
            Add(h.Type, h.Value, h.Source, h.Location);
        var list = rows.Select(r => new Indicator(r.Key.Type, r.Key.Value, r.Value.Sources, r.Value.Location))
            .OrderBy(i => Types.ToList().IndexOf(i.Type)).ThenBy(i => i.Value, StringComparer.Ordinal).ToList();
        return new IndicatorFacts(list.Count, list.GroupBy(i => i.Type).ToDictionary(g => g.Key, g => g.Count()), list, notes);
    }
}
