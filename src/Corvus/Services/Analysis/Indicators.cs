namespace Corvus.Services.Analysis;

/// <summary>An observable a reader found, with its source, location and evidence class.</summary>
public sealed record IndicatorHit(string Type, string Value, string Source, string? Location, string Evidence = IndicatorEvidence.String);

/// <summary>A deduplicated indicator with its readers, first location and strongest evidence class.</summary>
public sealed record Indicator(string Type, string Value, IReadOnlyList<string> Sources, string FirstLocation, string Evidence);

/// <summary>How an observable was found, weakest first.</summary>
public static class IndicatorEvidence
{
    /// <summary>Text matched in a string or a text run with no use of it seen.</summary>
    public const string String = "string";

    /// <summary>A link target, call argument or certificate field the file refers to.</summary>
    public const string Reference = "reference";

    /// <summary>Text recovered by decoding or peeling a layer of the file.</summary>
    public const string Decoded = "decoded";

    /// <summary>A value measured or read from the file itself, such as its hash or signer.</summary>
    public const string Computed = "computed";

    /// <summary>A name or fingerprint seen in captured network traffic.</summary>
    public const string Traffic = "traffic";

    /// <summary>A value a tenant's saved query result reports about the file, not read from the file; it is outside <see cref="Classes"/> and ranks with the weakest.</summary>
    public const string Tenant = "tenant";

    /// <summary>The classes, weakest first.</summary>
    public static readonly string[] Classes = [String, Reference, Decoded, Computed, Traffic];

    private static readonly int[] Scores = [15, 50, 70, 80, 85];

    // An unknown class ranks with the weakest.
    private static int Rank(string evidence) => Math.Max(0, Array.IndexOf(Classes, evidence));

    /// <summary>The STIX confidence (0 to 100) of a class; an unknown class gets the weakest score.</summary>
    public static int Confidence(string evidence) => Scores[Rank(evidence)];

    /// <summary>The stronger of two classes.</summary>
    public static string Stronger(string a, string b) => Rank(b) > Rank(a) ? b : a;
}

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
    public static List<IndicatorHit> FromText(string source, IEnumerable<(string Text, string Location)> fields, CancellationToken ct, string evidence = IndicatorEvidence.Reference) =>
        [.. Values.FromFields(fields, out _, ct).Where(v => NetworkTypes.Contains(v.Type))
            .Select(v => new IndicatorHit(v.Type, v.Value, source, v.Locations.FirstOrDefault(), evidence))];

    // Shorter runs are mostly identifiers and padding; 1.1.1.1 is the shortest
    // address that routes.
    private const int MinStringChars = 7, MaxStringChars = 2_048, MaxImageBytes = 256 << 20;

    /// <summary>
    /// Bounds of an image string scan: <paramref name="MaxPerPass"/> strings kept, shared by the passes or one budget each (<paramref name="PerPass"/>),
    /// UTF-16 read at both file offset parities (<paramref name="BothParities"/>), a file range not read, and runs a caller drops, counted.
    /// </summary>
    public sealed record ImageScanBounds(int MaxPerPass, bool PerPass = false, bool BothParities = false, (long Offset, long Size)? Excluded = null, Func<long, bool>? Skipped = null);

    /// <summary>What an image string scan did not read: runs dropped by <see cref="ImageScanBounds.Skipped"/> and each bound it hit.</summary>
    public sealed record ImageScanReport(int Skipped, IReadOnlyList<string> Limits);

    /// <summary>The network values of the printable ASCII and UTF-16 runs of a native image, each with its file offset; empty for none.</summary>
    public static List<IndicatorHit> FromImageStrings(string source, byte[] image, CancellationToken ct) =>
        FromImageStrings(source, image, ct, new ImageScanBounds(MaxPerReader), out _);

    /// <summary>The network values of the runs of a native image read within <paramref name="bounds"/>; <paramref name="report"/> names what was not read.</summary>
    public static List<IndicatorHit> FromImageStrings(string source, byte[] image, CancellationToken ct, ImageScanBounds bounds, out ImageScanReport report)
    {
        var fields = new List<(string, string)>();
        var limits = new List<string>();
        int skipped = 0;
        if (image.Length > MaxImageBytes) limits.Add($"only the first {MaxImageBytes:N0} bytes were scanned");
        void Scan(int step, int first, string encoding)
        {
            var run = new System.Text.StringBuilder();
            int start = 0, kept = 0;
            int end = (int)Math.Min(image.Length, MaxImageBytes);
            bool Open() => (bounds.PerPass ? kept : fields.Count) < bounds.MaxPerPass;
            int i = first;
            for (; i + step <= end && Open(); i += step)
            {
                if ((i & 0xFFFFF) == 0) ct.ThrowIfCancellationRequested();
                bool text = image[i] is >= 0x20 and < 0x7F && (step == 1 || image[i + 1] == 0)
                    && !(bounds.Excluded is { } x && i >= x.Offset && i < x.Offset + x.Size);
                if (text)
                {
                    if (run.Length == 0) start = i;
                    if (run.Length < MaxStringChars) run.Append((char)image[i]);
                    continue;
                }
                Flush();
            }
            if (i + step <= end) limits.Add($"{encoding} string scan stopped at {bounds.MaxPerPass:N0} strings");
            Flush();
            void Flush()
            {
                if (step == 1) TrimToDerLength(run, start, image);
                if (run.Length >= MinStringChars && run.ToString() is var t && (t.Contains("://") || t.Contains('@') || t.Contains('.') || t.Count(c => c == ':') >= 2))
                {
                    if (bounds.Skipped?.Invoke(start) == true) skipped++;
                    else { fields.Add((t, $"{encoding} string at file offset 0x{start:x}")); kept++; }
                }
                run.Clear();
            }
        }
        Scan(1, 0, "ASCII");
        Scan(2, 0, "UTF-16");
        if (bounds.BothParities) Scan(2, 1, "UTF-16 (odd offset)");
        report = new ImageScanReport(skipped, [.. limits.Distinct()]);
        return FromText(source, fields, ct, IndicatorEvidence.String);
    }

    // An IA5String or URI general name in DER states its length; the next tag byte is no part of it.
    private static void TrimToDerLength(System.Text.StringBuilder run, int start, byte[] image)
    {
        if (start < 2 || run.Length == 0) return;
        int length = image[start - 1], tagAt = start - 2;
        // Long form with one length byte: 0x81, then the length.
        if (tagAt >= 1 && image[tagAt] == 0x81) tagAt--;
        if (image[tagAt] is not (0x16 or 0x86) || length == 0 || length >= run.Length) return;
        run.Length = length;
    }

    /// <summary>The signer and issuer names and the OCSP, CRL and CA issuer URLs of certificates; self-issued certificates give no issuer.</summary>
    public static List<IndicatorHit> FromCertificates(string source, IEnumerable<Core.CertificateEntry> certificates, CancellationToken ct)
    {
        var hits = new List<IndicatorHit>();
        var urls = new List<(string, string)>();
        foreach (var c in certificates)
        {
            ct.ThrowIfCancellationRequested();
            if (c.Ca != true) hits.Add(new IndicatorHit("signer", c.Subject, source, $"certificate #{c.Index}", IndicatorEvidence.Decoded));
            if (!c.SelfIssued) hits.Add(new IndicatorHit("issuer", c.Issuer, source, $"certificate #{c.Index}", IndicatorEvidence.Decoded));
            foreach (var u in c.Urls)
            {
                int space = u.IndexOf(' ');
                urls.Add((space < 0 ? u : u[(space + 1)..], $"{(space < 0 ? "URL" : u[..space] + " URL")} of certificate #{c.Index}"));
            }
        }
        hits.AddRange(FromText(source, urls, ct, IndicatorEvidence.Decoded));
        return hits;
    }

    /// <summary>A domain name as read from a capture or document: trimmed, lower case, trailing dot dropped; empty for none.</summary>
    public static string Domain(string name) => name.Trim().TrimEnd('.').ToLowerInvariant();

    /// <summary>The indicator type of a host name: ipv4 or ipv6 for an address literal, else domain.</summary>
    public static string HostType(string host) =>
        System.Net.IPAddress.TryParse(host, out var ip) ? ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6 ? "ipv6" : "ipv4" : "domain";

    private static readonly string[] NetworkApis = ["System.Net.", "System.Uri::", "System.Diagnostics.Process::Start"];

    /// <summary>The class of an assembly value: a reference when the code passes it to a network API, else a string.</summary>
    internal static string AssemblyEvidence(ExtractedValue v) =>
        v.PassedTo.Any(api => NetworkApis.Any(n => api.Contains(n, StringComparison.Ordinal))) ? IndicatorEvidence.Reference : IndicatorEvidence.String;

    /// <summary>The hits of the file's assemblies and views merged by type and value; sources and first location keep reading order.</summary>
    public static IndicatorFacts Of(InspectionService.FileSummary summary)
    {
        var rows = new Dictionary<(string Type, string Value), (List<string> Sources, string Location, string Evidence)>();
        var notes = new List<string>();
        void Add(string type, string value, string source, string? location, string evidence)
        {
            var key = (type, value);
            var where = location == null ? source : $"{source}: {location}";
            if (!rows.TryGetValue(key, out var row)) rows[key] = row = ([], where, evidence);
            else rows[key] = row = (row.Sources, row.Location, IndicatorEvidence.Stronger(row.Evidence, evidence));
            if (!row.Sources.Contains(source)) row.Sources.Add(source);
        }
        foreach (var a in summary.Assemblies)
        {
            foreach (var v in a.NetworkValues ?? a.Values.Top.Where(v => NetworkTypes.Contains(v.Type)))
                Add(v.Type, v.Value, a.Path, v.Locations.FirstOrDefault(), AssemblyEvidence(v));
            if (a.NetworkValues == null && a.Values.Total > a.Values.Top.Count)
                notes.Add($"{a.Path}: {a.Values.Top.Count} of {a.Values.Total} extracted values listed; extract_strings lists all.");
        }
        foreach (var h in summary.Views.OrderBy(v => v.Key, StringComparer.Ordinal).SelectMany(v => v.Value.Indicators))
            Add(h.Type, h.Value, h.Source, h.Location, h.Evidence);
        var list = rows.Select(r => new Indicator(r.Key.Type, r.Key.Value, r.Value.Sources, r.Value.Location, r.Value.Evidence))
            .OrderBy(i => Types.ToList().IndexOf(i.Type)).ThenBy(i => i.Value, StringComparer.Ordinal).ToList();
        return new IndicatorFacts(list.Count, list.GroupBy(i => i.Type).ToDictionary(g => g.Key, g => g.Count()), list, notes);
    }
}
