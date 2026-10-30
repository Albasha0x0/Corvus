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

    /// <summary>Types written for network values and TLS client fingerprints.</summary>
    public static readonly IReadOnlyList<string> Types = ["url", "domain", "ipv4", "ipv6", "email", "ja3", "ja4"];

    private static readonly HashSet<string> NetworkTypes = new(StringComparer.Ordinal) { "url", "domain", "ipv4", "ipv6", "email" };

    /// <summary>The network values of field texts, each with its field's location; empty for none.</summary>
    public static List<IndicatorHit> FromText(string source, IEnumerable<(string Text, string Location)> fields, CancellationToken ct) =>
        [.. Values.FromFields(fields, out _, ct).Where(v => NetworkTypes.Contains(v.Type))
            .Select(v => new IndicatorHit(v.Type, v.Value, source, v.Locations.FirstOrDefault()))];

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
