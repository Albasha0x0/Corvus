using System.Globalization;
using System.Text.Json;

namespace Corvus.Services.Analysis.Dependencies;

/// <summary>One package entry of an OSV record: versions and range events.</summary>
internal sealed record OsvAffected(
    string Ecosystem, string Name, IReadOnlyList<string> Versions,
    IReadOnlyList<IReadOnlyList<(string Kind, string Value)>> Ranges);

/// <summary>An OSV record (osv.dev schema) reduced to what version matching and reporting read.</summary>
internal sealed record OsvRecord(
    string Id, IReadOnlyList<string> Aliases, string? Summary, string? Severity,
    bool Withdrawn, IReadOnlyList<OsvAffected> Affected)
{
    /// <summary>The record in <paramref name="json"/>; null when it is not JSON or has no id.</summary>
    internal static OsvRecord? Parse(byte[] json)
    {
        try
        {
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;
            if (Text(root, "id") is not { Length: > 0 } id) return null;
            var affected = new List<OsvAffected>();
            foreach (var a in Array(root, "affected"))
            {
                if (!a.TryGetProperty("package", out var p) ||
                    Text(p, "ecosystem") is not { } ecosystem || Text(p, "name") is not { } name) continue;
                var ranges = new List<IReadOnlyList<(string, string)>>();
                foreach (var r in Array(a, "ranges"))
                {
                    if (Text(r, "type") is not ("SEMVER" or "ECOSYSTEM")) continue;
                    ranges.Add([.. Array(r, "events")
                        .SelectMany(e => e.ValueKind == JsonValueKind.Object ? e.EnumerateObject() : [])
                        .Where(f => f.Value.ValueKind == JsonValueKind.String &&
                            f.Name is "introduced" or "fixed" or "last_affected")
                        .Select(f => (f.Name, f.Value.GetString()!))]);
                }
                // A release suffix ("Debian:12") is dropped; the base name sets the order.
                affected.Add(new(ecosystem.Split(':')[0], name,
                    [.. Array(a, "versions").Where(v => v.ValueKind == JsonValueKind.String).Select(v => v.GetString()!)],
                    ranges));
            }
            return new(id,
                [.. Array(root, "aliases").Where(v => v.ValueKind == JsonValueKind.String).Select(v => v.GetString()!)],
                Text(root, "summary"), SeverityOf(root), root.TryGetProperty("withdrawn", out _), affected);
        }
        catch (Exception ex) when (ex is JsonException or InvalidOperationException) { return null; }
    }

    /// <summary>Whether the version is affected; null when it cannot be ordered.</summary>
    internal bool? Affects(string ecosystem, string name, string version, out IReadOnlyList<string> fixedIn)
    {
        var fixes = new List<string>();
        fixedIn = fixes;
        bool? result = false;
        foreach (var a in Affected.Where(a => a.Ecosystem == ecosystem && NameMatches(ecosystem, a.Name, name)))
        {
            var hit = AffectedBy(a, ecosystem, version);
            if (hit == true)
            {
                result = true;
                fixes.AddRange(a.Ranges.SelectMany(r => r)
                    .Where(e => e.Kind == "fixed" && VersionOrder.Compare(ecosystem, version, e.Value) < 0)
                    .Select(e => e.Value));
            }
            else if (hit == null && result == false) result = null;
        }
        fixedIn = [.. fixes.Distinct(StringComparer.Ordinal)];
        return result;
    }

    /// <summary>Whether the names are one package under the ecosystem's rules.</summary>
    internal static bool NameMatches(string ecosystem, string a, string b) => ecosystem switch
    {
        "PyPI" => Purl.PyPIName(a) == Purl.PyPIName(b),
        "NuGet" => string.Equals(a, b, StringComparison.OrdinalIgnoreCase),
        _ => a == b,
    };

    private static bool? AffectedBy(OsvAffected a, string ecosystem, string version)
    {
        bool? unknown = false;
        foreach (var listed in a.Versions)
        {
            if (listed == version) return true;
            var c = VersionOrder.Compare(ecosystem, listed, version);
            if (c == 0) return true;
            if (c == null) unknown = null;
        }
        foreach (var events in a.Ranges)
        {
            // Events run in listed order; introduced opens, fixed and last_affected close.
            bool inRange = false, unordered = false;
            foreach (var (kind, value) in events)
            {
                if (kind == "introduced" && value == "0") { inRange = true; continue; }
                if (VersionOrder.Compare(ecosystem, version, value) is not { } c) { unordered = true; continue; }
                if (kind == "introduced" && c >= 0) inRange = true;
                else if (kind == "fixed" && c >= 0) inRange = false;
                else if (kind == "last_affected" && c > 0) inRange = false;
            }
            // A range with an unorderable event is unknown, not unaffected.
            if (unordered) unknown = null;
            else if (inRange) return true;
        }
        return unknown;
    }

    private static string? SeverityOf(JsonElement root)
    {
        double? best = null;
        foreach (var s in Array(root, "severity"))
            if (Text(s, "type") == "CVSS_V3" && Text(s, "score") is { } vector &&
                Cvss3(vector) is { } score && score > (best ?? -1)) best = score;
        if (best != null) return best.Value.ToString("0.0", CultureInfo.InvariantCulture);
        return root.TryGetProperty("database_specific", out var db) ? Text(db, "severity") : null;
    }

    /// <summary>The CVSS 3.x base score of a vector; null when a base metric is bad.</summary>
    internal static double? Cvss3(string vector)
    {
        var m = vector.Split('/').Skip(1).Select(p => p.Split(':')).Where(p => p.Length == 2)
            .GroupBy(p => p[0]).ToDictionary(g => g.Key, g => g.First()[1]);
        if (!vector.StartsWith("CVSS:3", StringComparison.Ordinal) ||
            !m.TryGetValue("S", out var scope) || scope is not ("U" or "C")) return null;
        bool changed = scope == "C";
        double? Pick(string key, params (string, double)[] values) =>
            m.TryGetValue(key, out var v) && values.FirstOrDefault(x => x.Item1 == v) is { Item1: not null } hit
                ? hit.Item2 : null;
        var av = Pick("AV", ("N", .85), ("A", .62), ("L", .55), ("P", .2));
        var ac = Pick("AC", ("L", .77), ("H", .44));
        var pr = Pick("PR", ("N", .85), ("L", changed ? .68 : .62), ("H", changed ? .5 : .27));
        var ui = Pick("UI", ("N", .85), ("R", .62));
        var c = Pick("C", ("H", .56), ("L", .22), ("N", 0));
        var i = Pick("I", ("H", .56), ("L", .22), ("N", 0));
        var a = Pick("A", ("H", .56), ("L", .22), ("N", 0));
        if (av == null || ac == null || pr == null || ui == null || c == null || i == null || a == null)
            return null;
        var iss = 1 - (1 - c.Value) * (1 - i.Value) * (1 - a.Value);
        var impact = changed ? 7.52 * (iss - 0.029) - 3.25 * Math.Pow(iss - 0.02, 15) : 6.42 * iss;
        if (impact <= 0) return 0;
        var exploitability = 8.22 * av.Value * ac.Value * pr.Value * ui.Value;
        return RoundUp(Math.Min((changed ? 1.08 : 1) * (impact + exploitability), 10));
    }

    // The CVSS 3.1 round-up, immune to binary floating point error.
    private static double RoundUp(double x)
    {
        long n = (long)Math.Round(x * 100000);
        return n % 10000 == 0 ? n / 100000.0 : (Math.Floor(n / 10000.0) + 1) / 10.0;
    }

    private static IEnumerable<JsonElement> Array(JsonElement e, string name) =>
        e.ValueKind == JsonValueKind.Object && e.TryGetProperty(name, out var a) &&
        a.ValueKind == JsonValueKind.Array ? a.EnumerateArray() : [];

    private static string? Text(JsonElement e, string name) =>
        e.ValueKind == JsonValueKind.Object && e.TryGetProperty(name, out var v) &&
        v.ValueKind == JsonValueKind.String ? v.GetString() : null;
}
