using System.Text.Json;
using Corvus.Native.Providers;

namespace Corvus.Services.Analysis.Dependencies;

/// <summary>
/// An advisory that applies to a component: the OSV id, its aliases (CVE, GHSA), summary, the highest CVSS score of its
/// group (null when none is given) and the versions that fix it.
/// </summary>
public sealed record DependencyAdvisory(string Component, string Name, string Version, string Id, IReadOnlyList<string> Aliases, string? Summary,
    string? Severity, IReadOnlyList<string> Fixed);

/// <summary>
/// The advisory check of a dependency inventory. State is "checked" or "not checked" (never "none found" without a check);
/// Checked counts the components with a package URL that were matched, NotChecked those without one.
/// </summary>
public sealed record DependencyAdvisories(string State, string? Checker, int Checked, int NotChecked, IReadOnlyList<DependencyAdvisory> Findings,
    string? Note);

/// <summary>Matches a dependency inventory's package URLs against OSV advisories with osv-scanner, offline.</summary>
internal static class OsvAdvisories
{
    private static readonly TimeSpan Timeout = TimeSpan.FromMinutes(5);
    private const long MaxOutput = 64L * 1024 * 1024;

    /// <summary>The variable osv-scanner reads its offline databases from; passed through to it when set.</summary>
    private const string DatabaseVariable = "OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY";

    /// <summary>The advisories of <paramref name="components"/>; "not checked" with the reason when osv-scanner is not usable or fails.</summary>
    public static DependencyAdvisories Check(IReadOnlyList<DependencyComponent> components, CancellationToken ct)
    {
        var tool = ExternalTools.OsvScanner;
        var candidates = components.Where(c => c.Purl != null).ToList();
        int without = components.Count - candidates.Count;
        var probe = ExternalTools.Probe(tool);
        if (!probe.Usable)
            return NotChecked(null, without + candidates.Count, $"advisories not checked: osv-scanner {probe.Problem}; {probe.Remediation}");
        var checker = $"osv-scanner {probe.Version ?? "(version unknown)"}, offline";
        if (candidates.Count == 0) return NotChecked(checker, without, "advisories not checked: no component has a package URL");
        var dir = Path.Combine(Path.GetTempPath(), "corvus-osv", $"{Environment.ProcessId}-{Guid.NewGuid():N}");
        try
        {
            Directory.CreateDirectory(dir);
            // osv-scanner picks its CycloneDX reader by the .cdx.json file name.
            var sbom = Path.Combine(dir, "components.cdx.json");
            File.WriteAllBytes(sbom, Bom(candidates));
            var environment = Environment.GetEnvironmentVariable(DatabaseVariable) is { Length: > 0 } db
                ? new Dictionary<string, string?> { [DatabaseVariable] = db } : null;
            var run = ExternalTools.Run(probe.Path!, ExternalTools.Arguments(tool, "scan", ("file", sbom)), Timeout, MaxOutput, ct, environment);
            return Read(run, candidates, without, checker);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            return NotChecked(checker, components.Count, $"advisories not checked: {ex.Message}");
        }
        finally
        {
            try { Directory.Delete(dir, true); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException) { }
        }
    }

    /// <summary>The advisories osv-scanner's JSON report names for <paramref name="candidates"/>, or "not checked" with its error.</summary>
    internal static DependencyAdvisories Read(ExternalTools.RunResult run, IReadOnlyList<DependencyComponent> candidates, int without, string checker)
    {
        // osv-scanner exits 0 with no advisory, 1 with advisories, and 127 or 128 on an error.
        if (run.StartError != null || run.TimedOut || run.Truncated || run.ExitCode is not (0 or 1))
        {
            var why = run.StartError ?? (run.TimedOut ? $"no answer within {Timeout.TotalMinutes:0} min" : run.Truncated ? $"a report over {MaxOutput / (1024 * 1024)} MiB"
                : $"exit {run.ExitCode}: {LastLines(run.Stderr)}");
            return NotChecked(checker, candidates.Count + without, $"advisories not checked: osv-scanner gave {why}");
        }
        var findings = new List<DependencyAdvisory>();
        try
        {
            using var doc = JsonDocument.Parse(run.Output);
            var byPurl = candidates.GroupBy(c => c.Purl!, StringComparer.OrdinalIgnoreCase).ToDictionary(g => g.Key, g => g.First(), StringComparer.OrdinalIgnoreCase);
            foreach (var result in Array(doc.RootElement, "results"))
            foreach (var package in Array(result, "packages"))
            {
                var info = package.GetProperty("package");
                var purl = Text(info, "purl");
                var name = Text(info, "name") ?? "";
                var version = Text(info, "version") ?? "";
                var component = purl != null && byPurl.TryGetValue(purl, out var c) ? c
                    : candidates.FirstOrDefault(x => x.Name.Equals(name, StringComparison.OrdinalIgnoreCase) && x.Version == version);
                var vulns = Array(package, "vulnerabilities").ToDictionary(v => Text(v, "id") ?? "", v => v, StringComparer.Ordinal);
                // A group is one advisory published under several ids (GHSA and CVE); it is reported once.
                var groups = Array(package, "groups").Select(g => (Ids: Strings(g, "ids"), Aliases: Strings(g, "aliases"), Severity: Text(g, "max_severity"))).ToList();
                if (groups.Count == 0) groups = [.. vulns.Keys.Select(id => (Ids: (IReadOnlyList<string>)[id], Aliases: (IReadOnlyList<string>)[], Severity: (string?)null))];
                foreach (var (ids, aliases, severity) in groups)
                {
                    if (ids.Count == 0) continue;
                    var id = ids[0];
                    var vuln = vulns.GetValueOrDefault(id);
                    findings.Add(new DependencyAdvisory(component?.Ref ?? purl ?? name, name, version, id,
                        [.. ids.Skip(1).Concat(aliases).Where(a => a != id).Distinct(StringComparer.Ordinal)],
                        vuln.ValueKind == JsonValueKind.Object ? Text(vuln, "summary") : null, severity is { Length: > 0 } ? severity : null,
                        vuln.ValueKind == JsonValueKind.Object ? Fixed(vuln, name) : []));
                }
            }
        }
        catch (Exception ex) when (ex is JsonException or InvalidOperationException or KeyNotFoundException)
        {
            return NotChecked(checker, candidates.Count + without, $"advisories not checked: osv-scanner's report could not be read ({ex.Message})");
        }
        var note = without > 0 ? $"{without} components without a package URL were not checked" : null;
        return new DependencyAdvisories("checked", checker, candidates.Count, without, findings, note);
    }

    private static DependencyAdvisories NotChecked(string? checker, int notChecked, string note) => new("not checked", checker, 0, notChecked, [], note);

    /// <summary>A minimal CycloneDX document of the components osv-scanner matches by package URL.</summary>
    private static byte[] Bom(IReadOnlyList<DependencyComponent> candidates)
    {
        using var stream = new MemoryStream();
        using (var w = new Utf8JsonWriter(stream))
        {
            w.WriteStartObject();
            w.WriteString("bomFormat", "CycloneDX");
            w.WriteString("specVersion", CycloneDx.SpecVersion);
            w.WriteNumber("version", 1);
            w.WriteStartArray("components");
            foreach (var c in candidates)
            {
                w.WriteStartObject();
                w.WriteString("bom-ref", c.Ref);
                w.WriteString("type", "library");
                w.WriteString("name", c.Name);
                if (c.Version != null) w.WriteString("version", c.Version);
                w.WriteString("purl", c.Purl);
                w.WriteEndObject();
            }
            w.WriteEndArray();
            w.WriteEndObject();
        }
        return stream.ToArray();
    }

    /// <summary>The fixed versions an advisory's ranges name for the package <paramref name="name"/>.</summary>
    private static List<string> Fixed(JsonElement vuln, string name) =>
        [.. Array(vuln, "affected")
            .Where(a => a.TryGetProperty("package", out var p) && string.Equals(Text(p, "name"), name, StringComparison.OrdinalIgnoreCase))
            .SelectMany(a => Array(a, "ranges")).SelectMany(r => Array(r, "events"))
            .Select(e => Text(e, "fixed")).OfType<string>().Distinct(StringComparer.Ordinal)];

    private static IEnumerable<JsonElement> Array(JsonElement e, string name) =>
        e.ValueKind == JsonValueKind.Object && e.TryGetProperty(name, out var a) && a.ValueKind == JsonValueKind.Array ? a.EnumerateArray() : [];

    private static string? Text(JsonElement e, string name) =>
        e.ValueKind == JsonValueKind.Object && e.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;

    private static IReadOnlyList<string> Strings(JsonElement e, string name) => [.. Array(e, name).Where(x => x.ValueKind == JsonValueKind.String).Select(x => x.GetString()!)];

    private static string LastLines(string text)
    {
        var lines = text.ReplaceLineEndings("\n").Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        var tail = string.Join("; ", lines.TakeLast(2));
        return tail.Length == 0 ? "no message" : tail[..Math.Min(tail.Length, 500)];
    }
}
