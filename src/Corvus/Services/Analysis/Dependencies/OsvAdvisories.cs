using System.IO.Compression;

namespace Corvus.Services.Analysis.Dependencies;

/// <summary>An OSV advisory for a component; Severity is null when unknown.</summary>
public sealed record DependencyAdvisory(
    string Component, string Name, string Version, string Id,
    IReadOnlyList<string> Aliases, string? Summary, string? Severity,
    IReadOnlyList<string> Fixed);

/// <summary>The advisory check of an inventory; Note names what was not checked.</summary>
public sealed record DependencyAdvisories(
    string State, string? Checker, int Checked, int NotChecked,
    IReadOnlyList<DependencyAdvisory> Findings, string? Note)
{
    /// <summary>Why a component, by Ref, was not matched; a component absent from it was.</summary>
    [System.Text.Json.Serialization.JsonIgnore]
    public IReadOnlyDictionary<string, string> Unmatched { get; init; } = new Dictionary<string, string>();
}

/// <summary>Matches components against OSV records in a local folder.</summary>
internal static class OsvAdvisories
{
    /// <summary>The variable naming the folder of OSV exports.</summary>
    internal const string DatabaseVariable = "CORVUS_OSV_DATABASE";

    private const int MaxRecordBytes = 8 * 1024 * 1024;

    private static readonly System.Collections.Concurrent.ConcurrentDictionary<string, Scan> Cache = new();

    /// <summary>The advisories of <paramref name="components"/>; "partial" when any was not matched.</summary>
    internal static DependencyAdvisories Check(IReadOnlyList<DependencyComponent> components, CancellationToken ct)
    {
        var candidates = components
            .Where(c => c.Purl != null && c.Version != null && VersionOrder.Osv(c.Ecosystem) != null).ToList();
        int without = components.Count - candidates.Count;
        var unmatched = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var c in components.Except(candidates))
            unmatched[c.Ref] = VersionOrder.Osv(c.Ecosystem) == null
                ? c.Ecosystem == "native" ? "no advisory source covers C libraries" : $"no advisory source covers {c.Ecosystem} components"
                : "no package URL or version";
        if (Native.Providers.ExternalTools.ReadVariable(DatabaseVariable) is not { Length: > 0 } root)
            return NotChecked(components, unmatched,
                $"advisories not checked: set {DatabaseVariable} to a folder of OSV exports, " +
                "one folder per ecosystem holding all.zip");
        if (!Directory.Exists(root))
            return NotChecked(components, unmatched,
                $"advisories not checked: {DatabaseVariable} names a folder that does not exist");

        var problems = new List<string>();
        var findings = new List<DependencyAdvisory>();
        int matched = 0;
        var read = new List<string>();
        foreach (var group in candidates.GroupBy(c => VersionOrder.Osv(c.Ecosystem)!))
        {
            var ecosystem = group.Key;
            var wanted = group.Select(c => Key(ecosystem, c.Name)).ToHashSet(StringComparer.Ordinal);
            var scan = Open(root, ecosystem, wanted, ct);
            if (scan == null || scan.Error != null)
            {
                var why = scan?.Error ?? $"no {ecosystem} database under {DatabaseVariable}";
                problems.Add($"{group.Count()} {ecosystem} components not checked: " + why);
                foreach (var c in group) unmatched[c.Ref] = why;
                continue;
            }
            int unordered = 0;
            foreach (var c in group)
            {
                bool ordered = true;
                var seen = new HashSet<string>(StringComparer.Ordinal);
                foreach (var record in scan.Records.Where(r => !r.Withdrawn))
                {
                    var hit = record.Affects(ecosystem, c.Name, c.Version!, out var fixedIn);
                    if (hit == null) ordered = false;
                    if (hit != true || !seen.Add(record.Id) || record.Aliases.Any(seen.Contains)) continue;
                    seen.UnionWith(record.Aliases);
                    findings.Add(new(c.Ref, c.Name, c.Version!, record.Id,
                        [.. record.Aliases.Where(a => a != record.Id)],
                        record.Summary, record.Severity, fixedIn));
                }
                if (ordered) matched++;
                else
                {
                    unordered++;
                    unmatched[c.Ref] = "a version could not be ordered";
                }
            }
            read.Add(ecosystem);
            if (unordered > 0)
                problems.Add($"{unordered} {ecosystem} components not checked: a version could not be ordered");
            if (scan.Skipped > 0)
                problems.Add($"{scan.Skipped:N0} of {scan.Total:N0} {ecosystem} records not read " +
                    $"(not JSON, corrupt or over {MaxRecordBytes / (1024 * 1024)} MiB)");
        }
        var notes = new List<string>(problems);
        if (without > 0)
            notes.Add($"{without} components without a package URL or a version, " +
                "or in an ecosystem OSV does not cover, were not checked");
        var note = notes.Count == 0 ? null : string.Join("; ", notes);
        if (matched == 0)
            return NotChecked(components, unmatched, "advisories not checked: " + (note ?? "no component to match"));
        var state = problems.Count == 0 && without == 0 ? "checked" : "partial";
        return new DependencyAdvisories(state, "in process", matched, components.Count - matched, findings, note) { Unmatched = unmatched };
    }

    private static string Key(string ecosystem, string name) => ecosystem switch
    {
        "PyPI" => Purl.PyPIName(name),
        "NuGet" => name.ToLowerInvariant(),
        _ => name,
    };

    private sealed record Scan(List<OsvRecord> Records, int Total, int Skipped, string? Error = null);

    // Reads the records naming a wanted package; null when no database exists.
    private static Scan? Open(string root, string ecosystem, HashSet<string> wanted, CancellationToken ct)
    {
        var folder = Path.Combine(root, ecosystem);
        var zip = Path.Combine(folder, "all.zip");
        var cacheKey = File.Exists(zip)
            ? $"{zip}|{File.GetLastWriteTimeUtc(zip).Ticks}|{new FileInfo(zip).Length}|" +
              string.Join('\n', wanted.Order(StringComparer.Ordinal))
            : null;
        if (cacheKey != null && Cache.TryGetValue(cacheKey, out var cached)) return cached;

        var records = new List<OsvRecord>();
        int total = 0, skipped = 0;
        void Add(byte[]? json)
        {
            ct.ThrowIfCancellationRequested();
            total++;
            var record = json == null ? null : OsvRecord.Parse(json);
            if (record == null) skipped++;
            else if (record.Affected.Any(a => a.Ecosystem == ecosystem && wanted.Contains(Key(ecosystem, a.Name))))
                records.Add(record);
        }
        try
        {
            if (cacheKey != null)
            {
                using var archive = ZipFile.OpenRead(zip);
                var entries = archive.Entries
                    .Where(e => e.FullName.EndsWith(".json", StringComparison.OrdinalIgnoreCase));
                foreach (var entry in entries)
                {
                    byte[]? bytes = null;
                    try { bytes = ReadBounded(entry); }
                    catch (InvalidDataException) { }
                    Add(bytes);
                }
                var scan = new Scan(records, total, skipped);
                if (Cache.Count >= 8) Cache.Clear();
                Cache[cacheKey] = scan;
                return scan;
            }
            if (!Directory.Exists(folder)) return null;
            foreach (var file in Directory.EnumerateFiles(folder, "*.json", SearchOption.AllDirectories))
                Add(new FileInfo(file).Length > MaxRecordBytes ? null : File.ReadAllBytes(file));
            return new(records, total, skipped);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or InvalidDataException)
        {
            return new([], 0, 0, $"the {ecosystem} database could not be read ({ex.Message})");
        }
    }

    // The declared size can be forged, so the copy itself stops at the bound.
    private static byte[]? ReadBounded(ZipArchiveEntry entry)
    {
        using var s = entry.Open();
        using var buffer = new MemoryStream();
        var chunk = new byte[81920];
        int n;
        while ((n = s.Read(chunk, 0, chunk.Length)) > 0)
        {
            buffer.Write(chunk, 0, n);
            if (buffer.Length > MaxRecordBytes) return null;
        }
        return buffer.ToArray();
    }

    // A component with no reason of its own takes the overall note.
    private static DependencyAdvisories NotChecked(IReadOnlyList<DependencyComponent> components, Dictionary<string, string> reasons, string note) =>
        new("not checked", null, 0, components.Count, [], note)
        {
            Unmatched = components.ToDictionary(c => c.Ref, c => reasons.GetValueOrDefault(c.Ref) ?? note, StringComparer.Ordinal),
        };
}
