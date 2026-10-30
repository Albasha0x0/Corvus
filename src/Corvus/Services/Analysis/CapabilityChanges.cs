using Corvus.Core;
using Corvus.Services.Web.Packages;
using FeatureReport = Corvus.Services.Analysis.InspectionService.FeatureReport;

namespace Corvus.Services.Analysis;

/// <summary>Capabilities and package findings added or removed between two builds; rows present on both sides are not listed.</summary>
public static class CapabilityChanges
{
    /// <summary>Evidence entries shown per row.</summary>
    private const int MaxEvidence = 3;

    /// <summary>Added or removed rows keyed "category/name" in key order, with evidence; capa only when both sides were labelled.</summary>
    public static (IReadOnlyList<EvidenceChange> Rows, IReadOnlyList<string> Notes) Of((FeatureReport Report, bool CapaLabelled) old,
        (FeatureReport Report, bool CapaLabelled) @new)
    {
        var notes = new List<string>();
        bool capa = old.CapaLabelled && @new.CapaLabelled;
        if (!capa && (old.CapaLabelled || @new.CapaLabelled || Native.Providers.ExternalTools.Locate(Native.Providers.ExternalTools.Capa) != null))
            notes.Add($"capa labels not compared: capa has not labelled the {(old.CapaLabelled ? "new" : @new.CapaLabelled ? "old" : "old and new")} " +
                      "build; survey_features category=capa on each build runs it");
        foreach (var (side, report) in new[] { ("old", old.Report), ("new", @new.Report) })
            if (Limits(report) is { Count: > 0 } limits)
                notes.Add($"the {side} build's survey is partial, so a row may stand for unread code: {string.Join("; ", limits.Take(MaxLimits))}" +
                          (limits.Count > MaxLimits ? $" (+{limits.Count - MaxLimits} more)" : ""));
        Dictionary<string, Feature> Keyed(FeatureReport r) => r.Features.Where(f => capa || f.Category != "capa")
            .GroupBy(f => $"{f.Category}/{f.Name}", StringComparer.Ordinal).ToDictionary(g => g.Key, g => g.First(), StringComparer.Ordinal);
        var before = Keyed(old.Report);
        var after = Keyed(@new.Report);
        var rows = before.Keys.Union(after.Keys, StringComparer.Ordinal).Where(k => before.ContainsKey(k) != after.ContainsKey(k)).Order(StringComparer.Ordinal)
            .Select(k => new EvidenceChange(after.ContainsKey(k) ? "added" : "removed", k, before.TryGetValue(k, out var o) ? Evidence(o) : null,
                after.TryGetValue(k, out var n) ? Evidence(n) : null, null)).ToList();
        return (rows, notes);
    }

    /// <summary>Findings keyed "category: detail" added or removed between two package versions; a moved finding is not a change.</summary>
    public static IReadOnlyList<EvidenceChange> Of(PackageReport old, PackageReport @new)
    {
        static Dictionary<string, PackageFinding> Keyed(PackageReport r) => r.Findings.GroupBy(f => $"{f.Category}: {f.Detail}", StringComparer.Ordinal)
            .ToDictionary(g => g.Key, g => g.First(), StringComparer.Ordinal);
        static string Where(PackageFinding f) => f.Level + (f.Path != null ? $" at {f.Path}{(f.Line != null ? $":{f.Line}" : "")}" : "");
        var before = Keyed(old);
        var after = Keyed(@new);
        return [.. before.Keys.Union(after.Keys, StringComparer.Ordinal).Where(k => before.ContainsKey(k) != after.ContainsKey(k)).Order(StringComparer.Ordinal)
            .Select(k => new EvidenceChange(after.ContainsKey(k) ? "added" : "removed", k, before.TryGetValue(k, out var o) ? Where(o) : null,
                after.TryGetValue(k, out var n) ? Where(n) : null, null))];
    }

    /// <summary>Policy facts added or removed between two package versions, and a summary line counting them with the findings by group.</summary>
    // Fact keys use prefixes no finding category uses. Null hosts on either side leave endpoints out.
    public static (IReadOnlyList<EvidenceChange> Rows, string Summary) Policy(PackageReport old, PackageReport @new, IReadOnlyList<EvidenceChange> findings)
    {
        static IEnumerable<string> Facts(PackageReport r) =>
            (r.Hosts ?? []).Select(h => "endpoint: " + h)
            .Concat((r.Binaries ?? []).Select(b => "native file: " + b))
            .Concat((r.Permissions ?? []).Concat(r.HostPermissions ?? []).Select(p => "permission granted: " + p))
            .Concat((r.Agents ?? []).Select(a => $"runs: {a.Kind} {a.Name}" + (a.Command != null ? $": {a.Command}" : "")))
            // The signer without its ref, so a release tag that moves on is not a change.
            .Concat((r.Provenance ?? []).Where(a => a.Signature == "verified").Select(a => $"signed provenance: {a.Format} by {a.Signer?.Split('@')[0]}"));
        var before = Facts(old).ToHashSet(StringComparer.Ordinal);
        var after = Facts(@new).ToHashSet(StringComparer.Ordinal);
        // With no verified provenance left, removed signer rows read as dropped.
        bool dropped = before.Any(IsProvenance) && !after.Any(IsProvenance);
        var rows = before.Union(after, StringComparer.Ordinal).Where(k => before.Contains(k) != after.Contains(k)).Order(StringComparer.Ordinal)
            .Select(k => new EvidenceChange(after.Contains(k) ? "added" : "removed", dropped && IsProvenance(k) ? "provenance dropped: " + k["signed provenance: ".Length..] : k, null, null, null)).ToList();

        // Policy groups, in the order a reviewer reads them; findings rows count by their category.
        (string Group, Func<string, bool> Has)[] groups =
        [
            ("install script(s)", k => k.StartsWith("install script: ", StringComparison.Ordinal)),
            ("endpoint(s)", k => k.StartsWith("endpoint: ", StringComparison.Ordinal)),
            ("native file(s)", k => k.StartsWith("native file: ", StringComparison.Ordinal)),
            ("permission(s)", k => k.StartsWith("permission granted: ", StringComparison.Ordinal)),
            ("run(s) on open, checkout or build", k => k.StartsWith("runs: ", StringComparison.Ordinal)),
            ("signed provenance", k => k.StartsWith("signed provenance: ", StringComparison.Ordinal) || k.StartsWith("provenance dropped: ", StringComparison.Ordinal) || k.StartsWith("provenance: ", StringComparison.Ordinal)),
            ("transformed or decoded code finding(s)", k => k.StartsWith("transformed code: ", StringComparison.Ordinal) || k.StartsWith("dynamic code: ", StringComparison.Ordinal)),
            ("network, process or credential finding(s)", k => k.StartsWith("network: ", StringComparison.Ordinal) || k.StartsWith("process: ", StringComparison.Ordinal)
                || k.StartsWith("credentials: ", StringComparison.Ordinal) || k.StartsWith("exfiltration: ", StringComparison.Ordinal)),
            ("GuardDog rule match(es)", k => k.StartsWith("rule match: ", StringComparison.Ordinal)),
        ];
        var all = findings.Concat(rows).ToList();
        string Count(string kind) => string.Join(", ", groups.Select(g => (g.Group, N: all.Count(r => r.Kind == kind && g.Has(r.Key)))).Where(g => g.N > 0).Select(g => $"{g.N} {g.Group}"));
        var added = Count("added");
        var removed = Count("removed");
        var summary = $"package policy: review {old.Review} -> {@new.Review}; added: {(added.Length > 0 ? added : "nothing")}; removed: {(removed.Length > 0 ? removed : "nothing")}" +
                      (old.Hosts == null || @new.Hosts == null ? "; endpoints not compared" : "");
        return (rows, summary);
    }

    private static bool IsProvenance(string key) => key.StartsWith("signed provenance: ", StringComparison.Ordinal);

    /// <summary>Time both surveys of a comparison may add to it; past it the capabilities are reported not compared.</summary>
    private static readonly TimeSpan SurveyBudget = TimeSpan.FromSeconds(2);

    /// <summary>Survey limits named per side; the count covers them all.</summary>
    private const int MaxLimits = 3;

    // Every survey note names something it could not read, except these descriptions of what the rules cover.
    private static readonly string[] Descriptions = ["native image: rules over ", "Apple app rules ", "category capa: ", "capa: "];

    private static List<string> Limits(FeatureReport report) =>
        [.. report.Notes.Where(n => !Descriptions.Any(d => n.StartsWith(d, StringComparison.Ordinal)))];

    private static string Evidence(Feature f) => string.Join("; ", f.Evidence.Take(MaxEvidence).Select(e =>
        $"{e.Feature} x{e.Count}{(e.Locations.Count > 0 ? $" at {e.Locations[0]}" : "")}"));

    /// <summary>Capability rows of two loaded builds and their report text; null rows, with the reason, when a survey fails or outlasts <paramref name="budget"/>.</summary>
    public static (IReadOnlyList<EvidenceChange>? Rows, string Text) Between(InspectionService inspection, string old, string @new, CancellationToken ct,
        TimeSpan? budget = null)
    {
        var (rows, text) = Surveys(inspection, old, @new, ct, budget);
        // Malcontent behaviours run only with the pack installed.
        var (behaviours, behaviourText) = MalcontentChanges.Between(inspection.BuildFile(old), inspection.BuildFile(@new), ct);
        if (behaviourText == null) return (rows, text);
        return (rows == null && behaviours.Count == 0 ? null : [.. rows ?? [], .. behaviours], text + behaviourText);
    }

    private static (IReadOnlyList<EvidenceChange>? Rows, string Text) Surveys(InspectionService inspection, string old, string @new, CancellationToken ct,
        TimeSpan? budget)
    {
        IReadOnlyList<EvidenceChange> rows;
        IReadOnlyList<string> notes;
        var limit = budget ?? SurveyBudget;
        // Build the shared rule patterns before the timer starts: the budget bounds this comparison's own surveys.
        Features.Prepare();
        using var timer = CancellationTokenSource.CreateLinkedTokenSource(ct);
        if (limit > TimeSpan.Zero) timer.CancelAfter(limit);
        else timer.Cancel();
        try { (rows, notes) = Of(inspection.BuildSurvey(old, timer.Token), inspection.BuildSurvey(@new, timer.Token)); }
        catch (Exception e) when (e is OperationCanceledException or ToolError { Code: ErrorCode.Cancelled or ErrorCode.Timeout } && !ct.IsCancellationRequested)
        {
            return (null, $"Capabilities not compared: surveying both builds takes over {limit.TotalSeconds:0.#} s; survey_features on each build lists them.\n");
        }
        catch (ToolError e) when (e.Code is not (ErrorCode.Cancelled or ErrorCode.Timeout))
        {
            return (null, $"Capabilities {(e.Code == ErrorCode.Unsupported ? NativeCapa.NotChecked : "not compared")}: {e.Message}\n");
        }
        var text = new System.Text.StringBuilder($"Capabilities (survey_features rules and kept capa labels): {rows.Count(r => r.Kind == "added")} added, " +
                                                 $"{rows.Count(r => r.Kind == "removed")} removed.\n");
        foreach (var r in rows) text.Append($"  {r.Kind} {r.Key}: {r.New ?? r.Old}\n");
        foreach (var n in notes) text.Append($"Note: {n}\n");
        return (rows, text.ToString());
    }
}
