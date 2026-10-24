using Corvus.Core;
using Corvus.Services.Web.Packages;
using FeatureReport = Corvus.Services.Analysis.InspectionService.FeatureReport;

namespace Corvus.Services.Analysis;

/// <summary>
/// What one build can do that the other cannot: the survey features and capa labels added or removed between two
/// builds, and the findings added or removed between two versions of a package. A capability both sides have is not
/// listed, whatever its evidence; capa labels are compared only when capa labelled both files.
/// </summary>
public static class CapabilityChanges
{
    /// <summary>Evidence entries shown per row.</summary>
    private const int MaxEvidence = 3;

    /// <summary>
    /// Rows keyed "category/name", added (only in <paramref name="new"/>) or removed (only in <paramref name="old"/>), in key
    /// order, each with the evidence of the side that has it; and notes naming what was left out.
    /// </summary>
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
                notes.Add($"the {side} build's survey is partial, so a row may stand for code it could not read: {string.Join("; ", limits.Take(MaxLimits))}" +
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

    /// <summary>
    /// Findings keyed "category: detail", added or removed between two versions of a package, with level and file:line;
    /// a finding both versions have is not listed, wherever it moved.
    /// </summary>
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

    /// <summary>
    /// The capability rows of two loaded builds (assemblies or native images) and the text that reports them; null rows,
    /// with the reason in the text, when a build could not be surveyed or both surveys outlast <paramref name="budget"/>
    /// (default <see cref="SurveyBudget"/>).
    /// </summary>
    public static (IReadOnlyList<EvidenceChange>? Rows, string Text) Between(InspectionService inspection, string old, string @new, CancellationToken ct,
        TimeSpan? budget = null)
    {
        IReadOnlyList<EvidenceChange> rows;
        IReadOnlyList<string> notes;
        var limit = budget ?? SurveyBudget;
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
