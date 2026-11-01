using Corvus.Services.Analysis;
using Corvus.Services.Web.Packages;

namespace Corvus.Tests;

/// <summary>How many reviewed packages each rule flagged at noteworthy and at review.</summary>
public static class RuleLoad
{
    /// <summary>Per rule id, the packages with a finding of that rule at each level; unread packages (null) are left out.</summary>
    public static IReadOnlyList<(string Rule, int Noteworthy, int Review)> Count(IEnumerable<PackageReport?> reports)
    {
        var read = reports.OfType<PackageReport>().ToList();
        return [.. read
            .SelectMany(r => r.Findings.Select(f => (f.Rule, f.Level)).Distinct())
            .GroupBy(x => x.Rule)
            .Select(g => (g.Key, g.Count(x => x.Level == FindingLevel.Noteworthy), g.Count(x => x.Level == FindingLevel.Review)))
            .OrderBy(x => x.Key, StringComparer.Ordinal)];
    }

    /// <summary>The rules whose noteworthy count exceeds <paramref name="budget"/> of <paramref name="read"/> packages; empty when none does.</summary>
    public static IReadOnlyList<string> OverBudget(IEnumerable<(string Rule, int Noteworthy, int Review)> load, int read, double budget) =>
        [.. load.Where(l => l.Noteworthy > read * budget).Select(l => l.Rule)];
}
