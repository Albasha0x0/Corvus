using Corvus.Core;

namespace Corvus.Services.Analysis;

/// <summary>The entries view: archive and disk image entries with an unsafe path, a file and folder of one name, the hidden attribute, or an executable two containers deep.</summary>
internal static class ArchiveNameView
{
    public sealed record Facts(IReadOnlyList<NameIssue> Entries);

    /// <summary>The view of <paramref name="issues"/>, one review finding per entry; null when there are none.</summary>
    public static FileView? Of(IReadOnlyList<NameIssue> issues)
    {
        if (issues.Count == 0) return null;
        var findings = issues.Select(i =>
        {
            var (rule, category) = i.Kind switch
            {
                "unsafe-path" => ("archive/unsafe-path", "path"),
                "collision" => ("archive/name-collision", "path"),
                "nested-executable" => ("archive/nested-executable", "nesting"),
                _ => ("archive/hidden-entry", "attribute"),
            };
            return new Finding(FindingRules.Check(rule, FindingLevel.Review), rule, category, $"'{MemberNames.Show(i.Name)}': {i.Why}", i.Name, "archive");
        }).ToList();
        return new FileView(new Facts(issues), [$"{issues.Count} entry name(s) to review."]) { Findings = findings };
    }
}
