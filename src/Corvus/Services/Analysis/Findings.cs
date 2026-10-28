namespace Corvus.Services.Analysis;

/// <summary>Finding levels and their order; any other string is not a level.</summary>
public static class FindingLevel
{
    public const string Noteworthy = "noteworthy";
    public const string Review = "review";
    public const string Info = "info";

    /// <summary>3 for noteworthy, 2 for review, 1 for info; 0 for anything else.</summary>
    public static int Rank(string? level) => level switch { Noteworthy => 3, Review => 2, Info => 1, _ => 0 };

    /// <summary>The highest level of <paramref name="levels"/>; "none" when there is none.</summary>
    public static string Strongest(IEnumerable<string> levels) =>
        levels.MaxBy(Rank) is { } top && Rank(top) > 0 ? top : "none";
}

/// <summary>One finding of any review path: level, stable rule id, category, evidence, location and the reader that made it.</summary>
/// <param name="Level">noteworthy, review or info, within the rule's row in <see cref="FindingRules"/>.</param>
/// <param name="Rule">The rule id; ids are never reused.</param>
/// <param name="Location">File, file:line, object or section; null when the finding is about the whole input.</param>
/// <param name="Source">package, packer, office, pdf, shortcut, installer, capture, malcontent or masvs.</param>
public sealed record Finding(string Level, string Rule, string Category, string Evidence, string? Location, string Source);

/// <summary>A row of the rule table.</summary>
/// <param name="Id">A rule id, or a family "prefix/*" for ids a rule pack names.</param>
/// <param name="Level">The highest level the rule emits.</param>
/// <param name="Noteworthy">The exact list or the combination that makes it noteworthy; null when it never is.</param>
/// <param name="Reason">What a match shows.</param>
public sealed record FindingRule(string Id, string Level, string? Noteworthy, string Reason);
