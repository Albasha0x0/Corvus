using System.Text;
using Corvus.Core;
using Corvus.Services.Analysis;

namespace Corvus.Tools;

// Records and text renderers of the containers family (SX-3): the text is compact rows, never the record's JSON.

/// <summary>survey_features: features with their match counts; evidence only for the category asked for.</summary>
public sealed record SurveyRecord(string Assembly, int MethodsScanned, IReadOnlyList<SurveyFeature> Features)
{
    public string? Category { get; init; }
    public IReadOnlyList<string>? Notes { get; init; }
}

/// <summary>Basis "derived": every piece of evidence is a string or argument constant.</summary>
public sealed record SurveyFeature(string Name, string Category, int Matches)
{
    public string? Attack { get; init; }
    public string? AttackName { get; init; }
    public string? Basis { get; init; }
    public IReadOnlyList<Evidence>? Evidence { get; init; }
}

internal static class ContainerText
{
    internal static string Escape(string s) => Format.EscapeMarkers(s).Replace("\r", "\\r").Replace("\n", "\\n");

    public static SurveyRecord Survey(InspectionService.FeatureReport report, string? category)
    {
        var features = report.Features.Select(f => new SurveyFeature(f.Name, f.Category, f.Evidence.Sum(e => e.Count))
        {
            Attack = f.Attack,
            AttackName = category != null ? f.AttackName : null,
            Basis = f.Evidence.Count > 0 && f.Evidence.All(e => e.Basis == "derived") ? "derived" : null,
            Evidence = category != null ? f.Evidence : null,
        }).ToList();
        return new SurveyRecord(report.Assembly, report.MethodsScanned, features)
        {
            Category = category,
            Notes = report.Notes.Count > 0 ? report.Notes : null,
        };
    }

    public static string Survey(SurveyRecord r)
    {
        var sb = new StringBuilder();
        sb.Append($"{Escape(r.Assembly)}: {r.Features.Count} feature(s){(r.Category is { } c && !c.Equals("all", StringComparison.OrdinalIgnoreCase) ? $" in {Escape(c)}" : "")}, " +
                  $"{r.MethodsScanned:N0} methods or functions scanned.\n");
        if (r.Category == null && r.Features.Count > 0) sb.Append("Evidence: category=<category>, a technique (T1055) or all.\n");
        foreach (var group in r.Features.GroupBy(f => f.Category))
        {
            sb.Append(group.Key).Append('\n');
            foreach (var f in group)
            {
                sb.Append("  ").Append(f.Name);
                if (f.Attack != null) sb.Append($" [{f.Attack}{(f.AttackName != null ? " " + f.AttackName : "")}]");
                sb.Append($", {f.Matches} match{(f.Matches == 1 ? "" : "es")}{(f.Basis != null ? " (derived from strings or constants)" : "")}\n");
                foreach (var e in f.Evidence ?? [])
                {
                    sb.Append($"    {Escape(e.Feature)} x{e.Count}{(e.Basis != null ? " (derived)" : "")}\n");
                    foreach (var at in e.Locations) sb.Append("      ").Append(Escape(at)).Append('\n');
                }
            }
        }
        if (r.Notes is { Count: > 0 } notes) foreach (var n in notes) sb.Append("Note: ").Append(Escape(n)).Append('\n');
        return sb.ToString();
    }
}
