using System.Text;
using Corvus.Core;
using Corvus.Mcp;
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

/// <summary>extract_strings: one page of values; valuesResultId keeps all of them (read_result text is CSV, json the items).</summary>
public sealed record ValuePage(string Assembly, IReadOnlyList<ExtractedValue> Items, int Offset, int Total)
{
    public IReadOnlyDictionary<string, int>? ByType { get; init; }
    public string? ValuesResultId { get; init; }
    public IReadOnlyList<string>? Notes { get; init; }
}

/// <summary>extract_embedded: one page of the items found (all are written with save=true).</summary>
public sealed record EmbeddedPage(string Assembly, IReadOnlyList<EmbeddedContent> Items, int Offset, int Total)
{
    public string? OutputDirectory { get; init; }
    public IReadOnlyList<string>? Notes { get; init; }
}

internal static class ContainerText
{
    public static string Embedded(InspectionService.EmbeddedReport report, int offset, int limit)
    {
        var header = new StringBuilder($"{Escape(report.Assembly)}: ");
        header.Append(report.Contents.Count == 0 ? "no embedded content" : string.Join(", ", report.Contents.GroupBy(c => c.Kind).Select(g => $"{g.Count()} {g.Key}"))).Append(".\n");
        if (report.OutputDirectory != null) header.Append($"Written to {report.OutputDirectory}.\n");
        foreach (var n in report.Notes) header.Append("Note: ").Append(Escape(n)).Append('\n');
        return ToolOutput.List(report.Contents, offset, limit, EmbeddedRow,
            rows => new EmbeddedPage(report.Assembly, rows, offset, report.Contents.Count)
            {
                OutputDirectory = report.OutputDirectory, Notes = report.Notes.Count > 0 ? report.Notes : null,
            }, "item", header.ToString());
    }

    private static string EmbeddedRow(EmbeddedContent c)
    {
        var sb = new StringBuilder($"{c.Kind} {c.Size:N0} bytes in {Escape(c.Source)}");
        if (c.Encoding.Count > 0) sb.Append(" via ").Append(Escape(string.Join(" > ", c.Encoding)));
        if (c.Basis != null) sb.Append($" ({c.Basis})");
        if (c.Detail != null) sb.Append(": ").Append(Escape(c.Detail.Length > 120 ? c.Detail[..120] + "…" : c.Detail));
        sb.Append($", sha256 {c.Sha256[..16]}…");
        if (c.SavedTo != null) sb.Append(" -> ").Append(c.SavedTo);
        if (c.LoadedAs != null) sb.Append($" (loaded as {c.LoadedAs})");
        return sb.ToString();
    }

    public static string Values(InspectionService.ValueReport report, int offset, int limit, string? kept)
    {
        var byType = report.Values.GroupBy(v => v.Type).ToDictionary(g => g.Key, g => g.Count());
        var header = new StringBuilder($"{Escape(report.Assembly)}: {string.Join(", ", byType.Select(t => $"{t.Value} {t.Key}"))}"
                                       + (byType.Count == 0 ? "no typed values" : "") + ".\n");
        if (kept != null) header.Append($"All values: read_result id={kept} (outputPath writes them; format=text is CSV, json the records).\n");
        foreach (var n in report.Notes) header.Append("Note: ").Append(Escape(n)).Append('\n');
        return ToolOutput.List(report.Values, offset, limit, ValueRow,
            rows => new ValuePage(report.Assembly, rows, offset, report.Total)
            {
                ByType = byType.Count > 0 ? byType : null, ValuesResultId = kept, Notes = report.Notes.Count > 0 ? report.Notes : null,
            }, "value", header.ToString());
    }

    private static string ValueRow(ExtractedValue v)
    {
        var sb = new StringBuilder($"{v.Type} {Escape(v.Value)} x{v.Count}");
        if (v.Detail != null) sb.Append($" ({Escape(v.Detail)})");
        if (v.Locations.Count > 0) sb.Append(" at ").Append(Escape(v.Locations[0])).Append(v.Locations.Count > 1 ? $" (+{v.Locations.Count - 1})" : "");
        if (v.PassedTo.Count > 0) sb.Append("; passed to ").Append(Escape(string.Join(", ", v.PassedTo)));
        return sb.ToString();
    }

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
