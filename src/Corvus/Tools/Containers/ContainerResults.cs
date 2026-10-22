using System.Text;
using System.Text.Json.Nodes;
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
    public string? Basis { get; init; }
    public IReadOnlyList<Evidence>? Evidence { get; init; }

    /// <summary>App rules: rule id, MASVS control, severity, matches in library code (not in Matches) and what to review.</summary>
    public string? Rule { get; init; }
    public string? Masvs { get; init; }
    public string? Severity { get; init; }
    public int? Library { get; init; }
    public string? Review { get; init; }
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

/// <summary>unpack_container: one page of the files (every file is written); next when nothing was extracted.</summary>
public sealed record UnpackPage(string Source, string Container, string OutputDirectory, IReadOnlyList<UnpackService.UnpackedFile> Items, int Offset, int Total)
{
    public UnpackService.NextCall? Next { get; init; }
    public IReadOnlyList<string>? Notes { get; init; }
}

/// <summary>
/// summarize_file: the overview (identity, hashes, signature, assemblies, highlights, entry points, value counts) and, for
/// another view, its facts as detail (described in the guide topic containers).
/// </summary>
public sealed record FileSummaryRecord(string Path, long Size, string Type, string Sha256, string Container, string View, IReadOnlyList<string> Views)
{
    public string? Md5 { get; init; }
    public string? Sha1 { get; init; }
    public double Entropy { get; init; }
    public string? Signature { get; init; }
    public IReadOnlyList<AssemblyRow>? Assemblies { get; init; }
    public IReadOnlyList<string>? Highlights { get; init; }
    public int? HighlightTotal { get; init; }
    public IReadOnlyList<string>? EntryPoints { get; init; }
    public IReadOnlyDictionary<string, int>? Values { get; init; }
    public JsonObject? Detail { get; init; }
    public IReadOnlyList<string>? Notes { get; init; }
}

/// <summary>An assembly of the file in the overview; features counts its survey_features matches.</summary>
public sealed record AssemblyRow(string Path, string Name, string Kind, string Architecture, int Features)
{
    public string? Version { get; init; }
    public string? Framework { get; init; }
    public bool? ReadyToRun { get; init; }
    public string? Merged { get; init; }
}

internal static class ContainerText
{
    public static string Unity(UnityOverview.Report r)
    {
        var sb = new StringBuilder($"{Escape(r.Product ?? Path.GetFileName(r.GameDirectory))}{(r.Company != null ? " by " + Escape(r.Company) : "")}: Unity " +
                                   $"{r.Engine.Version ?? "version unknown"} ({r.Engine.Agreement}), {r.Platform} {r.Architecture}{(r.ArchitectureSource != null ? $" (from {Escape(r.ArchitectureSource)})" : "")}\n");
        sb.Append($"Game: {r.GameDirectory}\n");
        if (r.DataDirectory != null) sb.Append($"Data: {r.DataDirectory}\n");
        if (r.Executable != null) sb.Append($"Executable: {r.Executable}\n");
        foreach (var c in r.Engine.Claims) sb.Append($"  version {Escape(c.Version)} from {c.Source}: {Escape(c.File)}\n");
        if (r.Engine.MetadataRange != null) sb.Append($"  metadata implies Unity {r.Engine.MetadataRange} ({r.Engine.MetadataCheck})\n");
        var b = r.Backend;
        sb.Append($"Backend: {b.Kind}");
        if (b.Kind == "il2cpp") sb.Append($", metadata {b.MetadataState}{(b.MetadataVersion is { } v ? $" v{v}" : "")}{(b.MetadataStateReason != null ? $" ({Escape(b.MetadataStateReason)})" : "")}, {b.Metadata ?? "no metadata"}; binary {b.NativeBinary ?? "not found"}");
        else if (b.Kind == "mono") sb.Append($", {b.ManagedAssemblies} assemblies ({b.ManagedState}) in {b.ManagedDirectory}{(b.MonoRuntime != null ? ", " + b.MonoRuntime : "")}{(b.DotnetProfile != null ? ", " + b.DotnetProfile : "")}");
        if (b.ScriptingAssemblies is { } s) sb.Append($", {s} scripting assemblies");
        if (b.UnreadableNameRatio is { } ratio) sb.Append($", {Corvus.Core.Format.Percent(ratio)} unreadable names of {b.NamesRead}");
        sb.Append('\n');
        foreach (var e in b.Evidence) sb.Append("  evidence: ").Append(Escape(e)).Append('\n');
        if (r.Markers.Count > 0) sb.Append("Markers:\n");
        foreach (var m in r.Markers) sb.Append($"  {m.Category} {Escape(m.Name)}: {Escape(m.Evidence)} ({m.Source})\n");
        if (r.Folders.Count > 0) sb.Append("Folders:\n");
        foreach (var f in r.Folders) sb.Append($"  {f.Kind} {Escape(f.Path)} ({f.Entries} entries){(f.Note != null ? " " + Escape(f.Note) : "")}\n");
        if (r.NextSteps.Count > 0) sb.Append("Next:\n");
        foreach (var n in r.NextSteps)
            sb.Append($"  {n.Tool ?? n.Action} {string.Join(" ", n.Arguments.Select(a => $"{a.Key}={a.Value}"))}: {Escape(n.Reason)}\n");
        foreach (var n in r.Notes) sb.Append("Note: ").Append(Escape(n)).Append('\n');
        return sb.ToString();
    }

    internal const int MaxHighlights = 25;
    private const int MaxEntryPoints = 10, MaxNotes = 12;

    /// <summary>The views of a summary: overview, managed (with assemblies), each provider view that applies, all.</summary>
    public static IReadOnlyList<string> ViewsOf(InspectionService.FileSummary s, bool triage) =>
        ["overview", .. s.Assemblies.Count > 0 ? ["managed"] : Array.Empty<string>(), .. s.Views.Keys.Union(triage ? ["native"] : []).Order(StringComparer.Ordinal), "all"];

    public static FileSummaryRecord Summary(InspectionService.FileSummary s, string view)
    {
        var views = ViewsOf(s, s.Triage != null);
        var name = view.Trim().ToLowerInvariant();
        if (!views.Contains(name))
            throw new ToolError(ErrorCode.InvalidArgument, $"view '{view}' does not apply to this file.", $"pass view as one of {string.Join(", ", views)}");
        var record = new FileSummaryRecord(s.File.Path, s.File.Size, s.File.Type, s.File.Sha256, s.Container, name, views);
        if (name != "overview") return record with { Detail = Detail(s, name), Notes = s.Notes.Count > 0 ? s.Notes : null };
        var main = s.Assemblies.FirstOrDefault();
        // The signature line already says who signed the file.
        var shown = s.Highlights.Where(h => !h.StartsWith("The file is Authenticode-signed by", StringComparison.Ordinal)).ToList();
        var highlights = shown.Take(MaxHighlights).ToList();
        return record with
        {
            Md5 = s.File.Md5, Sha1 = s.File.Sha1, Entropy = s.File.Entropy,
            Signature = SignatureLine(s.File.Certificate),
            Assemblies = s.Assemblies.Count > 0 ? s.Assemblies.Select(a => new AssemblyRow(a.Path, a.Identity.Name, a.Identity.Kind, a.Identity.Architecture, a.Features.Count)
            {
                Version = a.Identity.Version, Framework = a.Identity.TargetFramework, ReadyToRun = a.Identity.ReadyToRun ? true : null, Merged = a.Identity.Merged,
            }).ToList() : null,
            Highlights = highlights.Count > 0 ? highlights : null,
            HighlightTotal = shown.Count > highlights.Count ? shown.Count : null,
            EntryPoints = main?.EntryPoints.Count > 0 ? main.EntryPoints.Take(MaxEntryPoints).Select(e => $"{e.Kind}: {e.Member}").ToList() : null,
            Values = main?.Values.ByType.Count > 0 ? main.Values.ByType : null,
            Notes = s.Notes.Count > 0 ? [.. s.Notes.Take(MaxNotes), .. s.Notes.Count > MaxNotes ? [$"{s.Notes.Count - MaxNotes} more notes: view=all."] : Array.Empty<string>()] : null,
        };
    }

    private static JsonObject Detail(InspectionService.FileSummary s, string view)
    {
        JsonNode? Of(object? value) => value == null ? null : ToolOutput.Serialize(value);
        JsonNode? Native()
        {
            var facts = Of(s.Views.GetValueOrDefault("native")?.Detail) as JsonObject ?? [];
            if (s.Triage != null) facts["triage"] = Of(s.Triage); // a loaded image's code index
            return facts;
        }
        JsonNode? One(string name) => name switch
        {
            "managed" => new JsonObject { ["file"] = Of(s.File), ["assemblies"] = Of(s.Assemblies) },
            "native" => Native(),
            _ => Of(s.Views.GetValueOrDefault(name)?.Detail),
        };
        if (view != "all") return One(view) as JsonObject ?? [];
        var all = new JsonObject();
        foreach (var v in ViewsOf(s, s.Triage != null).Where(v => v is not ("overview" or "all"))) all[v] = One(v);
        all["highlights"] = Of(s.Highlights);
        return all;
    }

    private static string? SignatureLine(CertificateInfo c) =>
        !c.Present ? null
        : c.Problem != null ? $"unreadable: {c.Problem}"
        : $"{c.Signer}; digest {(c.DigestMatches == false ? "does not match (modified after signing)" : "matches")}; " +
          $"signature {(c.SignatureValid == false ? "does not verify" : "verifies")}{(c.Chain != null ? "; " + c.Chain : "")}";

    public static string Summary(FileSummaryRecord r)
    {
        var sb = new StringBuilder($"{Escape(Path.GetFileName(r.Path))}: {r.Type}, {r.Size:N0} bytes, {r.Container}");
        if (r.View == "overview")
        {
            sb.Append($", entropy {r.Entropy:0.00}\n{r.Path}\nsha256 {r.Sha256}\nsha1 {r.Sha1}  md5 {r.Md5}\n");
            sb.Append("Signature: ").Append(r.Signature != null ? Escape(r.Signature) : "none").Append('\n');
            if (r.Assemblies is { } assemblies)
            {
                sb.Append($"Assemblies ({assemblies.Count}, the first in full in view=managed):\n");
                foreach (var a in assemblies)
                    sb.Append($"  {Escape(a.Name)} {a.Version} {a.Kind}, {a.Framework ?? "no target framework"}, {a.Architecture}" +
                              $"{(a.ReadyToRun == true ? ", ReadyToRun" : "")}{(a.Merged != null ? ", " + Escape(a.Merged) : "")}, {a.Features} feature(s) [{Escape(a.Path)}]\n");
            }
            if (r.Highlights is { } highlights)
            {
                sb.Append(r.HighlightTotal is { } total ? $"Highlights ({highlights.Count} of {total}; view=all lists all):\n" : "Highlights:\n");
                foreach (var h in highlights) sb.Append("  - ").Append(Escape(h)).Append('\n');
            }
            if (r.EntryPoints is { } entries) sb.Append("Entry points: ").Append(Escape(string.Join("; ", entries))).Append('\n');
            if (r.Values is { } values) sb.Append("Typed values: ").Append(string.Join(", ", values.Select(v => $"{v.Value} {v.Key}"))).Append(" (extract_strings lists them)\n");
        }
        else
        {
            sb.Append($"; view {r.View}\n");
            if (r.Detail is { } detail) sb.Append(RecordText.Render(detail, null));
        }
        sb.Append("Views: ").Append(string.Join(", ", r.Views)).Append('\n');
        foreach (var n in r.Notes ?? []) sb.Append("Note: ").Append(Escape(n)).Append('\n');
        return sb.ToString();
    }

    public static string Unpack(UnpackService.UnpackReport r, int offset, int limit)
    {
        int written = r.Files.Count(f => f.Extracted != false);
        var header = new StringBuilder($"{Escape(r.Source)} ({r.Container}): {written} file(s) written to {r.OutputDirectory}.\n");
        if (r.Next is { } next)
            header.Append($"Next: {next.Tool} {string.Join(" ", next.Arguments.Select(a => $"{a.Key}={a.Value}"))} ({next.Reason}).\n");
        foreach (var n in r.Notes) header.Append("Note: ").Append(Escape(n)).Append('\n');
        // Paths under the output directory are relative to it (the record names it once).
        var files = r.Files.Select(f => f.Path.StartsWith(r.OutputDirectory, StringComparison.OrdinalIgnoreCase)
            ? f with { Path = Path.GetRelativePath(r.OutputDirectory, f.Path).Replace('\\', '/') } : f).ToList();
        string Row(UnpackService.UnpackedFile f)
        {
            var sb = new StringBuilder($"{f.Kind} {Escape(f.Path)} {f.Size:N0} bytes");
            if (f.ReadyToRun == true) sb.Append(", ReadyToRun");
            if (f.Merged != null) sb.Append(", ").Append(Escape(f.Merged));
            if (f.LoadedAs != null) sb.Append($", loaded as {f.LoadedAs}");
            if (f.Extracted == false) sb.Append($" (not extracted: {f.Origin})");
            else if (f.Origin.Length > 0) sb.Append($" [{Escape(f.Origin)}]");
            return sb.ToString();
        }
        return ToolOutput.List(files, offset, limit, Row,
            rows => new UnpackPage(r.Source, r.Container, r.OutputDirectory, rows, offset, r.Files.Count) { Next = r.Next, Notes = r.Notes.Count > 0 ? r.Notes : null },
            "file", header.ToString());
    }

    public static string Search(UnpackService.ContainerSearch s, int limit)
    {
        var header = new StringBuilder($"{Escape(Path.GetFileName(s.Source))} ({s.Container}): {s.Searched} searched.\n");
        foreach (var n in s.Notes) header.Append("Note: ").Append(Escape(n)).Append('\n');
        return ToolOutput.List(s.Items, s.Offset, limit, s.Total, m =>
                $"{m.Kind} {Escape(m.Name)}" + (m.Kind is "file" or "packet" ? "" : $" in {Escape(m.Path)}") + (m.Detail != null ? $" ({Escape(m.Detail)})" : "")
                + (m.Member != null ? $" at {Escape(m.Member)}" + (m.Location != null ? $" {Escape(m.Location)}" : "") : m.Location != null ? $" at {Escape(m.Location)}" : "")
                + (m.Seen != null && s.Items.Any(x => x.Seen != m.Seen) ? $" [{m.Seen}]" : ""),
            rows => s with { Items = [.. rows] }, "match", header.ToString());
    }

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
            Basis = f.Evidence.Count > 0 && f.Evidence.All(e => e.Basis == "derived") ? "derived" : null,
            Evidence = category != null ? f.Evidence : null,
            Rule = f.Rule?.Id,
            Masvs = f.Rule?.Masvs,
            Severity = f.Rule?.Severity,
            Library = f.Evidence.Sum(e => e.Library ?? 0) is > 0 and var library ? library : null,
            Review = category != null ? f.Rule?.Review : null,
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
        if (r.Category == null && r.Features.Count > 0) sb.Append("Evidence: category=<category>, a technique (T1055), a MASVS id or all.\n");
        foreach (var group in r.Features.GroupBy(f => f.Category))
        {
            sb.Append(group.Key).Append('\n');
            foreach (var f in group)
            {
                sb.Append("  ").Append(f.Name);
                if (f.Masvs != null) sb.Append($" [{f.Masvs} {f.Rule}, {f.Severity}]");
                sb.Append($", {f.Matches} match{(f.Matches == 1 ? "" : "es")}{(f.Library is { } lib ? $" (+{lib} in libraries)" : "")}" +
                          $"{(f.Basis != null ? " (derived from strings or constants)" : "")}\n");
                if (f.Review != null) sb.Append("    review: ").Append(f.Review).Append('\n');
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
