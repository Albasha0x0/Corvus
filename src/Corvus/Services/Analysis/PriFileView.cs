using Corvus.Core;
using Corvus.Core.Pri;

namespace Corvus.Services.Analysis;

/// <summary>
/// view=pri: a package resource index (resources.pri) read without the MRT API: format, resource maps, the qualifiers
/// in use, then a page of named resources (table= keeps names containing the text; offset=, limit=) with each
/// candidate's qualifiers, type and value: a string, a path in the package, or embedded data with its size and kind.
/// </summary>
internal sealed class PriFileView : IFileSummaryView
{
    private const int DefaultLimit = 50, MaxLimit = 1000, MaxValueChars = 500;

    public sealed record MapRow(string Name, string UniqueName, bool Primary, int Resources, int Candidates);

    public sealed record CandidateRow(string Qualifiers, string Type, string? Value, int? Size, string? Kind);

    public sealed record ResourceRow(string Map, string Name, IReadOnlyList<CandidateRow> Candidates);

    public sealed record Facts(string Format, int Sections, IReadOnlyList<MapRow> Maps, IReadOnlyDictionary<string, IReadOnlyList<string>> Qualifiers,
        string? Filter, int Matching, IReadOnlyList<ResourceRow> Resources, long Offset, long? Next, IReadOnlyList<string> Notes);

    public string Name => "pri";

    public FileView? Inspect(FileInput file, CancellationToken ct)
    {
        if (!PriFile.Looks(file.Head)) return null;
        PriFile pri;
        try { pri = PriFile.Read(file.Bytes); }
        catch (InvalidDataException ex) { throw new ToolError(ErrorCode.MalformedInput, $"{Path.GetFileName(file.Path)}: not a readable resource index: {ex.Message}"); }
        int limit = Math.Clamp(file.Options.Limit ?? DefaultLimit, 1, MaxLimit);
        long offset = Math.Max(0, file.Options.Offset);
        var filter = file.Options.View == Name && file.Options.Table is { Length: > 0 } t ? t.Trim() : null;
        var all = pri.Maps.SelectMany(m => m.Resources.Select(r => (Map: m, Resource: r)))
            .Where(x => filter == null || x.Resource.Name.Contains(filter, StringComparison.OrdinalIgnoreCase)).ToList();
        var page = all.Skip((int)Math.Min(offset, int.MaxValue)).Take(limit).Select(x => new ResourceRow(x.Map.Name, x.Resource.Name, [.. x.Resource.Candidates.Select(Row)])).ToList();
        long shown = offset + page.Count;
        long? next = shown < all.Count ? shown : null;
        var notes = new List<string>(pri.Notes);
        if (next != null) notes.Add($"offset={next} lists the next resources");
        int bare = pri.Maps.Sum(m => m.Resources.Count(r => r.Candidates.Count == 0));
        if (bare > 0) notes.Add($"{bare:N0} name(s) have no candidate in this file; a split file of the package (resources.<qualifier>.pri) holds them");
        var qualifiers = pri.DeclaredQualifiers.GroupBy(q => q.Name)
            .ToDictionary(g => g.Key, g => (IReadOnlyList<string>)[.. g.Select(q => q.Value).Distinct(StringComparer.OrdinalIgnoreCase).Order(StringComparer.OrdinalIgnoreCase)]);
        var maps = pri.Maps.Select(m => new MapRow(m.Name, m.UniqueName, m.Primary, m.Resources.Count, m.Resources.Sum(r => r.Candidates.Count))).ToList();
        var highlights = new List<string>
        {
            $"Package resource index ({pri.Format}): {string.Join(", ", maps.Select(m => $"{m.Name}: {m.Resources:N0} resource(s), {m.Candidates:N0} candidate(s)"))}" +
            (qualifiers.Count > 0 ? $"; qualifiers {string.Join(", ", qualifiers.Select(q => $"{q.Key} ({q.Value.Count})"))}" : "") + ".",
        };
        return new FileView(new Facts(pri.Format, pri.Sections.Count, maps, qualifiers, filter, all.Count, page, offset, next, notes), highlights);
    }

    private static CandidateRow Row(PriFile.Candidate c)
    {
        var qualifiers = c.Qualifiers.Count == 0 ? "neutral" : string.Join(", ", c.Qualifiers.Select(q => $"{q.Name}={q.Value}"));
        if (c.Data is { } data) return new(qualifiers, c.Type, null, data.Length, Blob.Identify(data));
        var value = c.Text is { Length: > MaxValueChars } text ? text[..MaxValueChars] + $"... ({text.Length:N0} characters)" : c.Text ?? c.Note;
        return new(qualifiers, c.Type, value, null, null);
    }
}
