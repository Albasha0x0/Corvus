using Corvus.Services.Web;
using Corvus.Services.Web.Scripts;

namespace Corvus.Services.Analysis;

/// <summary>
/// view=page: a saved web page (.html with the files saved beside it): each script and integrity-bearing link with where
/// its bytes are and its Subresource Integrity checked, the import maps, and the meta Content Security Policy with each
/// inline script's verdict under it (<see cref="SavedPage"/>). Nothing is fetched or run.
/// </summary>
internal sealed class PageFileView : IFileSummaryView
{
    private const long MaxPage = 16L << 20;

    public sealed record Facts(string? Url, string? Title, IReadOnlyList<SavedPage.Resource> Resources, IReadOnlyList<SavedPage.ImportEntry> Imports,
        IReadOnlyList<SavedPage.ImportIntegrity> ModuleIntegrity, IReadOnlyList<SavedPage.Policy> Policies, IReadOnlyList<string> Review, IReadOnlyList<string> Notes);

    public string Name => "page";

    public FileView? Inspect(FileInput file, CancellationToken ct)
    {
        if (file.Length > MaxPage || file.Streamed || file.Kind is not ("text" or "data" or "html")) return null;
        var ext = Path.GetExtension(file.Path).ToLowerInvariant();
        var text = ScriptText.Decode(file.Bytes, out _);
        if (ext is not (".html" or ".htm" or ".xhtml") && !text.AsSpan(0, Math.Min(text.Length, 512)).TrimStart().StartsWith("<!doctype html", StringComparison.OrdinalIgnoreCase)) return null;
        var page = SavedPage.Read(text, file.Path, ct);
        var review = new List<string>();
        foreach (var r in page.Resources)
        {
            var name = r.Source ?? $"inline {r.Kind} script";
            if (r.IntegrityCheck?.StartsWith("mismatch", StringComparison.Ordinal) == true) review.Add($"{name}: integrity {r.IntegrityCheck}");
            if (r.CspVerdict?.StartsWith("blocked", StringComparison.Ordinal) == true) review.Add($"{name}: {r.CspVerdict}");
            review.AddRange((r.Notes ?? []).Where(n => n.StartsWith("code from", StringComparison.Ordinal) || n.StartsWith("integrity on a cross-origin", StringComparison.Ordinal)).Select(n => $"{name}: {n}"));
        }
        review.AddRange(page.Policies.SelectMany(SavedPage.Weaknesses).Distinct());
        review.AddRange(page.Imports.Where(i => i.OtherOrigin).Take(20).Select(i => $"import map: {i.Specifier} maps to {i.Address}"));
        var facts = new Facts(page.Url, page.Title, page.Resources, page.Imports, page.ModuleIntegrity, page.Policies, review, page.Notes);
        return new FileView(facts, Highlights(page, review));
    }

    private static List<string> Highlights(SavedPage.Page p, List<string> review)
    {
        var scripts = p.Resources.Where(r => r.Element == "script").ToList();
        var counts = scripts.GroupBy(r => r.Location).OrderBy(g => g.Key, StringComparer.Ordinal).Select(g => $"{g.Count()} {g.Key}");
        var checkedCount = p.Resources.Count(r => r.IntegrityCheck?.StartsWith("match", StringComparison.Ordinal) == true);
        var list = new List<string>
        {
            $"Web page{(p.Url != null ? " saved from " + p.Url : "")}: {scripts.Count} script(s) ({string.Join(", ", counts)}), {checkedCount} integrity hash(es) matched, " +
            $"{(p.Imports.Count > 0 ? $"{p.Imports.Count} import map entries, " : "")}{(p.Policies.Count > 0 ? $"{p.Policies.Count} meta policy(ies)" : "policy unknown (none in the page)")}; view=page lists them.",
        };
        if (review.Count > 0) list.Add("Worth reviewing: " + string.Join("; ", review.Take(6)) + (review.Count > 6 ? "; ..." : "") + ".");
        return list;
    }
}
