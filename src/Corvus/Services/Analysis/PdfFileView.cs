using Corvus.Core;
using Corvus.Core.Documents;

namespace Corvus.Services.Analysis;

/// <summary>
/// view=pdf: a PDF's structure and active content (<see cref="PdfDocument"/>): version, objects, streams, incremental
/// updates, encryption, pdfid's keyword counts (with #xx-escaped names counted apart), actions with what triggers them,
/// JavaScript and XFA scripts with noteworthy calls by object and line, launched programs, URIs and embedded files.
/// </summary>
internal sealed class PdfFileView : IFileSummaryView
{
    public sealed record Script(int Object, string Trigger, int Length, string Start);

    public sealed record EmbeddedFile(int Object, string Name, string? Description, long Size, string Kind, string Sha256);

    /// <summary>Objects: the current ones; FileObjects: every "n g obj" in the file, earlier versions included; CompressedObjects: those read from object streams.</summary>
    public sealed record Facts(string? Version, long HeaderOffset, int Objects, int FileObjects, int CompressedObjects, int Streams, int ObjectStreams, int Updates, int XrefSections,
        long AfterLastEof, string? Encryption, IReadOnlyList<PdfKeywordCount> Keywords, IReadOnlyList<PdfAction> Actions, IReadOnlyList<Script> Scripts,
        IReadOnlyList<EmbeddedFile> EmbeddedFiles, IReadOnlyList<MacroFinding> Findings, IReadOnlyList<string> Notes);

    public string Name => "pdf";

    private const long MaxDocument = 1L << 30;

    public FileView? Inspect(FileInput file, CancellationToken ct)
    {
        if (!PdfFile.Looks(file.Head) || file.Length > MaxDocument) return null;
        var doc = PdfDocument.Read(file.Bytes, System.IO.Path.GetFileName(file.Path), ct);
        var pdf = doc.File;
        var notes = new List<string>(pdf.Notes);
        notes.AddRange(doc.UndecodedFilters.Take(20).Select(f => "not decoded: " + f));
        var facts = new Facts(pdf.Version, pdf.HeaderOffset, pdf.Current.Count(), pdf.Objects.Count(o => o.InObjectStream == null), pdf.Objects.Count(o => o.InObjectStream != null),
            pdf.Objects.Count(o => o.Stream != null), pdf.Objects.Count(o => o.Dict?.Name("Type") == "ObjStm"),
            Math.Max(0, pdf.EofMarkers - 1), pdf.XrefSections, pdf.AfterLastEof,
            pdf.Trailer?["Encrypt"] == null ? null : pdf.Security?.Description ?? "user password (not decrypted)",
            [.. doc.Keywords.Where(k => k.Count > 0)], doc.Actions,
            [.. doc.Scripts.Select(s => new Script(s.Object, s.Trigger, s.Code.Length, s.Code.Length <= 200 ? s.Code : s.Code[..200] + "..."))],
            [.. doc.Files.Select(f => new EmbeddedFile(f.Object, f.Name, f.Description, f.Bytes.Length, Blob.Identify(f.Bytes), Blob.Sha256(f.Bytes)))],
            doc.Findings, notes);
        return new FileView(facts, Highlights(doc, facts));
    }

    private static List<string> Highlights(PdfDocument doc, Facts f)
    {
        var h = new List<string>();
        var opens = doc.Actions.Where(a => a.Trigger.Contains("document opens", StringComparison.Ordinal) || a.Trigger.StartsWith("document-level", StringComparison.Ordinal)).ToList();
        if (doc.Scripts.Count > 0)
            h.Add($"JavaScript: {doc.Scripts.Count} script(s){(opens.Any(a => a.Type == "JavaScript") ? ", one runs when the document opens" : "")}.");
        foreach (var a in doc.Actions.Where(a => a.Type == "Launch").Take(3)) h.Add($"Launch action (object {a.Object}): {a.Target}.");
        foreach (var e in f.EmbeddedFiles.Take(5)) h.Add($"Embedded file {e.Name} ({e.Size:N0} bytes, {e.Kind}).");
        var noteworthy = doc.Findings.Where(x => x.Type == "Suspicious" && x.Keyword != "Launch").Select(x => x.Keyword).Distinct().ToList();
        if (noteworthy.Count > 0) h.Add($"Worth reviewing: {string.Join(", ", noteworthy.Take(8))}.");
        if (f.Encryption != null) h.Add($"Encrypted: {f.Encryption}.");
        if (f.Updates > 0) h.Add($"{f.Updates} incremental update(s): earlier object versions are in the file.");
        return h;
    }
}
