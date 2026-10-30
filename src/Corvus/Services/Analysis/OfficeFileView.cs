using Corvus.Core;
using Corvus.Core.Documents;

namespace Corvus.Services.Analysis;

/// <summary>view=office: active content of an OLE, OOXML, RTF, SYLK or OneNote document: VBA, Excel 4.0 macros, OLE objects, links, findings.</summary>
internal sealed class OfficeFileView : IFileSummaryView
{
    public sealed record Module(string Name, string Type, string Stream, int Lines, bool SourceMissing,
        [property: System.ComponentModel.Description("The module source with constants folded and layers peeled; absent when the reader changed nothing.")] string? Plain = null);

    public sealed record Project(string Storage, string? Name, int CodePage, IReadOnlyList<Module> Modules, IReadOnlyList<string> References);

    public sealed record EmbeddedFile(string Path, string Name, string? SourcePath, long Size, string Kind, string Sha256);

    public sealed record Facts(string Format, bool Encrypted, IReadOnlyList<Project> Projects, IReadOnlyList<MacroFinding> Findings,
        IReadOnlyList<WorkbookSheet>? Sheets, IReadOnlyList<string>? DefinedNames, int? XlmFormulas, IReadOnlyList<EmbeddedFile> Objects,
        IReadOnlyList<ExternalLink> Links, IReadOnlyList<string> Notes);

    public string Name => "office";

    /// <summary>Documents above this size are not read by the view.</summary>
    private const long MaxDocument = 512L << 20;

    public FileView? Inspect(FileInput file, CancellationToken ct)
    {
        bool ole = CompoundFile.Looks(file.Head) && !Core.Installers.MsiDatabase.Looks(file.Head) || OneNoteReader.Looks(file.Head) || RtfObjects.Looks(file.Head);
        if (!ole && !(file.Kind == "text" && XlmMacros.IsSylk(file.Head)) && !(file.Kind == "zip" && file.HasZipEntry(n => n == "[Content_Types].xml"))) return null;
        if (file.Length > MaxDocument) return null;
        var doc = OfficeDocument.Read(file.Bytes, System.IO.Path.GetFileName(file.Path), ct);
        if (doc == null) return null;
        bool active = doc.Projects.Count > 0 || doc.Xlm != null || doc.Objects.Count > 0 || doc.Links.Count > 0 || doc.Classes.Count > 0 || doc.Encrypted;
        // A document without active content is listed only when asked for.
        if (!active && file.Options.View != Name) return null;
        var budget = System.Diagnostics.Stopwatch.StartNew();
        var kept = new System.Runtime.CompilerServices.StrongBox<int>();
        var facts = new Facts(doc.Format, doc.Encrypted,
            [.. doc.Projects.Select(p => new Project(p.Storage, p.ProjectName, p.CodePage,
                [.. p.Modules.Select(m => new Module(m.Name, m.Type, m.Stream, m.Source.Length == 0 ? 0 : m.Source.Count(c => c == '\n') + 1, m.SourceMissing, Peel(m.Source, budget, kept, ct)))], p.References))],
            doc.Findings, doc.Xlm?.Sheets, doc.Xlm?.Names, doc.Xlm?.Cells.Count,
            [.. doc.Objects.Select(o => new EmbeddedFile(o.Path, o.Name, o.SourcePath, o.Bytes.Length, Blob.Identify(o.Bytes), Blob.Sha256(o.Bytes)))],
            doc.Links, doc.Notes);
        var links = doc.Links.Select(l => (l.Target, $"{l.Type} link in {l.Part}"));
        return new FileView(facts, Highlights(doc)) { Findings = FindingRules.FromMacros(doc.Findings, "office"), Indicators = IndicatorList.FromText("office", links, ct) };
    }

    private const int MaxPeeledSource = 1 << 20, MaxPeeledChars = 8000, MaxPeeledTotal = 64_000;

    // The overview budget is shared by all modules, so many modules cannot multiply it.
    private static string? Peel(string source, System.Diagnostics.Stopwatch budget, System.Runtime.CompilerServices.StrongBox<int> kept, CancellationToken ct)
    {
        int left = Services.Web.Scripts.ScriptBudget.OverviewMilliseconds - (int)budget.ElapsedMilliseconds;
        if (source.Length == 0 || source.Length > MaxPeeledSource || left <= 0 || kept.Value >= MaxPeeledTotal) return null;
        var r = Services.Web.Scripts.ScriptReader.Read(source, "vbscript", ct, milliseconds: left);
        if (r.Folded == 0 && r.Layers.Count == 0 && r.Recovered.Count == 0) return null;
        var text = r.Plain.Length > MaxPeeledChars ? r.Plain[..MaxPeeledChars] : r.Plain;
        kept.Value += text.Length;
        return text;
    }

    private static List<string> Highlights(OfficeDocument doc)
    {
        var h = new List<string>();
        int modules = doc.Projects.Sum(p => p.Modules.Count);
        if (modules > 0)
        {
            var auto = doc.Findings.Where(f => f.Type == "AutoExec").Select(f => f.Keyword).Distinct().ToList();
            h.Add($"VBA macros: {modules} module(s){(auto.Count > 0 ? $"; runs on its own through {string.Join(", ", auto.Take(5))}" : "")}.");
        }
        if (doc.Xlm is { HasMacroSheets: true } x)
            h.Add($"Excel 4.0 macro sheets: {string.Join(", ", x.Sheets.Where(s => s.Type == "macro sheet").Select(s => s.State == "visible" ? s.Name : $"{s.Name} ({s.State})"))}; {x.Cells.Count} formula(s).");
        var noteworthy = doc.Findings.Where(f => f.Type == "Suspicious").Select(f => f.Keyword).Distinct().ToList();
        if (noteworthy.Count > 0) h.Add($"Worth reviewing in the macros: {string.Join(", ", noteworthy.Take(8))}{(noteworthy.Count > 8 ? ", ..." : "")}.");
        var iocs = doc.Findings.Where(f => f.Type == "IOC").Select(f => f.Keyword).Distinct().ToList();
        if (iocs.Count > 0) h.Add($"Addresses and file names in the macros: {string.Join(", ", iocs.Take(5))}{(iocs.Count > 5 ? ", ..." : "")}.");
        foreach (var o in doc.Objects.Take(5)) h.Add($"Embedded object {o.Name} ({o.Bytes.Length:N0} bytes, {Blob.Identify(o.Bytes)}).");
        foreach (var l in doc.Links.Where(l => l.Type is "attachedTemplate" or "oleObject" or "frame" or "subDocument" or "template" or "objautlink").Take(3))
            h.Add($"External {l.Type}: {l.Target}.");
        if (doc.Encrypted) h.Add(doc.DecryptedPackage != null ? "Encrypted with Excel's built-in password: decrypted and read." : "The document is encrypted; its content is not read.");
        if (h.Count == 0) h.Add($"{doc.Format}: no macros, embedded objects or external links.");
        return h;
    }
}
