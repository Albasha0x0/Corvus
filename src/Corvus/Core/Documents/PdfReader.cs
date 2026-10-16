using System.Text;
using Corvus.Core.Archives;

namespace Corvus.Core.Documents;

/// <summary>
/// PDF files as containers: embedded files under their names, JavaScript actions as .js and XFA forms as .xml; with
/// allFiles every stream decoded through its filters (or as stored, when a filter is an image or crypt filter).
/// </summary>
internal sealed class PdfReader : IContainerReader
{
    public string Kind => "pdf";

    public bool Accepts(ReadOnlySpan<byte> data, string name) => PdfFile.Looks(data);

    public ContainerContents Open(byte[] data, string name, bool allFiles, AnalysisLimits limits, CancellationToken ct)
    {
        var doc = PdfDocument.Read(data, name, ct);
        var items = new List<ExtractedItem>();
        var entries = new List<ContainerEntry>();
        long total = 0;
        foreach (var f in doc.Files)
            ArchiveItems.Take(items, entries, "embedded file", "EmbeddedFiles/" + f.Name.Replace('\\', '/').Split('/')[^1], f.Bytes, true, limits, ref total);
        int n = 0;
        foreach (var s in doc.Scripts)
            ArchiveItems.Take(items, entries, "JavaScript", $"JavaScript/object{s.Object}{(++n > 1 ? $"_{n}" : "")}.js", Encoding.UTF8.GetBytes(s.Code), true, limits, ref total);
        foreach (var (obj, xml) in doc.Xfa)
            ArchiveItems.Take(items, entries, "XFA form", $"XFA/object{obj}.xml", xml, true, limits, ref total);
        if (allFiles)
            foreach (var o in doc.File.Current.Where(o => o.Stream != null))
            {
                ct.ThrowIfCancellationRequested();
                var bytes = doc.File.Decoded(o, out var stopped, limits.MaxItemBytes);
                ArchiveItems.Take(items, entries, "PDF stream", $"streams/object{o.Number}.{(stopped == null ? "bin" : "raw")}", bytes, true, limits, ref total);
            }
        var notes = new List<string>(doc.File.Notes);
        notes.AddRange(doc.UndecodedFilters.Take(20).Select(f => "not decoded: " + f));
        if (doc.Scripts.Count + doc.Files.Count + doc.Actions.Count > 0)
            notes.Add($"{doc.Actions.Count} action(s), {doc.Scripts.Count} script(s), {doc.Files.Count} embedded file(s); summarize_file view=pdf says what triggers each.");
        return new ContainerContents($"PDF {doc.File.Version}".TrimEnd(), items, notes) { Entries = entries };
    }
}
