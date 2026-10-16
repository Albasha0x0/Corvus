using System.Text;
using Corvus.Core.Archives;

namespace Corvus.Core.Documents;

/// <summary>
/// OLE compound files other than Windows Installer databases (.doc, .xls, .ppt, .msg, vbaProject.bin, OLE objects): every
/// stream listed; VBA module sources written as .bas / .cls / .frm, Excel 4.0 macro formulas as xlm_macros.txt, and OLE
/// Package objects under the name they were embedded with; other streams with allFiles, or when they hold a binary or package.
/// </summary>
internal sealed class CompoundFileReader : IContainerReader
{
    public string Kind => "ole";

    public bool Accepts(ReadOnlySpan<byte> data, string name) => CompoundFile.Looks(data) && !Installers.MsiDatabase.Looks(data);

    public ContainerContents Open(byte[] data, string name, bool allFiles, AnalysisLimits limits, CancellationToken ct)
    {
        var cf = CompoundFile.Read(data, name);
        var doc = OfficeDocument.FromCompound(cf, ct);
        var items = new List<ExtractedItem>();
        var entries = new List<ContainerEntry>();
        long total = 0;
        foreach (var p in doc.Projects)
            foreach (var m in p.Modules)
                ArchiveItems.Take(items, entries, "VBA module", StreamPath(p.Storage + "VBA/" + OfficeDocument.ModuleFile(m)), Encoding.UTF8.GetBytes(m.Source), true, limits, ref total);
        if (doc.Xlm is { HasMacroSheets: true } xlm)
            ArchiveItems.Take(items, entries, "Excel 4.0 macros", "xlm_macros.txt", Encoding.UTF8.GetBytes(xlm.Text), true, limits, ref total);
        if (doc.DecryptedPackage is { } package)
            ArchiveItems.Take(items, entries, "decrypted package", "EncryptedPackage.zip", package, true, limits, ref total);
        foreach (var o in doc.Objects)
            ArchiveItems.Take(items, entries, "OLE Package", StreamPath(o.Path[..(o.Path.LastIndexOf('/') + 1)]) + o.Name, o.Bytes, true, limits, ref total);
        foreach (var e in cf.Entries.Where(e => !e.IsStorage))
        {
            ct.ThrowIfCancellationRequested();
            byte[] bytes;
            try { bytes = cf.Read(e, limits.MaxItemBytes); }
            catch (ToolError ex) when (ex.Code == ErrorCode.LimitExceeded) { entries.Add(new ContainerEntry(StreamPath(e.Path), e.Size)); doc.Notes.Add(ex.Message); continue; }
            ArchiveItems.Take(items, entries, "OLE stream", StreamPath(e.Path), bytes, allFiles, limits, ref total);
        }
        var notes = new List<string>(doc.Notes);
        if (doc.Projects.Count > 0)
            notes.Add($"VBA: {doc.Projects.Sum(p => p.Modules.Count)} modules in {doc.Projects.Count} project(s); summarize_file view=office lists autorun entry points and noteworthy calls.");
        notes.AddRange(cf.Notes.Where(n => !notes.Contains(n)));
        return new ContainerContents(doc.Format, items, notes) { Entries = entries };
    }

    /// <summary>A stream path with control characters written as [n], as 7-Zip names them ("[1]Ole10Native").</summary>
    public static string StreamPath(string path) => string.Concat(path.Select(c => c < 32 ? $"[{(int)c}]" : c.ToString()));
}
