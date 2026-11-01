using Corvus.Core.Archives;

namespace Corvus.Core.Documents;

/// <summary>Reads compiled help (.chm) images as containers.</summary>
internal sealed class ChmReader : IContainerReader
{
    private static readonly HashSet<string> Pages = new(StringComparer.OrdinalIgnoreCase)
    {
        ".htm", ".html", ".xhtml", ".js", ".vbs", ".hta", ".hhc", ".hhk", ".hhp",
    };

    public string Kind => "chm";

    public bool Accepts(ReadOnlySpan<byte> data, string name) => ChmFile.Looks(data);

    public ContainerContents Open(byte[] data, string name, bool allFiles, AnalysisLimits limits, CancellationToken ct)
    {
        var chm = ChmFile.Read(data, name, ct);
        var items = new List<ExtractedItem>();
        var entries = new List<ContainerEntry>();
        var notes = new List<string>(chm.Notes);
        long total = 0;
        int unreadable = 0, refused = 0, overLimit = 0;
        // Offset order keeps each decoded segment in use until its files are read.
        foreach (var e in chm.Entries.OrderBy(e => e.Section).ThenBy(e => e.Offset))
        {
            ct.ThrowIfCancellationRequested();
            // Directories have no content; "::" names are the format's own streams.
            if (e.Name.EndsWith('/')) continue;
            bool system = e.Name.StartsWith("::", StringComparison.Ordinal);
            var path = e.Name.TrimStart('/');
            string compression;
            try { compression = chm.Compression(e); }
            catch (ToolError ex) when (ex.Code is ErrorCode.MalformedInput or ErrorCode.Unsupported)
            {
                entries.Add(new ContainerEntry(path, e.Length, "unreadable"));
                if (++unreadable <= 10) notes.Add($"{path}: {ex.Message}");
                continue;
            }
            if (system) { entries.Add(new ContainerEntry(path, e.Length, compression + ", format stream")); continue; }
            bool page = Pages.Contains(Path.GetExtension(path));
            if (path.Split('/').Any(AsarArchive.IsUnsafeName))
            {
                entries.Add(new ContainerEntry(path, e.Length, compression + ", unsafe name"));
                if (allFiles || page) refused++;
                continue;
            }
            // Pages and, with allFiles, every file are read; other files are
            // read to see whether they are binaries.
            byte[] bytes;
            try { bytes = chm.Extract(e, limits.MaxItemBytes, limits.MaxTotalBytes); }
            catch (ToolError ex) when (ex.Code == ErrorCode.LimitExceeded)
            {
                entries.Add(new ContainerEntry(path, e.Length, compression + ", over limit"));
                if (++overLimit <= 10) notes.Add($"{path}: {ex.Message} Set {AnalysisLimits.RaiseVariable} to raise the caps.");
                continue;
            }
            catch (Exception ex) when (ex is InvalidDataException || EntryDamage.Is(ex) || ex is ToolError { Code: ErrorCode.MalformedInput or ErrorCode.Unsupported })
            {
                entries.Add(new ContainerEntry(path, e.Length, compression + ", unreadable"));
                if (++unreadable <= 10) notes.Add($"{path}: {ex.Message}");
                continue;
            }
            entries.Add(new ContainerEntry(path, bytes.Length, compression));
            if (!(allFiles || page || ArchiveItems.Wanted(bytes)) || items.Count >= limits.MaxItems) continue;
            total += bytes.Length;
            if (total > limits.MaxTotalBytes)
                throw new ToolError(ErrorCode.LimitExceeded, $"extracting {path} passes the {limits.MaxTotalBytes:N0}-byte total limit.", $"unpack fewer files, or set {AnalysisLimits.RaiseVariable} to raise the caps");
            items.Add(new ExtractedItem(path, bytes, $"compiled help file ({compression})"));
        }
        if (unreadable > 10) notes.Add($"{unreadable - 10} more files unreadable");
        if (overLimit > 10) notes.Add($"{overLimit - 10} more files over the limits.");
        if (refused > 0) notes.Add($"{refused} files with unsafe names not extracted.");
        if (entries.Count > items.Count) notes.Add($"{entries.Count - items.Count} of {entries.Count} files not extracted (not pages or binaries; allFiles extracts every file).");
        return new ContainerContents(Kind, items, notes) { Entries = entries };
    }
}
