namespace Corvus.Services.Analysis;

/// <summary>search_container kind=file: inner files (and archive entries not extracted) whose name or path matches.</summary>
internal sealed class FileSearchKind : IContainerSearchKind
{
    public IReadOnlyList<string> Kinds => ["file"];

    public IEnumerable<ContainerMatch> Search(ContainerScope scope, string kind, Func<string, bool> matches, CancellationToken ct)
    {
        bool Matches(string path) => matches(path[(path.LastIndexOf('/') + 1)..]) || matches(path);
        var seen = new HashSet<string>(StringComparer.Ordinal);
        // A file written under a safe name (run.ps1 as run.ps1.bin) is one
        // row; its archive entry, under the recorded name, is not listed again.
        foreach (var item in scope.Items)
        {
            ct.ThrowIfCancellationRequested();
            seen.Add(item.Path);
            if (item.Original != null) seen.Add(item.Original);
            if (Matches(item.Path) || item.Original != null && Matches(item.Original))
                yield return new ContainerMatch(item.Path, item.Path, "file")
                {
                    Detail = $"{item.Kind}, {item.Bytes.Length:N0} bytes" + (item.Original != null ? $", recorded as {item.Original}" : ""),
                };
        }
        foreach (var entry in scope.Entries ?? [])
        {
            ct.ThrowIfCancellationRequested();
            if (seen.Add(entry.Path) && Matches(entry.Path))
                yield return new ContainerMatch(entry.Path, entry.Path, "file") { Detail = $"{entry.Size:N0} bytes" + (entry.Detail != null ? $", {entry.Detail}" : "") };
        }
    }
}
