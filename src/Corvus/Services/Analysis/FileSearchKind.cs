namespace Corvus.Services.Analysis;

/// <summary>search_container kind=file: inner files (and archive entries not extracted) whose name or path matches.</summary>
internal sealed class FileSearchKind : IContainerSearchKind
{
    public IReadOnlyList<string> Kinds => ["file"];

    public IEnumerable<ContainerMatch> Search(ContainerScope scope, string kind, Func<string, bool> matches, CancellationToken ct)
    {
        bool Matches(string path) => matches(path[(path.LastIndexOf('/') + 1)..]) || matches(path);
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var item in scope.Items)
        {
            ct.ThrowIfCancellationRequested();
            seen.Add(item.Path);
            if (Matches(item.Path)) yield return new ContainerMatch(item.Path, item.Path, "file") { Detail = $"{item.Kind}, {item.Bytes.Length:N0} bytes" };
        }
        foreach (var entry in scope.Entries ?? [])
        {
            ct.ThrowIfCancellationRequested();
            if (seen.Add(entry.Path) && Matches(entry.Path))
                yield return new ContainerMatch(entry.Path, entry.Path, "file") { Detail = $"{entry.Size:N0} bytes" + (entry.Detail != null ? $", {entry.Detail}" : "") };
        }
    }
}
