using Corvus.Core;
using Corvus.Services.Web.Packages;

namespace Corvus.Services.Analysis;

/// <summary>search_container kind=dependency: the lockfiles under a folder (or one lockfile) that resolve a package, queried as name or name@version.</summary>
internal sealed class DependencySearchKind : IContainerSearchKind
{
    public IReadOnlyList<string> Kinds => ["dependency"];

    public IEnumerable<ContainerMatch> Search(ContainerScope scope, string kind, Func<string, bool> matches, CancellationToken ct) => [];

    public UnpackService.ContainerSearch SearchFile(string path, string query, int offset, int limit, ContainerSearchArgs args, CancellationToken ct)
    {
        var source = Directory.Exists(Path.GetFullPath(path)) ? Path.GetFullPath(path) : InputFiles.RequireRegularFile(path, "file");
        if (string.IsNullOrWhiteSpace(query))
            throw new ToolError(ErrorCode.InvalidArgument, "kind=dependency takes a package name as query.", "pass a name or name@version, with * ? wildcards");
        query = query.Trim();
        // A version follows the last '@' past the first character, so a scoped name keeps its own.
        int at = query.LastIndexOf('@');
        var (name, version) = at > 0 ? (query[..at], query[(at + 1)..]) : (query, null);
        var nameMatch = Whole(name);
        var normalized = Whole(Lockfiles.Normalize(name));
        Func<string, bool>? versionMatch = version is { Length: > 0 } ? Whole(version) : null;
        var files = Lockfiles.Find(source, ct, out bool complete);
        var notes = new List<string>();
        if (!complete) notes.Add($"the walk stopped at {Lockfiles.MaxFiles} lockfiles or an unreadable folder; others are unknown");
        var rows = new List<ContainerMatch>();
        foreach (var relative in files)
        {
            ct.ThrowIfCancellationRequested();
            var full = File.Exists(source) ? source : Path.Combine(source, relative);
            if (Lockfiles.Load(full) is not { } lockfile)
            {
                notes.Add($"{relative}: not read");
                continue;
            }
            bool python = lockfile.Ecosystem == "pypi";
            foreach (var p in lockfile.Packages.DistinctBy(p => (p.Name, p.Version, p.Source)))
                if ((python ? normalized(p.Name) : nameMatch(p.Name)) && (versionMatch == null || versionMatch(p.Version)))
                    rows.Add(new ContainerMatch(relative, $"{p.Name}@{p.Version}", "dependency")
                    {
                        Detail = $"{lockfile.Format}, {p.Source}" + (p.Source != "registry" && p.Resolved != null ? $" {p.Resolved}" : "") + (p.InstallScript ? ", runs a script at install" : ""),
                    });
        }
        notes.Insert(0, $"{files.Count} lockfile(s) read; {rows.Select(r => r.Path).Distinct(StringComparer.Ordinal).Count()} resolve {query}.");
        return UnpackService.Ranked(source, Directory.Exists(source) ? "folder" : "file", files.Count, rows, name, offset, limit, notes);
    }

    // A package question names one package: whole names and versions, or * ? wildcards.
    private static Func<string, bool> Whole(string query) => query.Contains('*') || query.Contains('?')
        ? SearchService.CreateMatcher(query, regex: false)
        : s => string.Equals(s, query, StringComparison.OrdinalIgnoreCase);
}
