using System.IO.Compression;
using Corvus.Services.Web.Packages;

namespace Corvus.Services.Analysis;

/// <summary>view=package: reviews an npm, PyPI, VS Code or browser extension package, or a repository's agent configuration, without running it.</summary>
internal sealed class PackageFileView : IFileSummaryView
{
    private static readonly HashSet<string> RepositoryKinds = new(StringComparer.Ordinal) { "git hook", "git config", "dev container", "direnv", "build step" };

    private static readonly string[] Manifests = ["package.json", "manifest.json", "setup.py", "pyproject.toml", "PKG-INFO", "extension.vsixmanifest"];

    public string Name => "package";

    public FileView? Inspect(FileInput file, CancellationToken ct)
    {
        if (!Likely(file)) return null;
        var report = PackageReview.Review(file.Path, ct);
        if (report == null) return null;
        return new FileView(report, Highlights(report));
    }

    /// <summary>A cheap test before the package is read: its extension, its manifest name, or a zip whose directory lists a manifest.</summary>
    private static bool Likely(FileInput file)
    {
        var name = Path.GetFileName(file.Path).ToLowerInvariant();
        var ext = Path.GetExtension(name);
        if (ext is ".crx" or ".vsix" or ".whl" or ".xpi" or ".tgz" || name.EndsWith(".tar.gz", StringComparison.Ordinal)) return true;
        if (Manifests.Contains(Path.GetFileName(file.Path), StringComparer.Ordinal) || PackageFiles.AgentRoot(file.Path) != null) return true;
        if (file.Kind != "zip" || file.Streamed) return false;
        try
        {
            using var zip = new ZipArchive(new MemoryStream(file.Head, writable: false), ZipArchiveMode.Read);
            return zip.Entries.Take(20_000).Any(e => e.FullName.Count(c => c == '/') <= 1 && Manifests.Contains(e.Name, StringComparer.Ordinal)
                                                     || e.FullName.EndsWith(".dist-info/METADATA", StringComparison.Ordinal)
                                                     || e.FullName.Count(c => c == '/') <= 3 && Core.AgentFiles.Kind(e.FullName) != null);
        }
        catch (InvalidDataException) { return false; }
    }

    /// <summary>The view of a report already read.</summary>
    internal static FileView Of(PackageReport report) => new(report, Highlights(report));

    private static List<string> Highlights(PackageReport r)
    {
        var who = string.Join(" ", new[] { r.Ecosystem == "repository" ? r.Ecosystem : r.Ecosystem + " package", r.Name, r.Version }.Where(s => s != null));
        var install = r.Scripts.Where(s => s.AtInstall).Select(s => s.Name).ToList();
        var list = new List<string>
        {
            $"{who}: {r.Review}" + (r.Findings.Count > 0 ? $" ({r.Findings.Count} finding(s))" : "") +
            (install.Count > 0 ? $"; runs at install: {string.Join(", ", install)}" : "") + "; view=package lists scripts, entry points and findings.",
        };
        if (r.Partial != null) list.Add($"Partial: {r.Partial}.");
        static string Counts(IEnumerable<AgentEntry> entries) => string.Join(", ", entries.GroupBy(a => a.Kind).Select(g => $"{g.Count()} {g.Key}{(g.Count() > 1 ? "s" : "")}"));
        if (r.Agents?.Where(a => !RepositoryKinds.Contains(a.Kind)).ToList() is { Count: > 0 } agents) list.Add("Agent configuration: " + Counts(agents) + ".");
        if (r.Agents?.Where(a => RepositoryKinds.Contains(a.Kind)).ToList() is { Count: > 0 } runs) list.Add("Runs on open, checkout or build: " + Counts(runs) + ".");
        foreach (var a in (r.Provenance ?? []).Take(3))
            list.Add($"Provenance ({a.Format}): digest {a.Digest}, signature {a.Signature}" + (a.Chain != "not used" ? $", chain {a.Chain}" : "") + $", log {a.Log}"
                + (a.Repository != null ? $"; built from {a.Repository}" + (a.Commit != null ? $" at {a.Commit[..Math.Min(12, a.Commit.Length)]}" : "") : a.Signer != null ? $"; signer {a.Signer}" : "") + ".");
        list.AddRange(r.Findings.Where(f => f.Level == "noteworthy").Take(5).Select(f => $"Noteworthy {f.Category}: {f.Detail}"
            + (f.Path != null ? $" ({f.Path}{(f.Line != null ? $":{f.Line}" : "")})" : "")));
        return list;
    }
}
