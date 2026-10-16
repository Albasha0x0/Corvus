using System.IO.Compression;
using Corvus.Services.Web.Packages;

namespace Corvus.Services.Analysis;

/// <summary>
/// view=package: an npm tarball, a PyPI wheel or sdist, a VS Code extension (.vsix) or a browser extension (.crx, .xpi,
/// or a zip or folder with its manifest.json) reviewed before installing, nothing run: install-time scripts and what
/// their code reaches, entry points, permissions, native binaries, transformed code and names close to popular packages,
/// each finding marked noteworthy or worth reviewing.
/// </summary>
internal sealed class PackageFileView : IFileSummaryView
{
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
        if (Manifests.Contains(Path.GetFileName(file.Path), StringComparer.Ordinal)) return true;
        if (file.Kind != "zip" || file.Streamed) return false;
        try
        {
            using var zip = new ZipArchive(new MemoryStream(file.Head, writable: false), ZipArchiveMode.Read);
            return zip.Entries.Take(20_000).Any(e => e.FullName.Count(c => c == '/') <= 1 && Manifests.Contains(e.Name, StringComparer.Ordinal)
                                                     || e.FullName.EndsWith(".dist-info/METADATA", StringComparison.Ordinal));
        }
        catch (InvalidDataException) { return false; }
    }

    private static List<string> Highlights(PackageReport r)
    {
        var who = string.Join(" ", new[] { r.Name, r.Version }.Where(s => s != null));
        var install = r.Scripts.Where(s => s.AtInstall).Select(s => s.Name).ToList();
        var list = new List<string>
        {
            $"{r.Ecosystem} package {who}: {r.Review}" + (r.Findings.Count > 0 ? $" ({r.Findings.Count} finding(s))" : "") +
            (install.Count > 0 ? $"; runs at install: {string.Join(", ", install)}" : "") + "; view=package lists scripts, entry points and findings.",
        };
        list.AddRange(r.Findings.Where(f => f.Level == "noteworthy").Take(5).Select(f => $"Noteworthy {f.Category}: {f.Detail}" + (f.Path != null ? $" ({f.Path})" : "")));
        return list;
    }
}
