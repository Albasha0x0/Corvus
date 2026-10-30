using System.Text;
using Corvus.Services.Web.Packages;

namespace Corvus.Services.Analysis;

/// <summary>view=lockfile: an npm, pnpm, yarn, poetry, uv or hashed pip lockfile's resolved packages, counted by source.</summary>
internal sealed class LockfileFileView : IFileSummaryView
{
    /// <summary>Packages listed per group, and findings per file.</summary>
    private const int MaxListed = 50;

    public sealed record Facts(
        string Format, string Ecosystem, int Packages,
        IReadOnlyDictionary<string, int> BySource,
        IReadOnlyList<LockedPackage> OutsideRegistry,
        IReadOnlyList<string> InstallScripts,
        IReadOnlyList<string> Notes);

    public string Name => "lockfile";

    public FileView? Inspect(FileInput file, CancellationToken ct)
    {
        if (!Lockfiles.Named(Path.GetFileName(file.Path)) || file.Length > Lockfiles.MaxBytes) return null;
        if (Lockfiles.Read(file.Path, Encoding.UTF8.GetString(file.Bytes)) is not { } lockfile) return null;
        var outside = lockfile.Packages.Where(p => p.Source != "registry").ToList();
        var scripts = lockfile.Packages.Where(p => p.InstallScript).Select(p => $"{p.Name}@{p.Version}").Distinct(StringComparer.Ordinal).ToList();
        var notes = lockfile.Notes.ToList();
        if (outside.Count > MaxListed) notes.Add($"{outside.Count} packages from outside the registry; the first {MaxListed} are listed");
        if (scripts.Count > MaxListed) notes.Add($"{scripts.Count} packages run a script at install; the first {MaxListed} are listed");
        var facts = new Facts(lockfile.Format, lockfile.Ecosystem, lockfile.Packages.Count,
            lockfile.Packages.GroupBy(p => p.Source).OrderBy(g => g.Key, StringComparer.Ordinal).ToDictionary(g => g.Key, g => g.Count()),
            [.. outside.Take(MaxListed)], [.. scripts.Take(MaxListed)], notes);
        var name = Path.GetFileName(file.Path);
        // A local path is a workspace member or a vendored folder: a fact, not a finding.
        var findings = outside.Where(p => p.Source is "git" or "url").Take(MaxListed).Select(p => new PackageFinding("package/locked-source",
            p.Resolved?.StartsWith("http://", StringComparison.OrdinalIgnoreCase) == true ? "noteworthy" : "review", "dependency",
            $"{p.Name}@{p.Version} resolves from {p.Source} {p.Resolved}", name).ToFinding()).ToList();
        var highlights = new List<string>
        {
            $"{lockfile.Format}: {lockfile.Packages.Count} resolved package(s), " + string.Join(", ", facts.BySource.Select(kv => $"{kv.Value} {kv.Key}"))
            + (scripts.Count > 0 ? $"; {scripts.Count} run a script at install" : "") + "; view=lockfile lists them.",
        };
        highlights.AddRange(outside.Where(p => p.Source is "git" or "url").Take(5).Select(p => $"From {p.Source}: {p.Name}@{p.Version} ({p.Resolved})."));
        return new FileView(facts, highlights) { Findings = findings };
    }
}
