using System.ComponentModel;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;
using Corvus.Core;
using Corvus.Mcp;
using Corvus.Services.Analysis;

namespace Corvus.Tools;

[McpServerToolType]
public sealed class FolderTools(FolderCompare folders)
{
    [McpServerTool(Name = "compare_folders", Title = "Compare two folders or packages", UseStructuredContent = true)]
    [Description("Compare two folders, zip-family archives or files: modified, added, removed and moved entries, binary versions, text " +
                 "diffs and package findings. oldResult / newResult compare two kept results instead.")]
    public Task<FolderCompare.Comparison> CompareFolders(
        [Description("Old folder, archive or file.")] string? oldPath = null,
        [Description("New folder, archive or file.")] string? newPath = null,
        [Description("Entries listed.")] string change = "changed",
        [Description("Path globs to skip.")] string[]? exclude = null,
        [Description("Default: false on Windows and macOS.")] bool? caseSensitive = null,
        [Description("Per side; past it, incomplete.")] int maxEntries = FolderCompare.DefaultMaxEntries,
        [Description(ToolSupport.RowOffsetDescription)] int offset = 0,
        [Description("Entries per page.")] int limit = FolderCompare.DefaultLimit,
        [Description(NativeDiffTools.OldResultDescription)] string? oldResult = null,
        [Description(NativeDiffTools.NewResultDescription)] string? newResult = null,
        [Description("Leave out text diffs.")] bool noDiffs = false,
        RequestContext<CallToolRequestParams> context = null!,
        CancellationToken cancellationToken = default) => OrderedProgress.Run(context, progress =>
        EvidenceInput.FromArguments(oldResult, newResult, oldPath != null || newPath != null, "oldPath and newPath", context?.Services) is var (ev, changes)
            ? Task.FromResult(Evidence(ev, changes, offset, limit))
            : string.IsNullOrWhiteSpace(oldPath) || string.IsNullOrWhiteSpace(newPath)
                ? throw new ToolError(ErrorCode.InvalidArgument, $"{(string.IsNullOrWhiteSpace(oldPath) ? "oldPath" : "newPath")} is missing: compare_folders takes both paths.",
                    "pass oldPath and newPath, or oldResult and newResult")
            : Task.Run(() => WithPackageChanges(folders.Compare(oldPath, newPath, change, caseSensitive, exclude is { Length: > 0 } ? string.Join(";", exclude) : null, maxEntries,
                offset, limit, (done, total) => progress.Report(new ProgressNotificationValue { Progress = done, Total = total, Message = $"{done} of {total} files hashed" }),
                cancellationToken, !noDiffs), oldPath, newPath, cancellationToken), cancellationToken));

    /// <summary>Finding changes repeated in the notes; Changes holds them all.</summary>
    private const int MaxPackageRows = 50;

    private static readonly string[] PackageExtensions = [".tgz", ".tar.gz", ".whl", ".gem", ".nupkg", ".vsix", ".crx", ".xpi"];

    // A folder is reviewed only with a package manifest at its root: the review reads every file in it.
    private static readonly string[] FolderManifests = ["package.json", "pyproject.toml", "setup.py", "manifest.json", "composer.json"];

    // Gem and NuGet manifests are named for their package.
    private static readonly string[] FolderManifestPatterns = ["*.gemspec", "*.nuspec"];

    /// <summary>Adds package review changes and a policy note when both paths are packages; returns the comparison unchanged otherwise.</summary>
    private static FolderCompare.Comparison WithPackageChanges(FolderCompare.Comparison comparison, string oldPath, string newPath, CancellationToken ct)
    {
        static bool Package(string p) => File.Exists(p) && PackageExtensions.Any(e => p.EndsWith(e, StringComparison.OrdinalIgnoreCase))
                                         || Directory.Exists(p) && (FolderManifests.Any(m => File.Exists(Path.Combine(p, m)))
                                                                    || FolderManifestPatterns.Any(m => Directory.EnumerateFiles(p, m).Any()));
        if (comparison.Old.Complete && comparison.New.Complete) ToolOutput.Complete();
        if (!Package(oldPath) || !Package(newPath)) return comparison;
        if (Services.Web.Packages.PackageReview.Review(oldPath, ct, hosts: true) is not { Ecosystem: not "repository" } old
            || Services.Web.Packages.PackageReview.Review(newPath, ct, hosts: true) is not { Ecosystem: not "repository" } @new) return comparison;
        if ((old.Partial ?? @new.Partial) is { } partial) ToolOutput.Coverage("partial", "package review: " + partial, Limitations.Id(Limitation.RowCap));
        var findings = CapabilityChanges.Of(old, @new);
        var (facts, summary) = CapabilityChanges.Policy(old, @new, findings);
        var rows = findings.Concat(facts).ToList();
        return comparison with
        {
            Changes = rows,
            Notes = [summary, .. comparison.Notes, $"package review: {findings.Count(r => r.Kind == "added")} finding(s) added, {findings.Count(r => r.Kind == "removed")} removed, " +
                $"{facts.Count} policy fact(s) changed; Changes lists them", .. rows.Take(MaxPackageRows).Select(r => $"{r.Kind} {r.Key}" + ((r.New ?? r.Old) is { } at ? $": {at}" : ""))],
        };
    }

    /// <summary>Two kept results compared: the sides are the results, the rows their changes (unknown counts as unmatched).</summary>
    private static FolderCompare.Comparison Evidence(EvidenceSummary ev, IReadOnlyList<EvidenceChange> changes, int offset, int limit)
    {
        offset = Math.Max(0, offset);
        var page = changes.Skip(offset).Take(Math.Clamp(limit, 1, FolderCompare.MaxLimit)).ToList();
        bool complete = ev.Completeness == "complete";
        FolderCompare.Side Side(EvidenceSource s, int count) => new(s.Ref, "result", count, 0, complete, 0, 0, 0, []);
        return new FolderCompare.Comparison(Side(ev.Old, ev.Same + ev.Changed + ev.Removed), Side(ev.New, ev.Same + ev.Changed + ev.Added), ev.Basis, true,
            new FolderCompare.Counts(ev.Same, ev.Changed, ev.Added, ev.Removed, 0, 0, 0, 0, 0, ev.Unknown, 0, !complete), "evidence", offset, changes.Count,
            offset + page.Count < changes.Count, [], EvidenceInput.Text(ev).TrimEnd('\n').Split('\n'), 0) { Evidence = ev, Changes = page };
    }
}
