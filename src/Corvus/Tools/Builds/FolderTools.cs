using System.ComponentModel;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;
using Corvus.Core;
using Corvus.Mcp;
using Corvus.Services.Analysis;

namespace Corvus.Tools;

[McpServerToolType]
public sealed class FolderTools(FolderCompare folders, ServerOptions? serverOptions = null, Native.Providers.Worker.WorkerPool? workers = null)
{
    /// <summary>A comparison with the package review's partial reason, which the server reports as coverage.</summary>
    public sealed record FolderComparison(FolderCompare.Comparison Comparison, string? PackagePartial);

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
            : Task.Run(async () =>
            {
                var args = new FileWork.CompareFoldersArgs(oldPath, newPath, change, caseSensitive, exclude is { Length: > 0 } ? string.Join(";", exclude) : null, maxEntries, offset, limit, !noDiffs);
                var r = await FileIsolation.RunAsync(serverOptions, workers, FileWork.CompareFolders, args, oldPath,
                    () => CompareWith(folders, args, (done, total) => progress.Report(new ProgressNotificationValue { Progress = done, Total = total, Message = $"{done} of {total} files hashed" }),
                        cancellationToken), cancellationToken);
                if (r.Comparison.Old.Complete && r.Comparison.New.Complete) ToolOutput.Complete();
                if (r.PackagePartial is { } partial) ToolOutput.Coverage("partial", "package review: " + partial, Limitations.Id(Limitation.RowCap));
                return r.Comparison;
            }, cancellationToken));

    /// <summary>The comparison of two paths with the package and lockfile changes of both sides; <paramref name="progress"/> counts hashed files.</summary>
    public static FolderComparison CompareWith(FolderCompare folders, FileWork.CompareFoldersArgs a, Action<int, int>? progress, CancellationToken ct)
    {
        var (comparison, partial) = WithPackageChanges(folders.Compare(a.OldPath, a.NewPath, a.Change, a.CaseSensitive, a.Exclude, a.MaxEntries, a.Offset, a.Limit, progress, ct, a.Diffs),
            a.OldPath, a.NewPath, ct);
        return new FolderComparison(WithLockfileChanges(comparison, a.OldPath, a.NewPath, ct), partial);
    }

    /// <summary>Adds package changes for each lockfile both sides hold at one relative path (or two lockfiles of one format); returns the comparison unchanged when none are paired.</summary>
    private static FolderCompare.Comparison WithLockfileChanges(FolderCompare.Comparison comparison, string oldPath, string newPath, CancellationToken ct)
    {
        var olds = Services.Web.Packages.Lockfiles.Find(oldPath, ct, out bool oldComplete);
        var news = Services.Web.Packages.Lockfiles.Find(newPath, ct, out bool newComplete);
        // Two lockfiles given as files pair by format, whatever their folders.
        var pairs = File.Exists(oldPath) && File.Exists(newPath) && olds.Count == 1 && news.Count == 1
                    && string.Equals(olds[0], news[0], StringComparison.OrdinalIgnoreCase)
            ? [(olds[0], Old: oldPath, New: newPath)]
            : olds.Intersect(news, StringComparer.Ordinal).Select(r => (r, Old: Path.Combine(oldPath, r), New: Path.Combine(newPath, r))).ToList();
        if (pairs.Count == 0) return comparison;
        var rows = new List<EvidenceChange>();
        var notes = new List<string>();
        if (!oldComplete || !newComplete) notes.Add($"lockfiles: the walk stopped at {Services.Web.Packages.Lockfiles.MaxFiles} lockfiles or an unreadable folder; others are unknown");
        foreach (var (where, o, n) in pairs)
        {
            if (Services.Web.Packages.Lockfiles.Load(o) is not { } old || Services.Web.Packages.Lockfiles.Load(n) is not { } @new)
            {
                notes.Add($"lockfile {where}: not read on one side");
                continue;
            }
            var changes = Services.Web.Packages.Lockfiles.Diff(old, @new, where);
            rows.AddRange(changes);
            notes.Add($"lockfile {where}: {changes.Count(c => c.Kind == "added")} package(s) added, {changes.Count(c => c.Kind == "removed")} removed, " +
                $"{changes.Count(c => c.Kind == "changed")} changed, {changes.Count(c => c.New?.StartsWith("noteworthy", StringComparison.Ordinal) == true)} noteworthy");
        }
        notes.AddRange(rows.Where(r => r.New?.StartsWith("noteworthy", StringComparison.Ordinal) == true).Take(MaxPackageRows)
            .Select(r => $"{r.Kind} {r.Key}: {r.New}" + (r.Fields is { Count: > 0 } f ? $" ({string.Join(", ", f)})" : "")));
        return comparison with { Changes = [.. comparison.Changes ?? [], .. rows], Notes = [.. comparison.Notes, .. notes] };
    }

    /// <summary>Finding changes repeated in the notes; Changes holds them all.</summary>
    private const int MaxPackageRows = 50;

    private static readonly string[] PackageExtensions = [".tgz", ".tar.gz", ".whl", ".gem", ".nupkg", ".vsix", ".crx", ".xpi"];

    // A folder is reviewed only with a package manifest at its root: the review reads every file in it.
    private static readonly string[] FolderManifests = ["package.json", "pyproject.toml", "setup.py", "manifest.json", "composer.json"];

    // Gem and NuGet manifests are named for their package.
    private static readonly string[] FolderManifestPatterns = ["*.gemspec", "*.nuspec"];

    /// <summary>Adds package review changes and a policy note when both paths are packages; returns the comparison unchanged otherwise.</summary>
    private static (FolderCompare.Comparison Comparison, string? Partial) WithPackageChanges(FolderCompare.Comparison comparison, string oldPath, string newPath, CancellationToken ct)
    {
        static bool Package(string p) => File.Exists(p) && PackageExtensions.Any(e => p.EndsWith(e, StringComparison.OrdinalIgnoreCase))
                                         || Directory.Exists(p) && (FolderManifests.Any(m => File.Exists(Path.Combine(p, m)))
                                                                    || FolderManifestPatterns.Any(m => Directory.EnumerateFiles(p, m).Any()));
        Services.Web.Packages.PackageReport old, @new;
        if (Package(oldPath) && Package(newPath))
        {
            if (Services.Web.Packages.PackageReview.Review(oldPath, ct, hosts: true) is not { Ecosystem: not "repository" } o
                || Services.Web.Packages.PackageReview.Review(newPath, ct, hosts: true) is not { Ecosystem: not "repository" } n) return (comparison, null);
            (old, @new) = (o, n);
        }
        else if (Directory.Exists(oldPath) && Directory.Exists(newPath) && !Package(oldPath) && !Package(newPath))
        {
            // Two source trees: the agent configuration of each, so a changed MCP server entry or hook is listed.
            var o = Services.Web.Packages.PackageReview.ReviewAgentFolder(oldPath, ct);
            var n = Services.Web.Packages.PackageReview.ReviewAgentFolder(newPath, ct);
            if (o == null && n == null) return (comparison, null);
            old = o ?? Services.Web.Packages.PackageReview.EmptyAgentReport;
            @new = n ?? Services.Web.Packages.PackageReview.EmptyAgentReport;
        }
        else return (comparison, null);
        var findings = CapabilityChanges.Of(old, @new);
        var (facts, summary) = CapabilityChanges.Policy(old, @new, findings);
        // Behaviours of each changed code file need the malcontent pack; without it there are none.
        var (behaviours, behaviourNotes) = Package(oldPath) && Package(newPath)
            ? Services.Web.Packages.PackageBehaviours.Between(Services.Web.Packages.PackageFiles.Open(oldPath, ct)!, Services.Web.Packages.PackageFiles.Open(newPath, ct)!, ct)
            : ([], []);
        var rows = findings.Concat(facts).Concat(behaviours).ToList();
        return (comparison with
        {
            Changes = rows,
            Notes = [summary, .. behaviourNotes, .. comparison.Notes, $"package review: {findings.Count(r => r.Kind == "added")} finding(s) added, {findings.Count(r => r.Kind == "removed")} removed, " +
                $"{facts.Count} policy fact(s) changed; Changes lists them", .. rows.Take(MaxPackageRows).Select(r => $"{r.Kind} {r.Key}" + ((r.New ?? r.Old) is { } at ? $": {at}" : ""))],
        }, old.Partial ?? @new.Partial);
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
