using System.ComponentModel;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;
using Corvus.Core;
using Corvus.Services.Analysis;

namespace Corvus.Tools;

[McpServerToolType]
public sealed class FolderTools(FolderCompare folders)
{
    [McpServerTool(Name = "compare_folders", Title = "Compare two folders or packages", UseStructuredContent = true)]
    [Description("Compare two folders, zip-family archives or files per entry: modified, added, removed, moved, case-only renames, links, unreadable; " +
                 "changed binaries with MVID and version, text with a diff. oldResult / newResult compare two kept results instead.")]
    public Task<FolderCompare.Comparison> CompareFolders(
        [Description("Old folder, archive or file.")] string? oldPath = null,
        [Description("New folder, archive or file.")] string? newPath = null,
        [Description("Entries listed.")] string change = "changed",
        [Description("Globs of paths to skip.")] string[]? exclude = null,
        [Description("Default: false on Windows and macOS, true elsewhere.")] bool? caseSensitive = null,
        [Description("Per side; past it, incomplete.")] int maxEntries = FolderCompare.DefaultMaxEntries,
        [Description(ToolSupport.RowOffsetDescription)] int offset = 0,
        [Description("Max entries per page.")] int limit = FolderCompare.DefaultLimit,
        [Description(NativeDiffTools.OldResultDescription)] string? oldResult = null,
        [Description(NativeDiffTools.NewResultDescription)] string? newResult = null,
        RequestContext<CallToolRequestParams> context = null!,
        CancellationToken cancellationToken = default) => OrderedProgress.Run(context, progress =>
        EvidenceInput.FromArguments(oldResult, newResult, oldPath != null || newPath != null, "oldPath and newPath", context?.Services) is var (ev, changes)
            ? Task.FromResult(Evidence(ev, changes, offset, limit))
            : string.IsNullOrWhiteSpace(oldPath) || string.IsNullOrWhiteSpace(newPath)
                ? throw new ToolError(ErrorCode.InvalidArgument, $"{(string.IsNullOrWhiteSpace(oldPath) ? "oldPath" : "newPath")} is missing: compare_folders takes both paths.",
                    "pass oldPath and newPath, or oldResult and newResult")
            : Task.Run(() => folders.Compare(oldPath, newPath, change, caseSensitive, exclude is { Length: > 0 } ? string.Join(";", exclude) : null, maxEntries, offset, limit,
            (done, total) => progress.Report(new ProgressNotificationValue { Progress = done, Total = total, Message = $"{done} of {total} files hashed" }),
            cancellationToken), cancellationToken));

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
