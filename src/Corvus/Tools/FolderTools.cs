using System.ComponentModel;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;
using Corvus.Services.Analysis;

namespace Corvus.Tools;

[McpServerToolType]
public sealed class FolderTools(FolderCompare folders)
{
    [McpServerTool(Name = "compare_folders", Title = "Compare two folders or packages", UseStructuredContent = true)]
    [Description("Two folders, zip-family archives (by central-directory CRC) or files, per entry: modified, added, removed, " +
                 "moved, case-only renames, links (not followed), unreadable files; an incomplete side is never called unchanged. Changed " +
                 "binaries: MVID, version, machine, timestamp, next call; text: a diff.")]
    public Task<FolderCompare.Comparison> CompareFolders(
        [Description("Old folder, archive or file.")] string oldPath,
        [Description("New folder, archive or file.")] string newPath,
        [Description("Entries listed.")] string change = "changed",
        [Description("Globs to skip, ;-separated.")] string? exclude = null,
        [Description("Default false on Windows, macOS.")] bool? caseSensitive = null,
        [Description("Per side; past it, incomplete.")] int maxEntries = FolderCompare.DefaultMaxEntries,
        int offset = 0,
        int limit = FolderCompare.DefaultLimit,
        RequestContext<CallToolRequestParams> context = null!,
        CancellationToken cancellationToken = default) => OrderedProgress.Run(context, progress =>
        Task.Run(() => folders.Compare(oldPath, newPath, change, caseSensitive, exclude, maxEntries, offset, limit,
            (done, total) => progress.Report(new ProgressNotificationValue { Progress = done, Total = total, Message = $"{done} of {total} files hashed" }),
            cancellationToken), cancellationToken));
}
