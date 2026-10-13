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
    [Description("Compare two folders, zip-family archives or files per entry: modified, added, removed, moved, case-only renames, links, unreadable; " +
                 "changed binaries with MVID and version, text with a diff.")]
    public Task<FolderCompare.Comparison> CompareFolders(
        [Description("Old folder, archive or file.")] string oldPath,
        [Description("New folder, archive or file.")] string newPath,
        [Description("Entries listed.")] string change = "changed",
        [Description("Globs of paths to skip.")] string[]? exclude = null,
        [Description("Default: false on Windows and macOS, true elsewhere.")] bool? caseSensitive = null,
        [Description("Per side; past it, incomplete.")] int maxEntries = FolderCompare.DefaultMaxEntries,
        [Description(ToolSupport.RowOffsetDescription)] int offset = 0,
        [Description("Max entries per page.")] int limit = FolderCompare.DefaultLimit,
        RequestContext<CallToolRequestParams> context = null!,
        CancellationToken cancellationToken = default) => OrderedProgress.Run(context, progress =>
        Task.Run(() => folders.Compare(oldPath, newPath, change, caseSensitive, exclude is { Length: > 0 } ? string.Join(";", exclude) : null, maxEntries, offset, limit,
            (done, total) => progress.Report(new ProgressNotificationValue { Progress = done, Total = total, Message = $"{done} of {total} files hashed" }),
            cancellationToken), cancellationToken));
}
