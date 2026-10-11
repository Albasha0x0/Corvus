using System.ComponentModel;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;
using Corvus.Services;

namespace Corvus.Tools;

/// <summary>Crash analysis beyond one dump: crash text without a dump, and folders of dumps grouped by signature.</summary>
[McpServerToolType]
public sealed class CrashTools(StackTextService stacks, MinidumpService dumps)
{
    [McpServerTool(Name = "symbolize_stack_text", Title = "Symbolize crash text", UseStructuredContent = true)]
    [Description("Resolves crash text against the loaded build: Unity Player.log / error.log backtraces, Mono and Il2Cpp managed lines, .NET " +
                 "exception text, Report.wer, Event Log 1000/1026 text, debugger stacks and Android tombstones. Each frame gets our name, a buildCheck " +
                 "(time stamp, MVID, BuildId or the text's own name; a mismatch means another build) and the C# statement at an IL offset.")]
    public Task<StackTextService.SymbolizedStack> SymbolizeStackText(
        [Description("The crash text (up to 1 MiB). This or path.")] string? text = null,
        [Description("A log or report file; its last 8 MiB are read.")] string? path = null,
        [Description("Text format (auto detects it).")] string? format = "auto",
        [Description("Native image ids or paths (';'-separated); default every loaded one.")] string? images = null,
        [Description("Module load addresses, 'name=0xBASE;...', when the text has no module list.")] string? moduleBases = null,
        [Description("First frame returned.")] int offset = 0,
        [Description("Max frames returned.")] int limit = StackTextService.DefaultLimit,
        CancellationToken cancellationToken = default) =>
        Task.Run(() => stacks.Symbolize(text, path, format, images, moduleBases, offset, limit, cancellationToken), cancellationToken);

    [McpServerTool(Name = "bucket_minidumps", Title = "Group crash dumps", UseStructuredContent = true)]
    [Description("Groups a folder of minidumps by signature: exception code | faulting module!function | next frames (raising frames skipped); " +
                 ".NET: clr | exception type | top managed frames; no exception: hang | top frames. Names, not offsets, so rebases do not split a " +
                 "bucket. Each bucket lists its dump ids and its newest dump as representative. Cached per file: re-runs parse only new dumps.")]
    public Task<MinidumpService.DumpBuckets> BucketMinidumps(
        [Description("Folder of .dmp files.")] string folder,
        [Description("Also search subfolders.")] bool recursive = false,
        [Description("File patterns, ';'-separated (default *.dmp;*.mdmp).")] string? pattern = null,
        [Description("Frames after the faulting one in the signature.")] int topFrames = 3,
        [Description("More frames to skip, ';'-separated: module or module!function, '*' wildcards.")] string? skipModules = null,
        [Description("Put the faulting module's version in the signature.")] bool splitByVersion = false,
        [Description("auto: managed signatures for CLR exceptions when a local DAC is found; off: native only.")] string? managed = "auto",
        [Description("Most dumps bucketed, newest first.")] int maxDumps = MinidumpService.DefaultMaxDumps,
        [Description("Folders with the crashed program's binaries (';'-separated), for modules not at their recorded paths.")] string? imageDirectories = null,
        [Description("First bucket returned.")] int offset = 0,
        [Description("Max buckets returned.")] int limit = MinidumpService.DefaultListLimit,
        RequestContext<CallToolRequestParams> context = null!,
        CancellationToken cancellationToken = default) => OrderedProgress.Run(context, progress =>
        Task.Run(() => dumps.Bucket(folder, recursive, pattern, topFrames, skipModules, splitByVersion,
            !string.Equals(managed?.Trim(), "off", StringComparison.OrdinalIgnoreCase), maxDumps, imageDirectories, offset, limit,
            (done, total) => progress.Report(new ProgressNotificationValue { Progress = done, Total = total, Message = $"{done} of {total} dumps" }),
            cancellationToken), cancellationToken));
}
