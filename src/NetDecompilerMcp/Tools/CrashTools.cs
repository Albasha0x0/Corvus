using System.ComponentModel;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;
using NetDecompilerMcp.Services;

namespace NetDecompilerMcp.Tools;

/// <summary>Crash analysis beyond one dump: crash text without a dump, and folders of dumps grouped by signature.</summary>
[McpServerToolType]
public sealed class CrashTools(StackTextService stacks, MinidumpService dumps)
{
    [McpServerTool(Name = "symbolize_stack_text", Title = "Symbolize crash text", UseStructuredContent = true)]
    [Description("Resolves crash text against the loaded build: Unity Player.log / error.log backtraces (module list gives load addresses), " +
                 "Mono frames (by module MVID), Il2Cpp/Unity managed lines, .NET exception text (inner chain, NativeAOT), Report.wer, Event Log " +
                 "1000/1026 text, debugger stacks and Android tombstones. Each frame gets our name, a buildCheck (time stamp, MVID, BuildId or the " +
                 "text's own name) and the C# statement at an IL offset; unloaded modules are listed.")]
    public Task<StackTextService.SymbolizedStack> SymbolizeStackText(
        [Description("The crash text (up to 1 MiB). Pass this or path.")] string? text = null,
        [Description("A log or report file (Player.log, error.log, Report.wer, saved event text); its last 8 MiB are read.")] string? path = null,
        [Description("Text format; auto detects it.")] string? format = "auto",
        [Description("Native image ids or paths to resolve against (';'-separated); default every loaded native image.")] string? images = null,
        [Description("Module load addresses for absolute addresses, 'name=0xBASE;...' (the crash's module list in the text is used too).")] string? moduleBases = null,
        [Description("Index of the first frame returned.")] int offset = 0,
        [Description("Max frames returned (default 200).")] int limit = StackTextService.DefaultLimit,
        CancellationToken cancellationToken = default) =>
        Task.Run(() => stacks.Symbolize(text, path, format, images, moduleBases, offset, limit, cancellationToken), cancellationToken);

    [McpServerTool(Name = "bucket_minidumps", Title = "Group crash dumps", UseStructuredContent = true)]
    [Description("Groups a folder of minidumps by signature: exception code | faulting module!function | next frames (raising frames such as " +
                 "RaiseException and _CxxThrowException skipped); .NET: clr | exception type | top managed frames; no exception: hang | top frames. " +
                 "Function names, so rebases and offsets do not split a bucket; offsets and module versions are counted. Each bucket has dump ids " +
                 "and its newest dump as representative. Cached per file, so re-runs parse only new dumps.")]
    public Task<MinidumpService.DumpBuckets> BucketMinidumps(
        [Description("Folder with the .dmp files.")] string folder,
        [Description("Also search subfolders.")] bool recursive = false,
        [Description("File patterns, ';'-separated (default *.dmp;*.mdmp).")] string? pattern = null,
        [Description("Frames after the faulting one in the signature (default 3).")] int topFrames = 3,
        [Description("More frames to skip, ';'-separated: a module (ucrtbase) or module!function, '*' wildcards.")] string? skipModules = null,
        [Description("Put the faulting module's version in the signature.")] bool splitByVersion = false,
        [Description("auto: CLR exceptions get managed signatures when a local DAC is found; off: native frames only.")] string? managed = "auto",
        [Description("Most dumps bucketed, newest first (default 1000).")] int maxDumps = MinidumpService.DefaultMaxDumps,
        [Description("Folders with the crashed program's binaries (';'-separated), for module images not at their recorded paths.")] string? imageDirectories = null,
        [Description("Index of the first bucket returned.")] int offset = 0,
        [Description("Max buckets returned (default 50).")] int limit = MinidumpService.DefaultListLimit,
        RequestContext<CallToolRequestParams> context = null!,
        CancellationToken cancellationToken = default) => OrderedProgress.Run(context, progress =>
        Task.Run(() => dumps.Bucket(folder, recursive, pattern, topFrames, skipModules, splitByVersion,
            !string.Equals(managed?.Trim(), "off", StringComparison.OrdinalIgnoreCase), maxDumps, imageDirectories, offset, limit,
            (done, total) => progress.Report(new ProgressNotificationValue { Progress = done, Total = total, Message = $"{done} of {total} dumps" }),
            cancellationToken), cancellationToken));
}
