using System.ComponentModel;
using ModelContextProtocol;
using ModelContextProtocol.Protocol;
using ModelContextProtocol.Server;
using Corvus.Mcp;
using Corvus.Services;

namespace Corvus.Tools;

/// <summary>Crash analysis beyond one dump: crash text without a dump, and folders of dumps grouped by signature.</summary>
[McpServerToolType]
public sealed class CrashTools(StackTextService stacks, MinidumpService dumps)
{
    [McpServerTool(Name = "symbolize_stack_text", Title = "Symbolize crash text", UseStructuredContent = true, OutputSchemaType = typeof(StackTextService.SymbolizedStack))]
    [Description("Resolves crash text against the loaded build: Unity Player.log / error.log, Mono and Il2Cpp lines, .NET exception text, " +
                 "Report.wer, Event Log 1000/1026, debugger stacks, Android tombstones. Each frame gets our name, a buildCheck (time stamp, MVID, " +
                 "BuildId or the text's name; mismatch: another build) and C# statement at an IL offset.")]
    public Task<string> SymbolizeStackText(
        [Description("The crash text (up to 1 MiB). This or path.")] string? text = null,
        [Description("A log or report file; its last 8 MiB are read.")] string? path = null,
        [Description("Text format (auto detects it).")] string? format = "auto",
        [Description("Native image ids or paths (';'-separated); default all loaded.")] string? images = null,
        [Description("Module load addresses, 'name=0xBASE;...', when the text has no module list.")] string? moduleBases = null,
        [Description(ToolSupport.RowOffsetDescription)] int offset = 0,
        [Description(ToolSupport.LimitDescription)] int limit = StackTextService.DefaultLimit,
        [Description("One row per frame; default folds 3+ matching native frames of an image.")] bool allFrames = false,
        [Description(ToolSupport.MaxTokensDescription)] int? maxTokens = null,
        CancellationToken cancellationToken = default) => Task.Run(async () =>
    {
        var r = await stacks.Symbolize(text, path, format, images, moduleBases, offset, limit, !allFrames, cancellationToken);
        var header = $"format {r.Format}, {ToolSupport.Plural(r.Frames, "frame")}" + (r.UnrecognizedLines > 0 ? $", {r.UnrecognizedLines} unrecognized lines" : "") + "\n";
        if (r.Exception is { } e)
            header += $"exception: {e.Code}{(e.Name != null ? $" ({e.Name})" : "")} {e.Type} {e.Message}".Replace("  ", " ").TrimEnd() + "\n" +
                      string.Concat(e.Inner.Select(i => $"  inner: {i.Type}: {i.Message}\n"));
        header += string.Concat(r.ModulesMissing.Select(m => $"not loaded: {m.Module}{(m.Version != null ? $" {m.Version}" : "")}{(m.TimeDateStamp != null ? $" stamp {m.TimeDateStamp}" : "")} ({ToolSupport.Plural(m.Frames, "frame")})\n"));
        header += string.Concat(r.Notes.Select(n => $"note: {n}\n"));
        if (r.UnrecognizedSample.Count > 0 && r.Frames == 0) header += string.Concat(r.UnrecognizedSample.Select(l => $"unrecognized: {l}\n"));
        return ToolOutput.List(r.Items, r.Offset, limit, r.Total, DumpText.TextFrame, page => r with { Items = page }, "row", header);
    }, cancellationToken);

    [McpServerTool(Name = "bucket_minidumps", Title = "Group crash dumps", UseStructuredContent = true, OutputSchemaType = typeof(MinidumpService.DumpBuckets))]
    [Description("Groups a folder of minidumps by signature: code | faulting module!function | next frames (raising frames skipped); .NET: " +
                 "clr | exception type | top managed frames; no exception: hang | top frames. Names, not offsets, so rebases do not split a bucket. " +
                 "Each bucket names its dumps and newest representative. Cached per file.")]
    public Task<string> BucketMinidumps(
        [Description("Folder of .dmp or core files.")] string folder,
        [Description("Also search subfolders.")] bool recursive = false,
        [Description("File patterns, ';'-separated (default *.dmp;*.mdmp;*.core;core.*).")] string? pattern = null,
        [Description("Frames after the faulting one in the signature.")] int topFrames = 3,
        [Description("More frames to skip, ';'-separated: module or module!function, '*' wildcards.")] string? skipModules = null,
        [Description("Put the faulting module's version in the signature.")] bool splitByVersion = false,
        [Description("auto: managed signatures through a local DAC; off: native only.")] string? managed = "auto",
        [Description("Most dumps bucketed, newest first.")] int maxDumps = MinidumpService.DefaultMaxDumps,
        [Description("Folders (';'-separated) with the program's binaries.")] string? imageDirectories = null,
        [Description(ToolSupport.RowOffsetDescription)] int offset = 0,
        [Description(ToolSupport.LimitDescription)] int limit = MinidumpService.DefaultListLimit,
        [Description(ToolSupport.MaxTokensDescription)] int? maxTokens = null,
        RequestContext<CallToolRequestParams> context = null!,
        CancellationToken cancellationToken = default) => OrderedProgress.Run(context, progress =>
        Task.Run(async () =>
        {
            var r = await dumps.Bucket(folder, recursive, pattern, topFrames, skipModules, splitByVersion,
                !string.Equals(managed?.Trim(), "off", StringComparison.OrdinalIgnoreCase), maxDumps, imageDirectories, offset, limit,
                (done, total) => progress.Report(new ProgressNotificationValue { Progress = done, Total = total, Message = $"{done} of {total} dumps" }),
                cancellationToken);
            var c = r.Dumps;
            var header = $"{r.Folder}: {ToolSupport.Plural(c.Seen, "dump")} ({c.Parsed} parsed, {c.Cached} cached, {c.Failed} failed{(c.LimitReached ? ", maxDumps reached: the newest bucketed" : "")})\n" +
                         string.Concat(r.Failed.Select(f => $"failed: {f.Path}: {f.Reason}\n")) + string.Concat(r.Notes.Select(n => $"note: {n}\n"));
            return ToolOutput.List(r.Items, r.Offset, limit, r.Total, DumpText.Bucket, page => r with { Items = page }, "bucket", header);
        }, cancellationToken));
}
