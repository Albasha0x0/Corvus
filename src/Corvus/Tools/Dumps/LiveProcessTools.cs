using System.ComponentModel;
using ModelContextProtocol.Server;
using Corvus.Core;
using Corvus.Mcp;
using Corvus.Services;

namespace Corvus.Tools;

/// <summary>Read-only inspection of a running local process.</summary>
[McpServerToolType]
public sealed class LiveProcessTools(LiveProcessService live, LiveSessionService sessions)
{
    [McpServerTool(Name = "inspect_process", Title = "Inspect a running process (read-only)", UseStructuredContent = true, OutputSchemaType = typeof(LiveProcessService.LiveReport))]
    [Description("Inspects a running Windows process read-only, naming addresses as dumps do. view=summary: identity, " +
                 "counts, main module, largest committed regions; modules (PDB, file on disk), regions, threads (TEB, stack, start), stacks " +
                 "(registers and frames): paged rows. Query, VM-read and get-context access only; nothing is written, suspended or connected.")]
    public Task<string> InspectProcess(
        [Description("Process id (decimal or 0x hex), name (notepad[.exe]; a shared name is refused with the ids) or session id (live-1).")] string process,
        [Description("summary, modules, regions, threads or stacks.")] string view = "summary",
        [Description("threads: only this one; stacks: the thread walked (default first). Id or name.")] string? thread = null,
        [Description(ToolSupport.RowOffsetDescription)] int offset = 0,
        [Description(ToolSupport.LimitDescription)] int limit = LiveProcessService.DefaultLimit,
        [Description("regions: committed (default), all, executable, writable, image, private or mapped.")] string? regionFilter = null,
        [Description("view=stacks: max frames walked (up to 256).")] int maxFrames = LiveProcessService.DefaultFrames,
        [Description("Program binary folders (';'-separated), for modules whose file is unreadable.")] string? imageDirectories = null,
        [Description("Time limit in seconds (up to 120).")] int timeoutSeconds = LiveProcessService.DefaultTimeoutSeconds,
        [Description(ToolSupport.MaxTokensDescription)] int? maxTokens = null,
        CancellationToken cancellationToken = default) => Task.Run(async () =>
    {
        if (LiveSessionService.IsSessionId(process))
            process = sessions.Running(process).ProcessId.ToString(System.Globalization.CultureInfo.InvariantCulture);
        var r = await live.Inspect(process, view, thread, offset, limit, regionFilter, maxFrames, imageDirectories, timeoutSeconds, cancellationToken);
        var header = DumpText.LiveHeader(r);
        return r.View switch
        {
            "summary" => ToolOutput.Report(header + DumpText.LiveSummary(r), r),
            "modules" => Rows(r, header, o => DumpText.Module((MinidumpService.ModuleSummary)o), "module", limit),
            "regions" => Rows(r, header, o => DumpText.Memory((MinidumpService.MemoryRow)o), "region", limit),
            "threads" => Rows(r, header, o => DumpText.LiveThread((LiveProcessService.ThreadRow)o), "thread", limit),
            _ => Rows(r, header + (r.Thread is { } t ? "thread: " + DumpText.LiveThread(t) + "\n" : "") + (r.StackStop != null ? $"walk ended: {r.StackStop}\n" : ""),
                o => DumpText.Frame((MinidumpService.StackFrame)o), "frame", limit),
        };
    }, cancellationToken);

    private static string Rows(LiveProcessService.LiveReport r, string header, Func<object, string> render, string noun, int limit) =>
        ToolOutput.List(r.Items!, r.Offset ?? 0, limit, r.Total ?? 0, render, page => r with { Items = page }, noun, header);
}
