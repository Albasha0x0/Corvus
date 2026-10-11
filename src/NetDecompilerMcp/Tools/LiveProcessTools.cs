using System.ComponentModel;
using ModelContextProtocol.Server;
using NetDecompilerMcp.Services;

namespace NetDecompilerMcp.Tools;

/// <summary>Read-only inspection of a running local process.</summary>
[McpServerToolType]
public sealed class LiveProcessTools(LiveProcessService live)
{
    [McpServerTool(Name = "inspect_process", Title = "Inspect a running process (read-only)", UseStructuredContent = true)]
    [Description("A running local process (Windows), as open_minidump / dump_stack show a dump: modules (PDB, matching file on disk), memory " +
                 "regions (VirtualQuery view, paged and filtered), threads (TEB, stack range, start address, registers) and their call stacks, every " +
                 "address named as dump_stack names it. Read-only: opened with PROCESS_QUERY_INFORMATION | PROCESS_VM_READ and THREAD_GET_CONTEXT | " +
                 "THREAD_QUERY_INFORMATION only; nothing is written, suspended or attached, and every handle is closed before returning. Threads keep " +
                 "running, so registers are a snapshot.")]
    public Task<LiveProcessService.LiveReport> InspectProcess(
        [Description("Process id (decimal or 0x hex) or name (notepad or notepad.exe); a shared name is refused with the candidate ids.")] string process,
        [Description("Comma-separated: modules, regions, threads, stacks (implies threads) or all (default).")] string? sections = null,
        [Description("Only this thread: id or name.")] string? thread = null,
        [Description("First module listed.")] int modulesOffset = 0,
        [Description("Max modules listed.")] int modulesLimit = LiveProcessService.DefaultModules,
        [Description("First region listed (after regionFilter).")] int regionsOffset = 0,
        [Description("Max regions listed.")] int regionsLimit = LiveProcessService.DefaultRegions,
        [Description("Regions listed (default committed; all adds reserved and free).")] string? regionFilter = null,
        [Description("First thread listed.")] int threadsOffset = 0,
        [Description("Max threads listed.")] int threadsLimit = LiveProcessService.DefaultThreads,
        [Description("Max frames walked per thread (up to 256).")] int maxFrames = LiveProcessService.DefaultFrames,
        [Description("Folders with the program's binaries (';'-separated) for modules whose own file is not readable.")] string? imageDirectories = null,
        [Description("Time limit in seconds (up to 120).")] int timeoutSeconds = LiveProcessService.DefaultTimeoutSeconds,
        CancellationToken cancellationToken = default) =>
        live.Inspect(process, sections, thread, modulesOffset, modulesLimit, regionsOffset, regionsLimit, regionFilter, threadsOffset, threadsLimit, maxFrames,
            imageDirectories, timeoutSeconds, cancellationToken);
}
