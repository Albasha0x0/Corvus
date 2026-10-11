using System.ComponentModel;
using ModelContextProtocol.Server;
using NetDecompilerMcp.Services;

namespace NetDecompilerMcp.Tools;

/// <summary>Read-only inspection of a running local process.</summary>
[McpServerToolType]
public sealed class LiveProcessTools(LiveProcessService live)
{
    [McpServerTool(Name = "inspect_process", Title = "Inspect a running process (read-only)", UseStructuredContent = true)]
    [Description("Read-only look at a running local process (Windows): modules (path, base, size, timestamp, PDB, whether a matching file is on disk), " +
                 "memory regions (VirtualQuery view: state, protection, type, owning module; paged and filtered), threads (id, name, suspend count, " +
                 "priority, TEB, stack range, start address, registers, where each one is) and their call stacks (x64 unwind data / x86 call targets / EBP, " +
                 "scan frames marked heuristic), every address named as dump_stack names it: a loaded image's code index (user renames, PDB, Il2Cpp, " +
                 "discovered names), Il2Cpp dummy DLLs, a matching local PDB, or exports. Strictly read-only: the process is opened with " +
                 "PROCESS_QUERY_INFORMATION | PROCESS_VM_READ only, each thread briefly with THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION; no memory " +
                 "write, no breakpoint, no debugger attach, no thread suspension or injection; all handles are closed before the call returns " +
                 "(also on error, cancellation or timeout). Threads keep running, so a running thread's registers are a snapshot.")]
    public Task<LiveProcessService.LiveReport> InspectProcess(
        [Description("Process id (decimal or 0x hex) or process name (notepad or notepad.exe); a name shared by several processes is reported with their ids.")] string process,
        [Description("Comma-separated parts to report: modules, regions, threads, stacks (stacks implies threads), or all (default).")] string? sections = null,
        [Description("Only this thread: id (decimal or 0x hex) or thread name.")] string? thread = null,
        [Description("Index of the first module listed.")] int modulesOffset = 0,
        [Description("Max modules listed (default 50).")] int modulesLimit = LiveProcessService.DefaultModules,
        [Description("Index of the first region listed (after regionFilter).")] int regionsOffset = 0,
        [Description("Max regions listed (default 100).")] int regionsLimit = LiveProcessService.DefaultRegions,
        [Description("Regions listed: committed (default), all (with reserved and free), executable, writable, image, private or mapped.")] string? regionFilter = null,
        [Description("Index of the first thread listed.")] int threadsOffset = 0,
        [Description("Max threads listed (default 20).")] int threadsLimit = LiveProcessService.DefaultThreads,
        [Description("Max frames walked per thread (default 32, up to 256).")] int maxFrames = LiveProcessService.DefaultFrames,
        [Description("Folders with the program's binaries (';'-separated), searched by file name when a module's own file is not readable; the executable's folder is always searched.")] string? imageDirectories = null,
        [Description("Time limit in seconds (default 20, up to 120); on expiry every handle is closed and a timeout error is returned.")] int timeoutSeconds = LiveProcessService.DefaultTimeoutSeconds,
        CancellationToken cancellationToken = default) =>
        live.Inspect(process, sections, thread, modulesOffset, modulesLimit, regionsOffset, regionsLimit, regionFilter, threadsOffset, threadsLimit, maxFrames,
            imageDirectories, timeoutSeconds, cancellationToken);
}
