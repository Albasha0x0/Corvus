using System.ComponentModel;
using ModelContextProtocol.Server;
using NetDecompilerMcp.Native.Dump.Managed;
using NetDecompilerMcp.Services;

namespace NetDecompilerMcp.Tools;

/// <summary>Windows crash dumps (minidumps): summary, stack walks, captured memory.</summary>
[McpServerToolType]
public sealed class MinidumpTools(MinidumpService dumps)
{
    private const string DumpDescription = "A .dmp path or the id open_minidump returned.";
    private const string ImageDirectoriesDescription =
        "Folders with the crashed program's binaries (';'-separated), for modules whose recorded path is missing or holds another build; the dump's folder is always searched.";

    [McpServerTool(Name = "open_minidump", Title = "Open a crash dump", UseStructuredContent = true)]
    [Description("Summary of a Windows minidump (.dmp): OS, CPU, process; the exception (code, faulting thread, module!function, instruction, " +
                 "registers, a C++ exception's thrown type); the .NET state (managed exception with stack and inner chain, threads, heap); modules " +
                 "(version, PDB identity, whether a matching image is here) and threads, paged; unloaded modules, captured memory, parse issues. " +
                 "Gives the id the other dump tools take. Nothing from the dump runs; .NET decoding loads Microsoft's signature-checked DAC for that runtime build.")]
    public Task<MinidumpService.DumpSummary> OpenMinidump(
        [Description("The .dmp path (or an open dump's id).")] string path,
        [Description(ImageDirectoriesDescription)] string? imageDirectories = null,
        [Description("First module listed.")] int modulesOffset = 0,
        [Description("Max modules listed.")] int modulesLimit = MinidumpService.DefaultListLimit,
        [Description("First thread listed.")] int threadsOffset = 0,
        [Description("Max threads listed.")] int threadsLimit = MinidumpService.DefaultListLimit,
        [Description("The dumped runtime's DAC (mscordaccore.dll / mscordacwks.dll) or its folder, when that runtime build is not installed here.")] string? dacPath = null,
        [Description("Download the DAC from a symbol server when no local copy matches (network; refused under NDM_OFFLINE=1).")] bool downloadDac = false,
        CancellationToken cancellationToken = default) =>
        Task.Run(() => dumps.Summarize(path, imageDirectories, modulesOffset, modulesLimit, threadsOffset, threadsLimit,
            new DacRequest(string.IsNullOrWhiteSpace(dacPath) ? null : dacPath, downloadDac), cancellationToken), cancellationToken);

    [McpServerTool(Name = "dump_stack", Title = "Crash dump stack", UseStructuredContent = true)]
    [Description("Call stack of a minidump thread: x64 unwind data, x86 call targets and the EBP chain; JIT code without unwind data adds " +
                 "heuristic scanned frames. Names from loaded images (code index, PDB, Il2Cpp) or exports (nearest_export is a guess). .NET frames " +
                 "come from the DAC with token, IL offset, the loaded assembly and the C# statement; Mono JIT frames from the runtime's report beside the dump.")]
    public Task<MinidumpService.StackReport> DumpStack(
        [Description(DumpDescription)] string dump,
        [Description("Thread id, '#index', name or 'exception'. Default: the faulting thread, else the first.")] string? thread = null,
        [Description("Faulting thread: start at the exception context (.ecxr) or, false, at the thread's context when the dump was written.")] bool exceptionContext = true,
        [Description("Max frames walked (up to 1024).")] int maxFrames = 256,
        [Description("First frame returned.")] int offset = 0,
        [Description("Max frames returned.")] int limit = 100,
        [Description(ImageDirectoriesDescription)] string? imageDirectories = null,
        [Description("auto: .NET frames through a local DAC (or the one open_minidump loaded); off: native walk only.")] string? managed = "auto",
        CancellationToken cancellationToken = default) =>
        Task.Run(() => dumps.Stack(dump, thread, exceptionContext, maxFrames, offset, limit, imageDirectories,
            !string.Equals(managed?.Trim(), "off", StringComparison.OrdinalIgnoreCase), cancellationToken), cancellationToken);

    [McpServerTool(Name = "dump_heap", Title = "Crash dump .NET heap", UseStructuredContent = true)]
    [Description("The .NET GC heap of a minidump (through the DAC). stats: count and size per type, largest first; objects: matching objects " +
                 "(address, type, size, a string's value). Needs heap memory in the dump (else heap_not_captured).")]
    public Task<MinidumpService.HeapReport> DumpHeap(
        [Description(DumpDescription)] string dump,
        [Description("stats (per type) or objects (one row each).")] string? mode = "stats",
        [Description("Type full name, '*' / '?' wildcards; default all.")] string? type = null,
        [Description("Only objects of at least this many bytes.")] long minSize = 0,
        [Description("First row returned.")] int offset = 0,
        [Description("Max rows returned (up to 1000).")] int limit = MinidumpService.DefaultListLimit,
        [Description("Max objects walked.")] long maxObjects = MinidumpService.DefaultMaxHeapObjects,
        CancellationToken cancellationToken = default) =>
        Task.Run(() => dumps.Heap(dump, mode, type, (ulong)Math.Max(0, minSize), offset, limit, maxObjects, cancellationToken), cancellationToken);

    [McpServerTool(Name = "dump_object", Title = "Crash dump .NET object", UseStructuredContent = true)]
    [Description("One .NET object of a minidump (through the DAC): type, size, fields (references expanded depth levels), a string's or " +
                 "boxed value, or array elements.")]
    public Task<MinidumpService.ObjectReport> DumpObject(
        [Description(DumpDescription)] string dump,
        [Description("Hex address of the object.")] string address,
        [Description("Levels of referenced objects expanded (up to 3).")] int depth = 1,
        [Description("Max fields listed, nested ones included.")] int maxFields = 100,
        [Description("Max array elements listed.")] int maxArrayItems = 32,
        CancellationToken cancellationToken = default) =>
        Task.Run(() => dumps.Object(dump, address, depth, maxFields, maxArrayItems, cancellationToken), cancellationToken);

    [McpServerTool(Name = "read_dump_memory", Title = "Read crash dump memory", UseStructuredContent = true)]
    [Description("Hex dump of a dump's memory at an address, with what is there (module!function, captured range, protection). With " +
                 "imageFallback, bytes the dump lacks come from the module image (writable data then shows initial values); the source is reported.")]
    public Task<MinidumpService.MemoryRead> ReadDumpMemory(
        [Description(DumpDescription)] string dump,
        [Description("Hex address, 'module+0x1234', or a module name (its base).")] string address,
        [Description("Bytes to read (up to 65536).")] int length = 256,
        [Description("Read bytes the dump does not hold from the module image.")] bool imageFallback = true,
        CancellationToken cancellationToken = default) =>
        Task.Run(() => dumps.ReadMemory(dump, address, length, imageFallback, cancellationToken), cancellationToken);
}
