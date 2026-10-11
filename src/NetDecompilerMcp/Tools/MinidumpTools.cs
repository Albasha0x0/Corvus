using System.ComponentModel;
using ModelContextProtocol.Server;
using NetDecompilerMcp.Native.Dump.Managed;
using NetDecompilerMcp.Services;

namespace NetDecompilerMcp.Tools;

/// <summary>Windows crash dumps (minidumps): summary, stack walks, captured memory.</summary>
[McpServerToolType]
public sealed class MinidumpTools(MinidumpService dumps)
{
    private const string DumpDescription = "A minidump: the path of a .dmp file, or the id open_minidump returned (its file name).";
    private const string ImageDirectoriesDescription =
        "Folders with the crashed program's binaries (';'-separated), searched by file name when a module's recorded path is not on this machine " +
        "or holds another build. The dump's own folder is always searched.";

    [McpServerTool(Name = "open_minidump", Title = "Open a crash dump", UseStructuredContent = true)]
    [Description("Summary of a Windows minidump (.dmp): OS and CPU, process (id, times, integrity, WoW64, managed runtime), the exception (code and name, " +
                 "e.g. EXCEPTION_ACCESS_VIOLATION writing 0x0, the faulting thread, module+offset and function, the faulting instruction disassembled from " +
                 "dump memory or the module image, registers, the thrown type of a C++ exception), the .NET state (managed exception with stack and inner " +
                 "chain, threads, heap state), modules (path, base, size, timestamp, checksum, version, " +
                 "PDB name/GUID/age, and whether a matching image file exists on this machine), threads (ids, names, stack ranges, where each one is), " +
                 "unloaded modules, captured memory, handle counts by type, and what the parser could not read. Modules and threads are paged. " +
                 "The dump gets an id for the other dump tools. The dumped program is not run; .NET decoding loads Microsoft's signature-checked " +
                 "debugging library (DAC) for that runtime build, never code from the dump.")]
    public Task<MinidumpService.DumpSummary> OpenMinidump(
        [Description("Path of the .dmp file (or the id of an open dump).")] string path,
        [Description(ImageDirectoriesDescription)] string? imageDirectories = null,
        [Description("Index of the first module listed.")] int modulesOffset = 0,
        [Description("Max modules listed (default 50).")] int modulesLimit = MinidumpService.DefaultListLimit,
        [Description("Index of the first thread listed.")] int threadsOffset = 0,
        [Description("Max threads listed (default 50).")] int threadsLimit = MinidumpService.DefaultListLimit,
        [Description("The dumped runtime's DAC (mscordaccore.dll / mscordacwks.dll) or its folder, when the same runtime build is not installed here.")] string? dacPath = null,
        [Description("Download the DAC from the symbol server (_NT_SYMBOL_PATH's, else Microsoft's) when no local copy matches; refused under NDM_OFFLINE=1.")] bool downloadDac = false,
        CancellationToken cancellationToken = default) =>
        Task.Run(() => dumps.Summarize(path, imageDirectories, modulesOffset, modulesLimit, threadsOffset, threadsLimit,
            new DacRequest(string.IsNullOrWhiteSpace(dacPath) ? null : dacPath, downloadDac), cancellationToken), cancellationToken);

    [McpServerTool(Name = "dump_stack", Title = "Crash dump stack", UseStructuredContent = true)]
    [Description("Call stack of a thread in a minidump. x64: virtual unwind with the modules' .pdata unwind data (from the matching image file on disk, " +
                 "or the image in dump memory); x86: the EBP chain. Where unwind data is missing (JIT code, no image) the stack is scanned for return " +
                 "addresses and those frames are marked heuristic. Frames are named from a loaded native image's code index (user, PDB, Il2Cpp, discovered " +
                 "names), Il2Cpp dummy DLLs for GameAssembly.dll, a matching local PDB, or exports (nearest_export is a guess). .NET frames come from the " +
                 "runtime's own walk (DAC), merged by stack pointer, with token, IL offset and the loaded assembly of that build (by MVID). The faulting thread uses the exception context, like .ecxr.")]
    public Task<MinidumpService.StackReport> DumpStack(
        [Description(DumpDescription)] string dump,
        [Description("Thread id (decimal or 0x hex), '#index', a thread name, or 'exception'. Default: the faulting thread, else the first thread.")] string? thread = null,
        [Description("For the faulting thread, start from the context at the exception (true) or from the thread's context when the dump was written (false).")] bool exceptionContext = true,
        [Description("Max frames walked (default 256, up to 1024).")] int maxFrames = 256,
        [Description("Index of the first frame returned.")] int offset = 0,
        [Description("Max frames returned (default 100).")] int limit = 100,
        [Description(ImageDirectoriesDescription)] string? imageDirectories = null,
        [Description("auto: decode .NET frames through a local DAC (or the one open_minidump loaded); off: native walk only.")] string? managed = "auto",
        CancellationToken cancellationToken = default) =>
        Task.Run(() => dumps.Stack(dump, thread, exceptionContext, maxFrames, offset, limit, imageDirectories,
            !string.Equals(managed?.Trim(), "off", StringComparison.OrdinalIgnoreCase), cancellationToken), cancellationToken);

    [McpServerTool(Name = "dump_heap", Title = "Crash dump .NET heap", UseStructuredContent = true)]
    [Description("The .NET GC heap of a minidump (through the runtime's DAC). stats: count and size per type, largest first, with the loaded " +
                 "assembly and type token of that build; objects: matching objects (address, type, size, a string's value). Needs heap memory in the " +
                 "dump (else heap_not_captured). Bounded by maxObjects.")]
    public Task<MinidumpService.HeapReport> DumpHeap(
        [Description(DumpDescription)] string dump,
        [Description("stats (per type) or objects (one row per object).")] string? mode = "stats",
        [Description("Type full name, with '*' / '?' wildcards (System.Collections.Generic.List*); default all.")] string? type = null,
        [Description("Only objects of at least this many bytes.")] long minSize = 0,
        [Description("Index of the first row returned.")] int offset = 0,
        [Description("Max rows returned (default 50, up to 1000).")] int limit = MinidumpService.DefaultListLimit,
        [Description("Max objects walked (default 5,000,000).")] long maxObjects = MinidumpService.DefaultMaxHeapObjects,
        CancellationToken cancellationToken = default) =>
        Task.Run(() => dumps.Heap(dump, mode, type, (ulong)Math.Max(0, minSize), offset, limit, maxObjects, cancellationToken), cancellationToken);

    [McpServerTool(Name = "dump_object", Title = "Crash dump .NET object", UseStructuredContent = true)]
    [Description("One .NET object of a minidump (through the runtime's DAC): type, size, fields (references expanded depth levels, structs " +
                 "inline), a string's or boxed value, or array elements, with the type's loaded assembly and token.")]
    public Task<MinidumpService.ObjectReport> DumpObject(
        [Description(DumpDescription)] string dump,
        [Description("Hex address of the object.")] string address,
        [Description("Levels of referenced objects expanded (default 1, up to 3).")] int depth = 1,
        [Description("Max fields listed, nested ones included (default 100).")] int maxFields = 100,
        [Description("Max array elements listed (default 32).")] int maxArrayItems = 32,
        CancellationToken cancellationToken = default) =>
        Task.Run(() => dumps.Object(dump, address, depth, maxFields, maxArrayItems, cancellationToken), cancellationToken);

    [McpServerTool(Name = "read_dump_memory", Title = "Read crash dump memory", UseStructuredContent = true)]
    [Description("Hex dump of the dumped process's memory at an address: the bytes the dump captured, with what is there (module!function, " +
                 "captured range, page protection). Bytes the dump does not hold are read from the module image when imageFallback is true (code and " +
                 "read-only data match; writable data shows initial values), and the source is reported.")]
    public Task<MinidumpService.MemoryRead> ReadDumpMemory(
        [Description(DumpDescription)] string dump,
        [Description("Address: hex (0x7FF6A1B21000), 'module+0x1234', or a module name for its base.")] string address,
        [Description("Bytes to read (default 256, up to 65536).")] int length = 256,
        [Description("Read bytes the dump does not hold from the module image.")] bool imageFallback = true,
        CancellationToken cancellationToken = default) =>
        Task.Run(() => dumps.ReadMemory(dump, address, length, imageFallback, cancellationToken), cancellationToken);
}
