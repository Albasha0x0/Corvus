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
                 "dump memory or the module image, registers, the thrown type of a C++ exception), the .NET state (the managed exception with its message, " +
                 "stack and inner exceptions, threads, whether the heap can be walked), modules (path, base, size, timestamp, checksum, version, " +
                 "PDB name/GUID/age, and whether a matching image file exists on this machine), threads (ids, names, stack ranges, where each one is), " +
                 "unloaded modules, captured memory, handle counts by type, and what the parser could not read. Modules and threads are paged. " +
                 "The dump gets an id for dump_stack, dump_heap, dump_object and read_dump_memory. The dumped program is not run; decoding .NET state loads " +
                 "Microsoft's debugging library for that runtime build (its DAC, signature-checked) into this server, never code from the dump.")]
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
                 "runtime's own stack walk through its DAC, merged with the native frames by stack pointer: method, token, IL offset and the loaded assembly " +
                 "that is this build (by MVID), ready for decompile_member. The faulting thread uses the exception context, like .ecxr.")]
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
