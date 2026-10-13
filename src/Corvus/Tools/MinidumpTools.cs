using System.ComponentModel;
using ModelContextProtocol.Server;
using Corvus.Core;
using Corvus.Mcp;
using Corvus.Native.Dump.Managed;
using Corvus.Services;

namespace Corvus.Tools;

/// <summary>Windows crash dumps (minidumps): summary, stack walks, captured memory.</summary>
[McpServerToolType]
public sealed class MinidumpTools(MinidumpService dumps)
{
    private const string DumpDescription = "A .dmp path or the id open_minidump returned.";
    private const string ImageDirectoriesDescription =
        "Folders (';'-separated) with the program's binaries, for modules not at their recorded path; kept for the dump. Its own folder is always searched.";

    [McpServerTool(Name = "open_minidump", Title = "Open a crash dump", UseStructuredContent = true, OutputSchemaType = typeof(MinidumpService.DumpReport))]
    [Description("Reads a Windows minidump (.dmp). view=summary: OS, process, the exception (faulting thread, module!function, instruction, registers, " +
                 "a C++ exception's thrown type), faulting module and thread, the .NET state (managed exception with stack and inner chain, heap), " +
                 "counts. modules (version, PDB, whether a matching image is here), threads, memory, unloaded: paged rows. Gives the id the other " +
                 "dump tools take. Nothing from the dump runs; .NET decoding loads Microsoft's signature-checked DAC for that runtime build.")]
    public Task<string> OpenMinidump(
        [Description("The .dmp path (or an open dump's id).")] string path,
        [Description("summary, modules, threads, memory or unloaded.")] string view = "summary",
        [Description(ToolSupport.RowOffsetDescription)] int offset = 0,
        [Description(ToolSupport.LimitDescription)] int limit = MinidumpService.DefaultListLimit,
        [Description(ImageDirectoriesDescription)] string? imageDirectories = null,
        [Description("The dumped runtime's DAC (mscordaccore.dll / mscordacwks.dll) or its folder, when that runtime build is not installed here.")] string? dacPath = null,
        [Description("Download the DAC from a symbol server when no local copy matches (network; refused under CORVUS_OFFLINE=1).")] bool downloadDac = false,
        [Description(ToolSupport.MaxTokensDescription)] int? maxTokens = null,
        CancellationToken cancellationToken = default) => Task.Run(async () =>
    {
        var v = (view ?? "summary").Trim().ToLowerInvariant();
        switch (v)
        {
            case "summary":
                var report = await dumps.Summarize(path, imageDirectories, new DacRequest(string.IsNullOrWhiteSpace(dacPath) ? null : dacPath, downloadDac), cancellationToken);
                return ToolOutput.Report(DumpText.Summary(report), report);
            case "modules":
                var (mId, modules, mTotal) = dumps.Modules(path, imageDirectories, offset, limit);
                return Rows(mId, v, modules, offset, limit, mTotal, DumpText.Module, "module");
            case "threads":
                var (tId, threads, tTotal) = await dumps.Threads(path, imageDirectories, offset, limit, cancellationToken);
                return Rows(tId, v, threads, offset, limit, tTotal, DumpText.Thread, "thread");
            case "memory":
                var (rId, memory, rTotal) = dumps.Memory(path, offset, limit);
                return Rows(rId, v, memory, offset, limit, rTotal, DumpText.Memory, "region");
            case "unloaded":
                var (uId, unloaded, uTotal) = dumps.Unloaded(path, offset, limit);
                return Rows(uId, v, unloaded, offset, limit, uTotal, u => $"{u.Base}  {u.Name}  size {u.Size}  stamp {u.TimeDateStamp}", "unloaded module");
            default:
                throw new ToolError(ErrorCode.InvalidArgument, $"Unknown view '{view}'.", "pass view as one of " + string.Join(", ", MinidumpService.Views));
        }
    }, cancellationToken);

    private static string Rows<T>(string id, string view, IReadOnlyList<T> rows, int offset, int limit, int total, Func<T, string> render, string noun) where T : notnull =>
        ToolOutput.List(rows, offset, limit, total, render,
            page => new MinidumpService.DumpReport(id, view) { Items = page.Cast<object>().ToList(), Offset = offset, Total = total }, noun);

    [McpServerTool(Name = "dump_stack", Title = "Crash dump stack", UseStructuredContent = true, OutputSchemaType = typeof(MinidumpService.StackReport))]
    [Description("Call stack of a minidump thread: x64 unwind data, x86 call targets and the EBP chain; JIT code without unwind data adds " +
                 "scanned frames (basis inferred). Names from loaded images (code index, PDB, Il2Cpp) or exports. .NET frames (DAC): token, IL " +
                 "offset, assembly, C# statement; Mono JIT frames from the runtime's report beside the dump.")]
    public Task<string> DumpStack(
        [Description(DumpDescription)] string dump,
        [Description("Thread id, '#index', name or 'exception'. Default: the faulting thread, else the first.")] string? thread = null,
        [Description("Faulting thread: start at the exception context (.ecxr); false: its context at dump time.")] bool exceptionContext = true,
        [Description("Max frames walked (up to 1024).")] int maxFrames = 256,
        [Description(ToolSupport.RowOffsetDescription)] int offset = 0,
        [Description(ToolSupport.LimitDescription)] int limit = 100,
        [Description(ImageDirectoriesDescription)] string? imageDirectories = null,
        [Description("auto: .NET frames through the DAC; off: native walk only.")] string? managed = "auto",
        [Description(ToolSupport.MaxTokensDescription)] int? maxTokens = null,
        CancellationToken cancellationToken = default) => Task.Run(async () =>
    {
        var r = await dumps.Stack(dump, thread, exceptionContext, maxFrames, offset, limit, imageDirectories,
            !string.Equals(managed?.Trim(), "off", StringComparison.OrdinalIgnoreCase), cancellationToken);
        var header = $"{r.Dump} thread {r.ThreadId}{(r.ThreadName != null ? $" \"{r.ThreadName}\"" : "")}, {r.Architecture}, from the {r.Context} context; walk ended: {r.Stop}" +
                     (r.ScannedFrames > 0 ? $"; {r.ScannedFrames} scanned" : "") + (r.Managed != null ? $"; managed frames: {r.Managed}" : "") + "\n" +
                     (r.Registers != null ? $"registers: {r.Registers}\n" : "") + string.Concat(r.Notes.Select(n => $"note: {n}\n"));
        return ToolOutput.List(r.Items, r.Offset, limit, r.Total, DumpText.Frame, page => r with { Items = page }, "frame", header);
    }, cancellationToken);

    [McpServerTool(Name = "dump_heap", Title = "Crash dump .NET heap", UseStructuredContent = true, OutputSchemaType = typeof(MinidumpService.HeapReport))]
    [Description("Lists the .NET GC heap of a minidump (through the DAC). stats: count and size per type, largest first; objects: matching objects " +
                 "(address, type, size, a string's value). Needs heap memory in the dump (else heap_not_captured).")]
    public Task<string> DumpHeap(
        [Description(DumpDescription)] string dump,
        [Description("stats (per type) or objects (one row each).")] string? mode = "stats",
        [Description("Type full name, '*' / '?' wildcards; default all.")] string? type = null,
        [Description("Only objects of at least this many bytes.")] long minSize = 0,
        [Description(ToolSupport.RowOffsetDescription)] int offset = 0,
        [Description(ToolSupport.LimitDescription)] int limit = MinidumpService.DefaultListLimit,
        [Description("Max objects walked.")] long maxObjects = MinidumpService.DefaultMaxHeapObjects,
        [Description(ToolSupport.MaxTokensDescription)] int? maxTokens = null,
        CancellationToken cancellationToken = default) => Task.Run(async () =>
    {
        var r = await dumps.Heap(dump, mode, type, (ulong)Math.Max(0, minSize), offset, limit, maxObjects, cancellationToken);
        var header = $"{r.Dump}: {r.Walked:N0} objects walked, {r.MatchedBytes:N0} bytes matching{(r.Type != null ? $" type {r.Type}" : "")}{(r.MinSize > 0 ? $" of at least {r.MinSize} bytes" : "")}\n" +
                     string.Concat(r.Notes.Select(n => $"note: {n}\n"));
        return ToolOutput.List(r.Items, r.Offset, limit, r.Total, DumpText.HeapRow, page => r with { Items = page }, r.Mode == "stats" ? "type" : "object", header, r.TotalExact);
    }, cancellationToken);

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
