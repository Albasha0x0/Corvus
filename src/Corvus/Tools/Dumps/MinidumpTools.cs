using System.ComponentModel;
using ModelContextProtocol.Server;
using Corvus.Core;
using Corvus.Mcp;
using Corvus.Native.Dump.Managed;
using Corvus.Services;

namespace Corvus.Tools;

/// <summary>Windows crash dumps (minidumps): summary, stack walks, captured memory.</summary>
[McpServerToolType]
public sealed class MinidumpTools(MinidumpService dumps, LiveSessionService? sessions = null, ServerOptions? options = null)
{
    private const string DumpDescription = "A .dmp path or the id open_minidump returned.";
    private const string HeapSourceDescription = "A .dmp path, open_minidump's id, or a session id (live-1): its program, read while it runs.";
    private const string ImageDirectoriesDescription =
        "Program binary folders (';'-separated), kept for the dump, plus its own folder.";

    [McpServerTool(Name = "open_minidump", Title = "Open a crash dump", UseStructuredContent = true, OutputSchemaType = typeof(MinidumpService.DumpReport))]
    [Description("Reads a Windows minidump (.dmp) or Linux/Android ELF core; returns the dump id. view=summary: OS, process, exception " +
                 "(thread, module!function, registers, C++ type), .NET state (managed exception and heap); modules (version, " +
                 "PDB, image match), threads, memory, unloaded: paged rows. .NET loads Microsoft's signature-checked DAC.")]
    public Task<string> OpenMinidump(
        [Description("The .dmp path (or an open dump's id).")] string path,
        [Description("summary, modules, threads, memory or unloaded.")] string view = "summary",
        [Description(ToolSupport.RowOffsetDescription)] int offset = 0,
        [Description(ToolSupport.LimitDescription)] int limit = MinidumpService.DefaultListLimit,
        [Description(ImageDirectoriesDescription)] string? imageDirectories = null,
        [Description("DAC (mscordaccore.dll / mscordacwks.dll) file or folder for a build not installed.")] string? dacPath = null,
        [Description("Fetch a matching DAC from a symbol server (network; refused under CORVUS_OFFLINE=1).")] bool downloadDac = false,
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
    [Description("Call stack of a minidump thread: x64 unwind data, x86 PDB frame data, call targets, EBP chain; JIT code without " +
                 "unwind data: a stack scan. Names from loaded images (code index, PDB, Il2Cpp) or exports. .NET frames (DAC): token, IL " +
                 "offset, assembly, C# statement; Mono JIT frames from the runtime's report beside the dump. ELF cores: CFI, then frame pointer.")]
    public Task<string> DumpStack(
        [Description(DumpDescription)] string dump,
        [Description("Thread id, '#index', name or 'exception' (default: faulting thread, else first).")] string? thread = null,
        [Description("Faulting thread: its context at dump time, not the exception context (.ecxr).")] bool dumpTimeContext = false,
        [Description("Max frames walked (up to 1024).")] int maxFrames = 256,
        [Description(ToolSupport.RowOffsetDescription)] int offset = 0,
        [Description(ToolSupport.LimitDescription)] int limit = 100,
        [Description(ImageDirectoriesDescription)] string? imageDirectories = null,
        [Description("auto: .NET frames through the DAC; off: native walk only.")] string? managed = "auto",
        [Description(ToolSupport.MaxTokensDescription)] int? maxTokens = null,
        CancellationToken cancellationToken = default) => Task.Run(async () =>
    {
        var r = await dumps.Stack(dump, thread, !dumpTimeContext, maxFrames, offset, limit, imageDirectories,
            !string.Equals(managed?.Trim(), "off", StringComparison.OrdinalIgnoreCase), cancellationToken);
        var header = $"{r.Dump} thread {r.ThreadId}{(r.ThreadName != null ? $" \"{r.ThreadName}\"" : "")}, {r.Architecture}, from the {r.Context} context; walk ended: {r.Stop}" +
                     (r.ScannedFrames > 0 ? $"; {r.ScannedFrames} scanned" : "") + (r.Managed != null ? $"; managed frames: {r.Managed}" : "") + "\n" +
                     (r.Registers != null ? $"registers: {r.Registers}\n" : "") + string.Concat(r.Notes.Select(n => $"note: {n}\n"));
        return ToolOutput.List(r.Items, r.Offset, limit, r.Total, DumpText.Frame, page => r with { Items = page }, "frame", header);
    }, cancellationToken);

    [McpServerTool(Name = "dump_heap", Title = ".NET heap of a dump or session", UseStructuredContent = true, OutputSchemaType = typeof(MinidumpService.HeapReport))]
    [Description("Lists the .NET GC heap of a minidump or session (via the DAC). stats: count and size per type, largest first; objects: matching objects " +
                 "(address, type, size, a string's value). Needs heap memory in the dump (else heap_not_captured).")]
    public Task<string> DumpHeap(
        [Description(HeapSourceDescription)] string dump,
        [Description("stats (per type) or objects (one row each).")] string? mode = "stats",
        [Description("Type full name, '*' / '?' wildcards; default all.")] string? type = null,
        [Description("Min object size in bytes.")] long minSize = 0,
        [Description(ToolSupport.RowOffsetDescription)] int offset = 0,
        [Description(ToolSupport.LimitDescription)] int limit = MinidumpService.DefaultListLimit,
        [Description("Max objects walked.")] long maxObjects = MinidumpService.DefaultMaxHeapObjects,
        [Description(ToolSupport.MaxTokensDescription)] int? maxTokens = null,
        CancellationToken cancellationToken = default) => Task.Run(async () =>
    {
        var r = Session(dump) is { } session
            ? dumps.Heap(session, await sessions!.ClrAsync(session, cancellationToken), mode, type, (ulong)Math.Max(0, minSize), offset, limit, maxObjects, cancellationToken)
            : await dumps.Heap(dump, mode, type, (ulong)Math.Max(0, minSize), offset, limit, maxObjects, cancellationToken);
        var header = $"{r.Dump}: {r.Walked:N0} objects walked, {r.MatchedBytes:N0} bytes matching{(r.Type != null ? $" type {r.Type}" : "")}{(r.MinSize > 0 ? $" of at least {r.MinSize} bytes" : "")}\n" +
                     string.Concat(r.Notes.Select(n => $"note: {n}\n"));
        return ToolOutput.List(r.Items, r.Offset, limit, r.Total, DumpText.HeapRow, page => r with { Items = page }, r.Mode == "stats" ? "type" : "object", header, r.TotalExact);
    }, cancellationToken);

    [McpServerTool(Name = "dump_object", Title = ".NET object of a dump or session", UseStructuredContent = true)]
    [Description("One .NET object of a dump or session (DAC): type, size, fields (references expanded depth levels), a string's or " +
                 "boxed value, or array elements.")]
    public Task<MinidumpService.ObjectReport> DumpObject(
        [Description(HeapSourceDescription)] string dump,
        [Description("Hex address of the object.")] string address,
        [Description("Levels of referenced objects expanded (up to 3).")] int depth = 1,
        [Description("Max fields listed, nested ones included.")] int maxFields = 100,
        [Description("Max array elements listed.")] int maxArrayItems = 32,
        CancellationToken cancellationToken = default) =>
        Task.Run(async () => Session(dump) is { } session
            ? dumps.Object(session, await sessions!.ClrAsync(session, cancellationToken), address, depth, maxFields, maxArrayItems)
            : await dumps.Object(dump, address, depth, maxFields, maxArrayItems, cancellationToken), cancellationToken);

    /// <summary>The running session <paramref name="dump"/> names, or null for a dump.</summary>
    private LiveSession? Session(string dump)
    {
        if (!LiveSessionService.IsSessionId(dump)) return null;
        if (sessions == null || options?.AllowLive != true) throw LiveSessionTools.SessionsOff();
        return sessions.Running(dump);
    }

    [McpServerTool(Name = "read_dump_memory", Title = "Read crash dump memory", UseStructuredContent = true, OutputSchemaType = typeof(MinidumpService.MemoryRead))]
    [Description("Hex dump of a dump's memory at an address, with what is there (module!function, captured range, protection). " +
                 "Bytes the dump lacks come from the module image (writable data: initial values) unless dumpOnly.")]
    public Task<string> ReadDumpMemory(
        [Description(DumpDescription)] string dump,
        [Description("Hex address, 'module+0x1234', or a module name (its base).")] string address,
        [Description("Bytes to read (up to 65536).")] int length = 256,
        [Description("Only the bytes the dump holds, none from the module image.")] bool dumpOnly = false,
        [Description("Byte offset into the read (a page's nextOffset).")] int offset = 0,
        [Description(ToolSupport.MaxTokensDescription)] int? maxTokens = null,
        CancellationToken cancellationToken = default) => Task.Run(async () =>
    {
        var read = await dumps.ReadBytes(dump, address, length, !dumpOnly, cancellationToken);
        return MemoryPage(read, offset);
    }, cancellationToken);

    /// <summary>The hex dump lines from <paramref name="offset"/> that fit the call's budget in both parts; the record holds them once, as hex.</summary>
    internal static string MemoryPage(MinidumpService.MemoryBytes read, int offset)
    {
        var h = read.Head;
        offset = Math.Clamp(offset, 0, read.Data.Length);
        string header = $"{h.Dump} {h.Address}: {h.Length:N0} of {h.Requested:N0} bytes, {h.Source}" + (h.Location != null ? $", at {h.Location}" : "") +
                        (h.Region != null ? $", captured {h.Region}" : "") + (h.Protection != null ? $", {h.Protection}" : "") + "\n" + (h.Note != null ? $"note: {h.Note}\n" : "");
        (string Text, MinidumpService.MemoryRead Record) Page(int end)
        {
            var text = header + MinidumpService.HexDump(read.Va + (ulong)offset, read.Data.AsSpan(offset, end - offset), read.Is64);
            var record = h with { Code = Convert.ToHexString(read.Data, offset, end - offset), Offset = offset };
            if (end < read.Data.Length)
            {
                record = record with { NextOffset = end, NextAddress = $"0x{read.Va + (ulong)end:X}" };
                text += $"[More: offset={end}] (address {record.NextAddress})\n";
            }
            return (text, record);
        }
        int lines = (read.Data.Length - offset + MinidumpService.HexLine - 1) / MinidumpService.HexLine;
        int End(int k) => Math.Min(read.Data.Length, offset + k * MinidumpService.HexLine);
        int fit = lines;
        if (OutputCall.Budgeted is { } call && lines > 1)
        {
            bool Fits(int k)
            {
                var (text, record) = Page(End(k));
                return call.Fits(text) && call.Fits(System.Text.Json.JsonSerializer.Serialize(record, ToolOutput.Wire));
            }
            if (!Fits(lines))
            {
                int lo = 1, hi = lines - 1;
                while (lo < hi)
                {
                    int mid = (lo + hi + 1) / 2;
                    if (Fits(mid)) lo = mid; else hi = mid - 1;
                }
                fit = lo;
            }
        }
        var (pageText, pageRecord) = Page(End(fit));
        return ToolOutput.With(pageText, pageRecord);
    }
}
