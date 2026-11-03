using System.ComponentModel;
using ModelContextProtocol.Server;
using Corvus.Core;
using Corvus.Mcp;
using Corvus.Native.Dump.Managed;
using Corvus.Services;

namespace Corvus.Tools;

/// <summary>Windows crash dumps (minidumps): summary, stack walks, captured memory.</summary>
[McpServerToolType]
public sealed class MinidumpTools(MinidumpService dumps, LiveSessionService? sessions = null, ServerOptions? options = null, AssemblyWorkspace? workspace = null,
    Native.Providers.Worker.WorkerPool? workers = null)
{
    private const string DumpDescription = "A .dmp path or open_minidump's id.";
    private const string HeapSourceDescription = "A .dmp path, open_minidump's id or a session id (live-1): its program, read while it runs.";
    private const string ImageDirectoriesDescription =
        "Program binary folders (';'-separated), kept for the dump, plus its own.";

    [McpServerTool(Name = "open_minidump", Title = "Open a crash dump", UseStructuredContent = true, OutputSchemaType = typeof(MinidumpService.DumpReport))]
    [Description("Open a Windows minidump, ELF or Mach-O core, or region-set manifest; returns its id. view=summary: OS, " +
                 "process, exception, .NET state; other views page rows.")]
    public Task<string> OpenMinidump(
        [Description("The .dmp path or open dump id.")] string path,
        [Description("summary, modules, threads, memory, unloaded or changes.")] string view = "summary",
        [Description(ToolSupport.RowOffsetDescription)] int offset = 0,
        [Description(ToolSupport.LimitDescription)] int limit = MinidumpService.DefaultListLimit,
        [Description(ImageDirectoriesDescription)] string? imageDirectories = null,
        [Description("DAC file or folder for a build not installed.")] string? dacPath = null,
        [Description("Fetch a matching DAC (symbol server; refused under CORVUS_OFFLINE=1).")] bool downloadDac = false,
        [Description("view=memory: all (default) or unbacked.")] string? regionFilter = null,
        [Description("unbacked: YARA rules (text, file, folder, pack:name).")] string? yara = null,
        [Description("view=modules: new or empty image folder.")] string? outputPath = null,
        [Description("outputPath or view=changes: file name, 0x address, all, unlisted or code.")] string? modules = null,
        [Description("outputPath: file or mapped.")] string? layout = null,
        [Description("outputPath: restore or keep.")] string? imports = null,
        [Description("outputPath: loaded or preferred.")] string? @base = null,
        [Description(ToolSupport.MaxTokensDescription)] int? maxTokens = null,
        CancellationToken cancellationToken = default) => Task.Run(async () =>
    {
        // A missing dump is named before any argument combination is checked.
        var target = Target(path, imageDirectories);
        var v = (view ?? "summary").Trim().ToLowerInvariant();
        if (!MinidumpService.Views.Contains(v))
            throw new ToolError(ErrorCode.InvalidArgument, $"Unknown view '{view}'.", "pass view as one of " + string.Join(", ", MinidumpService.Views));
        var filter = (regionFilter ?? "all").Trim().ToLowerInvariant();
        if (!MinidumpService.MemoryFilters.Contains(filter))
            throw new ToolError(ErrorCode.InvalidArgument, $"regionFilter '{regionFilter}' is not one of {string.Join(", ", MinidumpService.MemoryFilters)}.");
        if (filter != "all" && v != "memory") throw new ToolError(ErrorCode.InvalidArgument, "regionFilter goes with view=memory.");
        if (!string.IsNullOrWhiteSpace(yara) && filter != "unbacked") throw new ToolError(ErrorCode.InvalidArgument, "yara goes with regionFilter=unbacked.");
        if (!string.IsNullOrWhiteSpace(outputPath) && v != "modules") throw new ToolError(ErrorCode.InvalidArgument, "outputPath goes with view=modules.", "pass view=modules");
        var saving = !string.IsNullOrWhiteSpace(outputPath);
        if (!saving && (new[] { layout, imports, @base }.Any(o => !string.IsNullOrWhiteSpace(o)) || v != "changes" && !string.IsNullOrWhiteSpace(modules)))
            throw new ToolError(ErrorCode.InvalidArgument, "modules, layout, imports and base go with outputPath; modules also with view=changes.", "pass outputPath");
        if (saving && offset > 0)
            throw new ToolError(ErrorCode.InvalidArgument, "A call with outputPath writes once and takes no offset.",
                "read_result with the resultId of the first call to page its rows");
        var save = MinidumpService.ModuleOptions.Parse(modules, layout, imports, @base);
        // A sandboxed worker writes only under labelled folders: it rebuilds into staging and the server fills the named folder.
        var staging = saving && FileIsolation.PoolFor(Isolation, workers) is { Sandboxed: true } ? FileWork.NewModuleStaging() : null;
        var final = saving ? SafeFile.Output(outputPath!) : null;
        if (staging != null) FileWork.RequireFreshFolder(final!);
        var args = new FileWork.DumpViewArgs(target, v, offset, limit, dacPath, downloadDac, filter == "all" ? null : filter,
            string.IsNullOrWhiteSpace(yara) ? null : yara, staging ?? final, saving || v == "changes" ? save.Module : null, save.Layout, save.Imports, save.Base);
        FileWork.DumpViewResult r;
        try
        {
            r = await FileIsolation.RunAsync(Isolation, workers, FileWork.DumpView, args, args.Dump.Path, () => FileWork.ViewOf(dumps, args, cancellationToken), cancellationToken);
            if (staging != null) r = FileWork.PlaceModules(r, staging, final!);
        }
        finally { if (staging != null) FileWork.DeleteStaging(staging); }
        if (r.Summary is { } report) return ToolOutput.Report(DumpText.Summary(report), report);
        if (r.Changes is { } changed) return Rows(r.Id!, v, changed, offset, limit, r.Total, ChangeLine, "changed range", r.Notes);
        if (r.Modules is { } written && saving) return Written(r.Id!, v, written, r.Notes);
        if (r.Modules is { } listed) return Rows(r.Id!, v, listed, offset, limit, r.Total, DumpText.Module, "module", r.Notes);
        if (r.Threads is { } threads) return Rows(r.Id!, v, threads, offset, limit, r.Total, DumpText.Thread, "thread");
        if (r.Unbacked is { } unbacked) return Rows(r.Id!, v, unbacked, offset, limit, r.Total, DumpText.Memory, "region", r.Notes);
        if (r.Memory is { } memory) return Rows(r.Id!, v, memory, offset, limit, r.Total, DumpText.Memory, "region");
        return Rows(r.Id!, v, r.Unloaded ?? [], offset, limit, r.Total, u => $"{u.Base}  {u.Name}  size {u.Size}  stamp {u.TimeDateStamp}", "unloaded module");
    }, cancellationToken);

    private static string ChangeLine(MinidumpService.ModuleChange c) =>
        $"{c.Module} {(c.Section.Length == 0 ? "-" : c.Section)} {c.Start} {c.Length} {c.Kind} {c.Name ?? "-"}: {c.Description}";

    /// <summary>Options for <see cref="FileIsolation"/>; null while images are loaded, since frame names come from this process's indexes.</summary>
    private ServerOptions? Isolation => workspace != null && workspace.Read(() => workspace.Natives.Count > 0 || workspace.Assemblies.Count > 0) ? null : options;

    private FileWork.DumpTarget Target(string dump, string? imageDirectories)
    {
        var (id, path, directories) = dumps.Resolve(dump, imageDirectories);
        return new FileWork.DumpTarget(id, path, directories);
    }

    // A writing call cannot be repeated for a later page: its record has no row offset, so the
    // server keeps the whole result and names it for read_result.
    private static string Written(string id, string view, IReadOnlyList<MinidumpService.CheckedModule> rows, IReadOnlyList<string>? notes)
    {
        // A code row without a file only names why no region was written.
        bool IsReason(MinidumpService.CheckedModule r) => r.Format == "code" && r.ImageFile == null;
        var reasons = rows.Where(IsReason).Select(r => r.ImageReason ?? "no reason given").ToList();
        var modules = rows.Where(r => !IsReason(r)).ToList();
        var written = modules.Where(r => r.ImageFile != null).ToList();
        var skipped = modules.Where(r => r.ImageFile == null).ToList();
        var sb = new System.Text.StringBuilder();
        if (notes is { Count: > 0 })
            foreach (var n in notes) sb.Append($"Note: {n}\n");
        if (written.Count > 0)
        {
            var of = skipped.Count > 0 ? $" of {modules.Count}" : "";
            sb.Append($"{written.Count} written module{(written.Count == 1 ? "" : "s")}{of}:\n");
            foreach (var r in written) sb.Append(DumpText.Module(r)).Append('\n');
        }
        else if (reasons.Count == 0)
            sb.Append("0 written modules.\n");
        foreach (var reason in reasons) sb.Append($"Nothing written: unknown, {reason}\n");
        if (written.Count > 0 && skipped.Count > 0)
        {
            sb.Append($"{skipped.Count} not written:\n");
            foreach (var r in skipped) sb.Append(DumpText.Module(r)).Append('\n');
        }
        return ToolOutput.Report(sb.ToString(), new MinidumpService.DumpReport(id, view) { Items = modules.Cast<object>().ToList(), Total = modules.Count, Notes = notes });
    }

    private static string Rows<T>(string id, string view, IReadOnlyList<T> rows, int offset, int limit, int total, Func<T, string> render, string noun,
        IReadOnlyList<string>? notes = null) where T : notnull =>
        ToolOutput.List(rows, offset, limit, total, render,
            page => new MinidumpService.DumpReport(id, view) { Items = page.Cast<object>().ToList(), Offset = offset, Total = total, Notes = notes }, noun,
            notes is { Count: > 0 } ? string.Concat(notes.Select(n => $"Note: {n}\n")) : null);

    [McpServerTool(Name = "dump_stack", Title = "Crash dump stack", UseStructuredContent = true, OutputSchemaType = typeof(MinidumpService.StackReport))]
    [Description("Walk the call stack of a dump thread, naming frames from loaded images, PDBs or exports. .NET frames add token, IL " +
                 "offset and C# statement.")]
    public Task<string> DumpStack(
        [Description(DumpDescription)] string dump,
        [Description("Thread id, '#index', name or 'exception' (default: faulting, else first).")] string? thread = null,
        [Description("Faulting thread: its context at dump time, not the exception's (.ecxr).")] bool dumpTimeContext = false,
        [Description("Max frames walked (up to 1024).")] int maxFrames = 256,
        [Description(ToolSupport.RowOffsetDescription)] int offset = 0,
        [Description(ToolSupport.LimitDescription)] int limit = 100,
        [Description(ImageDirectoriesDescription)] string? imageDirectories = null,
        [Description("auto: .NET frames via the DAC; off: native only.")] string? managed = "auto",
        [Description(ToolSupport.MaxTokensDescription)] int? maxTokens = null,
        CancellationToken cancellationToken = default) => Task.Run(async () =>
    {
        var args = new FileWork.StackArgs(Target(dump, imageDirectories), thread, !dumpTimeContext, maxFrames, offset, limit,
            !string.Equals(managed?.Trim(), "off", StringComparison.OrdinalIgnoreCase));
        var r = await FileIsolation.RunAsync(Isolation, workers, FileWork.DumpStack, args, args.Dump.Path,
            () => dumps.Stack(dump, thread, args.ExceptionContext, maxFrames, offset, limit, imageDirectories, args.Managed, cancellationToken).GetAwaiter().GetResult(),
            cancellationToken);
        var header = $"{r.Dump} thread {r.ThreadId}{(r.ThreadName != null ? $" \"{r.ThreadName}\"" : "")}, {r.Architecture}, from the {r.Context} context; walk ended: {r.Stop}" +
                     (r.ScannedFrames > 0 ? $"; {r.ScannedFrames} scanned" : "") + (r.Managed != null ? $"; managed frames: {r.Managed}" : "") + "\n" +
                     (r.Registers != null ? $"registers: {r.Registers}\n" : "") + string.Concat(r.Notes.Select(n => $"Note: {n}\n"));
        return ToolOutput.List(r.Items, r.Offset, limit, r.Total, DumpText.Frame, page => r with { Items = page }, "frame", header);
    }, cancellationToken);

    [McpServerTool(Name = "dump_heap", Title = ".NET heap of a dump or session", UseStructuredContent = true, OutputSchemaType = typeof(MinidumpService.HeapReport))]
    [Description("List the .NET GC heap of a dump or session: per-type counts and sizes, or matching objects (first 100000 paged). " +
                 "Needs heap memory in the dump, else heap_not_captured.")]
    public Task<string> DumpHeap(
        [Description(HeapSourceDescription)] string dump,
        [Description("stats (per type) or objects (one row each).")] string? mode = "stats",
        [Description("Type full name, * ? wildcards; default all.")] string? type = null,
        [Description("Min object size in bytes.")] long minSize = 0,
        [Description(ToolSupport.RowOffsetDescription)] int offset = 0,
        [Description(ToolSupport.LimitDescription)] int limit = MinidumpService.DefaultListLimit,
        [Description("Max objects walked.")] long maxObjects = MinidumpService.DefaultMaxHeapObjects,
        [Description(ToolSupport.MaxTokensDescription)] int? maxTokens = null,
        CancellationToken cancellationToken = default) => Task.Run(async () =>
    {
        var r = Session(dump) is { } session
            ? dumps.Heap(session, await sessions!.ClrAsync(session, cancellationToken), mode, type, (ulong)Math.Max(0, minSize), offset, limit, maxObjects, cancellationToken)
            : await HeapOfDump(dump, mode, type, (ulong)Math.Max(0, minSize), offset, limit, maxObjects, cancellationToken);
        var header = $"{r.Dump}: {r.Walked:N0} objects walked, {r.MatchedBytes:N0} bytes matching{(r.Type != null ? $" type {r.Type}" : "")}{(minSize > 0 ? $" of at least {minSize} bytes" : "")}\n" +
                     string.Concat(r.Notes.Select(n => $"Note: {n}\n"));
        return ToolOutput.List(r.Items, r.Offset, limit, r.Total, DumpText.HeapRow, page => r with { Items = page }, r.Mode == "stats" ? "type" : "object", header, r.TotalExact);
    }, cancellationToken);

    [McpServerTool(Name = "dump_object", Title = ".NET object of a dump or session", UseStructuredContent = true)]
    [Description("Read one .NET object of a dump or session: type, size, fields, a string's or boxed value, or array elements.")]
    public Task<MinidumpService.ObjectReport> DumpObject(
        [Description(HeapSourceDescription)] string dump,
        [Description("Hex address of the object.")] string address,
        [Description("Reference levels expanded (up to 3).")] int depth = 1,
        [Description("Max fields, nested included.")] int maxFields = 100,
        [Description("Max array elements.")] int maxArrayItems = 32,
        CancellationToken cancellationToken = default) =>
        Task.Run(async () => Session(dump) is { } session
            ? dumps.Object(session, await sessions!.ClrAsync(session, cancellationToken), address, depth, maxFields, maxArrayItems)
            : await ObjectOfDump(dump, address, depth, maxFields, maxArrayItems, cancellationToken), cancellationToken);

    private Task<MinidumpService.HeapReport> HeapOfDump(string dump, string? mode, string? type, ulong minSize, int offset, int limit, long maxObjects, CancellationToken ct)
    {
        var args = new FileWork.DumpHeapArgs(Target(dump, null), mode, type, minSize, offset, limit, maxObjects);
        return FileIsolation.RunAsync(Isolation, workers, FileWork.DumpHeap, args, args.Dump.Path,
            () => dumps.Heap(dump, mode, type, minSize, offset, limit, maxObjects, ct).GetAwaiter().GetResult(), ct);
    }

    private Task<MinidumpService.ObjectReport> ObjectOfDump(string dump, string address, int depth, int maxFields, int maxArrayItems, CancellationToken ct)
    {
        var args = new FileWork.DumpObjectArgs(Target(dump, null), address, depth, maxFields, maxArrayItems);
        return FileIsolation.RunAsync(Isolation, workers, FileWork.DumpObject, args, args.Dump.Path,
            () => dumps.Object(dump, address, depth, maxFields, maxArrayItems, ct).GetAwaiter().GetResult(), ct);
    }

    /// <summary>The running session <paramref name="dump"/> names, or null for a dump.</summary>
    private LiveSession? Session(string dump)
    {
        if (!LiveSessionService.IsSessionId(dump)) return null;
        if (sessions == null || options?.AllowLive != true) throw LiveSessionTools.SessionsOff();
        return sessions.Running(dump);
    }

    [McpServerTool(Name = "read_dump_memory", Title = "Read crash dump memory", UseStructuredContent = true, OutputSchemaType = typeof(MinidumpService.MemoryRead))]
    [Description("Hex dump of a dump's memory at an address, with its module, captured range and protection. Bytes the dump lacks " +
                 "come from the module image (writable data: initial values) unless dumpOnly.")]
    public Task<string> ReadDumpMemory(
        [Description(DumpDescription)] string dump,
        [Description("Hex address, module+0x1234 or module name (its base).")] string address,
        [Description("Bytes to read (up to 65536).")] int length = 256,
        [Description("Only the bytes the dump holds, none from the image.")] bool dumpOnly = false,
        [Description("Byte offset into the read (a page's nextOffset).")] int offset = 0,
        [Description(ToolSupport.MaxTokensDescription)] int? maxTokens = null,
        CancellationToken cancellationToken = default) => Task.Run(async () =>
    {
        var args = new FileWork.DumpReadArgs(Target(dump, null), address, length, !dumpOnly);
        var read = await FileIsolation.RunAsync(Isolation, workers, FileWork.DumpRead, args, args.Dump.Path,
            () => dumps.ReadBytes(dump, address, length, !dumpOnly, cancellationToken).GetAwaiter().GetResult(), cancellationToken);
        return MemoryPage(read, offset);
    }, cancellationToken);

    /// <summary>The hex dump lines from <paramref name="offset"/> that fit the call's budget in both parts; the record holds them once, as hex.</summary>
    internal static string MemoryPage(MinidumpService.MemoryBytes read, int offset)
    {
        var h = read.Head;
        offset = Math.Clamp(offset, 0, read.Data.Length);
        string header = $"{h.Dump} {h.Address}: {h.Length:N0} of {h.Requested:N0} bytes, {h.Source}" + (h.Location != null ? $", at {h.Location}" : "") +
                        (h.Region != null ? $", captured {h.Region}" : "") + (h.Protection != null ? $", {h.Protection}" : "") + "\n" + (h.Note != null ? $"Note: {h.Note}\n" : "");
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
