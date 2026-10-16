using System.ComponentModel;
using System.Diagnostics;
using Corvus.Core;
using Corvus.Native;
using Corvus.Native.Dump;
using Corvus.Native.Live;

namespace Corvus.Services;

/// <summary>
/// Read-only inspection of a running local process (Windows): modules, memory regions, threads and their stacks, named
/// as crash dumps are (<see cref="MinidumpService"/>: loaded images' code indexes with user, PDB, Il2Cpp and discovered
/// names, Il2Cpp dummy DLLs, local PDBs, exports). The process is opened for query and read only, threads one at a time
/// for their registers; every handle is closed before the call returns, also on errors, cancellation and timeouts.
/// The guarantee is documented in docs/live-inspection.md.
/// </summary>
public sealed class LiveProcessService(MinidumpService dumps)
{
    public const int DefaultLimit = 50, DefaultFrames = 64;
    public const int MaxFrames = 256, MaxListLimit = 1000, MaxTimeoutSeconds = 120, DefaultTimeoutSeconds = 20;
    private const int MaxCandidates = 20;

    /// <summary>inspect_process views: the summary report, then the paged lists (stacks: the frames of one thread).</summary>
    public static readonly string[] Views = ["summary", "modules", "regions", "threads", "stacks"];
    private static readonly string[] RegionFilters = ["committed", "all", "executable", "writable", "image", "private", "mapped"];
    private const int LargestRegions = 10;

    public sealed record ThreadRow(
        uint Id, string? Name,
        [property: Description("Read from the kernel (NtQueryInformationThread ThreadSuspendCount); inspection never changes it.")] uint? SuspendCount,
        int? Priority, string? Teb, string? StackLow, string? StackHigh,
        string? StartAddress,
        [property: Description("module!function of the thread's start address.")] string? StartSymbol,
        string? InstructionPointer, string? StackPointer,
        [property: Description("module!function+0xoffset of the instruction pointer.")] string? Location,
        string? Registers,
        [property: Description("What could not be read for this thread (exited, registers not read), or null.")] string? Error);

    public sealed record LiveCounts(int Modules, int Threads,
        [property: Description("Committed regions.")] int Regions,
        [property: Description("All regions, reserved and free included.")] int RegionsTotal);

    /// <summary>
    /// inspect_process: identity and the read-only guarantee in every view; view=summary adds counts, the main module and the
    /// largest committed regions; a list view fills items (module, region, thread or stack frame rows) with offset and total.
    /// </summary>
    public sealed record LiveReport(
        int ProcessId, string Name, string View, string? Path,
        [property: Description("x64, x86, ARM64: the process's own instruction set (x86 for a WoW64 process).")] string Architecture,
        bool Wow64,
        [property: Description("Managed runtime loaded in the process (CoreCLR, CLR, Mono) or Il2Cpp; null for none.")] string? Runtime,
        [property: Description("The handles this call opened, with their access rights: the read-only guarantee.")] IReadOnlyList<string> Access,
        [property: Description("Every handle to the process and its threads was closed before returning.")] bool Detached,
        int HandlesOpened, int HandlesClosed,
        [property: Description("The process was still running when inspection ended.")] bool StillRunning,
        long ElapsedMs,
        [property: Description("Where names and unwind data came from, and what was not covered.")] IReadOnlyList<string> Notes)
    {
        public string? StartTimeUtc { get; init; }
        public LiveCounts? Counts { get; init; }
        public MinidumpService.ModuleSummary? MainModule { get; init; }
        [Description("The largest committed regions.")] public IReadOnlyList<MinidumpService.MemoryRow>? LargestRegions { get; init; }
        [Description("view=stacks: the thread walked.")] public ThreadRow? Thread { get; init; }
        [Description("view=stacks: why the walk ended (end_of_stack, max_frames, left_the_stack, ...).")] public string? StackStop { get; init; }
        [Description("List views: module, region, thread or frame rows.")] public IReadOnlyList<object>? Items { get; init; }
        public int? Offset { get; init; }
        public int? Total { get; init; }
    }

    public async Task<LiveReport> Inspect(string process, string? view, string? thread, int offset, int limit, string? regionFilter, int maxFrames,
        string? imageDirectories, int timeoutSeconds, CancellationToken ct)
    {
        if (!OperatingSystem.IsWindows())
            throw new ToolError(ErrorCode.ProviderUnavailable, "live process inspection uses the Windows process API; this server is not running on Windows.",
                "inspect a minidump instead (open_minidump), or run the server on Windows") { Details = new { reason = "platform_not_windows" } };
        var v = (view ?? "summary").Trim().ToLowerInvariant();
        if (!Views.Contains(v)) throw new ToolError(ErrorCode.InvalidArgument, $"Unknown view '{view}'.", "pass view as one of " + string.Join(", ", Views));
        string filter = (regionFilter ?? "committed").Trim().ToLowerInvariant();
        if (!RegionFilters.Contains(filter))
            throw new ToolError(ErrorCode.InvalidArgument, $"regionFilter '{regionFilter}' is not one of {string.Join(", ", RegionFilters)}.");
        if (timeoutSeconds < 1 || timeoutSeconds > MaxTimeoutSeconds)
            throw new ToolError(ErrorCode.InvalidArgument, $"timeoutSeconds must be 1-{MaxTimeoutSeconds}.");
        var (pid, name) = Resolve(process);
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(TimeSpan.FromSeconds(timeoutSeconds));
        try
        {
            return await Task.Run(() => Run(pid, name, v, thread, Math.Max(0, offset), Math.Clamp(limit, 1, MaxListLimit), filter, Math.Clamp(maxFrames, 1, MaxFrames),
                imageDirectories, timeout.Token), timeout.Token);
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            throw new ToolError(ErrorCode.Timeout, $"inspecting process {pid} took longer than {timeoutSeconds} s; every handle was closed.",
                "list fewer rows (limit) or fewer frames (maxFrames)") { Details = new { reason = "timeout", pid } };
        }
    }

    private async Task<LiveReport> Run(int pid, string name, string view, string? threadFilter, int offset, int limit, string filter, int maxFrames,
        string? imageDirectories, CancellationToken ct)
    {
        var clock = Stopwatch.StartNew();
        var notes = new List<string>();
        ct.ThrowIfCancellationRequested();
        var live = LiveProcess.Attach(pid, ct);
        MinidumpService.Session? session = null;
        LiveReport report;
        try
        {
            var dirs = MinidumpService.Directories(imageDirectories, live.ImagePath ?? "");
            session = dumps.SessionFor($"pid {pid}", live, dirs);
            if (live.ModulesNote != null) notes.Add(live.ModulesNote);
            MinidumpService.HostsClr(live, out var runtime);
            if (runtime == null && live.Modules.Any(m => m.FileName.Equals("GameAssembly.dll", StringComparison.OrdinalIgnoreCase))) runtime = "Il2Cpp (Unity)";
            report = new LiveReport(pid, name, view, live.ImagePath, MinidumpService.ArchName(live.Arch, 0xFFFF), live.Wow64, runtime, AccessList(),
                false, 0, 0, false, 0, notes) { StartTimeUtc = view == "summary" ? live.StartTimeUtc?.ToString("u") : null };
            switch (view)
            {
                case "summary":
                {
                    var regions = live.Regions(ct);
                    var committed = regions.Where(r => r.State == 0x1000).ToList();
                    report = report with
                    {
                        Counts = new LiveCounts(live.Modules.Count, live.Threads(ct).Count, committed.Count, regions.Count),
                        MainModule = (live.Modules.FirstOrDefault(m => m.Path.Equals(live.ImagePath, StringComparison.OrdinalIgnoreCase)) ?? live.Modules.FirstOrDefault()) is { } main ? MinidumpService.ModuleRow(main, dirs, live.Arch) : null,
                        LargestRegions = committed.OrderByDescending(r => r.Size).ThenBy(r => r.Base).Take(LargestRegions).Select(r => MinidumpService.RegionRow(live, r, null)).ToList(),
                    };
                    if (regions.Count >= MinidumpLimits.MaxMemoryRegions) notes.Add($"only the first {MinidumpLimits.MaxMemoryRegions} regions were read");
                    break;
                }
                case "modules":
                    report = report with
                    {
                        Items = live.Modules.Skip(offset).Take(limit).Select(m => (object)MinidumpService.ModuleRow(m, dirs, live.Arch)).ToList(),
                        Offset = offset, Total = live.Modules.Count,
                    };
                    break;
                case "regions":
                {
                    var regions = live.Regions(ct);
                    var matching = regions.Where(r => Matches(r, filter)).ToList();
                    report = report with { Items = matching.Skip(offset).Take(limit).Select(r => (object)MinidumpService.RegionRow(live, r, null)).ToList(), Offset = offset, Total = matching.Count };
                    if (regions.Count >= MinidumpLimits.MaxMemoryRegions) notes.Add($"only the first {MinidumpLimits.MaxMemoryRegions} regions were read");
                    break;
                }
                case "threads":
                {
                    var entries = live.Threads(ct);
                    if (threadFilter is { Length: > 0 }) entries = PickThreads(live, entries, threadFilter);
                    var rows = new List<object>();
                    foreach (var e in entries.Skip(offset).Take(limit))
                    {
                        ct.ThrowIfCancellationRequested();
                        rows.Add((await ThreadRowFor(session, live, e, ct)).Row with { Registers = null });
                    }
                    report = report with { Items = rows, Offset = offset, Total = entries.Count };
                    if (!live.CanReadContexts) notes.Add($"registers of a {live.Arch} process are not read by this server ({System.Runtime.InteropServices.RuntimeInformation.ProcessArchitecture}).");
                    break;
                }
                default: // stacks: the frames of one thread
                {
                    var entries = live.Threads(ct);
                    var e = (threadFilter is { Length: > 0 } ? PickThreads(live, entries, threadFilter) : entries).FirstOrDefault()
                            ?? throw new ToolError(ErrorCode.NotFound, $"process {pid} has no thread to walk.", "view=threads lists them");
                    var (row, ctx, stackLow, stackHigh) = await ThreadRowFor(session, live, e, ct);
                    IReadOnlyList<MinidumpService.StackFrame> frames = [];
                    string? stop = null;
                    if (ctx != null)
                    {
                        var walk = session.Walker().Walk(ctx, stackLow, stackHigh, maxFrames, ct);
                        frames = await dumps.Frames(session, walk, offset, limit, ct);
                        stop = walk.Stop;
                        report = report with { Total = walk.Frames.Count };
                    }
                    else notes.Add(live.CanReadContexts ? $"thread {e.Id}: {row.Error ?? "no register context"}"
                        : $"stacks of a {live.Arch} process are not walked by this server ({System.Runtime.InteropServices.RuntimeInformation.ProcessArchitecture}).");
                    notes.Add("Threads were not suspended: the register context is a snapshot of a running thread, so a frame of a thread that was executing user code may be stale.");
                    notes.AddRange(MinidumpService.ModuleNotes(session));
                    report = report with { Thread = row, StackStop = stop, Items = frames.Cast<object>().ToList(), Offset = offset, Total = report.Total ?? 0 };
                    break;
                }
            }
            if (!live.IsRunning) notes.Add("the process exited while it was being inspected; reads after that returned nothing.");
            report = report with { StillRunning = live.IsRunning };
        }
        finally
        {
            if (session != null) session.Dispose();
            else live.Dispose();
        }
        return report with
        {
            Detached = live.HandlesOpened == live.HandlesClosed,
            HandlesOpened = live.HandlesOpened,
            HandlesClosed = live.HandlesClosed,
            ElapsedMs = clock.ElapsedMilliseconds,
        };
    }

    private async Task<(ThreadRow Row, DumpContext? Context, ulong StackLow, ulong StackHigh)> ThreadRowFor(MinidumpService.Session s, LiveProcess live, LiveThreadEntry e, CancellationToken ct)
    {
        var t = live.ReadThread(e.Id, context: true);
        string? startSymbol = t.StartAddress is { } sa && sa != 0 ? (await dumps.Locate(s, sa, false, ct)).Symbol : null;
        var ctx = t.Context;
        string? location = ctx != null ? (await dumps.Locate(s, ctx.Ip, false, ct)).Symbol : null;
        var row = new ThreadRow(t.Id, t.Name, t.SuspendCount, t.Priority ?? t.BasePriority ?? e.BasePriority, Opt(live, t.Teb), Opt(live, t.StackLow), Opt(live, t.StackHigh),
            Opt(live, t.StartAddress), startSymbol, ctx != null ? Hex(live, ctx.Ip) : null, ctx != null ? Hex(live, ctx.Sp) : null, location, ctx?.Format(), t.Error);
        return (row, ctx, t.StackLow ?? 0, t.StackHigh ?? 0);
    }

    /// <summary>A process id (decimal or 0x hex) or a process name (with or without .exe); a name must match one process.</summary>
    internal static (int Pid, string Name) Resolve(string process)
    {
        var text = (process ?? "").Trim();
        if (text.Length == 0) throw new ToolError(ErrorCode.InvalidArgument, "process is empty.", "pass a process id or a process name (e.g. notepad or notepad.exe)");
        ulong? number = text.StartsWith("0x", StringComparison.OrdinalIgnoreCase) ? NativeAddress.Number(text)
            : text.All(char.IsAsciiDigit) ? (ulong.TryParse(text, out var d) ? d : ulong.MaxValue) : null;
        if (number is { } n)
        {
            if (n == 0 || n > int.MaxValue) throw new ToolError(ErrorCode.InvalidArgument, $"'{text}' is not a valid process id.", "pass a process id or a process name");
            try
            {
                using var p = Process.GetProcessById((int)n);
                return ((int)n, p.ProcessName);
            }
            catch (ArgumentException)
            {
                throw new ToolError(ErrorCode.NotFound, $"no running process has id {n}.", "pass a running process id or a process name")
                { Details = new { reason = "process_not_found", pid = n } };
            }
        }
        string name = text.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) ? text[..^4] : text;
        var all = Process.GetProcesses();
        try
        {
            var exact = all.Where(p => p.ProcessName.Equals(name, StringComparison.OrdinalIgnoreCase) && p.Id != Environment.ProcessId)
                .Select(p => (p.Id, p.ProcessName, Session: SafeSession(p))).OrderBy(p => p.Id).ToList();
            if (exact.Count == 1) return (exact[0].Id, exact[0].ProcessName);
            if (exact.Count > 1)
                throw new ToolError(ErrorCode.Ambiguous,
                    $"{exact.Count} processes are named '{name}': {string.Join(", ", exact.Take(MaxCandidates).Select(c => $"pid {c.Id} (session {c.Session})"))}{(exact.Count > MaxCandidates ? ", ..." : "")}.",
                    "pass the process id")
                { Details = new { reason = "ambiguous", candidates = exact.Take(MaxCandidates).Select(c => new { pid = c.Id, name = c.ProcessName, session = c.Session }).ToList() } };
            var similar = all.Where(p => p.ProcessName.Contains(name, StringComparison.OrdinalIgnoreCase) && p.Id != Environment.ProcessId)
                .Select(p => $"{p.ProcessName} ({p.Id})").Order(StringComparer.OrdinalIgnoreCase).Take(MaxCandidates).ToList();
            throw new ToolError(ErrorCode.NotFound,
                $"no running process is named '{name}'." + (similar.Count > 0 ? $" Similar: {string.Join(", ", similar)}." : ""),
                "pass a process id or the exact process name (the file name without .exe)")
            { Details = new { reason = "process_not_found", similar } };
        }
        finally
        {
            foreach (var p in all) p.Dispose();
        }
    }

    private static int SafeSession(Process p)
    {
        try { return p.SessionId; }
        catch (Exception ex) when (ex is InvalidOperationException or Win32Exception or NotSupportedException) { return -1; }
    }

    private static IReadOnlyList<LiveThreadEntry> PickThreads(LiveProcess live, IReadOnlyList<LiveThreadEntry> entries, string text)
    {
        var t = text.Trim();
        ulong? id = t.StartsWith("0x", StringComparison.OrdinalIgnoreCase) ? NativeAddress.Number(t) : ulong.TryParse(t, out var dec) ? dec : null;
        if (id is { } v && entries.FirstOrDefault(e => e.Id == v) is { } byId) return [byId];
        if (id != null)
            throw new ToolError(ErrorCode.NotFound, $"process {live.Pid} has no thread {t}. Threads: {string.Join(", ", entries.Take(40).Select(e => e.Id))}{(entries.Count > 40 ? ", ..." : "")}.",
                "pass a thread id (decimal or 0x hex) or a thread name");
        // by name: the description each thread carries (one handle per thread, closed at once)
        var named = entries.Take(MinidumpLimits.MaxThreads).Where(e => string.Equals(live.ReadThread(e.Id, context: false).Name, t, StringComparison.OrdinalIgnoreCase)).ToList();
        if (named.Count == 1) return named;
        if (named.Count > 1) throw new ToolError(ErrorCode.Ambiguous, $"{named.Count} threads are named '{t}': {string.Join(", ", named.Select(e => e.Id))}.", "pass the thread id");
        throw new ToolError(ErrorCode.NotFound, $"process {live.Pid} has no thread '{t}'.", "pass a thread id (decimal or 0x hex) or a thread name");
    }

    internal static IReadOnlyList<string> AccessList() =>
    [
        $"process: OpenProcess PROCESS_QUERY_INFORMATION | PROCESS_VM_READ (0x{LiveProcess.ProcessAccess:X})",
        $"each listed thread, one at a time: OpenThread THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION (0x{LiveProcess.ThreadAccess:X})",
        "thread list: system snapshot (CreateToolhelp32Snapshot TH32CS_SNAPTHREAD), no handle to the process",
        "never: memory writes, protection changes, breakpoints, debugger attach, thread suspend/resume/creation, adding code to the process",
    ];

    private static bool Matches(DumpMemoryRegion r, string filter) => filter switch
    {
        "all" => true,
        "committed" => r.State == 0x1000,
        "executable" => r.IsExecutable,
        "writable" => r.State == 0x1000 && (r.Protect & 0xCC) != 0, // READWRITE, WRITECOPY, EXECUTE_READWRITE, EXECUTE_WRITECOPY
        "image" => r.State == 0x1000 && r.Type == 0x1000000,
        "private" => r.State == 0x1000 && r.Type == 0x20000,
        "mapped" => r.State == 0x1000 && r.Type == 0x40000,
        _ => false,
    };

    private static string Hex(LiveProcess p, ulong v) => MinidumpService.Hex(p, v);
    private static string? Opt(LiveProcess p, ulong? v) => v is { } x ? Hex(p, x) : null;
}
