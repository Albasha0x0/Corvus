using System.ComponentModel;
using System.Diagnostics;
using Corvus.Core;
using Corvus.Native;
using Corvus.Native.Dump;
using Corvus.Native.Live;

namespace Corvus.Services;

/// <summary>Read-only inspection of a running Windows process (modules, regions, threads, stacks, windows), named as
/// <see cref="MinidumpService"/> names dumps. The process is opened for query and read only; every handle is closed before
/// the call returns, also on errors, cancellation and timeouts (docs/live-inspection.md).</summary>
public sealed class LiveProcessService(MinidumpService dumps)
{
    public const int DefaultLimit = 50, DefaultFrames = 64;
    public const int MaxFrames = 256, MaxListLimit = 1000, MaxTimeoutSeconds = 120, DefaultTimeoutSeconds = 20;
    private const int MaxCandidates = 20;

    /// <summary>inspect_process views: the summary report, then the paged lists (stacks: the frames of one thread).</summary>
    public static readonly string[] Views = ["summary", "modules", "regions", "threads", "stacks", "windows"];
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

    /// <summary>One UI Automation element of view=windows, depth first, with its class procedure and notified parent.</summary>
    public sealed record UiRow(int Depth, string ControlType, string? Name, string? AutomationId, string? ClassName, string? Framework,
        string? Window, [property: Description("x,y width x height, in screen pixels.")] string Bounds, bool Enabled, bool Offscreen)
    {
        [Description("The window class's procedure (GCLP_WNDPROC).")] public string? ClassProcedure { get; init; }
        [Description("module!function of the class procedure.")] public string? ClassProcedureSymbol { get; init; }
        public int? ControlId { get; init; }
        [Description("A child control's notifications (WM_COMMAND, WM_NOTIFY) go to this parent class procedure, module!function.")] public string? Notifies { get; init; }
    }

    public sealed record LiveCounts(int Modules, int Threads,
        [property: Description("Committed regions.")] int Regions,
        [property: Description("All regions, reserved and free included.")] int RegionsTotal);

    /// <summary>inspect_process result: identity and access in every view, counts in view=summary, paged items in list views.</summary>
    public sealed record LiveReport(
        int ProcessId, string Name, string View, string? Path,
        [property: Description("x64, x86, ARM64: the process's own instruction set (x86 for a WoW64 process).")] string Architecture,
        bool Wow64,
        [property: Description("Managed runtime loaded in the process (CoreCLR, CLR, Mono) or AOT; null for none.")] string? Runtime,
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
        [Description("List views: module, region, thread, frame or element rows.")] public IReadOnlyList<object>? Items { get; init; }
        public int? Offset { get; init; }
        public int? Total { get; init; }
    }

    public async Task<LiveReport> Inspect(string process, string? view, string? thread, int offset, int limit, string? regionFilter, int maxFrames,
        string? imageDirectories, int timeoutSeconds, CancellationToken ct, string? imagePath = null)
    {
        // Check arguments first so a bad call is answered alike on every platform.
        var v = (view ?? "summary").Trim().ToLowerInvariant();
        if (!Views.Contains(v)) throw new ToolError(ErrorCode.InvalidArgument, $"Unknown view '{view}'.", "pass view as one of " + string.Join(", ", Views));
        string filter = (regionFilter ?? "committed").Trim().ToLowerInvariant();
        if (!RegionFilters.Contains(filter))
            throw new ToolError(ErrorCode.InvalidArgument, $"regionFilter '{regionFilter}' is not one of {string.Join(", ", RegionFilters)}.");
        if (imagePath != null && v != "windows") throw new ToolError(ErrorCode.InvalidArgument, "imagePath goes with view=windows.");
        if (timeoutSeconds < 1 || timeoutSeconds > MaxTimeoutSeconds)
            throw new ToolError(ErrorCode.InvalidArgument, $"timeoutSeconds must be 1-{MaxTimeoutSeconds}.");
        if (!OperatingSystem.IsWindows())
            throw new ToolError(ErrorCode.ProviderUnavailable, "live process inspection uses the Windows process API; this server is not running on Windows.",
                "inspect a minidump instead (open_minidump), or run the server on Windows") { Details = new { reason = "platform_not_windows" } };
        var (pid, name) = Resolve(process);
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(TimeSpan.FromSeconds(timeoutSeconds));
        try
        {
            return await Task.Run(() => Run(pid, name, v, thread, Math.Max(0, offset), Math.Clamp(limit, 1, MaxListLimit), filter, Math.Clamp(maxFrames, 1, MaxFrames),
                imageDirectories, timeout.Token, imagePath), timeout.Token);
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            throw new ToolError(ErrorCode.Timeout, $"inspecting process {pid} took longer than {timeoutSeconds} s; every handle was closed.",
                "list fewer rows (limit) or fewer frames (maxFrames)") { Details = new { reason = "timeout", pid } };
        }
    }

    private async Task<LiveReport> Run(int pid, string name, string view, string? threadFilter, int offset, int limit, string filter, int maxFrames,
        string? imageDirectories, CancellationToken ct, string? imagePath)
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
            if (runtime == null && live.Modules.Any(m => m.FileName.Equals("GameAssembly.dll", StringComparison.OrdinalIgnoreCase))) runtime = "AOT";
            report = new LiveReport(pid, name, view, live.ImagePath, MinidumpService.ArchName(live.Arch, 0xFFFF), live.Wow64, runtime, AccessList(view == "windows"),
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
                case "windows":
                    report = await Windows(report, session, pid, offset, limit, imagePath, notes, ct);
                    break;
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
                    notes.Add("Threads were not suspended, so frames of a running thread may be stale.");
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

    /// <summary>The refusal of process id 0, the System Idle Process.</summary>
    internal static ToolError IdleProcess() =>
        new(ErrorCode.Unsupported, "Process 0 is the System Idle Process: it has no image, memory or threads of its own to read.", "pass the id or name of a running program")
        { Details = new { reason = "idle_process", pid = 0 } };

    /// <summary>A process id (decimal or 0x hex) or a process name (with or without .exe); a name must match one process.</summary>
    internal static (int Pid, string Name) Resolve(string process)
    {
        var text = (process ?? "").Trim();
        if (text.Length == 0) throw new ToolError(ErrorCode.InvalidArgument, "process is empty.", "pass a process id or a process name (e.g. notepad or notepad.exe)");
        ulong? number = text.StartsWith("0x", StringComparison.OrdinalIgnoreCase) ? NativeAddress.Number(text)
            : text.All(char.IsAsciiDigit) ? (ulong.TryParse(text, out var d) ? d : ulong.MaxValue) : null;
        if (number is { } n)
        {
            if (n == 0) throw IdleProcess();
            if (n > int.MaxValue) throw new ToolError(ErrorCode.InvalidArgument, $"'{text}' is not a valid process id.", "pass a process id or a process name");
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
            if (exact is [{ Id: 0 }]) throw IdleProcess();
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
        // By thread description, one handle per thread, closed at once.
        var named = entries.Take(MinidumpLimits.MaxThreads).Where(e => string.Equals(live.ReadThread(e.Id, context: false).Name, t, StringComparison.OrdinalIgnoreCase)).ToList();
        if (named.Count == 1) return named;
        if (named.Count > 1) throw new ToolError(ErrorCode.Ambiguous, $"{named.Count} threads are named '{t}': {string.Join(", ", named.Select(e => e.Id))}.", "pass the thread id");
        throw new ToolError(ErrorCode.NotFound, $"process {live.Pid} has no thread '{t}'.", "pass a thread id (decimal or 0x hex) or a thread name");
    }

    internal static IReadOnlyList<string> AccessList(bool windows = false) =>
    [
        .. windows ? (string[])["view=windows: UI Automation queries and PrintWindow (WM_PRINT), answered by the program's UI threads; window class data (GetClassLongPtr)"] : [],
        $"process: OpenProcess PROCESS_QUERY_INFORMATION | PROCESS_VM_READ (0x{LiveProcess.ProcessAccess:X})",
        $"each listed thread, one at a time: OpenThread THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION (0x{LiveProcess.ThreadAccess:X})",
        "thread list: system snapshot (CreateToolhelp32Snapshot TH32CS_SNAPTHREAD), no handle to the process",
        "never: memory writes, protection changes, breakpoints, debugger attach, thread suspend/resume/creation, adding code to the process",
    ];

    // The UI Automation tree of the process's visible top-level windows, each window handle joined to its class procedure.
    private async Task<LiveReport> Windows(LiveReport report, MinidumpService.Session session, int pid, int offset, int limit, string? imagePath, List<string> notes, CancellationToken ct)
    {
        var windows = UiAutomation.TopLevelWindows(pid);
        if (windows.Count == 0) notes.Add($"process {pid} has no visible top-level window.");
        var elements = UiAutomation.Read(windows, ct, out var truncated);
        if (truncated) notes.Add($"the tree was cut at {UiAutomation.MaxElements} elements or {UiAutomation.MaxDepth} levels.");
        notes.Add("Procedures are class procedures; another process cannot read a window's own (GWLP_WNDPROC) or dialog (DWLP_DLGPROC) procedure, so a subclassed window's or dialog's own handler is unknown.");
        var symbols = new Dictionary<ulong, string?>();
        async Task<string?> Symbol(ulong address)
        {
            if (address == 0) return null;
            if (!symbols.TryGetValue(address, out var s)) symbols[address] = s = (await dumps.Locate(session, address, false, ct)).Symbol;
            return s;
        }
        var rows = new List<object>();
        foreach (var e in elements.Skip(offset).Take(limit))
        {
            var row = new UiRow(e.Depth, e.ControlType, e.Name, e.AutomationId, e.ClassName, e.Framework, e.Window == 0 ? null : $"0x{e.Window:X}",
                $"{e.X},{e.Y} {e.Width}x{e.Height}", e.Enabled, e.Offscreen);
            if (e.Window != 0)
            {
                var (procedure, id, parent) = UiAutomation.WindowClass(new IntPtr(unchecked((long)e.Window)));
                string? notifies = null;
                if (parent != IntPtr.Zero && UiAutomation.WindowClass(parent).ClassProcedure is var p && p != 0) notifies = await Symbol(p) ?? $"0x{p:X}";
                row = row with
                {
                    ClassProcedure = procedure == 0 ? null : $"0x{procedure:X}", ClassProcedureSymbol = await Symbol(procedure),
                    ControlId = parent != IntPtr.Zero ? id : null, Notifies = notifies,
                };
            }
            rows.Add(row);
        }
        report = report with { Items = rows, Offset = offset, Total = elements.Count };
        if (imagePath == null || windows.Count == 0) return report;
        var image = UiAutomation.Image(windows[0]);
        if (image == null)
        {
            notes.Add("the first window did not draw into an image (PrintWindow failed).");
            return report;
        }
        var path = Path.GetFullPath(imagePath);
        await File.WriteAllBytesAsync(path, image.Value.Png, ct);
        notes.Add($"image of window 0x{windows[0]:X} saved: {path} ({image.Value.Width}x{image.Value.Height}, {image.Value.Png.Length:N0} bytes)");
        return report;
    }

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
