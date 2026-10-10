using System.ComponentModel;
using System.Diagnostics;
using NetDecompilerMcp.Core;
using NetDecompilerMcp.Native;
using NetDecompilerMcp.Native.Dump;
using NetDecompilerMcp.Native.Live;

namespace NetDecompilerMcp.Services;

/// <summary>
/// Read-only inspection of a running local process (Windows): modules, memory regions, threads and their stacks, named
/// as crash dumps are (<see cref="MinidumpService"/>: loaded images' code indexes with user, PDB, Il2Cpp and discovered
/// names, Il2Cpp dummy DLLs, local PDBs, exports). The process is opened for query and read only, threads one at a time
/// for their registers; every handle is closed before the call returns, also on errors, cancellation and timeouts.
/// The guarantee is documented in docs/live-inspection.md.
/// </summary>
public sealed class LiveProcessService(MinidumpService dumps)
{
    public const int DefaultModules = 50, DefaultRegions = 100, DefaultThreads = 20, DefaultFrames = 32;
    public const int MaxFrames = 256, MaxListLimit = 1000, MaxTimeoutSeconds = 120, DefaultTimeoutSeconds = 20;
    private const int MaxCandidates = 20;

    private static readonly string[] Sections = ["modules", "regions", "threads", "stacks"];
    private static readonly string[] RegionFilters = ["committed", "all", "executable", "writable", "image", "private", "mapped"];

    public sealed record RegionRow(
        string Base, string End, string Size,
        [property: Description("commit, reserve or free.")] string State,
        [property: Description("Page protection, e.g. PAGE_EXECUTE_READ; null for reserved and free memory.")] string? Protection,
        [property: Description("image, mapped or private; null for free memory.")] string? Type,
        string? AllocationBase,
        [property: Description("The module whose image holds the region, or null.")] string? Module);

    public sealed record ThreadRow(
        uint Id, string? Name,
        [property: Description("Read from the kernel (NtQueryInformationThread ThreadSuspendCount); inspection never changes it.")] uint? SuspendCount,
        int? Priority, int? BasePriority, string? Teb, string? StackLow, string? StackHigh,
        string? StartAddress,
        [property: Description("module!function of the thread's start address.")] string? StartSymbol,
        string? InstructionPointer, string? StackPointer,
        [property: Description("module!function+0xoffset of the instruction pointer.")] string? Location,
        string? Registers,
        [property: Description("Frames walked (the walk is bounded by maxFrames); 0 when stacks are not requested.")] int FrameCount,
        IReadOnlyList<MinidumpService.StackFrame> Frames,
        [property: Description("Why the walk ended: end_of_stack, max_frames, left_the_stack, no_unwind_data, ...; null when not walked.")] string? StackStop,
        int HeuristicFrames,
        [property: Description("What could not be read for this thread (exited, registers not read), or null.")] string? Error);

    public sealed record LiveReport(
        int ProcessId, string Name, string? Path,
        [property: Description("x64, x86, ARM64: the process's own instruction set (x86 for a WoW64 process).")] string Architecture,
        bool Wow64, string? StartTimeUtc,
        [property: Description("Managed runtime loaded in the process (CoreCLR, CLR, Mono) or Il2Cpp; null for none.")] string? Runtime,
        [property: Description("The handles this call opened, with their access rights: the read-only guarantee.")] IReadOnlyList<string> Access,
        int ModuleCount, int ModulesOffset, bool ModulesTruncated, IReadOnlyList<MinidumpService.ModuleSummary> Modules,
        [property: Description("Regions matching regionFilter (all regions: regionsTotal).")] int RegionCount, int RegionsTotal, string RegionFilter,
        int RegionsOffset, bool RegionsTruncated, IReadOnlyList<RegionRow> Regions,
        int ThreadCount, int ThreadsOffset, bool ThreadsTruncated, IReadOnlyList<ThreadRow> Threads,
        [property: Description("Every handle to the process and its threads was closed before returning.")] bool Detached,
        int HandlesOpened, int HandlesClosed,
        [property: Description("The process was still running when inspection ended.")] bool StillRunning,
        long ElapsedMs,
        [property: Description("Where names and unwind data came from, and what was not covered.")] IReadOnlyList<string> Notes);

    public async Task<LiveReport> Inspect(
        string process, string? sections, string? thread, int modulesOffset, int modulesLimit, int regionsOffset, int regionsLimit, string? regionFilter,
        int threadsOffset, int threadsLimit, int maxFrames, string? imageDirectories, int timeoutSeconds, CancellationToken ct)
    {
        if (!OperatingSystem.IsWindows())
            throw new ToolError(ErrorCode.ProviderUnavailable, "live process inspection uses the Windows process API; this server is not running on Windows.",
                "inspect a minidump instead (open_minidump), or run the server on Windows") { Details = new { reason = "platform_not_windows" } };
        var want = ParseSections(sections);
        string filter = (regionFilter ?? "committed").Trim().ToLowerInvariant();
        if (!RegionFilters.Contains(filter))
            throw new ToolError(ErrorCode.InvalidArgument, $"regionFilter '{regionFilter}' is not one of {string.Join(", ", RegionFilters)}.");
        if (timeoutSeconds < 1 || timeoutSeconds > MaxTimeoutSeconds)
            throw new ToolError(ErrorCode.InvalidArgument, $"timeoutSeconds must be 1-{MaxTimeoutSeconds}.");
        var (pid, name) = Resolve(process);
        var dirsRequested = imageDirectories;
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(TimeSpan.FromSeconds(timeoutSeconds));
        try
        {
            return await Task.Run(() => Run(pid, name, want, thread, modulesOffset, modulesLimit, regionsOffset, regionsLimit, filter,
                threadsOffset, threadsLimit, maxFrames, dirsRequested, timeout.Token), timeout.Token);
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            throw new ToolError(ErrorCode.Timeout, $"inspecting process {pid} took longer than {timeoutSeconds} s; every handle was closed.",
                "list fewer threads (threadsLimit), fewer frames (maxFrames), or leave out stacks / regions") { Details = new { reason = "timeout", pid } };
        }
    }

    private async Task<LiveReport> Run(int pid, string name, HashSet<string> want, string? threadFilter, int modulesOffset, int modulesLimit,
        int regionsOffset, int regionsLimit, string filter, int threadsOffset, int threadsLimit, int maxFrames, string? imageDirectories, CancellationToken ct)
    {
        var clock = Stopwatch.StartNew();
        modulesOffset = Math.Max(0, modulesOffset);
        regionsOffset = Math.Max(0, regionsOffset);
        threadsOffset = Math.Max(0, threadsOffset);
        modulesLimit = Math.Clamp(modulesLimit, 1, MaxListLimit);
        regionsLimit = Math.Clamp(regionsLimit, 1, MaxListLimit);
        threadsLimit = Math.Clamp(threadsLimit, 1, MaxListLimit);
        maxFrames = Math.Clamp(maxFrames, 1, MaxFrames);
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

            var modules = new List<MinidumpService.ModuleSummary>();
            if (want.Contains("modules"))
                foreach (var m in live.Modules.Skip(modulesOffset).Take(modulesLimit))
                {
                    ct.ThrowIfCancellationRequested();
                    modules.Add(MinidumpService.ModuleRow(m, dirs, live.Arch));
                }

            var regionRows = new List<RegionRow>();
            int regionCount = 0, regionsTotal = 0;
            if (want.Contains("regions"))
            {
                var regions = live.Regions(ct);
                regionsTotal = regions.Count;
                var matching = regions.Where(r => Matches(r, filter)).ToList();
                regionCount = matching.Count;
                foreach (var r in matching.Skip(regionsOffset).Take(regionsLimit))
                    regionRows.Add(new RegionRow(Hex(live, r.Base), Hex(live, r.Base + r.Size), $"0x{r.Size:X}", StateName(r.State),
                        r.State == 0x1000 ? MinidumpService.ProtectName(r.Protect) : null, TypeName(r.Type),
                        r.State == 0x10000 ? null : Hex(live, r.AllocationBase), live.ModuleAt(r.Base)?.FileName));
                if (regionsTotal >= MinidumpLimits.MaxMemoryRegions) notes.Add($"only the first {MinidumpLimits.MaxMemoryRegions} regions were read");
            }

            // threads and stacks
            var rows = new List<ThreadRow>();
            int threadCount = 0;
            bool stacks = want.Contains("stacks");
            if (want.Contains("threads") || stacks)
            {
                var entries = live.Threads(ct);
                if (threadFilter is { Length: > 0 }) entries = PickThreads(live, entries, threadFilter);
                threadCount = entries.Count;
                var walker = new StackWalker(live, m => session.Code(m).Image);
                foreach (var e in entries.Skip(threadsOffset).Take(threadsLimit))
                {
                    ct.ThrowIfCancellationRequested();
                    rows.Add(await ThreadRowFor(session, live, walker, e, stacks, maxFrames, ct));
                }
                if (!live.CanReadContexts) notes.Add($"registers and stacks of a {live.Arch} process are not read by this server ({System.Runtime.InteropServices.RuntimeInformation.ProcessArchitecture}).");
                if (stacks && rows.Count > 0)
                    notes.Add("Threads were not suspended: each register context is a snapshot of a running thread, so a frame of a thread that was executing user code may be stale.");
            }
            if (stacks || rows.Count > 0) notes.AddRange(MinidumpService.ModuleNotes(session));
            bool running = live.IsRunning;
            if (!running) notes.Add("the process exited while it was being inspected; reads after that returned nothing.");
            report = new LiveReport(pid, name, live.ImagePath, MinidumpService.ArchName(live.Arch, 0xFFFF), live.Wow64, live.StartTimeUtc?.ToString("u"), runtime,
                AccessList(),
                live.Modules.Count, modulesOffset, want.Contains("modules") && modulesOffset + modules.Count < live.Modules.Count, modules,
                regionCount, regionsTotal, filter, regionsOffset, regionsOffset + regionRows.Count < regionCount, regionRows,
                threadCount, threadsOffset, threadsOffset + rows.Count < threadCount, rows,
                false, 0, 0, running, 0, notes);
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

    private async Task<ThreadRow> ThreadRowFor(MinidumpService.Session s, LiveProcess live, StackWalker walker, LiveThreadEntry e, bool stacks, int maxFrames, CancellationToken ct)
    {
        var t = live.ReadThread(e.Id, context: true);
        string? startSymbol = t.StartAddress is { } sa && sa != 0 ? (await dumps.Locate(s, sa, false, ct)).Symbol : null;
        var ctx = t.Context;
        string? location = ctx != null ? (await dumps.Locate(s, ctx.Ip, false, ct)).Symbol : null;
        IReadOnlyList<MinidumpService.StackFrame> frames = [];
        int frameCount = 0, heuristic = 0;
        string? stop = null;
        if (stacks && ctx != null)
        {
            var walk = walker.Walk(ctx, t.StackLow ?? 0, t.StackHigh ?? 0, maxFrames, ct);
            frames = await dumps.Frames(s, walk, 0, maxFrames, ct);
            frameCount = walk.Frames.Count;
            heuristic = walk.Frames.Count(f => f.Heuristic);
            stop = walk.Stop;
        }
        return new ThreadRow(t.Id, t.Name, t.SuspendCount, t.Priority, t.BasePriority ?? e.BasePriority, Opt(live, t.Teb), Opt(live, t.StackLow), Opt(live, t.StackHigh),
            Opt(live, t.StartAddress), startSymbol, ctx != null ? Hex(live, ctx.Ip) : null, ctx != null ? Hex(live, ctx.Sp) : null, location, ctx?.Format(),
            frameCount, frames, stop, heuristic, t.Error);
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

    private static HashSet<string> ParseSections(string? sections)
    {
        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var text = sections?.Trim();
        if (string.IsNullOrEmpty(text) || text.Equals("all", StringComparison.OrdinalIgnoreCase))
        {
            set.UnionWith(Sections);
            return set;
        }
        foreach (var part in text.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            var p = part.ToLowerInvariant();
            if (!Sections.Contains(p))
                throw new ToolError(ErrorCode.InvalidArgument, $"unknown section '{part}'.", $"pass a comma-separated list of {string.Join(", ", Sections)}, or all");
            set.Add(p);
        }
        if (set.Count == 0) throw new ToolError(ErrorCode.InvalidArgument, "sections is empty.", $"pass a comma-separated list of {string.Join(", ", Sections)}, or all");
        return set;
    }

    internal static IReadOnlyList<string> AccessList() =>
    [
        $"process: OpenProcess PROCESS_QUERY_INFORMATION | PROCESS_VM_READ (0x{LiveProcess.ProcessAccess:X})",
        $"each listed thread, one at a time: OpenThread THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION (0x{LiveProcess.ThreadAccess:X})",
        "thread list: system snapshot (CreateToolhelp32Snapshot TH32CS_SNAPTHREAD), no handle to the process",
        "never: memory writes, protection changes, breakpoints, debugger attach, thread suspend/resume/creation, code injection",
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

    private static string StateName(uint state) => state switch
    {
        0x1000 => "commit",
        0x2000 => "reserve",
        0x10000 => "free",
        _ => $"0x{state:X}",
    };

    private static string? TypeName(uint type) => type switch
    {
        0x1000000 => "image",
        0x40000 => "mapped",
        0x20000 => "private",
        0 => null,
        _ => $"0x{type:X}",
    };

    private static string Hex(LiveProcess p, ulong v) => MinidumpService.Hex(p, v);
    private static string? Opt(LiveProcess p, ulong? v) => v is { } x ? Hex(p, x) : null;
}
