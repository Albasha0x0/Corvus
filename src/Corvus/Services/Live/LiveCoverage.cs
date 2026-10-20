using System.Collections.Concurrent;
using System.Globalization;
using System.Text.Json.Nodes;
using Corvus.Core;
using Corvus.Native;
using Corvus.Native.Code;

namespace Corvus.Services;

/// <summary>
/// A code coverage run: stop points at the start of each function of an image, each stop counted and resumed at once; a
/// point that reaches the hit limit is cleared, so its count reads "at least". A managed run (no <see cref="Image"/>)
/// keys its points by metadata token and records which methods ran, from the runtime's record of the methods it prepared
/// code for, without counts.
/// </summary>
public sealed class LiveCoverageRun
{
    private readonly ConcurrentDictionary<uint, long> _hits = new();
    private readonly ConcurrentDictionary<string, uint> _live = new(StringComparer.Ordinal);
    private string _state = "recording";

    internal LiveCoverageRun(string id, LiveSession session, LoadedNative image, IReadOnlyList<LiveCoveragePoint> points, int hitLimit, ulong moduleBase)
    {
        Id = id;
        Session = session.Id;
        Program = session.Program;
        Image = image;
        ImageId = image.Id;
        Sha256 = image.OriginalSha256;
        Points = points;
        HitLimit = hitLimit;
        ModuleBase = moduleBase;
    }

    internal LiveCoverageRun(string id, LiveSession session, string imageId, string sha256, IReadOnlyList<LiveCoveragePoint> points)
    {
        Id = id;
        Session = session.Id;
        Program = session.Program;
        ImageId = imageId;
        Sha256 = sha256;
        Points = points;
        HitLimit = 1;
    }

    public string Id { get; }
    public string Session { get; }
    public string Program { get; }
    /// <summary>The native image counted; null for a managed run.</summary>
    public LoadedNative? Image { get; }
    public string ImageId { get; }
    public string Sha256 { get; }
    /// <summary>The counted addresses, in address order.</summary>
    public IReadOnlyList<LiveCoveragePoint> Points { get; }
    public int HitLimit { get; }
    internal ulong ModuleBase { get; private set; }
    /// <summary>The module the run waits for, until it loads and the points are set; null once placed.</summary>
    public string? PendingModule { get; private set; }
    /// <summary>Points refused before any was set (too short to count), by RVA.</summary>
    internal IReadOnlyDictionary<uint, string> Refusals { get; init; } = new Dictionary<uint, string>();

    internal void Wait(string module) => PendingModule = module;

    internal void Place(ulong moduleBase)
    {
        ModuleBase = moduleBase;
        PendingModule = null;
    }
    /// <summary>Functions left out because they run at process exit (see DetachCode).</summary>
    public int DetachFunctions { get; init; }
    public DateTime Started { get; } = DateTime.UtcNow;
    public DateTime? Stopped { get; private set; }

    /// <summary>recording, complete (stopped) or ended (the session ended first).</summary>
    public string State { get { lock (_live) return _state; } }

    private readonly ConcurrentDictionary<uint, string> _unplaced = new();

    public long HitsAt(uint rva) => _hits.GetValueOrDefault(rva);

    /// <summary>The points whose stop point was set; the others are left out of every count.</summary>
    public IReadOnlyList<LiveCoveragePoint> Placed => [.. Points.Where(p => !_unplaced.ContainsKey(p.Rva))];

    /// <summary>Points left out of every count, with the reason.</summary>
    public IReadOnlyDictionary<uint, string> Unplaced => _unplaced;

    internal void Refused(string pointId, uint rva, string reason)
    {
        _live.TryRemove(pointId, out _);
        _unplaced[rva] = reason;
    }

    /// <summary>Points that ran at least once.</summary>
    public int Ran => _hits.Count;

    private readonly ConcurrentDictionary<string, byte> _exits = new(StringComparer.Ordinal);

    internal void Arm(string pointId, uint rva) => _live[pointId] = rva;

    /// <summary>A stop point at one of the program's exit functions: when hit, every point of the session is cleared.</summary>
    internal void ArmExit(string pointId) => _exits[pointId] = 0;

    internal bool IsExit(string pointId) => _exits.ContainsKey(pointId);

    /// <summary>A managed run: records the methods that have run so far; with wait, after a read in progress ends (a last read before the run is complete).</summary>
    internal Func<bool, Task>? Sample { get; set; }
    internal Timer? Sampler { get; set; }
    private readonly SemaphoreSlim _sampling = new(1, 1);

    /// <summary>Runs <paramref name="read"/> unless one is in progress; with <paramref name="wait"/>, after it ends.</summary>
    internal async Task SampleAsync(Func<Task> read, bool wait)
    {
        if (!await _sampling.WaitAsync(wait ? Timeout.Infinite : 0).ConfigureAwait(false)) return;
        try { await read().ConfigureAwait(false); }
        finally { _sampling.Release(); }
    }

    // a read that ends after the run is complete adds nothing: the report already counted
    internal void MarkRan(uint token)
    {
        lock (_live)
            if (_state == "recording") _hits.TryAdd(token, 1);
    }

    internal IReadOnlyList<string> ExitPoints => [.. _exits.Keys];

    internal IReadOnlyList<string> Armed => [.. _live.Keys, .. _exits.Keys];

    /// <summary>The function starts whose stop point is still set.</summary>
    internal IReadOnlyList<uint> ArmedRvas => [.. _live.Values];

    /// <summary>Counts one stop; true when the point just reached the hit limit and is to be cleared.</summary>
    internal bool Hit(string pointId)
    {
        if (!_live.TryGetValue(pointId, out var rva)) return false;
        var n = _hits.AddOrUpdate(rva, 1, (_, c) => c + 1);
        return n >= HitLimit && _live.TryRemove(pointId, out _);
    }

    internal void Retire(string pointId)
    {
        _live.TryRemove(pointId, out _);
        _exits.TryRemove(pointId, out _);
    }

    internal void Finish(string state)
    {
        lock (_live)
        {
            if (_state != "recording") return;
            _state = state;
            Stopped = DateTime.UtcNow;
        }
        Sampler?.Dispose();
    }
}

/// <summary>A counted address: the RVA of a function start (a managed method's metadata token) and the function's name.</summary>
public sealed record LiveCoveragePoint(uint Rva, string Name);

public sealed partial class LiveSessionService
{
    /// <summary>Stop points one run may place.</summary>
    public const int MaxCoveragePoints = 5_000;
    /// <summary>The cap a run checks; tests lower it.</summary>
    internal int CoverageLimit { get; set; } = MaxCoveragePoints;
    private readonly ConcurrentDictionary<string, LiveCoverageRun> _coverage = new(StringComparer.OrdinalIgnoreCase);
    private int _nextCoverage;

    /// <summary>Tests: runs just before a coverage run is created.</summary>
    internal Func<Task>? BeforeCoverageRun { get; set; }

    public IReadOnlyList<LiveCoverageRun> CoverageRuns => _coverage.Values.OrderBy(r => int.Parse(r.Id[4..], CultureInfo.InvariantCulture)).ToList();

    public LiveCoverageRun GetCoverage(string id) =>
        _coverage.TryGetValue(id?.Trim() ?? "", out var r) ? r
            : throw new ToolError(ErrorCode.NotFound, $"No coverage run '{id}'.", "live_coverage action=list shows the runs; action=start begins one");

    /// <summary>
    /// Starts counting the functions of the program's image (or of module in "module!part") whose name contains
    /// <paramref name="match"/>.
    /// </summary>
    public async Task<LiveCoverageRun> StartCoverageAsync(LiveSession session, string? match, int hitLimit, CancellationToken ct)
    {
        string? module = null;
        if (match?.IndexOf('!') is > 0 and var bang) (module, match) = (match[..bang].Trim(), match[(bang + 1)..]);
        Live(session);
        await IndexedAsync(session, TimeSpan.FromSeconds(60), ct).ConfigureAwait(false);
        if (!string.IsNullOrWhiteSpace(module)) await RefreshModulesAsync(session, ct).ConfigureAwait(false);
        LiveModuleState? m;
        lock (session.Modules)
            m = string.IsNullOrWhiteSpace(module) ? session.Modules.FirstOrDefault() : session.Modules.FirstOrDefault(x => ModuleNamed(x, module));
        // a managed assembly, loaded or the program's own still to load
        var managed = m != null ? (Match(m) == null ? Managed(m.Path) : null)
            : string.IsNullOrWhiteSpace(module) ? null : AssemblyToLoad(session, module.Trim());
        if (managed != null) return await StartManagedCoverageAsync(session, managed, match, ct).ConfigureAwait(false);
        LoadedNative image;
        if (m != null)
        {
            LoadedNative? own = null;
            try { own = ImageOf(m); }
            catch (ToolError) { /* the error below names the file */ }
            image = own ?? throw new ToolError(ErrorCode.Unsupported, $"{m.Name}'s image ({m.Path}) cannot be found or read as a native image, so it has no static functions to count.",
                "count another module with match=<module>!<part>, or set stop points by live address (live_break at=0x...)");
        }
        else if (string.IsNullOrWhiteSpace(module)) throw new ToolError(ErrorCode.NotFound, "The program has no modules yet.", "live_session action=status lists its modules");
        else
            // a module the program loads later (a plug-in, a runtime) is counted from its first call, as a deferred stop point is set
            image = workspace.Natives.FirstOrDefault(n => n.SliceName == null && ModuleNamed(n.FilePath, module))
                    ?? throw new ToolError(ErrorCode.NotFound, $"The program has no module '{module}', and no loaded image is named so.",
                        "live_session action=status lists its modules; for one the program loads later, load_assembly path=<its file>, then start again: the run waits for it to load");
        var idx = code.Ready(image) ?? await code.Index(image, null, ct).ConfigureAwait(false);
        var filter = string.IsNullOrWhiteSpace(match) ? null : match.Trim();
        match = filter;
        var detach = DetachCode(image, idx);
        List<LiveCoveragePoint> points = [.. idx.Functions.Where(f => (f.Flags & FunctionFlags.Thunk) == 0 && !detach.Contains(f.Start))
            .Select(f => (f, Name: idx.NameAt(f.Start) ?? f.Name))
            .Where(x => filter == null || x.Name.Contains(filter, StringComparison.OrdinalIgnoreCase))
            .OrderBy(x => x.f.Start).Select(x => new LiveCoveragePoint(x.f.Start, x.Name))];
        // a function whose first block is shorter than this is refused, not counted
        var minBlock = MinCountableBlock(image.Image.Arch);
        var refused = new Dictionary<uint, string>();
        foreach (var p in points)
            if (idx.FunctionAt(p.Rva) is { } f && f.Size < 64 && idx.GetGraph(f, ct).Blocks.FirstOrDefault(b => b.Start == f.Start) is { } first)
            {
                if (first.End - first.Start < minBlock) refused[p.Rva] = "too short to count with stop-based coverage";
                // the stop point lands where the jump leads: through a CFG dispatch pointer, every indirect call of the process
                else if (first.InstructionCount == 1 && first.EndKind is BlockEnd.Jump or BlockEnd.IndirectJump or BlockEnd.TailCall)
                    refused[p.Rva] = "a single jump: its runs are counted at the function it leads to";
            }
        if (points.Count == 0)
            throw new ToolError(ErrorCode.NotFound, $"No function of {image.Id}{(match != null ? $" has a name containing '{match.Trim()}'" : " is indexed")}.", "list_functions shows the image's functions");
        if (points.Count > CoverageLimit)
        {
            var narrower = NarrowerMatches([.. points.Select(p => p.Name)], filter, CoverageLimit);
            var prefix = string.IsNullOrWhiteSpace(module) ? "" : module.Trim() + "!";
            throw new ToolError(ErrorCode.LimitExceeded,
                $"{points.Count:N0} functions of {image.Id}{(filter != null ? $" have a name containing '{filter}'" : "")}; a run counts at most {CoverageLimit:N0}.",
                narrower.Count > 0
                    ? "narrow it: " + string.Join(", ", narrower.Select(n => $"match={prefix}{n.Match} ({n.Count:N0})")) + ", or module!part for another module"
                    : "narrow it with match=<part of the names>, or module!part for another module");
        }

        if (BeforeCoverageRun is { } before) await before().ConfigureAwait(false);
        var run = new LiveCoverageRun("cov-" + Interlocked.Increment(ref _nextCoverage), session, image, points, hitLimit, m?.Base ?? 0) { DetachFunctions = detach.Count, Refusals = refused };
        _coverage[run.Id] = run;
        if (m != null)
        {
            await ArmCoverageAsync(session, run, ct).ConfigureAwait(false);
            EndedMeanwhile(session, run);
            return run;
        }
        run.Wait(module!.Trim());
        // known before the load, so the start reply counts what will be set
        for (int i = 0; i < points.Count; i++)
            if (refused.TryGetValue(points[i].Rva, out var reason)) run.Refused($"{run.Id}.{i + 1}", points[i].Rva, reason);
        // the worker holds the module's loading thread until the points are set; one without the op sets them after its first calls
        try { await session.Worker.RequestAsync("defer_module", new JsonObject { ["name"] = run.PendingModule }, RequestTimeout, ct).ConfigureAwait(false); }
        catch (ToolError) { }
        return run;
    }

    /// <summary>
    /// Up to <paramref name="take"/> matches within <paramref name="limit"/> functions, broadest first: name prefixes cut
    /// after a "::", "." or "_" (namespaces, classes, library prefixes) and, for unnamed functions, sub_ address prefixes.
    /// Each contains <paramref name="filter"/>, so it narrows the match given.
    /// </summary>
    internal static List<(string Match, int Count)> NarrowerMatches(IReadOnlyList<string> names, string? filter, int limit, int take = 5)
    {
        const int MaxDepth = 4;
        var starts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        foreach (var name in names)
        {
            int from = filter == null ? 0 : name.IndexOf(filter, StringComparison.OrdinalIgnoreCase) + filter.Length;
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            void Add(int end)
            {
                if (end >= from && end < name.Length && seen.Add(name[..end])) starts[name[..end]] = starts.GetValueOrDefault(name[..end]) + 1;
            }
            if (name.StartsWith("sub_", StringComparison.OrdinalIgnoreCase))
                for (int end = 5; end < name.Length; end++) Add(end);
            else
                for (int i = 0, depth = 0; i < name.Length - 1 && depth < MaxDepth; i++)
                {
                    int cut = name[i] is '.' or '_' ? i + 1 : name[i] == ':' && name[i + 1] == ':' ? i + 2 : -1;
                    if (cut < 0) continue;
                    Add(cut);
                    depth++;
                    i = cut - 1;
                }
        }
        var chosen = new List<(string Match, int Count)>();
        // a prefix count is a floor: a match is a substring, so the count shown is the one a run would place
        foreach (var (match, _) in starts.Where(s => s.Value is > 1 and var n && n <= limit).OrderByDescending(s => s.Value).ThenBy(s => s.Key, StringComparer.Ordinal))
        {
            if (chosen.Count == take) break;
            if (chosen.Any(c => match.StartsWith(c.Match, StringComparison.OrdinalIgnoreCase))) continue;
            int count = names.Count(n => n.Contains(match, StringComparison.OrdinalIgnoreCase));
            if (count <= limit) chosen.Add((match, count));
        }
        return chosen;
    }

    /// <summary>Sets the run's stop points where its module is loaded (<see cref="LiveCoverageRun.ModuleBase"/>).</summary>
    private async Task ArmCoverageAsync(LiveSession session, LiveCoverageRun run, CancellationToken ct)
    {
        var (points, moduleBase) = (run.Points, run.ModuleBase);
        var refused = new Dictionary<uint, string>(run.Refusals);
        // a hook at the start rewrites its first bytes, so a stop point or watch already inside them would be corrupted
        List<(string Id, ulong Address)> occupied;
        lock (session.StopPoints) occupied = [.. session.StopPoints.Values.Select(p => (p.Id, p.Address))];
        lock (session.Watches) occupied.AddRange(session.Watches.Values.Where(w => !w.Cleared).Select(w => (w.Id, w.Address)));
        foreach (var p in points)
            if (occupied.FirstOrDefault(o => o.Address > moduleBase + p.Rva && o.Address < moduleBase + p.Rva + WatchPatchBytes) is { Id: { } inside } o)
                refused[p.Rva] = $"{inside} sits {o.Address - (moduleBase + p.Rva)} bytes in, inside the bytes a hook at the start rewrites";
        try
        {
            for (int i = 0; i < points.Count; i++)
            {
                var id = $"{run.Id}.{i + 1}";
                if (refused.TryGetValue(points[i].Rva, out var reason))
                {
                    run.Refused(id, points[i].Rva, reason);
                    continue;
                }
                run.Arm(id, points[i].Rva);
                session.CoveragePoints[id] = run;
                try { await session.Worker.RequestAsync("set", new JsonObject { ["id"] = id, ["address"] = $"0x{moduleBase + points[i].Rva:X}", ["bare"] = true }, RequestTimeout, ct).ConfigureAwait(false); }
                catch (ToolError e) when (e.Code is ErrorCode.Failed or ErrorCode.InvalidArgument or ErrorCode.Unsupported or ErrorCode.NotFound) { run.Refused(id, points[i].Rva, "the stop point was refused: " + e.Message); }
            }
        }
        catch
        {
            await StopCoverageAsync(session, run, CancellationToken.None).ConfigureAwait(false);
            throw;
        }
        var image = run.Image!; // a managed run arms no points
        var idx = code.Ready(image) ?? await code.Index(image, null, ct).ConfigureAwait(false);
        int n = 0;
        foreach (var f in idx.Functions.Where(f => ExitFunctions.Contains(idx.NameAt(f.Start) ?? f.Name)))
        {
            var id = $"{run.Id}.exit{++n}";
            run.ArmExit(id);
            session.CoveragePoints[id] = run;
            try { await session.Worker.RequestAsync("set", new JsonObject { ["id"] = id, ["address"] = $"0x{moduleBase + f.Start:X}", ["bare"] = true }, RequestTimeout, ct).ConfigureAwait(false); }
            catch (ToolError e) when (e.Code is ErrorCode.Failed or ErrorCode.InvalidArgument or ErrorCode.Unsupported) { run.Retire(id); }
        }
    }

    /// <summary>Places the runs waiting for <paramref name="module"/>; returns the module names they waited under.</summary>
    private async Task<IReadOnlyList<string>> PlaceCoverageAsync(LiveSession session, LiveModuleState module)
    {
        var due = _coverage.Values.Where(r => r.Session == session.Id && r.State == "recording" && r.PendingModule is { } name && ModuleNamed(module, name)).ToList();
        var names = due.Select(r => r.PendingModule!).ToList();
        foreach (var run in due)
        {
            run.Place(module.Base);
            if (Match(module) is { } image && image.OriginalSha256 != run.Sha256)
            {
                for (int i = 0; i < run.Points.Count; i++)
                    run.Refused($"{run.Id}.{i + 1}", run.Points[i].Rva, $"{module.Name} loaded from {module.Path}, another build than the counted image");
                session.Add("error", null, module.Base, $"coverage run {run.Id} counts nothing: {module.Name} loaded from {module.Path}, another build than {run.Image?.FilePath}");
                continue;
            }
            try
            {
                await ArmCoverageAsync(session, run, CancellationToken.None).ConfigureAwait(false);
                session.Add("module", null, module.Base, $"coverage run {run.Id} set {run.Placed.Count:N0} stop point(s) ({module.Name} loaded)");
            }
            catch (Exception e) when (e is ToolError or TimeoutException or OperationCanceledException)
            {
                session.Add("error", null, null, $"coverage run {run.Id} could not be set when {module.Name} loaded: {e.Message}");
            }
        }
        return names;
    }

    /// <summary>A run whose program ended while it started missed the exit that ends runs: it is ended here.</summary>
    private static void EndedMeanwhile(LiveSession session, LiveCoverageRun run)
    {
        if (session.Ended != null) run.Finish("ended");
    }

    private static readonly TimeSpan ManagedSamplePeriod = TimeSpan.FromSeconds(1);

    /// <summary>
    /// Starts recording which methods of a managed assembly run: the runtime's record of the methods it prepared code for,
    /// read each second and when the program exits (its exiting thread is held at RtlExitUserProcess meanwhile).
    /// </summary>
    private async Task<LiveCoverageRun> StartManagedCoverageAsync(LiveSession session, LoadedAssembly asm, string? match, CancellationToken ct)
    {
        var file = Path.GetFileName(asm.FilePath);
        if (!OperatingSystem.IsWindows())
            throw new ToolError(ErrorCode.Unsupported, $"{file} is a managed assembly; its coverage is read from the runtime on Windows only.", "count a native module with match=module!part");
        var filter = string.IsNullOrWhiteSpace(match) ? null : match.Trim();
        var points = workspace.Read(() => asm.Module.GetTypes().SelectMany(t => t.Methods).Where(x => x.HasBody)
            .Select(x => new LiveCoveragePoint(x.MDToken.Raw, Format.MemberLabel(x)))
            .Where(p => filter == null || p.Name.Contains(filter, StringComparison.OrdinalIgnoreCase)).OrderBy(p => p.Rva).ToList());
        if (points.Count == 0)
            throw new ToolError(ErrorCode.NotFound, $"No method of {file}{(filter != null ? $" has a name containing '{filter}'" : " has a body")}.", "search_symbols shows the assembly's methods");
        if (await ClrAsync(session, ct).ConfigureAwait(false) is { Unavailable: { } reason } && !reason.StartsWith("load_failed", StringComparison.Ordinal))
            throw new ToolError(ErrorCode.Unsupported, $"The program's runtime cannot be read: {reason}.", "count a native module with match=module!part");
        if (BeforeCoverageRun is { } before) await before().ConfigureAwait(false);
        var run = new LiveCoverageRun("cov-" + Interlocked.Increment(ref _nextCoverage), session, file, asm.OriginalSha256, points);
        var tokens = points.Select(p => p.Rva).ToHashSet();
        var path = asm.FilePath;
        run.Sample = wait => run.SampleAsync(async () =>
        {
            try
            {
                if (run.State == "recording" && await ClrAsync(session, CancellationToken.None).ConfigureAwait(false) is { Unavailable: null } clr)
                    foreach (var token in clr.Prepared(path))
                        if (tokens.Contains(token)) run.MarkRan(token);
            }
            catch (Exception e) when (e is ToolError or InvalidOperationException or ObjectDisposedException or OperationCanceledException) { }
        }, wait);
        _coverage[run.Id] = run;
        try
        {
            var exit = await ResolveNativeAsync(session, "ntdll!RtlExitUserProcess", ct).ConfigureAwait(false);
            var id = $"{run.Id}.exit1";
            run.ArmExit(id);
            session.CoveragePoints[id] = run;
            try { await session.Worker.RequestAsync("set", new JsonObject { ["id"] = id, ["address"] = $"0x{exit:X}" }, RequestTimeout, ct).ConfigureAwait(false); }
            catch (ToolError e) when (e.Code is ErrorCode.Failed or ErrorCode.InvalidArgument or ErrorCode.Unsupported) { run.Retire(id); }
        }
        catch (ToolError e) when (e.Code is ErrorCode.NotFound or ErrorCode.Unsupported) { } // then the methods of the last second before exit are missed
        await run.Sample(true).ConfigureAwait(false);
        run.Sampler = new Timer(_ => _ = run.Sample(false), null, ManagedSamplePeriod, ManagedSamplePeriod);
        EndedMeanwhile(session, run);
        return run;
    }

    /// <summary>
    /// Functions reachable from the TLS callbacks (and a DLL's entry point): they also run at process exit, after the
    /// program's other threads have ended, where a held thread could never be resumed.
    /// </summary>
    private static HashSet<uint> DetachCode(LoadedNative image, NativeCodeIndex index)
    {
        var seen = new HashSet<uint>();
        if (image.Image is not Native.Pe.PeFile pe) return seen;
        var work = new Stack<uint>(pe.TlsCallbackRvas);
        if (pe.IsDll && pe.EntryPointRva != 0) work.Push(pe.EntryPointRva);
        while (work.Count > 0)
            if (index.FunctionAt(work.Pop()) is { } f && seen.Add(f.Start))
                foreach (var c in index.Callees(f))
                    if (c.Function is { } callee && !seen.Contains(callee.Start)) work.Push(callee.Start);
        return seen;
    }

    /// <summary>Static calls between the given functions of the run's image, as caller and callee RVAs.</summary>
    public async Task<IReadOnlyList<(uint From, uint To)>> CoverageCallsAsync(LiveCoverageRun run, IReadOnlySet<uint> among, CancellationToken ct)
    {
        var image = run.Image ?? throw new ToolError(ErrorCode.Unsupported, $"{run.Id} records managed methods: it has no static call graph to draw.", "format=text");
        var idx = code.Ready(image) ?? await code.Index(image, null, ct).ConfigureAwait(false);
        var edges = new HashSet<(uint, uint)>();
        foreach (var rva in among)
            if (idx.FunctionAt(rva) is { } f && f.Start == rva)
                foreach (var c in idx.Callees(f, CallEdgeFilter.Direct))
                    if (c.Function is { } callee && among.Contains(callee.Start)) edges.Add((rva, callee.Start));
        return [.. edges.OrderBy(e => e.Item1).ThenBy(e => e.Item2)];
    }

    /// <summary>Clears the run's points that are still set (a managed run reads the runtime a last time); its counts stay.</summary>
    public async Task StopCoverageAsync(LiveSession session, LiveCoverageRun run, CancellationToken ct)
    {
        if (run.Sample is { } sample && session.Ended == null) await sample(true).ConfigureAwait(false);
        await ClearPoints(session, run, "complete", ct).ConfigureAwait(false);
    }

    private static async Task ClearPoints(LiveSession session, LiveCoverageRun run, string state, CancellationToken ct = default)
    {
        run.Finish(state);
        foreach (var id in run.Armed)
        {
            run.Retire(id);
            if (session.Closed || session.Ended != null || !session.Worker.IsAlive) continue;
            try { await session.Worker.RequestAsync("clear", new JsonObject { ["id"] = id }, RequestTimeout, ct).ConfigureAwait(false); }
            catch (ToolError) { /* the session ended meanwhile */ }
        }
    }

    /// <summary>Minimum block length a stop-based run can count, per architecture.</summary>
    private static uint MinCountableBlock(NativeArch arch) => arch switch { NativeArch.X86 or NativeArch.X64 => 5, NativeArch.Arm => 8, _ => 16 };

    /// <summary>The C runtime's exit functions as an image links them in.</summary>
    private static readonly HashSet<string> ExitFunctions = new(StringComparer.Ordinal) { "exit", "_exit", "_Exit", "quick_exit", "_cexit", "_c_exit", "abort" };

    /// <summary>Resumes a thread held at a coverage point.</summary>
    private static async Task Resume(LiveSession session, long? thread)
    {
        // the resume can reach the worker before it has the stop's thread as held: then it resumes nothing, and is sent again
        for (int attempt = 0; attempt < 200 && !session.Closed && session.Ended == null; attempt++)
        {
            var args = new JsonObject();
            if (thread != null) args["thread"] = thread;
            var r = await session.Worker.RequestAsync("resume", args, RequestTimeout, CancellationToken.None).ConfigureAwait(false);
            if (thread == null || r.GetProperty("resumed").EnumerateArray().Any(x => x.GetInt64() == thread)) return;
            await Task.Delay(Math.Min(50, 1 + attempt)).ConfigureAwait(false);
        }
    }

    /// <summary>A stop at a coverage point: counted, the thread resumed at once, the point cleared at the hit limit.</summary>
    private static void CoverageStop(LiveSession session, LiveCoverageRun run, string point, long? thread)
    {
        if (run.IsExit(point))
        {
            _ = Task.Run(async () =>
            {
                try
                {
                    // past exit nothing resumes a held thread, so every point goes before this one resumes; managed runs read the runtime first
                    var runs = session.CoveragePoints.Values.Distinct().ToList();
                    foreach (var r in runs)
                        if (r.Sample is { } sample) await sample(true).ConfigureAwait(false);
                    foreach (var r in runs) await ClearPoints(session, r, "complete").ConfigureAwait(false);
                    await Resume(session, thread).ConfigureAwait(false);
                }
                catch (Exception e) when (e is ToolError or InvalidOperationException or ObjectDisposedException) { /* the session ended meanwhile */ }
            });
            return;
        }
        // a stop that raced the clear is resumed uncounted: the id stays mapped to its run
        bool retire = run.Hit(point);
        // events arrive on the worker's reader thread, which also reads the responses: requests go out from another
        _ = Task.Run(async () =>
        {
            try
            {
                if (retire) await session.Worker.RequestAsync("clear", new JsonObject { ["id"] = point }, RequestTimeout, CancellationToken.None).ConfigureAwait(false);
                await Resume(session, thread).ConfigureAwait(false);
            }
            catch (Exception e) when (e is ToolError or InvalidOperationException or ObjectDisposedException) { /* the session ended meanwhile */ }
        });
    }

    private void EndCoverage(LiveSession session)
    {
        foreach (var run in _coverage.Values.Where(r => r.Session == session.Id)) run.Finish("ended");
        session.CoveragePoints.Clear();
    }
}
