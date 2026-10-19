using System.Collections.Concurrent;
using System.Globalization;
using System.Text.Json.Nodes;
using Corvus.Core;
using Corvus.Native;
using Corvus.Native.Code;

namespace Corvus.Services;

/// <summary>
/// A code coverage run: stop points at the start of each function of an image, each stop counted and resumed at once; a
/// point that reaches the hit limit is cleared, so its count reads "at least".
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

    public string Id { get; }
    public string Session { get; }
    public string Program { get; }
    public LoadedNative Image { get; }
    public string ImageId { get; }
    public string Sha256 { get; }
    /// <summary>The counted addresses, in address order.</summary>
    public IReadOnlyList<LiveCoveragePoint> Points { get; }
    public int HitLimit { get; }
    internal ulong ModuleBase { get; }
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
    }
}

/// <summary>A counted address: the RVA of a function start and the function's name.</summary>
public sealed record LiveCoveragePoint(uint Rva, string Name);

public sealed partial class LiveSessionService
{
    /// <summary>Stop points one run may place.</summary>
    public const int MaxCoveragePoints = 5_000;
    private readonly ConcurrentDictionary<string, LiveCoverageRun> _coverage = new(StringComparer.OrdinalIgnoreCase);
    private int _nextCoverage;

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
        LiveModuleState m;
        lock (session.Modules)
            m = (string.IsNullOrWhiteSpace(module) ? session.Modules.FirstOrDefault()
                    : session.Modules.FirstOrDefault(x => x.Name.Equals(module.Trim(), StringComparison.OrdinalIgnoreCase)
                                                          || Path.GetFileNameWithoutExtension(x.Name).Equals(module.Trim(), StringComparison.OrdinalIgnoreCase)))
                ?? throw new ToolError(ErrorCode.NotFound, $"The program has no module '{module}'.", "live_session action=status lists its modules");
        var image = Match(m) ?? throw new ToolError(ErrorCode.Unsupported, $"{m.Name} matches no loaded image, so it has no static functions to count.", $"load_assembly path={m.Path}");
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
        // a hook at the start rewrites its first bytes, so a stop point or watch already inside them would be corrupted
        List<(string Id, ulong Address)> occupied;
        lock (session.StopPoints) occupied = [.. session.StopPoints.Values.Select(p => (p.Id, p.Address))];
        lock (session.Watches) occupied.AddRange(session.Watches.Values.Where(w => !w.Cleared).Select(w => (w.Id, w.Address)));
        foreach (var p in points)
            if (occupied.FirstOrDefault(o => o.Address > m.Base + p.Rva && o.Address < m.Base + p.Rva + WatchPatchBytes) is { Id: { } inside } o)
                refused[p.Rva] = $"{inside} sits {o.Address - (m.Base + p.Rva)} bytes in, inside the bytes a hook at the start rewrites";
        if (points.Count == 0)
            throw new ToolError(ErrorCode.NotFound, $"No function of {image.Id}{(match != null ? $" has a name containing '{match.Trim()}'" : " is indexed")}.", "list_functions shows the image's functions");
        if (points.Count > MaxCoveragePoints)
            throw new ToolError(ErrorCode.LimitExceeded, $"{image.Id} has {points.Count:N0} functions; a run counts at most {MaxCoveragePoints:N0}.",
                "narrow it with match=<part of the names>, or module!part for another module");

        var run = new LiveCoverageRun("cov-" + Interlocked.Increment(ref _nextCoverage), session, image, points, hitLimit, m.Base) { DetachFunctions = detach.Count };
        _coverage[run.Id] = run;
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
                try { await session.Worker.RequestAsync("set", new JsonObject { ["id"] = id, ["address"] = $"0x{m.Base + points[i].Rva:X}" }, RequestTimeout, ct).ConfigureAwait(false); }
                catch (ToolError e) when (e.Code is ErrorCode.Failed or ErrorCode.InvalidArgument or ErrorCode.Unsupported or ErrorCode.NotFound) { run.Refused(id, points[i].Rva, "the stop point was refused: " + e.Message); }
            }
        }
        catch
        {
            await StopCoverageAsync(session, run, CancellationToken.None).ConfigureAwait(false);
            throw;
        }
        int n = 0;
        foreach (var f in idx.Functions.Where(f => ExitFunctions.Contains(idx.NameAt(f.Start) ?? f.Name)))
        {
            var id = $"{run.Id}.exit{++n}";
            run.ArmExit(id);
            session.CoveragePoints[id] = run;
            try { await session.Worker.RequestAsync("set", new JsonObject { ["id"] = id, ["address"] = $"0x{m.Base + f.Start:X}" }, RequestTimeout, ct).ConfigureAwait(false); }
            catch (ToolError e) when (e.Code is ErrorCode.Failed or ErrorCode.InvalidArgument or ErrorCode.Unsupported) { run.Retire(id); }
        }
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
        var idx = code.Ready(run.Image) ?? await code.Index(run.Image, null, ct).ConfigureAwait(false);
        var edges = new HashSet<(uint, uint)>();
        foreach (var rva in among)
            if (idx.FunctionAt(rva) is { } f && f.Start == rva)
                foreach (var c in idx.Callees(f, CallEdgeFilter.Direct))
                    if (c.Function is { } callee && among.Contains(callee.Start)) edges.Add((rva, callee.Start));
        return [.. edges.OrderBy(e => e.Item1).ThenBy(e => e.Item2)];
    }

    /// <summary>Clears the run's points that are still set; its counts stay.</summary>
    public Task StopCoverageAsync(LiveSession session, LiveCoverageRun run, CancellationToken ct) => ClearPoints(session, run, "complete", ct);

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
                    // past exit nothing resumes a held thread, so every point goes before this one resumes
                    foreach (var r in session.CoveragePoints.Values.Distinct()) await ClearPoints(session, r, "complete").ConfigureAwait(false);
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
