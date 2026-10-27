using System.Collections.Concurrent;
using System.Globalization;
using Corvus.Core;
using Corvus.Native.Diagnostics;

namespace Corvus.Services;

/// <summary>An entry of a timeline with its sequence number, the cursor live_timeline pages by.</summary>
public sealed record LiveTimelineEntry(long Sequence, DateTime Time, string Category, string Name, int? ProcessId = null);

/// <summary>An activity trace of a session's program from the OS diagnostics channel, as a bounded ring of entries.</summary>
public sealed class LiveTimelineRun
{
    public const int Capacity = 100_000;
    private readonly Queue<LiveTimelineEntry> _ring = new();
    private long _sequence;
    private string _state = "recording";

    internal LiveTimelineRun(string id, LiveSession session, string source)
    {
        Id = id;
        Session = session.Id;
        // An attached program is named by its image, not the id it was attached by.
        lock (session.Modules) Program = session.Modules.FirstOrDefault()?.Path is { Length: > 0 } image ? image : session.Program;
        ProcessId = session.ProcessId;
        Source = source;
    }

    public string Id { get; }
    public string Session { get; }
    public string Program { get; }
    public int ProcessId { get; }
    /// <summary>The diagnostics channel, as the platform names it.</summary>
    public string Source { get; }
    public DateTime Started { get; } = DateTime.UtcNow;
    public DateTime? Stopped { get; private set; }
    internal IActivityTrace? Trace { get; set; }
    internal Task? Stopping { get; set; }

    /// <summary>recording or complete.</summary>
    public string State { get { lock (_ring) return _state; } }

    /// <summary>Entries the ring dropped, oldest first.</summary>
    public long Dropped { get; private set; }

    public long Count { get { lock (_ring) return _sequence; } }

    internal void Add(ActivityEntry e)
    {
        lock (_ring)
        {
            _ring.Enqueue(new LiveTimelineEntry(++_sequence, e.Time, e.Category, e.Name, e.ProcessId));
            if (_ring.Count > Capacity)
            {
                _ring.Dequeue();
                Dropped++;
            }
        }
    }

    /// <summary>Entries from <paramref name="from"/> (a sequence) on, filtered; the first sequence kept tells what was dropped, More that a match follows the page.</summary>
    public (IReadOnlyList<LiveTimelineEntry> Entries, long FirstKept, long Last, bool More) Page(long from, string? category, string? match, int limit)
    {
        lock (_ring)
        {
            var first = _ring.Count > 0 ? _ring.Peek().Sequence : _sequence + 1;
            var rows = Kept(category, match).Where(e => e.Sequence >= from).Take(limit + 1).ToList();
            var more = rows.Count > limit;
            if (more) rows.RemoveAt(limit);
            return (rows, first, _sequence, more);
        }
    }

    /// <summary>The entries kept, filtered by category and a part of the name.</summary>
    public IReadOnlyList<LiveTimelineEntry> Entries(string? category, string? match)
    {
        lock (_ring) return Kept(category, match).ToList();
    }

    private IEnumerable<LiveTimelineEntry> Kept(string? category, string? match) =>
        _ring.Where(e => (category == null || e.Category == category) && (match == null || e.Name.Contains(match, StringComparison.OrdinalIgnoreCase)));

    internal void Finish()
    {
        lock (_ring)
        {
            if (_state != "recording") return;
            _state = "complete";
            Stopped = DateTime.UtcNow;
        }
    }
}

public sealed partial class LiveSessionService
{
    /// <summary>The categories an entry has.</summary>
    public static readonly IReadOnlyList<string> TimelineCategories = ["file", "registry", "network", "process"];
    private readonly ConcurrentDictionary<string, LiveTimelineRun> _timelines = new(StringComparer.OrdinalIgnoreCase);
    private int _nextTimeline;

    /// <summary>The diagnostics channel timelines read.</summary>
    public IActivityTraceSource ActivitySource { get; set; } = ActivityTraceSources.ForThisMachine();

    public IReadOnlyList<LiveTimelineRun> TimelineRuns => _timelines.Values.OrderBy(r => int.Parse(r.Id[3..], CultureInfo.InvariantCulture)).ToList();

    public LiveTimelineRun GetTimeline(string id) =>
        _timelines.TryGetValue(id?.Trim() ?? "", out var r) ? r
            : throw new ToolError(ErrorCode.NotFound, $"No timeline '{id}'.", "live_timeline action=list shows the timelines; action=start begins one");

    /// <summary>Starts tracing the session's program; one recording timeline per session.</summary>
    public LiveTimelineRun StartTimeline(LiveSession session)
    {
        Live(session);
        if (ActivitySource.Unavailable() is { } missing) throw new ToolError(ErrorCode.ProviderUnavailable, missing.Reason, missing.Remediation);
        if (_timelines.Values.FirstOrDefault(r => r.Session == session.Id && r.State == "recording") is { } open)
            throw new ToolError(ErrorCode.Conflict, $"{open.Id} is already recording {session.Id}.", $"live_timeline action=stop run={open.Id} first");
        if (_timelines.Values.Count(r => r.State == "recording") >= MaxSessions)
            throw new ToolError(ErrorCode.LimitExceeded, $"{MaxSessions} timelines are recording.", "stop one with live_timeline action=stop");
        var run = new LiveTimelineRun("tl-" + Interlocked.Increment(ref _nextTimeline), session, ActivitySource.Name);
        // The session's own helpers (the agent and its unpacked DLLs) open from the workers folder; filter them out.
        var own = OwnFiles(Path.Combine(Native.Providers.AnalysisCache.DefaultRoot, "workers"));
        run.Trace = ActivitySource.Start(session.ProcessId, e =>
        {
            if (e.Category != "file" || !own(e.Name)) run.Add(e);
        });
        _timelines[run.Id] = run;
        return run;
    }

    /// <summary>Whether a traced file is under <paramref name="folder"/>, matched in full and final form, short names expanded.</summary>
    internal static Func<string, bool> OwnFiles(string folder)
    {
        var full = Path.TrimEndingDirectorySeparator(Path.GetFullPath(folder));
        var final = Directory.Exists(full) ? LiveProgramScope.Canonical(full) : full;
        string[] prefixes = [.. new[] { full, final }.Distinct(StringComparer.OrdinalIgnoreCase).Select(p => p + Path.DirectorySeparatorChar)];
        bool Under(string name) => prefixes.Any(p => name.StartsWith(p, StringComparison.OrdinalIgnoreCase));
        return name => Under(name) || (name.Contains('~') && Path.IsPathFullyQualified(name) && Under(Expanded(name)));

        static string Expanded(string name)
        {
            try { return LiveProgramScope.Canonical(name); }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException) { return name; }
        }
    }

    /// <summary>Set arithmetic over two timelines' distinct (category, name) pairs; times and counts are not compared.</summary>
    public static (IReadOnlyList<(string Category, string Name)> OnlyA, IReadOnlyList<(string Category, string Name)> OnlyB, int Common) TimelineDiff(
        LiveTimelineRun a, LiveTimelineRun b, string? category, string? match)
    {
        HashSet<(string, string)> Pairs(LiveTimelineRun r) => r.Entries(category, match).Select(e => (e.Category, e.Name)).ToHashSet();
        var inA = Pairs(a);
        var inB = Pairs(b);
        List<(string Category, string Name)> Only(HashSet<(string, string)> x, HashSet<(string, string)> y) =>
            [.. x.Where(p => !y.Contains(p)).OrderBy(p => TimelineCategories.ToList().IndexOf(p.Item1)).ThenBy(p => p.Item2, StringComparer.OrdinalIgnoreCase)];
        return (Only(inA, inB), Only(inB, inA), inA.Count(inB.Contains));
    }

    /// <summary>Ends the trace once what the OS still buffers has arrived; the entries stay.</summary>
    public Task StopTimelineAsync(LiveTimelineRun run)
    {
        lock (run)
            return run.Stopping ??= Task.Run(async () =>
            {
                try
                {
                    if (run.Trace is { } trace) await trace.StopAsync().ConfigureAwait(false);
                }
                finally { run.Finish(); }
            });
    }

    /// <summary>The program ended: its timelines finish once the last buffers arrive.</summary>
    private void EndTimeline(LiveSession session)
    {
        foreach (var run in _timelines.Values.Where(r => r.Session == session.Id)) _ = StopTimelineAsync(run);
    }

    /// <summary>Every trace ends with the server: an event tracing session outlives the process that started it.</summary>
    private void StopTimelines()
    {
        var stopping = _timelines.Values.Select(StopTimelineAsync).ToArray();
        try { Task.WaitAll(stopping, TimeSpan.FromSeconds(8)); }
        // A trace that failed to stop is removed at the next server start.
        catch (AggregateException) { }
    }
}
