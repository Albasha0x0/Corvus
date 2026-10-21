using System.ComponentModel;
using System.Globalization;
using System.Text;
using ModelContextProtocol.Server;
using Corvus.Core;
using Corvus.Mcp;
using Corvus.Services;

namespace Corvus.Tools;

public sealed partial class LiveSessionTools
{
    public sealed record LiveTimelineRow(long Sequence,
        [property: Description("UTC, ISO 8601.")] string Time,
        [property: Description("file, registry, network or process.")] string Category,
        [property: Description("As the OS reports it: a path, registry key or value, endpoint or program.")] string Name)
    {
        public int? ProcessId { get; init; }
    }

    public sealed record LiveTimelineName(string Category, string Name, long Count, [property: Description("UTC, ISO 8601.")] string First);

    public sealed record LiveTimelineSummary(string Run, string Session, string Program, int ProcessId,
        [property: Description("The diagnostics channel: event tracing (ETW) on Windows.")] string Source,
        [property: Description("recording or complete.")] string State,
        long Entries);

    public sealed record LiveTimelinePage(LiveTimelineSummary? Run, IReadOnlyList<LiveTimelineRow> Items,
        [property: Description("Cursor for the next page; null at the end.")] string? Cursor,
        IReadOnlyList<LiveTimelineSummary> Runs)
    {
        [Description("Entries the ring dropped before this page.")]
        public long Dropped { get; init; }
        [Description("action=report: each name with its count and first time.")]
        public IReadOnlyList<LiveTimelineName>? Names { get; init; }
        [Description("action=diff.")]
        public LiveTimelineDiff? Diff { get; init; }
    }

    public sealed record LiveTimelinePair(string Category, string Name);

    public sealed record LiveTimelineDiff([property: Description("Timeline b; Run is timeline a.")] LiveTimelineSummary Other,
        [property: Description("This page's pairs recorded in a and not in b.")] IReadOnlyList<LiveTimelinePair> OnlyA,
        [property: Description("This page's pairs recorded in b and not in a.")] IReadOnlyList<LiveTimelinePair> OnlyB,
        int OnlyATotal, int OnlyBTotal, int Common);

    /// <summary>A row of the diff's one paged list: the pairs only in a, then those only in b.</summary>
    private sealed record TimelineDiffRow(int Index, bool InA, string Category, string Name);

    [McpServerTool(Name = "live_timeline", Title = "Activity trace of a session", UseStructuredContent = true, OutputSchemaType = typeof(LiveTimelinePage))]
    [Description("Collect a timestamped trace of the files, registry keys, endpoints and child processes a session's program opens, from the OS diagnostics channel (event tracing on Windows); entries page with a cursor, report counts each name, diff lists the names unique to each of two traces.")]
    public Task<string> LiveTimeline(
        [Description("Session id; start only.")] string? session = null,
        [Description("What to do.")] string action = "list",
        [Description("Timeline id (tl-1; omitted: the only one); list without it or a filter shows the timelines.")] string? run = null,
        [Description("diff: the first timeline.")] string? a = null,
        [Description("diff: the second timeline.")] string? b = null,
        [Description("Only file, registry, network or process.")] string? category = null,
        [Description("Only names containing this.")] string? match = null,
        [Description("list: cursor from an earlier page; default the oldest entry kept.")] string? cursor = null,
        [Description(ToolSupport.RowOffsetDescription + " (report).")] int offset = 0,
        [Description(ToolSupport.LimitDescription)] int limit = 100,
        CancellationToken cancellationToken = default) =>
        Task.Run(async () =>
        {
            Require(spawn: false);
            var act = action.Trim().ToLowerInvariant();
            limit = ToolSupport.ClampLimit(limit, 1_000);
            var c = Category(category);
            var m = string.IsNullOrWhiteSpace(match) ? null : match.Trim();
            switch (act)
            {
                case "start":
                {
                    var s = live.Get(RequireSession(session));
                    var r = live.StartTimeline(s);
                    var text = $"{r.Id} tracing {s.Id} ({Path.GetFileName(r.Program)}, pid {r.ProcessId}) through {r.Source}: files, registry keys, endpoints and child processes\n" +
                               (s.State == "suspended" ? "the program is still suspended: live_break action=continue starts it\n" : "") +
                               $"next: live_timeline action=list run={r.Id}\n";
                    return ToolOutput.With(text, new LiveTimelinePage(TimelineSummary(r), [], null, []));
                }
                case "stop":
                {
                    var r = live.GetTimeline(RequireTimeline(run, session));
                    await live.StopTimelineAsync(r).ConfigureAwait(false);
                    return ToolOutput.With($"{r.Id} complete: {ToolSupport.Plural((int)Math.Min(int.MaxValue, r.Count), "entry")}\n", new LiveTimelinePage(TimelineSummary(r), [], null, []));
                }
                case "list" when string.IsNullOrWhiteSpace(run) && c == null && m == null && string.IsNullOrWhiteSpace(cursor):
                {
                    var runs = live.TimelineRuns.Where(r => string.IsNullOrWhiteSpace(session) || r.Session.Equals(session.Trim(), StringComparison.OrdinalIgnoreCase))
                        .Select(TimelineSummary).ToList();
                    var text = runs.Count == 0 ? "No timelines.\n"
                        : string.Concat(runs.Select(r => $"{r.Run} {r.Session} {Path.GetFileName(r.Program)}: {r.Entries:N0} entries, {r.State}\n"));
                    return ToolOutput.With(text, new LiveTimelinePage(null, [], null, runs));
                }
                case "list":
                    return TimelinePage(live.GetTimeline(RequireTimeline(run, session)), c, m, cursor, limit);
                case "report":
                    return TimelineReport(live.GetTimeline(RequireTimeline(run, session)), c, m, offset, limit);
                case "diff":
                {
                    if (string.IsNullOrWhiteSpace(a) || string.IsNullOrWhiteSpace(b))
                        throw new ToolError(ErrorCode.InvalidArgument, "action=diff needs a and b.", "a=<first timeline> b=<second timeline>, ids from live_timeline action=list");
                    var (ra, rb) = (live.GetTimeline(a), live.GetTimeline(b));
                    if (ReferenceEquals(ra, rb))
                        throw new ToolError(ErrorCode.InvalidArgument, $"a and b are both {ra.Id}.", "pass two different timelines");
                    return TimelineDiff(ra, rb, c, m, offset, limit);
                }
                default:
                    throw new ToolError(ErrorCode.InvalidArgument, $"Unknown action '{action}'.", "action=start, stop, list, report or diff");
            }
        }, cancellationToken);

    private string RequireTimeline(string? run, string? session) =>
        OnlyRun(run, session, live.TimelineRuns.Select(r => (r.Id, r.Session)), "live_timeline");

    private static string? Category(string? category)
    {
        if (string.IsNullOrWhiteSpace(category)) return null;
        var c = category.Trim().ToLowerInvariant();
        return LiveSessionService.TimelineCategories.Contains(c) ? c
            : throw new ToolError(ErrorCode.InvalidArgument, $"Unknown category '{category}'.", "category=file, registry, network or process");
    }

    private static LiveTimelineSummary TimelineSummary(LiveTimelineRun r) => new(r.Id, r.Session, r.Program, r.ProcessId, r.Source, r.State, r.Count);

    private static string Iso(DateTime t) => t.ToString("yyyy-MM-ddTHH:mm:ss.fffffffZ", CultureInfo.InvariantCulture);

    /// <summary>Seconds since the timeline started, as the text shows each entry.</summary>
    private static string Since(LiveTimelineRun r, DateTime t) => $"+{Math.Max(0, (t - r.Started).TotalSeconds):0.000}s";

    private static string TimelinePage(LiveTimelineRun r, string? category, string? match, string? cursor, int limit)
    {
        long start = 0;
        if (!string.IsNullOrWhiteSpace(cursor) && !long.TryParse(cursor.Trim(), NumberStyles.None, CultureInfo.InvariantCulture, out start))
            throw new ToolError(ErrorCode.InvalidArgument, $"Bad cursor '{cursor}'.", "pass the cursor of an earlier page");
        var (page, firstKept, last, more) = r.Page(start, category, match, limit);
        long dropped = start > 0 && start < firstKept ? firstKept - start : 0;
        (string, object) Render(int count)
        {
            var entries = page.Take(count).ToList();
            var text = new StringBuilder();
            if (dropped > 0) text.AppendLine($"{dropped:N0} entries before this page were dropped (a timeline keeps {LiveTimelineRun.Capacity:N0})");
            foreach (var e in entries) text.AppendLine($"#{e.Sequence} {Since(r, e.Time)} {e.Category} {e.Name}{(e.ProcessId is { } pid ? $" (process {pid})" : "")}");
            // past the last match the whole ring was scanned: the next poll starts after its end
            var cut = entries.Count > 0 && (count < page.Count || more);
            var next = cut ? entries[^1].Sequence + 1 : Math.Max(Math.Max(start, firstKept), last + 1);
            string? nextCursor = cut ? next.ToString(CultureInfo.InvariantCulture) : null;
            text.AppendLine(entries.Count == 0 && start <= 1 ? $"No entries ({r.State})."
                : nextCursor != null ? $"more: cursor={nextCursor}"
                : r.State == "recording" ? $"end of the timeline so far; poll again with cursor={next}" : "end of the timeline (complete)");
            var rows = entries.Select(e => new LiveTimelineRow(e.Sequence, Iso(e.Time), e.Category, e.Name) { ProcessId = e.ProcessId }).ToList();
            return (text.ToString(), new LiveTimelinePage(TimelineSummary(r), rows, nextCursor, []) { Dropped = dropped });
        }
        return FitPage(page.Count, Render);
    }

    /// <summary>Each name once, with how often it came and when first, in category order, then by first time.</summary>
    private static string TimelineReport(LiveTimelineRun r, string? category, string? match, int offset, int limit)
    {
        var entries = r.Entries(category, match);
        var names = entries.GroupBy(e => (e.Category, e.Name))
            .Select(g => new LiveTimelineName(g.Key.Category, g.Key.Name, g.LongCount(), Iso(g.First().Time)))
            .OrderBy(x => LiveSessionService.TimelineCategories.ToList().IndexOf(x.Category)).ThenBy(x => x.First, StringComparer.Ordinal).ToList();
        var counts = string.Join(", ", LiveSessionService.TimelineCategories.Select(c => (c, n: entries.Count(e => e.Category == c))).Where(x => x.n > 0).Select(x => $"{x.c} {x.n:N0}"));
        var head = $"{r.Id} {r.Session} {Path.GetFileName(r.Program)}: {ToolSupport.Plural(entries.Count, "entry")}{(counts.Length > 0 ? $" ({counts})" : "")}, " +
                   $"{ToolSupport.Plural(names.Count, "name")}, {r.State}{(r.Dropped > 0 ? $"; {r.Dropped:N0} oldest entries dropped" : "")}\n";
        return ToolOutput.List(names, offset, limit, x => $"{x.Count,8:N0}  {x.Category,-8}  {x.Name}",
            page => new LiveTimelinePage(TimelineSummary(r), [], null, []) { Names = page }, "name", head);
    }

    /// <summary>The pairs only in a, then only in b, as one paged list; each side's first row on a page carries its heading.</summary>
    private static string TimelineDiff(LiveTimelineRun a, LiveTimelineRun b, string? category, string? match, int offset, int limit)
    {
        var (onlyA, onlyB, common) = LiveSessionService.TimelineDiff(a, b, category, match);
        var rows = onlyA.Select((p, i) => new TimelineDiffRow(i, true, p.Category, p.Name))
            .Concat(onlyB.Select((p, i) => new TimelineDiffRow(onlyA.Count + i, false, p.Category, p.Name))).ToList();
        var head = $"{a.Id} {Path.GetFileName(a.Program)} and {b.Id} {Path.GetFileName(b.Program)}: {ToolSupport.Plural(onlyA.Count, "name")} only in {a.Id}, " +
                   $"{onlyB.Count:N0} only in {b.Id}, {common:N0} in both\n";
        // a heading row's entry continues on the next line at column 4 (ToolOutput.Line); other entries, after the row's 2, match it
        string Render(TimelineDiffRow x) =>
            (x.Index == Math.Max(0, offset) || x.Index == onlyA.Count ? $"only in {(x.InA ? a.Id : b.Id)}:\n" : "  ") + $"{x.Category,-8}  {x.Name}";
        return ToolOutput.List(rows, offset, limit, Render, page => new LiveTimelinePage(TimelineSummary(a), [], null, [])
        {
            Diff = new LiveTimelineDiff(TimelineSummary(b), [.. page.Where(x => x.InA).Select(x => new LiveTimelinePair(x.Category, x.Name))],
                [.. page.Where(x => !x.InA).Select(x => new LiveTimelinePair(x.Category, x.Name))], onlyA.Count, onlyB.Count, common),
        }, "name", head);
    }
}
