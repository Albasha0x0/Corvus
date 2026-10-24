using System.ComponentModel;
using System.Globalization;
using System.Text;
using ModelContextProtocol.Server;
using Corvus.Core;
using Corvus.Mcp;
using Corvus.Native;
using Corvus.Native.Code;
using Corvus.Services;

namespace Corvus.Tools;

public sealed partial class LiveSessionTools
{
    public sealed record LiveCoverageRow(
        [property: Description("Function start (VA).")] string Address,
        string Name,
        [property: Description("Stops counted; at the hit limit, a lower bound.")] long Hits,
        bool Ran);

    public sealed record LiveCoverageSummary(string Run, string Session, string Image, string Sha256,
        [property: Description("recording, complete or ended.")] string State,
        int Points, int Ran, int HitLimit)
    {
        [Description("Functions refused; reasons in the text.")]
        public int Unplaced { get; init; }
        [Description("No read of the runtime succeeded: unseen methods are unknown.")]
        public bool Unread { get; init; }
    }

    public sealed record LiveCoverageReport(LiveCoverageSummary? Run, IReadOnlyList<LiveCoverageRow> Items, int Offset,
        [property: Description("Absent with format=dot (offset counts characters).")] int? Total, IReadOnlyList<LiveCoverageSummary> Runs)
    {
        public IReadOnlyList<LiveNamedAddress>? NamedAddresses { get; init; }
        [Description("format=dot: a page of the call graph (Graphviz DOT).")]
        public string? Code { get; init; }
        public int? NextOffset { get; init; }
        public int? TotalChars { get; init; }
        [Description("action=diff.")]
        public LiveCoverageDiff? Diff { get; init; }
    }

    public sealed record LiveCoverageDiff(LiveCoverageSummary Other,
        IReadOnlyList<LiveCoverageRow> OnlyInRun,
        IReadOnlyList<LiveCoverageRow> OnlyInOther,
        int OnlyInRunTotal, int OnlyInOtherTotal, int InBoth, int InNeither);

    [McpServerTool(Name = "live_coverage", Title = "Code coverage of a session", UseStructuredContent = true, OutputSchemaType = typeof(LiveCoverageReport))]
    [Description("Collect code coverage in a session: which functions of an image ran and how often, on the static call graph; diff compares two runs.")]
    public Task<string> LiveCoverage(
        [Description("Session id; start only.")] string? session = null,
        [Description("What to do.")] string action = "list",
        [Description("Run id (cov-1; omitted: the only run); diff: the first run.")] string? run = null,
        [Description("diff: the run compared with.")] string? other = null,
        [Description("Only function names containing this; start: module!part for another module.")] string? match = null,
        [Description("start: stops per function before its point is cleared.")] int hitLimit = 100,
        [Description("report: ran, missed or all.")] string show = "ran",
        [Description("report: text, or dot (call graph; offset counts characters).")] string format = "text",
        [Description(ToolSupport.RowOffsetDescription)] int offset = 0,
        [Description(ToolSupport.LimitDescription)] int limit = 100,
        CancellationToken cancellationToken = default) =>
        Task.Run(async () =>
        {
            Require(spawn: false);
            var a = action.Trim().ToLowerInvariant();
            limit = ToolSupport.ClampLimit(limit, 1_000);
            switch (a)
            {
                case "start":
                {
                    var s = live.Get(RequireSession(session));
                    var r = await live.StartCoverageAsync(s, match, Math.Clamp(hitLimit, 1, 100_000), cancellationToken).ConfigureAwait(false);
                    var text = (r.Image == null
                                   ? $"{r.Id} recording which of {ToolSupport.Plural(r.Placed.Count, "method")} of {r.ImageId} run in {s.Id}, from {(r.JitBodies != null ? "the JIT's compiles from now on" : "the runtime's record of the methods it prepared code for")} (calls are not counted)\n"
                               : r.PendingModule is { } pending
                                   ? $"{r.Id} waits for {pending} to load, then counts {ToolSupport.Plural(r.Placed.Count, "function")} of {r.ImageId} in {s.Id} from its first call; each point is cleared after {r.HitLimit:N0} stop(s)\n"
                                   : $"{r.Id} counting {ToolSupport.Plural(r.Placed.Count, "function")} of {r.ImageId} in {s.Id}; each point is cleared after {r.HitLimit:N0} stop(s)\n") +
                               (r.DetachFunctions > 0 ? $"{ToolSupport.Plural(r.DetachFunctions, "function")} reached from TLS callbacks or the DLL entry point left out: they run at process exit, after the other threads end\n" : "") +
                               string.Concat(r.Unplaced.Values.Select(x => x.Split('\n')[0]).GroupBy(x => x).Select(g => $"{ToolSupport.Plural(g.Count(), "function")} left out: {g.Key}\n")) +
                               (s.State == "suspended" ? "the program is still suspended: live_break action=continue starts it\n" : "") +
                               $"next: live_coverage action=report run={r.Id}\n";
                    return ToolOutput.With(text, new LiveCoverageReport(Summary(r), [], 0, 0, []));
                }
                case "stop":
                {
                    var r = live.GetCoverage(RequireRun(run, session));
                    await live.StopCoverageAsync(live.Get(r.Session), r, cancellationToken).ConfigureAwait(false);
                    // a run whose program ended first keeps that state: its counts stop at the end, not at this stop
                    var state = r.State == "ended" ? "ended with its program, before the stop" : r.State;
                    return ToolOutput.With($"{r.Id} {state}: {Ran(r)}\n",
                        new LiveCoverageReport(Summary(r), [], 0, 0, []));
                }
                case "list":
                {
                    var listed = live.CoverageRuns.Where(r => string.IsNullOrWhiteSpace(session) || r.Session.Equals(session.Trim(), StringComparison.OrdinalIgnoreCase)).ToList();
                    var text = listed.Count == 0 ? "No coverage runs.\n"
                        : string.Concat(listed.Select(r => $"{r.Id} {r.Session} {r.ImageId}: {Ran(r)}, {r.State}\n"));
                    return ToolOutput.With(text, new LiveCoverageReport(null, [], 0, 0, listed.Select(Summary).ToList()));
                }
                case "report":
                    return await CoverageReport(live.GetCoverage(RequireRun(run, session)), match, show, format, offset, limit, cancellationToken).ConfigureAwait(false);
                case "diff":
                    return CoverageDiff(live.GetCoverage(RequireRun(run, session)),
                        live.GetCoverage(string.IsNullOrWhiteSpace(other) ? throw new ToolError(ErrorCode.InvalidArgument, "action=diff needs other.", "other=<the second run id>") : other), limit);
                default:
                    throw new ToolError(ErrorCode.InvalidArgument, $"Unknown action '{action}'.", "action=start, stop, list, report or diff");
            }
        }, cancellationToken);

    private const int MaxCoverageNamed = 20;
    /// <summary>Functions one DOT graph draws.</summary>
    private const int MaxCoverageDot = 200;
    private readonly OutputPager _pager = new(options);

    private string RequireRun(string? run, string? session) =>
        OnlyRun(run, session, live.CoverageRuns.Select(r => (r.Id, r.Session)), "live_coverage");

    /// <summary>The run named, else the only run (of the session, when one is named).</summary>
    private static string OnlyRun(string? run, string? session, IEnumerable<(string Id, string Session)> runs, string tool)
    {
        if (!string.IsNullOrWhiteSpace(run)) return run;
        var ids = runs.Where(r => string.IsNullOrWhiteSpace(session) || r.Session.Equals(session.Trim(), StringComparison.OrdinalIgnoreCase)).Select(r => r.Id).ToList();
        return ids.Count == 1 ? ids[0] : throw new ToolError(ErrorCode.InvalidArgument,
            ids.Count == 0 ? "This action needs run, and there is none." : $"This action needs run: {string.Join(", ", ids)}.", $"run=<id from {tool} action=list>");
    }

    private static LiveCoverageSummary Summary(Services.LiveCoverageRun r) =>
        new(r.Id, r.Session, r.ImageId, r.Sha256, r.State, r.Placed.Count, r.Ran, r.HitLimit) { Unplaced = r.Unplaced.Count, Unread = r.Unread };

    /// <summary>How many of the run's functions ran; for a run whose runtime was never read, the rest are unknown.</summary>
    private static string Ran(Services.LiveCoverageRun r) => r.Unread
        ? $"{r.Ran:N0} of {ToolSupport.Plural(r.Placed.Count, "function")} seen to run; the rest are unknown, not missed: no read of the program's runtime succeeded"
        : $"{r.Ran:N0} of {ToolSupport.Plural(r.Placed.Count, "function")} ran";

    /// <summary>A function's VA; a managed method's metadata token.</summary>
    private static string Va(Services.LiveCoverageRun r, uint rva) => r.Image == null ? $"0x{rva:X8}" : NativeAddress.Va(r.Image.Image, rva);

    private static LiveCoverageRow Row(Services.LiveCoverageRun r, LiveCoveragePoint p)
    {
        var hits = r.HitsAt(p.Rva);
        return new LiveCoverageRow(Va(r, p.Rva), p.Name, hits, hits > 0);
    }

    private static string Count(Services.LiveCoverageRun r, long hits) =>
        hits == 0 ? (r.Unread ? "?" : "-") : r.Image == null ? "ran" : hits >= r.HitLimit ? $"{r.HitLimit:N0}+" : hits.ToString("N0", CultureInfo.InvariantCulture);

    private async Task<string> CoverageReport(Services.LiveCoverageRun r, string? match, string show, string format, int offset, int limit, CancellationToken ct)
    {
        var mode = show.Trim().ToLowerInvariant();
        if (mode is not ("ran" or "missed" or "all")) throw new ToolError(ErrorCode.InvalidArgument, $"Unknown show '{show}'.", "show=ran, missed or all");
        var dot = format.Trim().ToLowerInvariant() switch
        {
            "text" => false,
            "dot" => true,
            _ => throw new ToolError(ErrorCode.InvalidArgument, $"Unknown format '{format}'.", "format=text or dot"),
        };
        var filter = string.IsNullOrWhiteSpace(match) ? null : match.Trim();
        var placed = r.Placed;
        var points = placed.Where(p => filter == null || p.Name.Contains(filter, StringComparison.OrdinalIgnoreCase))
            .Where(p => mode == "all" || (mode == "ran") == (r.HitsAt(p.Rva) > 0)).ToList();
        // the busiest first
        var rows = points.Select(p => Row(r, p)).OrderByDescending(x => x.Hits).ThenBy(x => x.Address, StringComparer.Ordinal).ToList();
        var head = new StringBuilder($"{r.Id} {r.ImageId}: {Ran(r)}" + (r.Unread ? "" : $" ({(placed.Count == 0 ? 0 : 100.0 * r.Ran / placed.Count):0.#}%)") +
                                     $", {r.State}{(r.PendingModule is { } pending ? $", waiting for {pending} to load" : "")}\n");
        if (dot)
        {
            if (points.Count > MaxCoverageDot)
                throw new ToolError(ErrorCode.LimitExceeded, $"The report lists {points.Count:N0} functions; format=dot draws at most {MaxCoverageDot}.",
                    "narrow it with match=<part of the names> or show=ran");
            var graph = Dot(r, points, await live.CoverageCallsAsync(r, points.Select(p => p.Rva).ToHashSet(), ct).ConfigureAwait(false));
            // the graph stands in for the rows, paged by characters like code
            return ToolOutput.Text(_pager, head + graph, offset, new LiveCoverageReport(Summary(r), [], offset, null, []));
        }
        return ToolOutput.List(rows, offset, limit, x => $"{Count(r, x.Hits),8}  {x.Address}  {x.Name}", page => new LiveCoverageReport(Summary(r), page, offset, rows.Count, [])
        {
            // a sample for read_result format=verify: the rows already carry every address and name
            NamedAddresses = r.Image == null ? null : Named(page.Take(MaxCoverageNamed).Select(x => new EvidenceName(r.ImageId, r.Sha256, Rva(r, x.Address), x.Name)).ToList()),
        }, "function", head.ToString());
    }

    private static uint Rva(Services.LiveCoverageRun r, string va) => (uint)(ulong.Parse(va[2..], NumberStyles.HexNumber, CultureInfo.InvariantCulture) - r.Image!.Image.ImageBase);

    /// <summary>
    /// The static call graph in Graphviz DOT: node n&lt;i&gt; per function in address order, labeled with the count;
    /// functions that never ran dashed.
    /// </summary>
    private static string Dot(Services.LiveCoverageRun r, IReadOnlyList<LiveCoveragePoint> points, IReadOnlyList<(uint From, uint To)> calls)
    {
        var node = new Dictionary<uint, int>();
        var sb = new StringBuilder($"digraph \"{r.Id}\" {{\n  node [shape=box fontname=monospace];\n");
        foreach (var p in points)
        {
            node[p.Rva] = node.Count + 1;
            var hits = r.HitsAt(p.Rva);
            sb.Append($"  n{node.Count} [label=\"{p.Name.Replace("\\", "\\\\").Replace("\"", "\\\"")}\\n{Count(r, hits)}\"{(hits == 0 ? " style=dashed" : "")}];\n");
        }
        foreach (var (from, to) in calls) sb.Append($"  n{node[from]} -> n{node[to]};\n");
        return sb.Append("}\n").ToString();
    }

    /// <summary>Set arithmetic over two runs' counted points: what ran only in each, in both, in neither.</summary>
    private static string CoverageDiff(Services.LiveCoverageRun a, Services.LiveCoverageRun b, int limit)
    {
        if (!string.Equals(a.Sha256, b.Sha256, StringComparison.OrdinalIgnoreCase))
            throw new ToolError(ErrorCode.Conflict, $"{a.Id} counted {a.ImageId} (SHA-256 {a.Sha256[..12]}…) and {b.Id} {b.ImageId} (SHA-256 {b.Sha256[..12]}…): different builds.",
                "compare runs of the same build; for two builds, map the addresses with map_address_between_builds");
        var bPoints = b.Placed.ToDictionary(p => p.Rva);
        var onlyA = new List<LiveCoverageRow>();
        var onlyB = new List<LiveCoverageRow>();
        int both = 0, neither = 0;
        foreach (var p in a.Placed)
        {
            bool inA = a.HitsAt(p.Rva) > 0, inB = bPoints.ContainsKey(p.Rva) && b.HitsAt(p.Rva) > 0;
            if (inA && inB) both++;
            else if (inA) onlyA.Add(Row(a, p));
            else if (inB) onlyB.Add(Row(b, bPoints[p.Rva]));
            else neither++;
        }
        var text = new StringBuilder($"{a.Id} and {b.Id} on {a.ImageId}: {ToolSupport.Plural(onlyA.Count, "function")} ran only in {a.Id}, {onlyB.Count:N0} only in {b.Id}, {both:N0} in both, {neither:N0} in neither\n");
        foreach (var unread in new[] { a, b }.Where(r => r.Unread))
            text.AppendLine($"{unread.Id} never read the program's runtime: a function it did not see run is unknown there, not missed");
        foreach (var (id, rows) in new[] { (a.Id, onlyA), (b.Id, onlyB) })
        {
            if (rows.Count == 0) continue;
            text.AppendLine($"only in {id}:");
            foreach (var x in rows.Take(limit)) text.AppendLine($"{Count(id == a.Id ? a : b, x.Hits),8}  {x.Address}  {x.Name}");
            if (rows.Count > limit) text.AppendLine($"  ... {rows.Count - limit:N0} more (limit={rows.Count})");
        }
        return ToolOutput.With(text.ToString(), new LiveCoverageReport(Summary(a), [], 0, 0, [])
        {
            Diff = new LiveCoverageDiff(Summary(b), [.. onlyA.Take(limit)], [.. onlyB.Take(limit)], onlyA.Count, onlyB.Count, both, neither),
        });
    }
}
