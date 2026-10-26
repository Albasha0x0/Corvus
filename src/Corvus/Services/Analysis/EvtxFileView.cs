using Corvus.Core;
using Corvus.Core.Logs;

namespace Corvus.Services.Analysis;

/// <summary>
/// view=evtx: a Windows event log file as a timeline: header facts, record and recovered-record counts, the time span,
/// counts by level, provider and event id, then a page of events (offset=, limit=) in file order; table= keeps the events
/// of one provider, one event id or one provider/id pair.
/// </summary>
internal sealed class EvtxFileView : IFileSummaryView
{
    private const int DefaultLimit = 50, MaxLimit = 1000, MaxNames = 40, MaxData = 24, MaxValue = 400;

    /// <summary>One event of the page: times, ids, System fields and up to 24 event data values (each up to 400 characters).</summary>
    public sealed record Row(DateTime? Created, ulong? EventRecordId, int? Level, string? Provider, int? EventId, string? Channel, string? Computer,
        int? ProcessId, int? ThreadId, string? UserId, IReadOnlyList<KeyValuePair<string, string>> Data, bool Recovered, int Chunk);

    public sealed record Facts(EvtxFile.FileHeader Header, int Chunks, long Records, long Recovered, DateTime? First, DateTime? Last,
        IReadOnlyDictionary<string, long> Levels, IReadOnlyDictionary<string, long> Providers, IReadOnlyDictionary<string, long> EventIds,
        string? Filter, long Matched, long Offset, long? Next, IReadOnlyList<Row> Page, IReadOnlyList<string> Notes);

    public string Name => "evtx";

    public FileView? Inspect(FileInput file, CancellationToken ct)
    {
        if (!EvtxFile.Looks(file.Head)) return null;
        int limit = Math.Clamp(file.Options.Limit ?? DefaultLimit, 1, MaxLimit);
        long offset = Math.Max(0, file.Options.Offset), matched = 0;
        var filter = file.Options.View == Name ? file.Options.Table?.Trim() : null;
        var levels = new Dictionary<string, long>(StringComparer.Ordinal);
        var providers = new Dictionary<string, long>(StringComparer.Ordinal);
        var ids = new Dictionary<string, long>(StringComparer.Ordinal);
        var page = new List<Row>();
        DateTime? first = null, last = null;
        EvtxFile log;
        try
        {
            using var s = file.OpenRead();
            log = EvtxFile.Read(s, e =>
            {
                var provider = e.Provider ?? "?";
                Count(levels, LevelName(e.Level));
                Count(providers, provider);
                Count(ids, $"{provider}/{e.EventId}");
                if (e.Created is { } t && !e.Recovered)
                {
                    if (first == null || t < first) first = t;
                    if (last == null || t > last) last = t;
                }
                if (filter != null && !Keeps(filter, e)) return;
                if (matched >= offset && page.Count < limit) page.Add(RowOf(e));
                matched++;
            }, ct);
        }
        catch (InvalidDataException ex) { throw new ToolError(ErrorCode.MalformedInput, $"{Path.GetFileName(file.Path)}: not a readable event log: {ex.Message}"); }
        long? next = offset + page.Count < matched ? offset + page.Count : null;
        var notes = new List<string>(log.Notes);
        if (next != null) notes.Add($"offset={next} lists the next events");
        if (filter != null && matched == 0) notes.Add($"no event of provider or event id '{filter}'");
        if (providers.Count > MaxNames || ids.Count > MaxNames) notes.Add($"providers and event ids: the {MaxNames} most frequent");
        var highlights = new List<string>
        {
            $"Windows event log {log.Header.Major}.{log.Header.Minor}: {log.Records:N0} event(s) in {log.Chunks} chunk(s)" +
            (first != null ? $", {first:yyyy-MM-dd HH:mm:ss} to {last:yyyy-MM-dd HH:mm:ss} UTC" : "") +
            (log.Recovered > 0 ? $"; {log.Recovered:N0} recovered from free space" : "") + ".",
        };
        if (providers.Count > 0)
            highlights.Add("Most frequent: " + string.Join(", ", Top(ids).Take(5).Select(p => $"{p.Key} ({p.Value:N0})")) + ".");
        if (levels.TryGetValue("error", out var errors) || levels.ContainsKey("critical"))
            highlights.Add($"{errors:N0} error(s){(levels.TryGetValue("critical", out var critical) ? $", {critical:N0} critical" : "")}.");
        if (log.Header.Dirty) highlights.Add("The header is marked dirty: the log was not closed cleanly.");
        return new FileView(new Facts(log.Header, log.Chunks, log.Records, log.Recovered, first, last, levels, Top(providers), Top(ids), filter, matched,
            offset, next, page, notes), highlights);
    }

    private static bool Keeps(string filter, EvtxFile.Event e)
    {
        int slash = filter.LastIndexOf('/');
        if (slash > 0) return string.Equals(e.Provider, filter[..slash], StringComparison.OrdinalIgnoreCase) && $"{e.EventId}" == filter[(slash + 1)..];
        return int.TryParse(filter, out var id) ? e.EventId == id : string.Equals(e.Provider, filter, StringComparison.OrdinalIgnoreCase);
    }

    private static Row RowOf(EvtxFile.Event e) => new(e.Created, e.EventRecordId, e.Level, e.Provider, e.EventId, e.Channel, e.Computer, e.ProcessId,
        e.ThreadId, e.UserId, [.. e.Data.Take(MaxData).Select(d => new KeyValuePair<string, string>(d.Key, d.Value.Length > MaxValue ? d.Value[..MaxValue] + "..." : d.Value))],
        e.Recovered, e.Chunk);

    /// <summary>The level names of the Windows event schema; other values by number.</summary>
    private static string LevelName(int? level) => level switch
    {
        0 => "log always", 1 => "critical", 2 => "error", 3 => "warning", 4 => "information", 5 => "verbose", null => "none",
        _ => level.Value.ToString(System.Globalization.CultureInfo.InvariantCulture),
    };

    private static void Count(Dictionary<string, long> d, string key) => d[key] = d.GetValueOrDefault(key) + 1;

    private static Dictionary<string, long> Top(Dictionary<string, long> d) =>
        d.OrderByDescending(p => p.Value).ThenBy(p => p.Key, StringComparer.Ordinal).Take(MaxNames).ToDictionary();
}
