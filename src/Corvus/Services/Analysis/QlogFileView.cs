using Corvus.Core;
using Corvus.Core.Pcap;

namespace Corvus.Services.Analysis;

/// <summary>view=qlog: a qlog file's traces with event and packet counts, drops and closes, then a page of events (offset=, limit=).</summary>
internal sealed class QlogFileView : IFileSummaryView
{
    private const int DefaultLimit = 50, MaxLimit = 1000, MaxNames = 40;

    public sealed record TraceEntry(string Vantage, string? Title, string? Odcid, long Events, double? First, double? Last,
        IReadOnlyDictionary<string, long> Counts, IReadOnlyDictionary<string, long> PacketsSent, IReadOnlyDictionary<string, long> PacketsReceived,
        long Dropped, IReadOnlyList<string> Closes);

    public sealed record Facts(string Format, string Version, IReadOnlyList<TraceEntry> Traces, long Events, long Offset, long? Next,
        IReadOnlyList<Qlog.Event> Page, IReadOnlyList<string> Notes);

    public string Name => "qlog";

    public FileView? Inspect(FileInput file, CancellationToken ct)
    {
        if (!Qlog.Looks(file.Head)) return null;
        int limit = Math.Clamp(file.Options.Limit ?? DefaultLimit, 1, MaxLimit);
        long offset = Math.Max(0, file.Options.Offset), seen = 0;
        var page = new List<Qlog.Event>();
        Qlog q;
        try
        {
            using var s = file.OpenRead();
            q = Qlog.Read(s, e =>
            {
                if (seen >= offset && page.Count < limit) page.Add(e);
                seen++;
            }, ct);
        }
        catch (InvalidDataException ex) { throw new ToolError(ErrorCode.MalformedInput, $"{Path.GetFileName(file.Path)}: not a readable qlog file: {ex.Message}"); }
        long? next = offset + page.Count < seen ? offset + page.Count : null;
        var traces = q.Traces.Select(t => new TraceEntry(t.Vantage, t.Title, t.Odcid, t.Events, t.First, t.Last,
            t.Counts.OrderByDescending(c => c.Value).ThenBy(c => c.Key, StringComparer.Ordinal).Take(MaxNames).ToDictionary(),
            t.PacketsSent, t.PacketsReceived, t.Dropped, t.Closes)).ToList();
        var notes = new List<string>();
        if (next != null) notes.Add($"offset={next} lists the next events");
        if (q.Traces.Any(t => t.Counts.Count > MaxNames)) notes.Add($"event counts: the {MaxNames} most frequent names per trace");
        var highlights = new List<string>
        {
            $"qlog {q.Version} ({q.Format}): {q.Traces.Count} trace(s), {q.Events:N0} events" +
            (q.Traces.Count > 0 ? $"; {string.Join(", ", q.Traces.Take(4).Select(Describe))}{(q.Traces.Count > 4 ? ", ..." : "")}" : "") + ".",
        };
        foreach (var t in q.Traces.Where(t => t.Closes.Count > 0).Take(4)) highlights.Add($"{t.Vantage} connection closed: {t.Closes[0]}.");
        return new FileView(new Facts(q.Format, q.Version, traces, q.Events, offset, next, page, notes), highlights);
    }

    private static string Describe(Qlog.Trace t)
    {
        long sent = t.PacketsSent.Values.Sum(), received = t.PacketsReceived.Values.Sum();
        var span = t.First is double f && t.Last is double l ? $" over {l - f:0.#} ms" : "";
        return $"{t.Vantage} ({t.Events:N0} events{span}, {sent:N0} packets sent, {received:N0} received{(t.Dropped > 0 ? $", {t.Dropped:N0} dropped" : "")})";
    }
}
