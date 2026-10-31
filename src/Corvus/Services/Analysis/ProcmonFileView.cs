using Corvus.Core;
using Corvus.Core.Documents;
using Corvus.Core.Logs;

namespace Corvus.Services.Analysis;

/// <summary>view=procmon: a Process Monitor .pml or CSV log as counts and a page of events (offset=, limit=); table= keeps one process, PID, operation or result.</summary>
internal sealed class ProcmonFileView : IFileSummaryView
{
    private const int DefaultLimit = 50, MaxLimit = 1000, MaxNames = 40, MaxProcesses = 500, MaxText = 400;

    public sealed record Facts(string Format, ProcmonLog.FileHeader? Header, long Events, DateTime? First, DateTime? Last,
        IReadOnlyDictionary<string, long> Operations, IReadOnlyDictionary<string, long> Processes, IReadOnlyDictionary<string, long> Results,
        IReadOnlyList<ProcmonLog.Process> ProcessTable, string? Filter, long Matched, long Offset, long? Next, IReadOnlyList<ProcmonLog.Event> Page,
        IReadOnlyList<string> Notes);

    public string Name => "procmon";

    public FileView? Inspect(FileInput file, CancellationToken ct)
    {
        if (!ProcmonLog.Looks(file.Head)) return null;
        int limit = Math.Clamp(file.Options.Limit ?? DefaultLimit, 1, MaxLimit);
        long offset = Math.Max(0, file.Options.Offset), matched = 0;
        var filter = file.Options.View == Name ? file.Options.Table?.Trim() : null;
        var operations = new Dictionary<string, long>(StringComparer.Ordinal);
        var processes = new Dictionary<string, long>(StringComparer.Ordinal);
        var results = new Dictionary<string, long>(StringComparer.Ordinal);
        var page = new List<ProcmonLog.Event>();
        DateTime? first = null, last = null;
        ProcmonLog log;
        try
        {
            using var s = file.OpenRead();
            log = ProcmonLog.Read(s, e =>
            {
                Count(operations, e.Operation);
                Count(processes, e.Pid is { } pid ? $"{e.ProcessName} ({pid})" : e.ProcessName);
                Count(results, e.Result.Length > 0 ? e.Result : "(none)");
                if (e.Time is { } t)
                {
                    if (first == null || t < first) first = t;
                    if (last == null || t > last) last = t;
                }
                if (filter != null && !Keeps(filter, e)) return;
                if (matched >= offset && page.Count < limit) page.Add(Shorten(e));
                matched++;
            }, ct);
        }
        catch (Exception ex) when (ex is InvalidDataException or EndOfStreamException)
        {
            throw new ToolError(ErrorCode.MalformedInput, $"{Path.GetFileName(file.Path)}: not a readable Process Monitor log: {ex.Message}");
        }
        long? next = offset + page.Count < matched ? offset + page.Count : null;
        var notes = new List<string>(log.Notes);
        if (next != null) notes.Add($"offset={next} lists the next events");
        if (filter != null && matched == 0) notes.Add($"no event of process, PID, operation or result '{filter}'");
        if (operations.Count > MaxNames || processes.Count > MaxNames || results.Count > MaxNames) notes.Add($"operations, processes and results: the {MaxNames} most frequent");
        if (log.Processes.Count > MaxProcesses) notes.Add($"process table: the first {MaxProcesses} of {log.Processes.Count:N0}");
        var highlights = new List<string>
        {
            $"{log.Format}: {log.Events:N0} event(s)" + (log.Header is { } h ? $" captured on {h.Computer} (Windows {h.Windows}), {log.Processes.Count:N0} process(es)" : "") +
            (first != null ? $", {first:yyyy-MM-dd HH:mm:ss.fff} to {last:HH:mm:ss.fff} UTC" : "") + ".",
        };
        if (operations.Count > 0) highlights.Add("Most frequent: " + string.Join(", ", Top(operations).Take(5).Select(p => $"{p.Key} ({p.Value:N0})")) + ".");
        var created = log.Processes.Count(p => p.Started != null && first != null && p.Started >= first);
        if (created > 0) highlights.Add($"{created} process(es) started during the capture.");
        return new FileView(new Facts(log.Format, log.Header, log.Events, first, last, Top(operations), Top(processes), Top(results),
            [.. log.Processes.Take(MaxProcesses).Select(Shorten)], filter, matched, offset, next, page, notes), highlights)
        {
            Findings = [.. log.Processes.SelectMany(p => FindingRules.FromLaunchers(Launchers.Match(p.CommandLine), "procmon", $"PID {p.Pid}"))],
        };
    }

    private static bool Keeps(string filter, ProcmonLog.Event e) =>
        int.TryParse(filter, out var pid) ? e.Pid == pid
            : string.Equals(e.ProcessName, filter, StringComparison.OrdinalIgnoreCase) || string.Equals(e.Operation, filter, StringComparison.OrdinalIgnoreCase)
              || string.Equals(e.Result, filter, StringComparison.OrdinalIgnoreCase);

    private static string Cut(string s) => s.Length > MaxText ? s[..MaxText] + "..." : s;

    private static ProcmonLog.Event Shorten(ProcmonLog.Event e) => e with { Path = Cut(e.Path), Detail = e.Detail is { } d ? Cut(d) : null };

    private static ProcmonLog.Process Shorten(ProcmonLog.Process p) => p with { CommandLine = Cut(p.CommandLine) };

    private static void Count(Dictionary<string, long> d, string key) => d[key] = d.GetValueOrDefault(key) + 1;

    private static Dictionary<string, long> Top(Dictionary<string, long> d) =>
        d.OrderByDescending(p => p.Value).ThenBy(p => p.Key, StringComparer.Ordinal).Take(MaxNames).ToDictionary();
}
