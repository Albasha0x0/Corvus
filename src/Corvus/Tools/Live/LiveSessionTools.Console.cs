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
    private const int ConsoleTailLines = 10;

    public sealed record LiveConsoleRow(long Sequence, [property: Description("UTC, ISO 8601.")] string Time, string Text)
    {
        [Description("The line the console is still writing (a prompt, say).")]
        public bool Partial { get; init; }
    }

    public sealed record LiveConsoleStepRow(int Step, [property: Description("As written.")] string Line,
        [property: Description("done, stopped or not run.")] string Outcome, long Milliseconds,
        [property: Description("Why the step stopped.")] string? Detail);

    public sealed record LiveConsoleSummary(string Run, string Program, int ProcessId,
        [property: Description("The console host: the pseudoconsole (ConPTY) on Windows.")] string Host,
        [property: Description("running, exited or stopped.")] string State, int? ExitCode,
        [property: Description("complete, stopped at step N, or none.")] string Script,
        long Lines);

    public sealed record LiveConsolePage(LiveConsoleSummary? Run, IReadOnlyList<LiveConsoleRow> Items,
        [property: Description("Cursor for the next page; null at the end.")] string? Cursor,
        IReadOnlyList<LiveConsoleSummary> Runs)
    {
        [Description("start and status: each script step with its outcome.")]
        public IReadOnlyList<LiveConsoleStepRow>? Steps { get; init; }
        [Description("Lines the ring dropped before this page.")]
        public long Dropped { get; init; }
    }

    [McpServerTool(Name = "live_console", Title = "Scripted console run", UseStructuredContent = true, OutputSchemaType = typeof(LiveConsolePage))]
    [Description("Run a program under a console host (the pseudoconsole on Windows) driven by a script of send, wait, resize and delay steps; reports each step's outcome and pages the transcript with a cursor.")]
    public Task<string> LiveConsole(
        [Description("What to do.")] string action = "list",
        [Description("start: program path.")] string? program = null,
        [Description("start: program arguments.")] string[]? arguments = null,
        [Description("start: steps, one per line: send TEXT, wait TEXT (output contains it), resize COLUMNS ROWS, delay MS; TEXT takes \\r (Enter), \\n, \\t, \\e, \\xHH.")] string[]? script = null,
        [Description("Console run id (con-1; omitted: the only one).")] string? run = null,
        [Description("Seconds each wait step waits (1-300).")] int timeoutSeconds = 10,
        [Description("transcript: cursor from an earlier page; default the oldest line kept.")] string? cursor = null,
        [Description(ToolSupport.LimitDescription)] int limit = 100,
        CancellationToken cancellationToken = default) =>
        Task.Run(async () =>
        {
            var act = action.Trim().ToLowerInvariant();
            Require(spawn: act == "start");
            limit = ToolSupport.ClampLimit(limit, 1_000);
            switch (act)
            {
                case "start":
                {
                    if (string.IsNullOrWhiteSpace(program))
                        throw new ToolError(ErrorCode.InvalidArgument, "action=start needs program.", "program=<path to a console program>");
                    if (timeoutSeconds is < 1 or > 300)
                        throw new ToolError(ErrorCode.InvalidArgument, $"timeoutSeconds {timeoutSeconds} is out of range.", "timeoutSeconds=1-300");
                    var steps = LiveSessionService.ParseConsoleScript(script ?? []);
                    var r = live.StartConsole(Scoped(spawn: true, program), arguments ?? []);
                    var outcomes = await live.RunConsoleScriptAsync(r, steps, TimeSpan.FromSeconds(timeoutSeconds), cancellationToken).ConfigureAwait(false);
                    var text = new StringBuilder($"{r.Id} {Path.GetFileName(r.Program)} (pid {r.ProcessId}) in a {DefaultSize()} {r.Host}\n");
                    ConsoleSteps(r, outcomes, text);
                    text.AppendLine($"next: live_console action=transcript run={r.Id}");
                    return ToolOutput.With(text.ToString(), new LiveConsolePage(ConsoleSummary(r), [], null, []) { Steps = StepRows(outcomes) });
                }
                case "stop":
                {
                    var r = live.GetConsole(RequireConsole(run));
                    await live.StopConsoleAsync(r).ConfigureAwait(false);
                    return ToolOutput.With($"{r.Id} {r.State}{Exit(r)}: {ToolSupport.Plural((int)Math.Min(int.MaxValue, r.Count), "line")}\n", new LiveConsolePage(ConsoleSummary(r), [], null, []));
                }
                case "list":
                {
                    var runs = live.ConsoleRuns.Select(ConsoleSummary).ToList();
                    var text = runs.Count == 0 ? "No console runs.\n"
                        : string.Concat(runs.Select(r => $"{r.Run} {Path.GetFileName(r.Program)} pid {r.ProcessId}: {r.State}{(r.ExitCode is { } c ? $" ({c})" : "")}, script {r.Script}, {r.Lines:N0} lines\n"));
                    return ToolOutput.With(text, new LiveConsolePage(null, [], null, runs));
                }
                case "status":
                {
                    var r = live.GetConsole(RequireConsole(run));
                    var text = new StringBuilder($"{r.Id} {Path.GetFileName(r.Program)} (pid {r.ProcessId}) in a {r.Columns}x{r.Rows} {r.Host}\n");
                    ConsoleSteps(r, r.Steps, text);
                    return ToolOutput.With(text.ToString(), new LiveConsolePage(ConsoleSummary(r), [], null, []) { Steps = StepRows(r.Steps) });
                }
                case "transcript":
                    return ConsoleTranscript(live.GetConsole(RequireConsole(run)), cursor, limit);
                default:
                    throw new ToolError(ErrorCode.InvalidArgument, $"Unknown action '{action}'.", "action=start, stop, list, status or transcript");
            }
        }, cancellationToken);

    private static string DefaultSize() => $"{LiveSessionService.DefaultColumns}x{LiveSessionService.DefaultRows}";

    private string RequireConsole(string? run) => OnlyRun(run, null, live.ConsoleRuns.Select(r => (r.Id, "")), "live_console");

    private static string Exit(LiveConsoleRun r) => r.ExitCode is { } c ? $" (exit code {c})" : "";

    private static LiveConsoleSummary ConsoleSummary(LiveConsoleRun r) => new(r.Id, r.Program, r.ProcessId, r.Host, r.State, r.ExitCode, r.Script, r.Count);

    private static List<LiveConsoleStepRow> StepRows(IReadOnlyList<LiveConsoleOutcome> outcomes) =>
        [.. outcomes.Select(o => new LiveConsoleStepRow(o.Step.Number, o.Step.Line, o.Outcome, o.Milliseconds, o.Detail))];

    /// <summary>Each step with its outcome; a stopped script adds what the console showed last.</summary>
    private static void ConsoleSteps(LiveConsoleRun r, IReadOnlyList<LiveConsoleOutcome> outcomes, StringBuilder text)
    {
        int width = outcomes.Count == 0 ? 0 : outcomes.Max(o => o.Step.Line.Length);
        foreach (var o in outcomes)
            text.AppendLine($"step {o.Step.Number,-3} {o.Step.Line.PadRight(width)}  " +
                            (o.Outcome == "stopped" ? $"stopped: {o.Detail}" : o.Outcome == "done" && o.Step.Verb is "wait" or "delay" ? $"done  {o.Milliseconds:N0} ms" : o.Outcome));
        var stop = outcomes.FirstOrDefault(o => o.Outcome == "stopped");
        if (stop != null)
        {
            var tail = r.Tail(ConsoleTailLines);
            text.AppendLine(tail.Count == 0 ? "the console showed nothing" : $"the console showed (last {ToolSupport.Plural(tail.Count, "line")}):");
            foreach (var l in tail) text.AppendLine($"  #{l.Sequence} {l.Text}");
        }
        var state = r.State == "running" ? "the program is running" : r.State == "stopped" ? "the run was stopped" : $"the program exited with code {r.ExitCode}";
        int notRun = outcomes.Count(o => o.Outcome == "not run");
        text.AppendLine(outcomes.Count == 0 ? $"no script; {state}"
            : stop != null ? $"script stopped at step {stop.Step.Number} of {outcomes.Count}{(notRun > 0 ? $", {ToolSupport.Plural(notRun, "step")} not run" : "")}; {state}"
            : $"script complete ({ToolSupport.Plural(outcomes.Count, "step")}); {state}");
    }

    private static string ConsoleTranscript(LiveConsoleRun r, string? cursor, int limit)
    {
        long start = 0;
        if (!string.IsNullOrWhiteSpace(cursor) && !long.TryParse(cursor.Trim(), NumberStyles.None, CultureInfo.InvariantCulture, out start))
            throw new ToolError(ErrorCode.InvalidArgument, $"Bad cursor '{cursor}'.", "pass the cursor of an earlier page");
        var (page, firstKept, last) = r.Page(start, limit);
        long dropped = start > 0 && start < firstKept ? firstKept - start : 0;
        (string, object) Render(int count)
        {
            var lines = page.Take(count).ToList();
            var text = new StringBuilder();
            if (dropped > 0) text.AppendLine($"{dropped:N0} lines before this page were dropped (a transcript keeps {LiveConsoleRun.Capacity:N0})");
            foreach (var l in lines) text.AppendLine($"#{l.Sequence} {l.Text}");
            // a partial line is shown again on the next poll, with what was written since
            var next = lines.Count == 0 ? Math.Max(start, firstKept) : lines[^1].Partial ? lines[^1].Sequence : lines[^1].Sequence + 1;
            string? nextCursor = (lines.Count == limit || count < page.Count) && lines[^1].Sequence < last ? next.ToString(CultureInfo.InvariantCulture) : null;
            text.AppendLine(lines.Count == 0 && start <= 1 ? $"No output ({r.State})."
                : nextCursor != null ? $"more: cursor={nextCursor}"
                : r.State == "running" ? $"end of the transcript so far; poll again with cursor={next}" : $"end of the transcript ({r.State}{(r.ExitCode is { } c ? $", exit code {c}" : "")})");
            var rows = lines.Select(l => new LiveConsoleRow(l.Sequence, Iso(l.Time), l.Text) { Partial = l.Partial }).ToList();
            return (text.ToString(), new LiveConsolePage(ConsoleSummary(r), rows, nextCursor, []) { Dropped = dropped });
        }
        return FitPage(page.Count, Render);
    }
}
