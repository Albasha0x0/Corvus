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
        [Description("Still being written.")]
        public bool Partial { get; init; }
    }

    public sealed record LiveConsoleStepRow(int Step, [property: Description("As written.")] string Line,
        [property: Description("pending, running, done, stopped, cancelled or not run.")] string Outcome, long Milliseconds,
        [property: Description("Why it stopped.")] string? Detail);

    public sealed record LiveConsoleSummary(string Run, string Program, int ProcessId,
        [property: Description("The console host: the pseudoconsole (ConPTY) on Windows.")] string Host,
        [property: Description("running, exited or stopped.")] string State, int? ExitCode,
        [property: Description("none, running step N, complete, stopped at step N or cancelled at step N.")] string Script,
        long Lines);

    public sealed record LiveConsolePage(LiveConsoleSummary? Run, IReadOnlyList<LiveConsoleRow> Items,
        [property: Description("Cursor for the next page; null at the end.")] string? Cursor,
        IReadOnlyList<LiveConsoleSummary> Runs)
    {
        [Description("Each script step with its outcome.")]
        public IReadOnlyList<LiveConsoleStepRow>? Steps { get; init; }
        [Description("Lines dropped before this page.")]
        public long Dropped { get; init; }
    }

    [McpServerTool(Name = "live_console", Title = "Scripted console run", UseStructuredContent = true, OutputSchemaType = typeof(LiveConsolePage))]
    [Description("Drive a program with a background script; status shows steps, transcript pages output.")]
    public Task<string> LiveConsole(
        [Description("Action.")] string action = "list",
        [Description("start: program path.")] string? program = null,
        [Description("start: arguments.")] string[]? arguments = null,
        [Description("start: steps, one per line: send TEXT, wait TEXT (output contains it), resize COLUMNS ROWS, delay MS; TEXT takes \\r (Enter), \\n, \\t, \\e, \\xHH.")] string[]? script = null,
        [Description("Run id (con-1; omitted: the only one).")] string? run = null,
        [Description("Seconds per wait step (1-300).")] int timeoutSeconds = 10,
        [Description("transcript: cursor of a page; default the oldest line.")] string? cursor = null,
        [Description(ToolSupport.LimitDescription)] int limit = 100,
        [Description("status: seconds to wait for the script, 0-300.")] int waitSeconds = 0,
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
                    live.StartConsoleScript(r, steps, TimeSpan.FromSeconds(timeoutSeconds));
                    var text = new StringBuilder($"{r.Id} {Path.GetFileName(r.Program)} (pid {r.ProcessId}) in a {DefaultSize()} {r.Host}\n");
                    ConsoleSteps(r, r.Steps, text);
                    text.AppendLine(ScriptNext(r, steps, timeoutSeconds));
                    return ToolOutput.With(text.ToString(), new LiveConsolePage(ConsoleSummary(r), [], null, []) { Steps = StepRows(r.Steps) });
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
                    if (waitSeconds is < 0 or > 300)
                        throw new ToolError(ErrorCode.InvalidArgument, $"waitSeconds {waitSeconds} is outside 0-300.", "waitSeconds=30");
                    if (waitSeconds > 0) await LiveSessionService.WaitScriptAsync(r, TimeSpan.FromSeconds(waitSeconds), cancellationToken).ConfigureAwait(false);
                    var text = new StringBuilder($"{r.Id} {Path.GetFileName(r.Program)} (pid {r.ProcessId}) in a {r.Columns}x{r.Rows} {r.Host}\n");
                    ConsoleSteps(r, r.Steps, text);
                    text.AppendLine(r.IsScriptRunning
                        ? $"next: live_console action=status run={r.Id} waitSeconds=30 waits for the script; action=stop ends it"
                        : $"next: live_console action=transcript run={r.Id}");
                    return ToolOutput.With(text.ToString(), new LiveConsolePage(ConsoleSummary(r), [], null, []) { Steps = StepRows(r.Steps) });
                }
                case "transcript":
                    return ConsoleTranscript(live.GetConsole(RequireConsole(run)), cursor, limit);
                default:
                    throw new ToolError(ErrorCode.InvalidArgument, $"Unknown action '{action}'.", "action=start, stop, list, status or transcript");
            }
        // Not started under the token: a cancel ends only the status wait.
        });

    /// <summary>The longest the script can run and the call that waits for it.</summary>
    private static string ScriptNext(LiveConsoleRun r, IReadOnlyList<LiveConsoleStep> steps, int timeoutSeconds)
    {
        if (steps.Count == 0) return $"next: live_console action=transcript run={r.Id}";
        var bound = steps.Count(s => s.Verb == "wait") * (double)timeoutSeconds + steps.Where(s => s.Verb == "delay").Sum(s => s.First) / 1000.0;
        var wait = Math.Clamp((int)Math.Ceiling(bound), 1, 300);
        var more = bound > wait ? "; repeat it while the script is running" : "";
        return $"the script runs in the background, at most {bound:0.###} s (timeoutSeconds per wait step plus delays)\n" +
               $"next: live_console action=status run={r.Id} waitSeconds={wait} waits for the script{more}; action=stop ends it";
    }

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
                            (o.Outcome is "stopped" or "cancelled" ? $"{o.Outcome}: {o.Detail}" : o.Outcome == "done" && o.Step.Verb is "wait" or "delay" ? $"done  {o.Milliseconds:N0} ms" : o.Outcome));
        var stop = outcomes.FirstOrDefault(o => o.Outcome is "stopped" or "cancelled");
        if (stop != null)
        {
            var tail = r.Tail(ConsoleTailLines);
            text.AppendLine(tail.Count == 0 ? "the console showed nothing" : $"the console showed (last {ToolSupport.Plural(tail.Count, "line")}):");
            foreach (var l in tail) text.AppendLine($"  #{l.Sequence} {l.Text}");
        }
        var state = r.State == "running" ? "the program is running" : r.State == "stopped" ? "the run was stopped" : $"the program exited with code {r.ExitCode}";
        int notRun = outcomes.Count(o => o.Outcome == "not run");
        var active = outcomes.FirstOrDefault(o => o.Outcome is "running" or "pending");
        text.AppendLine(outcomes.Count == 0 ? $"no script; {state}"
            : stop != null ? $"script {stop.Outcome} at step {stop.Step.Number} of {outcomes.Count}{(notRun > 0 ? $", {ToolSupport.Plural(notRun, "step")} not run" : "")}; {state}"
            : active != null ? $"script running at step {active.Step.Number} of {outcomes.Count}; {state}"
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
            // A partial line is shown again on the next poll, with what was written since.
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
