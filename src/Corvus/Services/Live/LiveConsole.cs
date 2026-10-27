using System.Collections.Concurrent;
using System.Globalization;
using System.Text;
using Corvus.Core;
using Corvus.Native.Diagnostics;

namespace Corvus.Services;

/// <summary>A transcript line with its sequence number, the cursor live_console pages by; a partial line is still being written.</summary>
public sealed record LiveConsoleLine(long Sequence, DateTime Time, string Text, bool Partial);

/// <summary>One step of a console script as written: send, wait, resize or delay, with its decoded text or numbers.</summary>
public sealed record LiveConsoleStep(int Number, string Line, string Verb, string Text, int First, int Second);

/// <summary>What a step did: done, stopped (with why) or not run.</summary>
public sealed record LiveConsoleOutcome(LiveConsoleStep Step, string Outcome, long Milliseconds, string? Detail);

/// <summary>A program run under a console host: its output as plain text lines in a bounded ring, and each script step's outcome.</summary>
public sealed class LiveConsoleRun
{
    public const int Capacity = 20_000;
    /// <summary>Characters a wait searches: the output since the last match, at most this many.</summary>
    private const int SearchLimit = 256 * 1024;
    private readonly Queue<LiveConsoleLine> _ring = new();
    private readonly StringBuilder _open = new();
    private readonly StringBuilder _search = new();
    private readonly VirtualTerminalText _vt = new();
    private readonly List<LiveConsoleOutcome> _steps = [];
    private TaskCompletionSource _changed = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private DateTime _openTime;
    private long _sequence;
    private string _state = "running";

    internal LiveConsoleRun(string id, string program, IReadOnlyList<string> arguments, string host, int columns, int rows)
    {
        (Id, Program, Arguments, Host, Columns, Rows) = (id, program, arguments, host, columns, rows);
    }

    public string Id { get; }
    public string Program { get; }
    public IReadOnlyList<string> Arguments { get; }
    /// <summary>The console host, as the platform names it.</summary>
    public string Host { get; }
    public int Columns { get; internal set; }
    public int Rows { get; internal set; }
    public int ProcessId { get; internal set; }
    public DateTime Started { get; } = DateTime.UtcNow;
    internal IConsoleProcess? Process { get; set; }
    internal bool StopRequested { get; set; }

    /// <summary>running, exited or stopped.</summary>
    public string State { get { lock (_ring) return _state; } }
    public int? ExitCode { get; private set; }
    public long Dropped { get; private set; }

    /// <summary>Lines so far, the partial one included.</summary>
    public long Count { get { lock (_ring) return _sequence + (_open.Length > 0 ? 1 : 0); } }

    public IReadOnlyList<LiveConsoleOutcome> Steps { get { lock (_steps) return [.. _steps]; } }

    /// <summary>complete, stopped at step N, or none.</summary>
    public string Script
    {
        get
        {
            lock (_steps)
                return _steps.Count == 0 ? "none"
                    : _steps.FirstOrDefault(s => s.Outcome == "stopped") is { } stop ? $"stopped at step {stop.Step.Number}" : "complete";
        }
    }

    internal void Record(LiveConsoleOutcome outcome)
    {
        lock (_steps) _steps.Add(outcome);
    }

    internal void Append(string output)
    {
        var plain = _vt.Plain(output);
        if (plain.Length == 0) return;
        lock (_ring)
        {
            foreach (char c in plain)
            {
                if (c != '\n')
                {
                    if (_open.Length == 0) _openTime = DateTime.UtcNow;
                    _open.Append(c);
                    continue;
                }
                _ring.Enqueue(new LiveConsoleLine(++_sequence, _open.Length > 0 ? _openTime : DateTime.UtcNow, _open.ToString(), false));
                _open.Clear();
                if (_ring.Count > Capacity)
                {
                    _ring.Dequeue();
                    Dropped++;
                }
            }
            _search.Append(plain);
            if (_search.Length > SearchLimit) _search.Remove(0, _search.Length - SearchLimit);
            Signal();
        }
    }

    internal void Finish(int exitCode)
    {
        lock (_ring)
        {
            if (_state != "running") return;
            (_state, ExitCode) = (StopRequested ? "stopped" : "exited", exitCode);
            Signal();
        }
    }

    private void Signal()
    {
        _changed.TrySetResult();
        _changed = new(TaskCreationOptions.RunContinuationsAsynchronously);
    }

    /// <summary>Waits until the output since the last match contains <paramref name="text"/>; the match consumes the output up to its end.</summary>
    internal async Task<bool> WaitForAsync(string text, TimeSpan timeout, TimeProvider time, CancellationToken ct)
    {
        long start = time.GetTimestamp();
        while (true)
        {
            Task changed;
            lock (_ring)
            {
                int at = _search.ToString().IndexOf(text, StringComparison.Ordinal);
                if (at >= 0)
                {
                    _search.Remove(0, at + text.Length);
                    return true;
                }
                if (_state != "running") return false;
                changed = _changed.Task;
            }
            var left = timeout - time.GetElapsedTime(start);
            if (left <= TimeSpan.Zero) return false;
            await Task.WhenAny(changed, Task.Delay(left, time, ct)).ConfigureAwait(false);
            ct.ThrowIfCancellationRequested();
        }
    }

    /// <summary>Lines from <paramref name="from"/> (a sequence) on, the partial line last; the first sequence kept tells what was dropped.</summary>
    public (IReadOnlyList<LiveConsoleLine> Lines, long FirstKept, long Last) Page(long from, int limit)
    {
        lock (_ring)
        {
            var first = _ring.Count > 0 ? _ring.Peek().Sequence : _sequence + 1;
            return (All().Where(l => l.Sequence >= from).Take(limit).ToList(), first, Count);
        }
    }

    /// <summary>The last <paramref name="count"/> lines, the partial one included.</summary>
    public IReadOnlyList<LiveConsoleLine> Tail(int count)
    {
        lock (_ring)
        {
            var all = All().ToList();
            return all.Skip(Math.Max(0, all.Count - count)).ToList();
        }
    }

    private IEnumerable<LiveConsoleLine> All() =>
        _open.Length == 0 ? _ring : _ring.Append(new LiveConsoleLine(_sequence + 1, _openTime, _open.ToString(), true));
}

public sealed partial class LiveSessionService
{
    public const int DefaultColumns = 120, DefaultRows = 30;
    private const int MaxSteps = 200, MaxDelayMs = 60_000;
    private readonly ConcurrentDictionary<string, LiveConsoleRun> _consoles = new(StringComparer.OrdinalIgnoreCase);
    private int _nextConsole;

    /// <summary>The console host console runs start programs under.</summary>
    public IConsoleHost ConsoleHost { get; set; } = ConsoleHosts.ForThisMachine();

    /// <summary>The clock script waits and delays are measured by.</summary>
    public TimeProvider ConsoleTime { get; init; } = TimeProvider.System;

    public IReadOnlyList<LiveConsoleRun> ConsoleRuns => _consoles.Values.OrderBy(r => int.Parse(r.Id[4..], CultureInfo.InvariantCulture)).ToList();

    public LiveConsoleRun GetConsole(string id) =>
        _consoles.TryGetValue(id?.Trim() ?? "", out var r) ? r
            : throw new ToolError(ErrorCode.NotFound, $"No console run '{id}'.", "live_console action=list shows the runs; action=start begins one");

    // Text escapes: \r, \n, \t, \e, \xHH and \\.
    /// <summary>Parses send/wait &lt;text&gt;, resize &lt;columns&gt; &lt;rows&gt; and delay &lt;ms&gt; lines; skips blank and # lines; throws on a bad step.</summary>
    public static IReadOnlyList<LiveConsoleStep> ParseConsoleScript(IEnumerable<string> script)
    {
        var steps = new List<LiveConsoleStep>();
        foreach (var raw in script.SelectMany(s => s.Split('\n')))
        {
            var line = raw.TrimEnd('\r').TrimStart();
            if (line.Length == 0 || line[0] == '#') continue;
            int space = line.IndexOf(' ');
            var verb = (space < 0 ? line : line[..space]).ToLowerInvariant();
            var rest = space < 0 ? "" : line[(space + 1)..];
            int number = steps.Count + 1;
            ToolError Bad(string why) => new(ErrorCode.InvalidArgument, $"Script step {number} '{line}': {why}.",
                "steps: send <text>, wait <text>, resize <columns> <rows>, delay <ms>; \\r presses Enter");
            switch (verb)
            {
                case "send" or "wait":
                    var text = Unescape(rest, Bad);
                    if (text.Length == 0) throw Bad($"{verb} needs text");
                    steps.Add(new(number, line, verb, text, 0, 0));
                    break;
                case "resize":
                    var size = rest.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                    if (size.Length != 2 || !int.TryParse(size[0], NumberStyles.None, CultureInfo.InvariantCulture, out int columns) || columns is < 1 or > 1000
                        || !int.TryParse(size[1], NumberStyles.None, CultureInfo.InvariantCulture, out int rows) || rows is < 1 or > 1000)
                        throw Bad("resize needs columns and rows, 1-1000 each");
                    steps.Add(new(number, line, verb, "", columns, rows));
                    break;
                case "delay":
                    if (!int.TryParse(rest.Trim(), NumberStyles.None, CultureInfo.InvariantCulture, out int ms) || ms > MaxDelayMs)
                        throw Bad($"delay needs milliseconds, 0-{MaxDelayMs:N0}");
                    steps.Add(new(number, line, verb, "", ms, 0));
                    break;
                default:
                    throw Bad($"unknown step '{verb}'");
            }
            if (steps.Count > MaxSteps) throw Bad($"a script has at most {MaxSteps} steps");
        }
        return steps;
    }

    private static string Unescape(string text, Func<string, ToolError> bad)
    {
        var sb = new StringBuilder(text.Length);
        for (int i = 0; i < text.Length; i++)
        {
            if (text[i] != '\\' || i + 1 == text.Length) { sb.Append(text[i]); continue; }
            char c = text[++i];
            switch (c)
            {
                case 'r': sb.Append('\r'); break;
                case 'n': sb.Append('\n'); break;
                case 't': sb.Append('\t'); break;
                case 'e': sb.Append('\x1b'); break;
                case '\\': sb.Append('\\'); break;
                case 'x' when i + 2 < text.Length && byte.TryParse(text.AsSpan(i + 1, 2), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out byte b):
                    sb.Append((char)b);
                    i += 2;
                    break;
                default: throw bad($"unknown escape \\{c}");
            }
        }
        return sb.ToString();
    }

    /// <summary>Starts <paramref name="program"/> under the console host; the run keeps its output until the server exits.</summary>
    public LiveConsoleRun StartConsole(string program, IReadOnlyList<string> arguments)
    {
        if (ConsoleHost.Unavailable() is { } missing) throw new ToolError(ErrorCode.ProviderUnavailable, missing.Reason, missing.Remediation);
        var path = InputFiles.RequireRegularFile(program.Trim());
        if (_consoles.Values.Count(r => r.State == "running") >= MaxSessions)
            throw new ToolError(ErrorCode.LimitExceeded, $"{MaxSessions} console runs are running.", "stop one with live_console action=stop");
        var run = new LiveConsoleRun("con-" + Interlocked.Increment(ref _nextConsole), path, arguments, ConsoleHost.Name, DefaultColumns, DefaultRows);
        var process = ConsoleHost.Start(path, arguments, run.Columns, run.Rows, run.Append);
        (run.Process, run.ProcessId) = (process, process.ProcessId);
        process.Exited.ContinueWith(t => run.Finish(t.IsCompletedSuccessfully ? t.Result : -1), CancellationToken.None,
            TaskContinuationOptions.ExecuteSynchronously, TaskScheduler.Default);
        _consoles[run.Id] = run;
        return run;
    }

    /// <summary>Runs the steps in order; the first that cannot complete stops the script, and the steps after it are not run.</summary>
    public async Task<IReadOnlyList<LiveConsoleOutcome>> RunConsoleScriptAsync(LiveConsoleRun run, IReadOnlyList<LiveConsoleStep> steps, TimeSpan waitTimeout, CancellationToken ct)
    {
        var outcomes = new List<LiveConsoleOutcome>();
        string? stopped = null;
        foreach (var step in steps)
        {
            if (stopped != null)
            {
                outcomes.Add(new(step, "not run", 0, null));
                continue;
            }
            long began = ConsoleTime.GetTimestamp();
            string? why = null;
            switch (step.Verb)
            {
                case "send":
                    if (run.State != "running") why = Ended(run);
                    else
                        try { run.Process!.Write(step.Text); }
                        catch (Exception e) when (e is IOException or InvalidOperationException or ObjectDisposedException) { why = $"the console did not take the input: {e.Message}"; }
                    break;
                case "wait":
                    if (!await run.WaitForAsync(step.Text, waitTimeout, ConsoleTime, ct).ConfigureAwait(false))
                        why = run.State != "running" ? $"{Ended(run)} before output containing \"{Visible(step.Text)}\""
                            : $"no output containing \"{Visible(step.Text)}\" within {waitTimeout.TotalMilliseconds:N0} ms";
                    break;
                case "resize":
                    if (run.State != "running") why = Ended(run);
                    else
                    {
                        run.Process!.Resize(step.First, step.Second);
                        (run.Columns, run.Rows) = (step.First, step.Second);
                    }
                    break;
                case "delay":
                    await Task.Delay(TimeSpan.FromMilliseconds(step.First), ConsoleTime, ct).ConfigureAwait(false);
                    break;
            }
            stopped = why;
            outcomes.Add(new(step, why == null ? "done" : "stopped", (long)ConsoleTime.GetElapsedTime(began).TotalMilliseconds, why));
        }
        foreach (var o in outcomes) run.Record(o);
        return outcomes;
    }

    private static string Ended(LiveConsoleRun r) => r.State == "stopped" ? "the run was stopped" : $"the program exited with code {r.ExitCode}";

    /// <summary>Text as a script writes it: control characters as escapes.</summary>
    public static string Visible(string text) =>
        string.Concat(text.Select(c => c switch
        {
            '\r' => "\\r", '\n' => "\\n", '\t' => "\\t", '\x1b' => "\\e", '\\' => "\\\\",
            < ' ' or '\x7f' => $"\\x{(int)c:X2}",
            _ => c.ToString(),
        }));

    /// <summary>Ends the program; the transcript stays.</summary>
    public async Task StopConsoleAsync(LiveConsoleRun run)
    {
        if (run.State != "running" || run.Process is not { } process) return;
        run.StopRequested = true;
        process.Kill();
        await Task.WhenAny(process.Exited, Task.Delay(TimeSpan.FromSeconds(8))).ConfigureAwait(false);
        if (process.Exited.IsCompletedSuccessfully) run.Finish(process.Exited.Result);
    }

    /// <summary>Every program run under a console ends with the server (their jobs end them as well should the server be killed).</summary>
    private void StopConsoles()
    {
        foreach (var run in _consoles.Values)
        {
            run.StopRequested = true;
            run.Process?.Dispose();
        }
    }
}
