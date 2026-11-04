using System.Diagnostics;
using System.Globalization;
using System.Text.RegularExpressions;
using Corvus.Core;
using ModelContextProtocol.Protocol;
using Xunit.Abstractions;

namespace Corvus.Tests;

/// <summary>The session tool calls the real session tests share: each call and its time go to the test output.</summary>
public abstract class LiveToolCalls(ITestOutputHelper output)
{
    protected ITestOutputHelper Output { get; } = output;

    /// <summary>The steps this test completed; the session tool calls record theirs.</summary>
    protected TestPhases Phases { get; } = new(output);

    /// <summary>Calls <paramref name="tool"/>; with <paramref name="log"/> false only its time and size are written.</summary>
    private protected async Task<(string Text, bool IsError)> Call(InProcessServer server, string tool, Dictionary<string, object?> args, bool log = true)
    {
        var sw = Stopwatch.StartNew();
        var r = await server.Client.CallToolAsync(tool, args);
        var text = string.Concat(r.Content.OfType<TextContentBlock>().Select(b => b.Text));
        var call = $"{tool} {string.Join(" ", args.Select(a => $"{a.Key}={(a.Value is string[] l ? string.Join(",", l) : a.Value)}"))} ({sw.ElapsedMilliseconds} ms)";
        Output.WriteLine(log ? $"{call}:\n{text}" : $"{call}: {text.Length:N0} chars");
        Phases.Record(tool, args, text, r.IsError == true);
        if (args.GetValueOrDefault("session") is string named) _lastSession = named;
        return (text, r.IsError == true);
    }

    private protected async Task<string> Ok(InProcessServer server, string tool, Dictionary<string, object?> args, bool log = true)
    {
        var (text, failed) = await Call(server, tool, args, log);
        Assert.False(failed, $"{text}\n{Phases.Summary()}\n{(failed ? TargetState(server) : "")}");
        return text;
    }

    private string? _lastSession;

    /// <summary>The target's CPU time and threads and the worker's quiet time for the session the test last named; "" without one.</summary>
    private protected string TargetState(InProcessServer server, string? session = null)
    {
        var service = server.Services.GetService(typeof(Corvus.Services.LiveSessionService)) as Corvus.Services.LiveSessionService;
        var s = service?.Sessions.FirstOrDefault(x => x.Id.Equals(session ?? _lastSession ?? "live-1", StringComparison.OrdinalIgnoreCase));
        return s == null || s.ProcessId == 0 ? "" : $"{s.Id} target: " + LiveTargetDiagnostics.Describe(s.ProcessId, s.Worker.SinceLastLine);
    }

    /// <summary>Calls <paramref name="tool"/> expecting the error <paramref name="code"/> within a minute; returns its text.</summary>
    private protected async Task<string> Refused(InProcessServer server, string tool, Dictionary<string, object?> args, string code)
    {
        var (text, failed) = await Call(server, tool, args).WaitAsync(TimeSpan.FromMinutes(1));
        Assert.True(failed, text);
        Assert.Contains($"Error ({code}", text);
        return text;
    }

    private protected Task<InProcessServer> Server(bool scripting = false) => Phases.Run("server start", () => InProcessServer.StartAsync(options: new ServerOptions
    {
        BackgroundIndexing = false, WatchFiles = false, AllowLiveAttach = true, AllowLiveSpawn = true, LiveAllowAny = true, LiveScripting = scripting,
    }));

    /// <summary>Starts <paramref name="exe"/> suspended as <paramref name="session"/>; returns its process id.</summary>
    private protected async Task<int> Spawn(InProcessServer server, string exe, string session, params string[] arguments)
    {
        var open = await Ok(server, "live_session", new() { ["action"] = "spawn", ["program"] = exe, ["arguments"] = arguments });
        Assert.Contains($"{session} (frida): ", open);
        Assert.Contains("suspended", open);
        return int.Parse(Regex.Match(open, @"pid (\d+)").Groups[1].Value, CultureInfo.InvariantCulture);
    }

    private protected async Task<string> UntilExited(InProcessServer server, string session, int seconds = 120)
    {
        for (int i = 0; i < seconds * 10; i++)
        {
            var (status, _) = await Call(server, "live_session", new() { ["action"] = "status", ["session"] = session });
            if (status.Contains(", exited")) return status;
            await Task.Delay(100);
        }
        Assert.Fail($"{session} did not exit within {seconds} s; {Phases.Summary()}\n{TargetState(server, session)}");
        return "";
    }

    /// <summary>Writes the stack of each of the first <paramref name="threads"/> threads of <paramref name="pid"/> to the test output.</summary>
    private protected async Task AllStacks(InProcessServer server, int pid, int threads = 32)
    {
        var process = pid.ToString(CultureInfo.InvariantCulture);
        var (list, _) = await Call(server, "inspect_process", new() { ["process"] = process, ["view"] = "threads", ["limit"] = threads });
        foreach (Match m in Regex.Matches(list, @"^\s*(\d+)(?: ""[^""]*"")?: ", RegexOptions.Multiline))
            await Call(server, "inspect_process", new() { ["process"] = process, ["view"] = "stacks", ["thread"] = m.Groups[1].Value });
    }

    /// <summary>Waits for a stop in 30 s slices until the session's events stall; the idle answer is returned as the last text.</summary>
    private protected Task<string> WaitStop(InProcessServer server, string session, string action = "continue")
    {
        var first = true;
        return WaitStop(
            async () =>
            {
                // Resume once; later slices only wait, so a held stop is never resumed.
                var slice = first ? action : "list";
                first = false;
                return await Ok(server, "live_break", new() { ["session"] = session, ["action"] = slice, ["wait"] = true, ["waitSeconds"] = 30 });
            },
            () => EventCount(server, session),
            new StallRule(ServerOptions.StallWindow()));
    }

    /// <summary>Returns the stop after <paramref name="action"/> ("continue" resumes first, "list" only waits); fails with the last status, the events and the target state when the session stalls.</summary>
    private protected async Task<string> StopWithin(InProcessServer server, string session, string action = "continue")
    {
        var stop = await WaitStop(server, session, action);
        if (stop.Contains("no stop within", StringComparison.Ordinal))
            Assert.Fail($"{stop}\n{Phases.Summary()}\n{TargetState(server, session)}\nevents:\n{await Events(server, session, log: false)}");
        return stop;
    }

    private async Task<int> EventCount(InProcessServer server, string session) => (await Events(server, session, log: false)).Split('\n').Length;

    /// <summary>Polls <paramref name="probe"/> every 200 ms until it returns a value; fails with the last status and the target state when the session's events stall.</summary>
    private protected async Task<string> HeldWithin(InProcessServer server, string session, Func<string, string?> probe, string what)
    {
        var rule = new StallRule(ServerOptions.StallWindow());
        var status = "";
        var result = await Poll(
            async () =>
            {
                status = await Ok(server, "live_session", new() { ["action"] = "status", ["session"] = session });
                return probe(status);
            },
            () => EventCount(server, session),
            rule);
        if (result == null) Assert.Fail($"{what}: {status}\n{rule.LastUnitText}\n{Phases.Summary()}\n{TargetState(server, session)}\nevents:\n{await Events(server, session, log: false)}");
        return result!;
    }

    /// <summary>Repeats <paramref name="probe"/> until it returns a value; null when <paramref name="eventCount"/> stops growing for the rule's window.</summary>
    internal static async Task<string?> Poll(Func<Task<string?>> probe, Func<Task<int>> eventCount, StallRule rule)
    {
        var seen = -1;
        while (true)
        {
            if (await probe() is { } found) return found;
            var count = await eventCount();
            if (count != seen) { seen = count; rule.Progress($"{count} event lines"); }
            else if (rule.Stalled(null)) return null;
            await Task.Delay(200);
        }
    }

    /// <summary>Repeats <paramref name="slice"/> until it returns a stop; ends when <paramref name="eventCount"/> stops growing for the rule's window.</summary>
    internal static async Task<string> WaitStop(Func<Task<string>> slice, Func<Task<int>> eventCount, StallRule rule)
    {
        var seen = -1;
        while (true)
        {
            var stop = await slice();
            // Matches the idle answer of live_break wait=true (LiveSessionTools).
            if (!stop.Contains("no stop within", StringComparison.Ordinal)) return stop;
            var count = await eventCount();
            if (count != seen) { seen = count; rule.Progress($"{count} event lines"); }
            else if (rule.Stalled(null)) return $"{stop}{Environment.NewLine}{rule.LastUnitText}";
        }
    }

    /// <summary>All events of one kind, every page.</summary>
    private protected async Task<string> Events(InProcessServer server, string session, string? kind = null, string? from = null, bool log = true)
    {
        var all = new System.Text.StringBuilder();
        string? cursor = null;
        for (int page = 0; page < 200; page++)
        {
            var args = new Dictionary<string, object?> { ["session"] = session, ["limit"] = 500 };
            if (kind != null) args["kind"] = kind;
            if (from != null) args["from"] = from;
            if (cursor != null) args["cursor"] = cursor;
            var (text, failed) = await Call(server, "live_events", args, log);
            Assert.False(failed, text);
            all.Append(text);
            var next = Regex.Match(text, @"cursor=(\S+)");
            if (!next.Success || !text.Contains("more", StringComparison.OrdinalIgnoreCase)) break;
            cursor = next.Groups[1].Value;
        }
        return all.ToString();
    }

    protected static void Ended(int pid, int waitMs = 10_000)
    {
        try
        {
            using var p = Process.GetProcessById(pid);
            Assert.True(p.WaitForExit(waitMs), $"process {pid} is still running{State(pid)}");
        }
        catch (ArgumentException) { /* already gone */ }
    }

    // A stopped process (T) was left held; a sleeping or running one (S, R) is only slow.
    private static string State(int pid)
    {
        try
        {
            var stat = File.ReadAllText($"/proc/{pid}/stat");
            return $" (state {stat[(stat.LastIndexOf(')') + 2)..].Split(' ')[0]})";
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException) { return ""; }
    }
}
