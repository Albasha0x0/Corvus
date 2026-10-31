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
