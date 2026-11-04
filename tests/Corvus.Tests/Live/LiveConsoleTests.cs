using Corvus.Core;
using Corvus.Native.Diagnostics;
using Corvus.Services;
using Corvus.Tools;

namespace Corvus.Tests;

/// <summary>A console host whose program answers each input through <see cref="Answer"/>; the test writes its output and ends it.</summary>
internal sealed class ScriptedConsoleHost : IConsoleHost
{
    public string? Missing { get; init; }
    public Func<string, string?>? Answer { get; set; }
    public bool ResizeFails { get; set; }
    public Console? Last { get; private set; }

    public string Name => "scripted console";

    public ConsoleHostUnavailable? Unavailable() => Missing == null ? null : new(Missing, "use Windows");

    public IConsoleProcess Start(string program, IReadOnlyList<string> arguments, int columns, int rows, Action<string> output) =>
        Last = new Console(this, output, (columns, rows));

    internal sealed class Console(ScriptedConsoleHost host, Action<string> output, (int, int) size) : IConsoleProcess
    {
        private readonly TaskCompletionSource<int> _exited = new(TaskCreationOptions.RunContinuationsAsynchronously);
        public List<string> Input { get; } = [];
        public (int Columns, int Rows) Size { get; private set; } = size;
        public int ProcessId => 4242;
        public Task<int> Exited => _exited.Task;

        public void Show(string text) => output(text);
        public void Exit(int code) => _exited.TrySetResult(code);

        public void Write(string text)
        {
            Input.Add(text);
            if (host.Answer?.Invoke(text) is { } answer) output(answer);
        }

        public void Resize(int columns, int rows)
        {
            if (host.ResizeFails) throw new InvalidOperationException("resize refused");
            Size = (columns, rows);
        }
        public void Kill() => Exit(1);
        public void Dispose() => Kill();
    }
}

/// <summary>Console runs on a scripted host: steps in order, waits matched against the output, a stopped step reported with the transcript tail, and the transcript paged.</summary>
public sealed class LiveConsoleTests : IDisposable
{
    private readonly AssemblyWorkspace _workspace = new();
    private readonly TempDir _dir = new();
    private readonly LiveSessionService _service;
    private readonly ScriptedConsoleHost _host;
    private readonly LiveSessionTools _tools;
    private readonly ArmedClock _clock = new();
    private readonly string _program;

    public LiveConsoleTests()
    {
        _host = new ScriptedConsoleHost { Answer = input => input == "Ada\r" ? "Ada\r\n\x1b[32mhello, Ada\x1b[0m\r\n> " : null };
        _service = new LiveSessionService(_workspace, new NativeCodeService(_workspace, SharedCodeIndex.Options())) { ConsoleHost = _host, ConsoleTime = _clock };
        _tools = new LiveSessionTools(new ServerOptions { AllowLive = true, AllowLiveSpawn = true, LiveAllowAny = true }, _service);
        _program = _dir.File("prompt.exe");
        File.WriteAllBytes(_program, [0x4D, 0x5A]);
    }

    public void Dispose()
    {
        _service.Dispose();
        _workspace.Dispose();
        _dir.Dispose();
    }

    /// <summary>
    /// Starts the run, shows the prompt, moves the clock through the script's
    /// timers until it ends, and returns the run's status.
    /// </summary>
    private async Task<string> Start(int timeoutSeconds, params string[] script)
    {
        await _tools.LiveConsole("start", program: _program, script: script, timeoutSeconds: timeoutSeconds);
        // The prompt is shown before the clock moves, so a wait for it matches whether its timeout fired or not.
        _host.Last!.Show("\x1b]0;prompt.exe\a\x1b[?25lname?\x1b[1C");
        await _clock.RunUntilAsync(_service.GetConsole("con-1").ScriptDone);
        return await _tools.LiveConsole("status", run: "con-1");
    }

    [Fact]
    public async Task Steps_run_in_order_and_waits_match_the_output()
    {
        var text = await Start(10, "wait name?", "send Ada\\r", "# the program greets", "wait hello, Ada", "resize 80 24\ndelay 10");
        Assert.Matches(@"step 1\s+wait name\?\s+done\s+[\d,]+ ms\r?\nstep 2\s+send Ada\\r\s+done\r?\nstep 3\s+wait hello, Ada\s+done", text);
        Assert.Contains("script complete (5 steps); the program is running", text);
        Assert.Equal(["Ada\r"], _host.Last!.Input);
        Assert.Equal((80, 24), _host.Last.Size);

        // Escape sequences are left out; cursor-forward reads as a space.
        var transcript = await _tools.LiveConsole("transcript", run: "con-1");
        Assert.Matches(@"#1 name\? Ada\r?\n#2 hello, Ada\r?\n#3 > \r?\nend of the transcript so far; poll again with cursor=3", transcript);

        _host.Last.Exit(0);
        for (var waited = System.Diagnostics.Stopwatch.StartNew(); _service.GetConsole("con-1").State == "running" && waited.Elapsed < TimeSpan.FromMinutes(1);) await Task.Delay(10);
        Assert.Contains("con-1 prompt.exe pid 4242: exited (0), script complete, 3 lines", await _tools.LiveConsole());
    }

    [Fact]
    public async Task A_step_that_never_matches_stops_the_run_with_the_transcript_tail()
    {
        var text = await Start(1, "wait name?", "send Ada\\r", "wait goodbye", "send x");
        Assert.Contains("stopped: no output containing \"goodbye\" within 1,000 ms", text);
        Assert.Matches(@"the console showed \(last 3 lines\):\r?\n  #1 name\? Ada\r?\n  #2 hello, Ada\r?\n  #3 > ", text);
        Assert.Contains("script stopped at step 3 of 4, 1 step not run; the program is running", text);
        Assert.Equal(["Ada\r"], _host.Last!.Input);

        var status = await _tools.LiveConsole("status"); // the only run
        Assert.Matches(@"step 4\s+send x\s+not run", status);
        Assert.Contains("con-1 prompt.exe pid 4242: running, script stopped at step 3", await _tools.LiveConsole());
        Assert.Contains(_workspace.DrainNotices(), n => n.StartsWith("con-1 script stopped at step 3"));

        // Stop leaves a run whose program has exited as it was.
        _host.Last.Exit(3);
        for (var waited = System.Diagnostics.Stopwatch.StartNew(); _service.GetConsole("con-1").State == "running" && waited.Elapsed < TimeSpan.FromMinutes(1);) await Task.Delay(10);
        var stop = await _tools.LiveConsole("stop", run: "con-1");
        Assert.Contains("con-1 exited (exit code 3)", stop);
    }

    [Fact]
    public async Task A_never_matching_wait_returns_from_start_in_under_a_second()
    {
        // Wall-clock bound: start must not wait for the 10 s step timeout.
        var clock = System.Diagnostics.Stopwatch.StartNew();
        var text = await _tools.LiveConsole("start", program: _program, script: ["wait goodbye"], timeoutSeconds: 10);
        Assert.True(clock.Elapsed < TimeSpan.FromSeconds(1), $"start took {clock.Elapsed}");
        // The script starts in the background; status waits until it reaches its step.
        Assert.Matches(@"step 1\s+wait goodbye\s+running", await _tools.LiveConsole("status", waitSeconds: 1));
        Assert.Contains("con-1 prompt.exe", text);
        Assert.Contains("the script runs in the background, at most 10 s", text);
        Assert.Contains("Next: live_console action=status run=con-1 waitSeconds=10 waits for the script", text);
    }

    [Fact]
    public async Task Status_with_waitSeconds_shows_the_waiting_step()
    {
        await _tools.LiveConsole("start", program: _program, script: ["send x", "wait goodbye", "send y"], timeoutSeconds: 10);
        // The wait runs on the real clock; the script's own timers stay on the armed clock.
        var status = await _tools.LiveConsole("status", waitSeconds: 1);
        Assert.Matches(@"step 2\s+wait goodbye\s+running", status);
        Assert.Matches(@"step 3\s+send y\s+pending", status);
        Assert.Contains("script running at step 2 of 3", status);
        Assert.Contains("Next: live_console action=status run=con-1 waitSeconds=30", status);
        Assert.Equal(ErrorCode.InvalidArgument, (await Assert.ThrowsAsync<ToolError>(() => _tools.LiveConsole("status", waitSeconds: 301))).Code);
    }

    [Fact]
    public async Task Stop_cancels_a_waiting_script_and_a_notice_names_the_next_call()
    {
        await _tools.LiveConsole("start", program: _program, script: ["wait goodbye", "send y"], timeoutSeconds: 10);
        // CI run 41292755924 (ubuntu): the stop replied before the script ended.
        await _tools.LiveConsole("stop", run: "con-1");
        var status = await _tools.LiveConsole("status", run: "con-1");
        Assert.Matches(@"step 1\s+wait goodbye\s+cancelled: ended by action=stop", status);
        Assert.Matches(@"step 2\s+send y\s+not run", status);
        Assert.Contains("con-1 prompt.exe pid 4242: stopped (1), script cancelled at step 1", await _tools.LiveConsole());
        Assert.Contains(_workspace.DrainNotices(), n => n.StartsWith("con-1 script cancelled at step 1") && n.Contains("Next: live_console action=transcript run=con-1"));
    }

    [Fact]
    public async Task A_resize_that_throws_stops_the_script_and_a_notice_names_the_step()
    {
        _host.ResizeFails = true;
        var status = await Start(10, "resize 80 24", "send y");
        Assert.Matches(@"step 1\s+resize 80 24\s+stopped: resize refused", status);
        Assert.Matches(@"step 2\s+send y\s+not run", status);
        Assert.Contains(_workspace.DrainNotices(), n => n.StartsWith("con-1 script stopped at step 1 (resize refused)"));
    }

    [Fact]
    public async Task Stop_during_a_send_step_cancels_the_steps_after_it()
    {
        // The first input cancels the script, as action=stop does.
        _host.Answer = _ =>
        {
            _service.GetConsole("con-1").CancelScript();
            return null;
        };
        var status = await Start(10, "send a", "send b", "send c");
        Assert.Matches(@"step 1\s+send a\s+done", status);
        Assert.Matches(@"step 2\s+send b\s+cancelled", status);
        Assert.Single(_host.Last!.Input);
    }

    [Fact]
    public async Task A_completed_script_sends_a_complete_notice()
    {
        await Start(10, "send Ada\r");
        Assert.Contains(_workspace.DrainNotices(), n => n.StartsWith("con-1 script complete (1 steps)"));
    }

    [Fact]
    public async Task A_cancelled_status_call_ends_the_wait_and_the_script_keeps_running()
    {
        await _tools.LiveConsole("start", program: _program, script: ["wait goodbye"], timeoutSeconds: 10);
        using var cancel = new CancellationTokenSource(TimeSpan.FromMilliseconds(100));
        var status = await _tools.LiveConsole("status", waitSeconds: 30, cancellationToken: cancel.Token);
        Assert.Matches(@"step 1\s+wait goodbye\s+running", status);
        Assert.False(_service.GetConsole("con-1").ScriptDone.IsCompleted);
    }

    [Fact]
    public async Task Status_with_waitSeconds_returns_at_once_for_a_run_without_a_script()
    {
        await _tools.LiveConsole("start", program: _program);
        var status = await _tools.LiveConsole("status", waitSeconds: 300);
        Assert.Contains("Next: live_console action=transcript run=con-1", status);
    }

    [Fact]
    public async Task The_transcript_pages_with_a_cursor()
    {
        await Start(10, "wait name?");
        for (int i = 1; i <= 4; i++) _host.Last!.Show($"line {i}\r\n");
        _host.Last!.Show("more? ");

        var first = await _tools.LiveConsole("transcript", run: "con-1", limit: 2);
        Assert.Matches(@"#1 name\? line 1\r?\n#2 line 2\r?\nmore: cursor=3\r?\n", first);
        var rest = await _tools.LiveConsole("transcript", run: "con-1", cursor: "3");
        Assert.Matches(@"#3 line 3\r?\n#4 line 4\r?\n#5 more\? \r?\nend of the transcript so far; poll again with cursor=5", rest);
        Assert.Equal(rest, await _tools.LiveConsole("transcript", run: "con-1", cursor: "3", limit: 3)); // a page of exactly the rest ends the transcript
        // The partial line comes again with what was written since.
        _host.Last.Show("yes\r\n");
        Assert.Contains("#5 more? yes", await _tools.LiveConsole("transcript", run: "con-1", cursor: "5"));

        Assert.Contains("con-1 stopped (exit code 1): 5 lines", await _tools.LiveConsole("stop", run: "con-1"));
        Assert.Contains("end of the transcript (stopped, exit code 1)", await _tools.LiveConsole("transcript", run: "con-1", cursor: "6"));
    }

    [Fact]
    public async Task A_page_cut_to_the_output_budget_continues_after_its_last_line()
    {
        await Start(10, "wait name?");
        for (int i = 1; i <= 3000; i++) _host.Last!.Show($"line {i} {new string('x', 40)}\r\n");
        using var pipeline = new OutputPipeline();
        var seen = await pipeline.PageAll("live_console", 600, (cursor, ct) => _tools.LiveConsole("transcript", run: "con-1", cursor: cursor, limit: 1000, cancellationToken: ct),
            @"line (\d+) x");
        Assert.Equal(Enumerable.Range(1, 3000), seen);
    }

    [Fact]
    public async Task Bad_scripts_and_a_missing_host_are_refused()
    {
        var bad = await Assert.ThrowsAsync<ToolError>(() => _tools.LiveConsole("start", program: _program, script: ["wait name?", "type Ada"]));
        Assert.Equal(ErrorCode.InvalidArgument, bad.Code);
        Assert.Contains("Script step 2 'type Ada': unknown step 'type'", bad.Message);
        Assert.Equal(ErrorCode.InvalidArgument, (await Assert.ThrowsAsync<ToolError>(() => _tools.LiveConsole("start", program: _program, script: ["resize 80"]))).Code);
        foreach (var seconds in new[] { 0, 301 })
            Assert.Equal(ErrorCode.InvalidArgument, (await Assert.ThrowsAsync<ToolError>(() => _tools.LiveConsole("start", program: _program, timeoutSeconds: seconds))).Code);
        Assert.Equal(ErrorCode.InvalidArgument, (await Assert.ThrowsAsync<ToolError>(() => _tools.LiveConsole("start"))).Code);
        Assert.Equal(ErrorCode.NotFound, (await Assert.ThrowsAsync<ToolError>(() => _tools.LiveConsole("status", run: "con-9"))).Code);
        Assert.Null(_host.Last);

        using var workspace = new AssemblyWorkspace();
        using var service = new LiveSessionService(workspace, new NativeCodeService(workspace, SharedCodeIndex.Options())) { ConsoleHost = new ScriptedConsoleHost { Missing = "no console here" } };
        var tools = new LiveSessionTools(new ServerOptions { AllowLive = true, AllowLiveSpawn = true, LiveAllowAny = true }, service);
        Assert.Equal(ErrorCode.ProviderUnavailable, (await Assert.ThrowsAsync<ToolError>(() => tools.LiveConsole("start", program: _program))).Code);
    }

    [Fact]
    public void Virtual_terminal_output_reads_as_plain_text_across_chunks()
    {
        var vt = new VirtualTerminalText();
        Assert.Equal("a", vt.Plain("a\x1b[3"));
        Assert.Equal("   c\n", vt.Plain("Cc\r\n"));
        Assert.Equal("d", new VirtualTerminalText().Plain("\x1b]0;title\x1b\\d"));
        Assert.Equal(@"send x\r\e\x07", "send x" + LiveSessionService.Visible("\r\x1b\a"));
    }
}
