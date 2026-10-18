using Corvus.Core;
using Corvus.Native.Diagnostics;
using Corvus.Services;
using Corvus.Tools;

namespace Corvus.Tests;

/// <summary>A console host whose program answers each input through <see cref="Answer"/>; the test writes its output and ends it.</summary>
internal sealed class ScriptedConsoleHost : IConsoleHost
{
    public string? Missing { get; init; }
    public Func<string, string?>? Answer { get; init; }
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

        public void Resize(int columns, int rows) => Size = (columns, rows);
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
    private readonly string _program;

    public LiveConsoleTests()
    {
        _host = new ScriptedConsoleHost { Answer = input => input == "Ada\r" ? "Ada\r\n\x1b[32mhello, Ada\x1b[0m\r\n> " : null };
        _service = new LiveSessionService(_workspace, new NativeCodeService(_workspace, new ServerOptions())) { ConsoleHost = _host };
        _tools = new LiveSessionTools(new ServerOptions { AllowLive = true, AllowLiveSpawn = true }, _service);
        _program = _dir.File("prompt.exe");
        File.WriteAllBytes(_program, [0x4D, 0x5A]);
    }

    public void Dispose()
    {
        _service.Dispose();
        _workspace.Dispose();
        _dir.Dispose();
    }

    /// <summary>Starts the run and shows the prompt once the script is waiting for it.</summary>
    private Task<string> Start(int timeoutSeconds, params string[] script)
    {
        var call = _tools.LiveConsole("start", program: _program, script: script, timeoutSeconds: timeoutSeconds);
        _ = Task.Run(async () =>
        {
            while (_host.Last == null) await Task.Delay(5);
            _host.Last.Show("\x1b]0;prompt.exe\a\x1b[?25lname?\x1b[1C");
        });
        return call;
    }

    [Fact]
    public async Task Steps_run_in_order_and_waits_match_the_output()
    {
        var text = await Start(10, "wait name?", "send Ada\\r", "# the program greets", "wait hello, Ada", "resize 80 24\ndelay 10");
        Assert.Matches(@"step 1\s+wait name\?\s+done\s+[\d,]+ ms\r?\nstep 2\s+send Ada\\r\s+done\r?\nstep 3\s+wait hello, Ada\s+done", text);
        Assert.Contains("script complete (5 steps); the program is running", text);
        Assert.Equal(["Ada\r"], _host.Last!.Input);
        Assert.Equal((80, 24), _host.Last.Size);

        // escape sequences are left out; cursor-forward reads as a space
        var transcript = await _tools.LiveConsole("transcript", run: "con-1");
        Assert.Matches(@"#1 name\? Ada\r?\n#2 hello, Ada\r?\n#3 > \r?\nend of the transcript so far; poll again with cursor=3", transcript);

        _host.Last.Exit(0);
        for (int i = 0; i < 100 && _service.GetConsole("con-1").State == "running"; i++) await Task.Delay(10);
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

        var status = await _tools.LiveConsole("status", run: "con-1");
        Assert.Matches(@"step 4\s+send x\s+not run", status);
        Assert.Contains("con-1 prompt.exe pid 4242: running, script stopped at step 3", await _tools.LiveConsole());

        // stop leaves a run whose program has exited as it was
        _host.Last.Exit(3);
        for (int i = 0; i < 100 && _service.GetConsole("con-1").State == "running"; i++) await Task.Delay(10);
        var stop = await _tools.LiveConsole("stop", run: "con-1");
        Assert.Contains("con-1 exited (exit code 3)", stop);
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
        // the partial line comes again with what was written since
        _host.Last.Show("yes\r\n");
        Assert.Contains("#5 more? yes", await _tools.LiveConsole("transcript", run: "con-1", cursor: "5"));

        Assert.Contains("con-1 stopped (exit code 1): 5 lines", await _tools.LiveConsole("stop", run: "con-1"));
        Assert.Contains("end of the transcript (stopped, exit code 1)", await _tools.LiveConsole("transcript", run: "con-1", cursor: "6"));
    }

    [Fact]
    public async Task Bad_scripts_and_a_missing_host_are_refused()
    {
        var bad = await Assert.ThrowsAsync<ToolError>(() => _tools.LiveConsole("start", program: _program, script: ["wait name?", "type Ada"]));
        Assert.Equal(ErrorCode.InvalidArgument, bad.Code);
        Assert.Contains("Script step 2 'type Ada': unknown step 'type'", bad.Message);
        Assert.Equal(ErrorCode.InvalidArgument, (await Assert.ThrowsAsync<ToolError>(() => _tools.LiveConsole("start", program: _program, script: ["resize 80"]))).Code);
        Assert.Null(_host.Last);

        using var workspace = new AssemblyWorkspace();
        using var service = new LiveSessionService(workspace, new NativeCodeService(workspace, new ServerOptions())) { ConsoleHost = new ScriptedConsoleHost { Missing = "no console here" } };
        var tools = new LiveSessionTools(new ServerOptions { AllowLive = true, AllowLiveSpawn = true }, service);
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
