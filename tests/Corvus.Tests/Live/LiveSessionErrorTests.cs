using Corvus.Core;
using Corvus.Services;
using Corvus.Tools;

namespace Corvus.Tests;

/// <summary>Each session tool's refusals on a scripted backend: missing and bad arguments, unknown ids, a closed session, the session limit.</summary>
public sealed class LiveSessionErrorTests : IDisposable
{
    private const ulong Base = 0x7ff6_1000_0000;
    private static readonly string Sqlite = RealPackages.File("SQLitePCLRaw.lib.e_sqlite3", "2.1.11", "runtimes", "win-x64", "native", "e_sqlite3.dll");
    private readonly AssemblyWorkspace _workspace = new();
    private readonly LiveSessionService _service;
    private readonly LiveSessionTools _tools;

    public LiveSessionErrorTests()
    {
        _service = new LiveSessionService(_workspace, new NativeCodeService(_workspace, SharedCodeIndex.Options())) { Backend = new ScriptedLiveBackend(Sqlite, Base, 0x200000) };
        _tools = new LiveSessionTools(new ServerOptions { AllowLive = true, AllowLiveAttach = true, AllowLiveSpawn = true, LiveScripting = true }, _service);
    }

    public void Dispose()
    {
        _service.Dispose();
        _workspace.Dispose();
    }

    private static async Task Refused(ErrorCode code, Func<Task<string>> call, string? message = null)
    {
        var e = await Assert.ThrowsAsync<ToolError>(call);
        Assert.True(code == e.Code, $"{e.Code}: {e.Message}");
        if (message != null) Assert.Contains(message, e.Message);
        Assert.False(string.IsNullOrWhiteSpace(e.Remediation), e.Message);
    }

    [Fact]
    public async Task Unknown_actions_and_missing_arguments_are_refused_with_the_next_step()
    {
        await _tools.LiveSession("attach", program: "99994242");
        await Refused(ErrorCode.InvalidArgument, () => _tools.LiveSession("open"), "Unknown action 'open'");
        await Refused(ErrorCode.InvalidArgument, () => _tools.LiveSession("attach"), "needs program");
        await Refused(ErrorCode.InvalidArgument, () => _tools.LiveSession("status"), "needs session");
        await Refused(ErrorCode.InvalidArgument, () => _tools.LiveBreak("live-1", "step"), "Unknown action");
        await Refused(ErrorCode.InvalidArgument, () => _tools.LiveBreak("live-1", "set"), "needs at");
        await Refused(ErrorCode.InvalidArgument, () => _tools.LiveBreak("live-1", "clear"), "needs stopPoint");
        await Refused(ErrorCode.InvalidArgument, () => _tools.LiveBreak("live-1", "continue", thread: "main"), "Bad thread id");
        await Refused(ErrorCode.InvalidArgument, () => _tools.LiveWatchCalls("live-1", "pause"), "Unknown action");
        await Refused(ErrorCode.InvalidArgument, () => _tools.LiveWatchCalls("live-1", "set"), "needs at");
        await Refused(ErrorCode.InvalidArgument, () => _tools.LiveWatchCalls("live-1", "clear"), "needs watch");
        await Refused(ErrorCode.InvalidArgument, () => _tools.LiveScriptCalls("live-1", "run"), "Unknown action");
        await Refused(ErrorCode.InvalidArgument, () => _tools.LiveScriptCalls("live-1", "load"), "one of them");
        await Refused(ErrorCode.InvalidArgument, () => _tools.LiveScriptCalls("live-1", "load", source: "send(1);", path: "a.js"), "one of them");
        await Refused(ErrorCode.InvalidArgument, () => _tools.LiveScriptCalls("live-1", "unload"), "needs script");
        await Refused(ErrorCode.InvalidArgument, () => _tools.LiveCoverage("live-1", "pause"), "Unknown action");
        await Refused(ErrorCode.InvalidArgument, () => _tools.LiveCoverage(action: "start"), "needs session");
        await Refused(ErrorCode.InvalidArgument, () => _tools.LiveTimeline("live-1", "pause"), "Unknown action");
        await Refused(ErrorCode.InvalidArgument, () => _tools.LiveConsole("pause"), "Unknown action");
    }

    [Fact]
    public async Task A_Frida_outside_the_tested_range_opens_with_a_warning_and_one_too_old_is_refused()
    {
        foreach (var (version, warned) in new[] { ("18.0.1", true), ("17.24.3", false) })
        {
            using var service = new LiveSessionService(_workspace, new NativeCodeService(_workspace, SharedCodeIndex.Options()))
                { Backend = new ScriptedLiveBackend(Sqlite, Base, 0x200000) { FridaVersion = version } };
            var tools = new LiveSessionTools(new ServerOptions { AllowLiveAttach = true }, service);
            await tools.LiveSession("attach", program: "99994242");
            var events = await tools.LiveEvents("live-1");
            Assert.Equal(warned, events.Contains($"Frida {version} is outside the tested range {Native.Providers.Live.FridaVersions.TestedRange}"));
        }
        using var old = new LiveSessionService(_workspace, new NativeCodeService(_workspace, SharedCodeIndex.Options()))
            { Backend = new ScriptedLiveBackend(Sqlite, Base, 0x200000) { FridaVersion = "16.5.9" } };
        await Refused(ErrorCode.ProviderUnavailable, () => new LiveSessionTools(new ServerOptions { AllowLiveAttach = true }, old).LiveSession("attach", program: "99994242"),
            "Frida 16.5.9 is older than 17.0.0");
        Assert.Empty(old.Sessions);
    }

    [Theory]
    [InlineData("17.24.3", "17.24.3")]
    [InlineData("17.5.0-dev.3", "17.5.0")]
    [InlineData("18", "18.0.0")]
    [InlineData("test", null)]
    public void Frida_versions_parse_from_their_leading_numbers(string text, string? expected) =>
        Assert.Equal(expected, Native.Providers.Live.FridaVersions.Parse(text)?.ToString());

    [Fact]
    public async Task Unknown_ids_are_not_found()
    {
        await _tools.LiveSession("attach", program: "99994242");
        await Refused(ErrorCode.NotFound, () => _tools.LiveSession("status", session: "live-9"), "No session 'live-9'");
        await Refused(ErrorCode.NotFound, () => _tools.LiveBreak("live-9"));
        await Refused(ErrorCode.NotFound, () => _tools.LiveRead("live-9", memory: "0x10"));
        await Refused(ErrorCode.NotFound, () => _tools.LiveEvents("live-9"));
        await Refused(ErrorCode.NotFound, () => _tools.LiveBreak("live-1", "set", at: "no_such_function_anywhere"));
        await Refused(ErrorCode.NotFound, () => _tools.LiveBreak("live-1", "clear", stopPoint: "s7"), "no stop point 's7'");
        await Refused(ErrorCode.NotFound, () => _tools.LiveWatchCalls("live-1", "clear", watch: "w7"), "no watch 'w7'");
        await Refused(ErrorCode.NotFound, () => _tools.LiveScriptCalls("live-1", "unload", script: "u7"), "no script 'u7'");
        await Refused(ErrorCode.NotFound, () => _tools.LiveCoverage(action: "report", run: "cov-7"), "No coverage run 'cov-7'");
        await Refused(ErrorCode.NotFound, () => _tools.LiveSession("spawn", program: Path.Combine(Path.GetTempPath(), "no-such-program-" + Guid.NewGuid().ToString("N") + ".exe")));
        await _tools.LiveBreak("live-1", "set", at: "sqlite3_open");
        Assert.Contains("s1 cleared", await _tools.LiveBreak("live-1", "clear", stopPoint: "s1"));
        await Refused(ErrorCode.NotFound, () => _tools.LiveBreak("live-1", "clear", stopPoint: "s1"));
    }

    [Fact]
    public async Task A_closed_session_refuses_changes_and_keeps_its_lists_and_events_readable()
    {
        await _tools.LiveSession("attach", program: "99994242");
        await _tools.LiveBreak("live-1", "set", at: "sqlite3_open");
        await _tools.LiveSession("close", session: "live-1");
        foreach (var call in new Func<Task<string>>[]
                 {
                     () => _tools.LiveBreak("live-1", "set", at: "sqlite3_close"), () => _tools.LiveBreak("live-1", "clear", stopPoint: "s1"),
                     () => _tools.LiveBreak("live-1", "continue"), () => _tools.LiveWatchCalls("live-1", "set", at: "sqlite3_close"),
                     () => _tools.LiveRead("live-1", memory: "0x10"), () => _tools.LiveScriptCalls("live-1", "load", source: "send(1);"),
                     () => _tools.LiveCoverage("live-1", "start"), () => _tools.LiveSession("snapshot", session: "live-1"),
                 })
            await Refused(ErrorCode.Unsupported, call, "Session live-1 is closed");
        Assert.Contains("live-1: closed, 1 stop point(s)", await _tools.LiveBreak("live-1"));
        Assert.Contains("live-1: closed, 0 watch(es)", await _tools.LiveWatchCalls("live-1"));
        Assert.Contains("live-1: closed, 0 script(s)", await _tools.LiveScriptCalls("live-1"));
        Assert.Contains("session closed (closed by request)", await _tools.LiveEvents("live-1", kind: "exit"));
        Assert.Contains("live-1 (scripted): ", await _tools.LiveSession("list"));
    }

    [Fact]
    public async Task A_ninth_open_session_is_refused_until_one_closes()
    {
        for (int i = 0; i < LiveSessionService.MaxSessions; i++)
        {
            _service.Backend = new ScriptedLiveBackend(Sqlite, Base, 0x200000) { ProcessId = 99995001 + 2 * i };
            await _tools.LiveSession("attach", program: $"{99995001 + 2 * i}");
        }
        _service.Backend = new ScriptedLiveBackend(Sqlite, Base, 0x200000) { ProcessId = 99996001 };
        await Refused(ErrorCode.LimitExceeded, () => _tools.LiveSession("attach", program: "99996001"), $"{LiveSessionService.MaxSessions} sessions are open");
        await _tools.LiveSession("close", session: "live-3");
        Assert.Contains("live-9 (scripted)", await _tools.LiveSession("attach", program: "99996001"));
    }

    [Fact]
    public async Task Inspect_process_takes_a_session_id_only_while_its_program_runs()
    {
        if (!OperatingSystem.IsWindows()) return;
        static System.Diagnostics.Process Child() => System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(
            Path.Combine(Environment.SystemDirectory, "findstr.exe"), "x") { RedirectStandardInput = true, UseShellExecute = false, CreateNoWindow = true })!;
        using var observed = Child();
        using var other = Child();
        var backend = new ScriptedLiveBackend(Sqlite, Base, 0x200000) { ProcessId = observed.Id };
        using var service = new LiveSessionService(_workspace, new NativeCodeService(_workspace, SharedCodeIndex.Options())) { Backend = backend };
        using var dumps = new MinidumpService();
        var inspect = new LiveProcessTools(new LiveProcessService(dumps), service);
        try
        {
            await new LiveSessionTools(new ServerOptions { AllowLiveAttach = true }, service).LiveSession("attach", program: $"{observed.Id}");
            Assert.Contains($"{observed.Id}", await inspect.InspectProcess("live-1"));
            await Refused(ErrorCode.NotFound, () => inspect.InspectProcess("live-2"), "No session 'live-2'");
            observed.StandardInput.Close();
            await observed.WaitForExitAsync();
            backend.Worker!.Emit(new System.Text.Json.Nodes.JsonObject { ["event"] = "exit", ["reason"] = "process-terminated" });
            for (var waited = System.Diagnostics.Stopwatch.StartNew(); service.Get("live-1").State != "exited" && waited.Elapsed < TimeSpan.FromMinutes(1);) await Task.Delay(50);
            service.Get("live-1").ProcessId = other.Id; // the id given to a new process
            await Refused(ErrorCode.NotFound, () => inspect.InspectProcess("live-1"), "The program of session live-1 has ended");
        }
        finally
        {
            other.Kill();
            if (!observed.HasExited) observed.Kill();
        }
    }

    [Fact]
    public async Task A_script_loads_from_a_file_up_to_its_size_limit()
    {
        await _tools.LiveSession("attach", program: "99994242");
        using var dir = new TempDir();
        File.WriteAllText(dir.File("trace.js"), "send('from a file');");
        Assert.Contains($"u1 loaded ({dir.File("trace.js")})", await _tools.LiveScriptCalls("live-1", "load", path: dir.File("trace.js")));
        File.WriteAllText(dir.File("big.js"), "//" + new string('x', 1 << 20));
        await Refused(ErrorCode.LimitExceeded, () => _tools.LiveScriptCalls("live-1", "load", path: dir.File("big.js")), "over 1 MB");
        await Refused(ErrorCode.LimitExceeded, () => _tools.LiveScriptCalls("live-1", "load", source: "//" + new string('x', 1 << 20)), "over 1 MB");
        Assert.Contains(", 1 script(s)", await _tools.LiveScriptCalls("live-1"));
    }
}
