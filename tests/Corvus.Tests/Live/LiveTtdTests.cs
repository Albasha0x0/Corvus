using System.Diagnostics;
using Corvus.Core;
using Corvus.Services;
using Corvus.Tools;

namespace Corvus.Tests;

/// <summary>Sessions on a TTD recording: stop points, watched calls and memory replayed from the file.</summary>
public sealed class LiveTtdTests : IDisposable
{
    private readonly AssemblyWorkspace _workspace = new();
    private readonly TempDir _dir = new();
    private readonly LiveSessionService _service;
    private readonly LiveSessionTools _tools;
    private readonly Xunit.Abstractions.ITestOutputHelper _output;

    public LiveTtdTests(Xunit.Abstractions.ITestOutputHelper output)
    {
        _output = output;
        _service = new LiveSessionService(_workspace, new NativeCodeService(_workspace, SharedCodeIndex.Options()));
        _tools = new LiveSessionTools(new ServerOptions { AllowLiveAttach = true }, _service);
    }

    // main calls add five times, then opens a file that is not there.
    private const string App = """
        #include <windows.h>
        #include <stdio.h>

        __declspec(dllexport) __declspec(noinline) int add(int a, int b) { return a + b; }

        int main(void)
        {
            int total = 0;
            for (int i = 0; i < 5; i++) total = add(total, i);
            HANDLE h = CreateFileW(L"missing-input.txt", GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
            printf("%d %d\n", total, h == INVALID_HANDLE_VALUE);
            return 0;
        }
        """;

    public void Dispose()
    {
        _service.Dispose();
        _workspace.Dispose();
        _dir.Dispose();
    }

    [Fact]
    public async Task A_recording_is_opened_by_attach_only()
    {
        var e = await Assert.ThrowsAsync<ToolError>(() => _service.OpenAsync(true, "ttd:" + _dir.File("app.run"), [], default));
        Assert.Contains("action=attach program=ttd:<path>", e.Message);
    }

    [Fact]
    public async Task A_recording_without_the_replay_engine_names_the_setting()
    {
        if (!OperatingSystem.IsWindows() || Environment.GetEnvironmentVariable("CORVUS_TTD") != null) return;
        var e = await Assert.ThrowsAsync<ToolError>(() => _service.OpenAsync(false, "ttd:" + _dir.File("app.run"), [], default));
        Assert.Equal(ErrorCode.ProviderUnavailable, e.Code);
        Assert.Contains("CORVUS_TTD", e.Message + e.Remediation);
    }

    /// <summary>
    /// The calls to add and to CreateFileW, and the stop at add, equal what WinDbg's TTD.Calls reports for the same
    /// recording: arguments (0,0) (0,1) (1,2) (3,3) (6,4), results 0 1 3 6 10, one CreateFileW returning -1.
    /// </summary>
    [RequiresRealDataFact("CORVUS_TTD")]
    [Trait("Speed", "Slow")]
    public async Task The_calls_and_stops_of_a_recording_replay_as_the_program_made_them()
    {
        var trace = Record();
        if (trace == null) return;
        var opened = await _tools.LiveSession("attach", program: "ttd:" + trace);
        _output.WriteLine(opened);
        Assert.Contains("(ttd)", opened);
        Assert.Contains("app.exe", opened);

        var set = await _tools.LiveBreak("live-1", "set", at: "app.exe!add");
        _output.WriteLine(set);
        Assert.Contains("program started", await _tools.LiveBreak("live-1", "continue"));
        var stop = await _tools.LiveBreak("live-1", wait: true, waitSeconds: 120);
        _output.WriteLine(stop);
        Assert.Contains("stopped at s1 (app.exe!add)", stop);
        // main and the CRT start code have no export names: they show as app.exe!sub_*.
        Assert.Matches(@"#1 0x[0-9A-F]+ app\.exe!sub_[0-9A-F]+\+0x[0-9A-F]+\s+#2 0x[0-9A-F]+ app\.exe!sub_[0-9A-F]+\+0x[0-9A-F]+\s+#3 0x[0-9A-F]+ KERNEL32\.DLL!BaseThreadInitThunk\+0x[0-9A-F]+\s+#4 0x[0-9A-F]+ ntdll\.dll!RtlUserThreadStart\+0x", stop);

        Assert.Matches("stop point s1 hit 1 at position [0-9A-F]+:[0-9A-F]+", await _tools.LiveEvents("live-1", kind: "stop"));
        // At add's first instruction the stack holds the return address into main, frame #1.
        var read = await _tools.LiveRead("live-1", memory: "rsp", type: "pointer");
        _output.WriteLine(read);
        var returnAddress = System.Text.RegularExpressions.Regex.Match(stop, "#1 (0x[0-9A-F]+)").Groups[1].Value;
        Assert.Contains(returnAddress, read, StringComparison.OrdinalIgnoreCase);
        await _tools.LiveBreak("live-1", "clear", stopPoint: "s1");
        _output.WriteLine(await _tools.LiveWatchCalls("live-1", "set", at: "app.exe!add", arguments: 2));
        _output.WriteLine(await _tools.LiveWatchCalls("live-1", "set", at: "kernelbase.dll!CreateFileW"));
        await _tools.LiveBreak("live-1", "continue");
        var ended = await WaitForExit();
        var calls = await _tools.LiveEvents("live-1", kind: "call");
        _output.WriteLine(calls);
        foreach (var call in new[] { "a0=0x0, a1=0x0) -> 0x0", "a0=0x0, a1=0x1) -> 0x1", "a0=0x1, a1=0x2) -> 0x3", "a0=0x3, a1=0x3) -> 0x6", "a0=0x6, a1=0x4) -> 0xA" })
            Assert.Contains(call, calls);
        Assert.Contains("missing-input.txt", calls);
        Assert.Contains("the recording ends", ended);
        await _tools.LiveSession("close", session: "live-1");
    }

    private async Task<string> WaitForExit()
    {
        for (int i = 0; i < 240; i++)
        {
            var events = await _tools.LiveEvents("live-1", kind: "exit");
            if (events.Contains("recording", StringComparison.Ordinal)) return events;
            await Task.Delay(500);
        }
        return "";
    }

    // Builds App and records one run of it with TTD.exe from CORVUS_TTD; null without the C++ toolset.
    private string? Record()
    {
        if (!OperatingSystem.IsWindows() || VisualStudio.VcVarsAll() is not { } vcvars) return null;
        File.WriteAllText(_dir.File("app.c"), App);
        var (code, log) = Tools.Run(new ProcessStartInfo("cmd.exe")
        {
            WorkingDirectory = _dir.Path,
            Arguments = $"/s /c \"\"{vcvars}\" x64 >nul && cl /nologo /O1 /Zi app.c /link /DEBUG /INCREMENTAL:NO\"",
        }, 300_000);
        Assert.True(code == 0 && File.Exists(_dir.File("app.exe")), log);
        var ttd = Path.Combine(Environment.GetEnvironmentVariable("CORVUS_TTD")!, "TTD.exe");
        var record = new ProcessStartInfo(ttd) { WorkingDirectory = _dir.Path };
        foreach (var a in new[] { "-acceptEula", "-out", _dir.Path, _dir.File("app.exe") }) record.ArgumentList.Add(a);
        (code, log) = Tools.Run(record, 300_000);
        var trace = Directory.GetFiles(_dir.Path, "*.run").FirstOrDefault();
        Assert.True(trace != null, $"TTD.exe exited {code} without a recording: {log}");
        return trace;
    }
}
