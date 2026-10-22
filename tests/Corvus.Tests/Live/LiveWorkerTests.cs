using System.Diagnostics;
using System.Globalization;
using Corvus.Native.Providers;

namespace Corvus.Tests;

/// <summary>The session worker on a stand-in frida module, for the paths a real Frida takes only now and then.</summary>
public sealed class LiveWorkerTests : IDisposable
{
    private readonly TempDir _dir = new();

    public void Dispose() => _dir.Dispose();

    // The stand-in starts a sleeping child per spawn, records its pid, and
    // times out on the first spawn as Frida 17.24.3 did on macOS ARM64.
    private const string StandInFrida = """
        import os
        import subprocess

        __version__ = "17.24.3"


        class TimedOutError(Exception): pass
        class ExecutableNotFoundError(Exception): pass
        class ProcessNotFoundError(Exception): pass
        class PermissionDeniedError(Exception): pass
        class InvalidOperationError(Exception): pass
        class InvalidArgumentError(Exception): pass


        class _Exports:
            def info(self):
                return {"pid": 0, "arch": "arm64", "platform": "darwin", "modules": []}


        class _Script:
            exports_sync = _Exports()
            def on(self, *args): pass
            def load(self): pass


        class _Session:
            def on(self, *args): pass
            def create_script(self, source): return _Script()
            def detach(self): pass


        class _Device:
            starts = 0
            def on(self, *args): pass
            def spawn(self, argv, **kwargs):
                _Device.starts += 1
                child = subprocess.Popen(["sleep", "60"])
                with open(os.path.join(os.path.dirname(__file__), "started.txt"), "a") as f:
                    f.write("%d\n" % child.pid)
                if _Device.starts == 1:
                    raise TimedOutError("unexpectedly timed out while initializing suspended process")
                return child.pid
            def attach(self, pid): return _Session()
            def kill(self, pid): os.kill(pid, 9)


        def get_local_device():
            return _Device()
        """;

    // The stand-in attaches to any process and refuses a stop point at 0xbad, as
    // Frida refuses an instruction too short to hook.
    private const string RefusingFrida = """
        __version__ = "17.24.3"


        class ProcessNotFoundError(Exception): pass
        class PermissionDeniedError(Exception): pass
        class InvalidOperationError(Exception): pass


        class _Exports:
            def info(self):
                return {"pid": 4242, "arch": "x64", "platform": "windows", "modules": []}
            def set(self, id, address, bare):
                if address == "0xbad":
                    raise InvalidOperationError("unable to intercept instruction at 0xbad; please file a bug")
                return True


        class _Script:
            exports_sync = _Exports()
            def on(self, *args): pass
            def load(self): pass


        class _Session:
            def on(self, *args): pass
            def create_script(self, source): return _Script()
            def detach(self): pass


        class _Device:
            def on(self, *args): pass
            def attach(self, pid): return _Session()


        def get_local_device():
            return _Device()
        """;

    /// <summary>The worker on <paramref name="frida"/>, a stand-in frida module beside it.</summary>
    private Process StartWorker(string frida)
    {
        var python = PythonLocator.Find([], []) ?? throw new InvalidOperationException("no Python 3");
        var worker = _dir.File("live_worker.py");
        File.WriteAllBytes(worker, EmbeddedScript.Read("Corvus.Native.Providers.Live.live_worker.py"));
        File.WriteAllText(_dir.File("frida.py"), frida);
        var agent = _dir.File("live_agent.js");
        File.WriteAllText(agent, "");
        // Without -I, so the stand-in beside the worker is the frida it imports.
        return Process.Start(new ProcessStartInfo(python.Executable, new[] { "-u", worker, agent })
            { RedirectStandardInput = true, RedirectStandardOutput = true, UseShellExecute = false })!;
    }

    /// <summary>The reply to request <paramref name="id"/>; null when the worker ended first.</summary>
    private static string? Request(Process p, int id, string op, string args)
    {
        p.StandardInput.WriteLine($$"""{"id":{{id}},"op":"{{op}}","args":{{args}}}""");
        p.StandardInput.Flush();
        string? reply;
        while ((reply = p.StandardOutput.ReadLine()) != null && !reply.Contains($"\"id\":{id},", StringComparison.Ordinal)) { }
        return reply;
    }

    [Fact]
    public void Set_many_reports_a_refused_point_and_sets_the_rest()
    {
        using var p = StartWorker(RefusingFrida);
        try
        {
            Assert.Contains("\"ok\":true", Request(p, 1, "open", """{"attach":"4242"}"""));
            var reply = Request(p, 2, "set_many", """{"points":[{"id":"a","address":"0x10","bare":true},{"id":"b","address":"0xbad","bare":true},{"id":"c","address":"0x20","bare":true}]}""");
            Assert.NotNull(reply);
            Assert.Contains("""{"id":"a","ok":true}""", reply);
            Assert.Contains("""{"id":"b","ok":false,"error":{"code":"failed","message":"InvalidOperationError: unable to intercept instruction at 0xbad; please file a bug"}}""", reply);
            Assert.Contains("""{"id":"c","ok":true}""", reply);
        }
        finally
        {
            p.Kill();
            p.WaitForExit(10_000);
        }
    }

    [PosixFact("The worker lists the processes it started with ps.")]
    public void A_start_Frida_timed_out_on_is_ended_and_tried_once_more()
    {
        using var p = StartWorker(StandInFrida);
        int[] started = [];
        try
        {
            var reply = Request(p, 1, "open", """{"spawn":"/bin/true"}""");
            started = [.. File.ReadAllLines(_dir.File("started.txt")).Select(l => int.Parse(l, CultureInfo.InvariantCulture))];
            Assert.NotNull(reply);
            Assert.Contains("\"ok\":true", reply);
            Assert.Equal(2, started.Length);
            Assert.Matches($@"timed out while initializing suspended process; ended process {started[0]} and started the program again", reply);
            Assert.True(Gone(started[0]), $"the first start, process {started[0]}, still runs");
            Assert.False(Gone(started[1], wait: false), "the second start was ended");
        }
        finally
        {
            p.Kill();
            p.WaitForExit(10_000);
            foreach (var pid in started)
                try { Process.GetProcessById(pid).Kill(); } catch (Exception e) when (e is ArgumentException or InvalidOperationException) { }
        }
    }

    // A killed child the worker has not reaped stays as a zombie, which
    // ps names with state Z.
    private static bool Gone(int pid, bool wait = true)
    {
        for (var sw = Stopwatch.StartNew(); ; Thread.Sleep(100))
        {
            var ps = Process.Start(new ProcessStartInfo("ps", ["-o", "stat=", "-p", pid.ToString(CultureInfo.InvariantCulture)]) { RedirectStandardOutput = true })!;
            var state = ps.StandardOutput.ReadToEnd().Trim();
            ps.WaitForExit();
            if (state.Length == 0 || state.StartsWith('Z')) return true;
            if (!wait || sw.Elapsed > TimeSpan.FromSeconds(5)) return false;
        }
    }
}
