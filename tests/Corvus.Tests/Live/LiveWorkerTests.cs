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

    [PosixFact("The worker lists the processes it started with ps.")]
    public void A_start_Frida_timed_out_on_is_ended_and_tried_once_more()
    {
        var python = PythonLocator.Find([], []) ?? throw new InvalidOperationException("no Python 3");
        var worker = _dir.File("live_worker.py");
        File.WriteAllBytes(worker, EmbeddedScript.Read("Corvus.Native.Providers.Live.live_worker.py"));
        File.WriteAllText(_dir.File("frida.py"), StandInFrida);
        var agent = _dir.File("live_agent.js");
        File.WriteAllText(agent, "");
        // Without -I, so the stand-in beside the worker is the frida it imports.
        using var p = Process.Start(new ProcessStartInfo(python.Executable, new[] { "-u", worker, agent })
            { RedirectStandardInput = true, RedirectStandardOutput = true, UseShellExecute = false })!;
        int[] started = [];
        try
        {
            p.StandardInput.WriteLine("""{"id":1,"op":"open","args":{"spawn":"/bin/true"}}""");
            p.StandardInput.Flush();
            string? reply;
            while ((reply = p.StandardOutput.ReadLine()) != null && !reply.Contains("\"id\":1", StringComparison.Ordinal)) { }
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
