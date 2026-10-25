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
            def set(self, id, address, bare, limit=0):
                if address == "0xbad":
                    raise InvalidOperationError("unable to intercept instruction at 0xbad; please file a bug")
                return True
            def clear(self, id):
                return id != "gone"


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

    // The stand-in's script reports a stop from each point as it is set: a
    // counted one, as the agent sends for a point with a hit limit, from thread
    // 7, and a held one from thread 8.
    private const string CountingFrida = """
        __version__ = "17.24.3"


        class ProcessNotFoundError(Exception): pass
        class PermissionDeniedError(Exception): pass
        class InvalidOperationError(Exception): pass


        class _Exports:
            def info(self):
                return {"pid": 4242, "arch": "x64", "platform": "windows", "modules": []}
            def set(self, id, address, bare, limit=0):
                stop = {"type": "stop", "point": id, "tid": 7 if limit > 0 else 8, "hits": 1, "registers": {}, "frames": [address]}
                if limit > 0:
                    stop["counted"] = True
                _Script.receive({"type": "send", "payload": stop}, None)
                return True


        class _Script:
            exports_sync = _Exports()
            receive = None
            def on(self, signal, callback):
                if signal == "message":
                    _Script.receive = callback
            def load(self): pass
            def post(self, message): pass


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

    // The stand-in holds thread 8 at the point set, and a resume posted for it
    // starts the exit 0.2 s later: the exit status, then the process's end.
    // An unload is recorded in unloaded.txt.
    private const string ExitingFrida = """
        import os
        import threading

        __version__ = "17.24.3"


        class ProcessNotFoundError(Exception): pass
        class PermissionDeniedError(Exception): pass
        class InvalidOperationError(Exception): pass


        class _Exports:
            def info(self):
                return {"pid": 4242, "arch": "x64", "platform": "windows", "modules": []}
            def set(self, id, address, bare, limit=0):
                _Script.receive({"type": "send", "payload": {"type": "stop", "point": id, "tid": 8, "hits": 1, "registers": {}, "frames": [address]}}, None)
                return True
            def close_begin(self):
                return {"awaited": ["exit-8"] if _Script.exiting else [], "exiting": _Script.exiting}


        class _Script:
            exports_sync = _Exports()
            receive = None
            exiting = False
            def on(self, signal, callback):
                if signal == "message":
                    _Script.receive = callback
            def load(self): pass
            def post(self, message):
                if message["type"] == "resume-8":
                    threading.Timer(0.2, _Script.exit).start()
            @staticmethod
            def exit():
                _Script.exiting = True
                _Script.receive({"type": "send", "payload": {"type": "exit_status", "tid": 8, "code": 5, "ack": True}}, None)
                threading.Timer(0.2, lambda: _Session.detached("process-terminated", None)).start()
            def unload(self):
                with open(os.path.join(os.path.dirname(__file__), "unloaded.txt"), "w") as f:
                    f.write("unloaded")


        class _Session:
            detached = None
            def on(self, signal, callback):
                if signal == "detached":
                    _Session.detached = callback
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

    [Fact]
    public void Clear_many_names_the_points_it_cleared()
    {
        using var p = StartWorker(RefusingFrida);
        try
        {
            Assert.Contains("\"ok\":true", Request(p, 1, "open", """{"attach":"4242"}"""));
            Assert.Contains("""{"cleared":["a","c"]}""", Request(p, 2, "clear_many", """{"ids":["a","gone","c"]}"""));
        }
        finally
        {
            p.Kill();
            p.WaitForExit(10_000);
        }
    }

    [Fact]
    public void A_counted_stop_leaves_its_thread_running_and_a_held_stop_holds_it()
    {
        using var p = StartWorker(CountingFrida);
        try
        {
            Assert.Contains("\"ok\":true", Request(p, 1, "open", """{"attach":"4242"}"""));
            Assert.Contains("\"ok\":true", Request(p, 2, "set_many", """{"points":[{"id":"a","address":"0x10","bare":true,"limit":1}]}"""));
            Assert.Contains("\"ok\":true", Request(p, 3, "set", """{"id":"b","address":"0x20","bare":true}"""));
            Assert.Contains("\"resumed\":[8]", Request(p, 4, "resume", "{}"));
        }
        finally
        {
            p.Kill();
            p.WaitForExit(10_000);
        }
    }

    [Fact]
    public void A_close_that_lets_a_held_thread_go_waits_for_its_exit_and_unloads_nothing()
    {
        using var p = StartWorker(ExitingFrida);
        try
        {
            Assert.Contains("\"ok\":true", Request(p, 1, "open", """{"attach":"4242"}"""));
            Assert.Contains("\"ok\":true", Request(p, 2, "set", """{"id":"a","address":"0x10"}"""));
            Assert.Contains("\"ok\":true", Request(p, 3, "close", "{}"));
            Assert.False(File.Exists(_dir.File("unloaded.txt")), "the close unloaded the script during the exit");
        }
        finally
        {
            if (!p.HasExited) p.Kill();
            p.WaitForExit(10_000);
        }
    }

    [Fact]
    public void A_close_after_a_resume_that_let_no_thread_go_unloads_at_once()
    {
        using var p = StartWorker(ExitingFrida);
        try
        {
            Assert.Contains("\"ok\":true", Request(p, 1, "open", """{"attach":"4242"}"""));
            Assert.Contains("\"resumed\":[]", Request(p, 2, "resume", "{}"));
            var clock = Stopwatch.StartNew();
            Assert.Contains("\"ok\":true", Request(p, 3, "close", "{}"));
            // The exit grace is 1 s; no exit comes here, so a close that waits takes all of it.
            Assert.True(clock.Elapsed < TimeSpan.FromSeconds(0.9), $"the close waited {clock.ElapsedMilliseconds} ms for an exit");
            Assert.True(File.Exists(_dir.File("unloaded.txt")), "the close did not unload the script");
        }
        finally
        {
            if (!p.HasExited) p.Kill();
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

    // The stand-in reports child 999999 when gating is enabled, 0.3 s late as on
    // a busy runner, reaches a hold script's code at its load, and logs each
    // attach, resume, unload and detach.
    private const string StandInGate = """
        import os
        import time

        __version__ = "17.24.3"
        _log = os.path.join(os.path.dirname(__file__), "calls.txt")


        def log(line):
            with open(_log, "a") as f:
                f.write(line + "\n")


        class TimedOutError(Exception): pass
        class ExecutableNotFoundError(Exception): pass
        class ProcessNotFoundError(Exception): pass
        class PermissionDeniedError(Exception): pass
        class InvalidOperationError(Exception): pass
        class InvalidArgumentError(Exception): pass


        class _Child:
            pid, parent_pid, path, argv, identifier = 999999, 100, "/app/child", ["child"], None
            @property
            def origin(self):
                time.sleep(0.3)
                return "spawn"


        class _Exports:
            def info(self): return {"pid": 100, "arch": "x64", "platform": "linux", "modules": []}
            def follow_children(self): pass
            def close_begin(self): return {"awaited": [], "exiting": False}


        class _Script:
            exports_sync = _Exports()
            def __init__(self, pid, source):
                self.pid, self.hold, self.handler = pid, "MemoryAccessMonitor" in source, None
            def on(self, signal, handler): self.handler = handler
            def load(self):
                if self.hold: self.handler({"type": "send", "payload": "held"}, None)
            def post(self, message):
                if self.hold and message.get("type") == "release": self.handler({"type": "send", "payload": "released"}, None)
            def unload(self): log("unload %d" % self.pid)


        class _Session:
            def __init__(self, device, pid): self.device, self.pid = device, pid
            def on(self, *args): pass
            def create_script(self, source): return _Script(self.pid, source)
            def enable_child_gating(self): self.device.added(_Child())
            def detach(self): log("detach %d" % self.pid)


        class _Device:
            added = None
            def on(self, signal, handler):
                if signal == "child-added": self.added = handler
            def attach(self, pid):
                log("attach %d" % pid)
                return _Session(self, pid)
            def resume(self, pid): log("resume %d" % pid)


        def get_local_device():
            return _Device()
        """;

    [PosixFact("The worker reads the child's image through /proc.")]
    public void A_hold_asked_again_stays_and_a_kept_hold_session_leaves_only_at_drop_child()
    {
        var python = PythonLocator.Find([], []) ?? throw new InvalidOperationException("no Python 3");
        var worker = _dir.File("live_worker.py");
        File.WriteAllBytes(worker, EmbeddedScript.Read("Corvus.Native.Providers.Live.live_worker.py"));
        File.WriteAllText(_dir.File("frida.py"), StandInGate);
        var agent = _dir.File("live_agent.js");
        File.WriteAllText(agent, "");
        using var p = Process.Start(new ProcessStartInfo(python.Executable, new[] { "-u", worker, agent })
            { RedirectStandardInput = true, RedirectStandardOutput = true, UseShellExecute = false })!;
        var id = 0;
        var seen = new List<string>();
        string Until(string text)
        {
            if (seen.FirstOrDefault(l => l.Contains(text, StringComparison.Ordinal)) is { } earlier) return earlier;
            string? line;
            while ((line = p.StandardOutput.ReadLine()) != null && !line.Contains(text, StringComparison.Ordinal)) seen.Add(line);
            Assert.NotNull(line);
            return line;
        }
        string Call(string op, string args)
        {
            p.StandardInput.WriteLine($$"""{"id":{{++id}},"op":"{{op}}","args":{{args}}}""");
            p.StandardInput.Flush();
            return Until($"\"id\":{id},");
        }
        string[] Calls() => File.ReadAllLines(_dir.File("calls.txt"));
        try
        {
            Call("open", """{"attach":"100","children":{}}""");
            // The worker takes a child on a thread of its own; the server resumes one only after its child event.
            Until("\"event\":\"child\"");
            Assert.Contains("\"held\":true", Call("resume_child", """{"pid":999999,"hold":true}"""));
            Assert.Contains("\"held\":true", Call("resume_child", """{"pid":999999,"hold":true}"""));
            Assert.Equal(["attach 100", "attach 999999", "resume 999999"], Calls());
            Call("resume_child", """{"pid":999999,"keep":true}""");
            Assert.Equal("unload 999999", Calls()[^1]);
            Assert.Contains("\"kept\":1", Call("close", """{"end":false,"keep_handed":true}"""));
            Assert.DoesNotContain("detach 999999", Calls());
            Assert.Contains("\"dropped\":true,\"kept\":0", Call("drop_child", """{"pid":999999}"""));
            Assert.Equal("detach 999999", Calls()[^1]);
            Assert.Contains("\"kept\":0", Call("close", """{"end":false}"""));
            Assert.True(p.WaitForExit(10_000), "the worker runs on after a close that keeps nothing");
        }
        finally
        {
            if (!p.HasExited) p.Kill();
        }
    }

    // The stand-in's attach fails as Frida 17.24.3 reports a D-Bus call past
    // GLib's 25 s limit; its kill records the pid it ends.
    private const string TransportTimeoutFrida = """
        import os

        __version__ = "17.24.3"


        class TimedOutError(Exception): pass
        class TransportError(Exception): pass
        class ExecutableNotFoundError(Exception): pass
        class ProcessNotFoundError(Exception): pass
        class PermissionDeniedError(Exception): pass
        class InvalidOperationError(Exception): pass
        class InvalidArgumentError(Exception): pass


        class _Device:
            def on(self, *args): pass
            def spawn(self, argv, **kwargs): return 4242
            def attach(self, pid): raise TransportError("Timeout was reached")
            def kill(self, pid):
                with open(os.path.join(os.path.dirname(__file__), "killed.txt"), "a") as f:
                    f.write("%d\n" % pid)


        def get_local_device():
            return _Device()
        """;

    [Fact]
    public void A_call_Frida_gave_up_waiting_on_is_a_timeout_and_the_started_program_is_ended()
    {
        var python = PythonLocator.Find([], []) ?? throw new InvalidOperationException("no Python 3");
        var worker = _dir.File("live_worker.py");
        File.WriteAllBytes(worker, EmbeddedScript.Read("Corvus.Native.Providers.Live.live_worker.py"));
        File.WriteAllText(_dir.File("frida.py"), TransportTimeoutFrida);
        var agent = _dir.File("live_agent.js");
        File.WriteAllText(agent, "");
        // Without -I, so the stand-in beside the worker is the frida it imports.
        using var p = Process.Start(new ProcessStartInfo(python.Executable, new[] { "-u", worker, agent })
            { RedirectStandardInput = true, RedirectStandardOutput = true, UseShellExecute = false })!;
        try
        {
            p.StandardInput.WriteLine("""{"id":1,"op":"open","args":{"spawn":"program"}}""");
            p.StandardInput.Flush();
            string? reply;
            while ((reply = p.StandardOutput.ReadLine()) != null && !reply.Contains("\"id\":1", StringComparison.Ordinal)) { }
            Assert.Equal("""{"id":1,"ok":false,"error":{"code":"timeout","message":"TransportError: Timeout was reached"}}""", reply);
            Assert.Equal(["4242"], File.ReadAllLines(_dir.File("killed.txt")));
        }
        finally
        {
            p.Kill();
            p.WaitForExit(10_000);
        }
    }

    private const string DeviceFrida = """
        __version__ = "17.24.3"


        class InvalidArgumentError(Exception): pass


        class _Device:
            def on(self, *args): pass
            def spawn(self, target, **kwargs): raise AssertionError("spawned")


        def get_device(serial, timeout=0):
            if serial != "emulator-5554": raise InvalidArgumentError("device not found")
            return _Device()
        """;

    [Fact]
    public void A_device_adb_does_not_list_and_a_package_given_arguments_are_refused_before_a_spawn()
    {
        var python = PythonLocator.Find([], []) ?? throw new InvalidOperationException("no Python 3");
        var worker = _dir.File("live_worker.py");
        File.WriteAllBytes(worker, EmbeddedScript.Read("Corvus.Native.Providers.Live.live_worker.py"));
        File.WriteAllText(_dir.File("frida.py"), DeviceFrida);
        var agent = _dir.File("live_agent.js");
        File.WriteAllText(agent, "");
        string Open(string args)
        {
            // Without -I, so the stand-in beside the worker is the frida it imports.
            using var p = Process.Start(new ProcessStartInfo(python.Executable, new[] { "-u", worker, agent })
                { RedirectStandardInput = true, RedirectStandardOutput = true, UseShellExecute = false })!;
            try
            {
                p.StandardInput.WriteLine("{\"id\":1,\"op\":\"open\",\"args\":" + args + "}");
                p.StandardInput.Flush();
                string? reply;
                while ((reply = p.StandardOutput.ReadLine()) != null && !reply.Contains("\"id\":1", StringComparison.Ordinal)) { }
                return reply ?? "";
            }
            finally
            {
                p.Kill();
                p.WaitForExit(10_000);
            }
        }
        Assert.Contains("\"code\":\"not_found\"", Open("""{"device":"emulator-9999","spawn":"com.example.ledger"}"""));
        var package = Open("""{"device":"emulator-5554","spawn":"com.example.ledger","arguments":["-x"]}""");
        Assert.Contains("\"code\":\"invalid_argument\"", package);
        Assert.Contains("starts without arguments or environment variables", package);
    }

    [Fact]
    public void A_timeout_the_worker_reports_names_a_retry()
    {
        Assert.StartsWith("Frida gave up waiting", Corvus.Native.Providers.Live.FridaBackend.Remediation(Corvus.Core.ErrorCode.Timeout, "TransportError: Timeout was reached"));
        Assert.Null(Corvus.Native.Providers.Live.FridaBackend.Remediation(Corvus.Core.ErrorCode.Timeout, "read"));
        Assert.Null(Corvus.Native.Providers.Live.FridaBackend.Remediation(Corvus.Core.ErrorCode.Failed, "TransportError: something else"));
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
