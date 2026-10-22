"""Session worker: a local program observed through Frida, on the worker protocol (one JSON object per line).

Ops: hello; open {attach, stopped | spawn, arguments, cwd, temp, tmp, children}; info; set {id, address}; clear {id}; watch {id, address, args,
perSecond}; unwatch {id}; defer_module {name}; undefer_module {name}; release_load {thread}; load_script {id, source} (replies with its top-level exception);
unload_script {id}; read {address, length}; resume {thread}; resume_child {pid, stopped | hold | keep}; drop_child {pid};
close {end, keep_handed}.
Events: ready, stop (with stack: the bytes from the stack pointer up, outside Windows), calls, module, thread, exception, exit_status, output, exit, script_error, user_script, child.
A program started here stays suspended until the first resume; close resumes every held thread, and ends the
program only when this worker started it. A module named by defer_module holds its loading thread (module event with
held) until release_load; a fatal exception event, and exit_status {code}, hold their thread until the
worker has read them.
With children {names} on open, a program the process starts is held at its start (Frida's child gating) and reported
as a child event; one whose image name is not in names (when given) is resumed at once. resume_child lets a held child
run, or with stopped (Linux) leaves it stopped for open {attach, stopped} in another worker; with hold (Linux) it
runs with its first thread held at the main module's code (held: whether it got there) for an open {attach} in another
worker, until resume_child for that pid again; with keep, the hold's session then stays attached until drop_child, so
that the other worker's agent leaves first. close resumes every child still held; with keep_handed the worker keeps those
sessions and serves drop_child until a close keeps none (kept: how many it keeps).
"""
import json
import os
import signal
import subprocess
import sys
import threading
import time

_out = threading.Lock()
OUTPUT_CHUNK = 4096  # bytes of one program output chunk kept in its event
# Seconds a close waits for a thread it just let go from a stop to begin the
# program's exit.
EXIT_GRACE = 1.0

# Holds the first thread that runs the main module's code until release. The exec gate resumes a child past its entry
# point and past __libc_start_main, so a hook there never runs; a page access always does. A disable inside onAccess
# ended the child with SIGSEGV in this worker (not reproduced in a standalone script), so the held thread gives every
# page back its protection instead: no later access faults into another session's exception handler.
HOLD_AT_CODE = """
const release = recv('release', () => {});
let held = false;
const ranges = Process.mainModule.enumerateRanges('--x');
MemoryAccessMonitor.enable(ranges.map(r => ({ base: r.base, size: r.size })), { onAccess() {
  if (held) return;
  held = true;
  for (const r of ranges) Memory.protect(r.base, r.size, r.protection);
  send('held');
  release.wait();
  send('released');
} });
"""
HOLD_WAIT = 5  # seconds a hold waits for the child to reach its code; one that never does runs on unheld


def parent_of(pid):
    """The parent process id /proc reports (Linux); None elsewhere or once the process is gone."""
    try:
        with open("/proc/%d/status" % pid, "r", encoding="ascii", errors="replace") as f:
            for line in f:
                if line.startswith("PPid:"):
                    return int(line.split()[1])
    except (OSError, ValueError, IndexError):
        pass
    return None


def image_of(pid):
    """The path of the image a process runs, as /proc/<pid>/exe links it (Linux); None elsewhere."""
    try:
        return os.readlink("/proc/%d/exe" % pid)
    except OSError:
        return None


def descendants(root):
    """The processes below root as {pid: command}, read from ps (macOS, Linux); None where ps cannot be read."""
    if os.name == "nt":
        return None
    try:
        ps = subprocess.Popen(["ps", "-A", "-o", "pid=,ppid=,comm="], stdout=subprocess.PIPE, text=True)
        listed = ps.communicate(timeout=10)[0]
    except (OSError, subprocess.SubprocessError):
        return None
    parents, names = {}, {}
    for line in listed.splitlines():
        fields = line.split(None, 2)
        if len(fields) == 3 and fields[0].isdigit() and fields[1].isdigit():
            parents[int(fields[0])] = int(fields[1])
            names[int(fields[0])] = fields[2]
    below, found = {root}, True
    while found:
        found = False
        for pid, ppid in parents.items():
            if ppid in below and pid not in below:
                below.add(pid)
                found = True
    return {pid: names[pid] for pid in below - {root, ps.pid}}


def emit(obj):
    line = json.dumps(obj, ensure_ascii=True, separators=(",", ":"))
    with _out:
        sys.stdout.write(line + "\n")
        sys.stdout.flush()


def error_of(e):
    """The protocol error for an exception Frida raised: a call it gave up waiting on is a timeout, else failed."""
    message = "%s: %s" % (type(e).__name__, e)
    # A D-Bus call to Frida's helper or agent that passes GLib's 25 s default ends in "Timeout was reached", which
    # Frida reports as TransportError (throw_dbus_error, frida-core 17.24.3).
    timed_out = getattr(frida, "TimedOutError", ())
    transport = getattr(frida, "TransportError", ())
    if isinstance(e, timed_out) or isinstance(e, transport) and "timeout was reached" in str(e).lower():
        return {"code": "timeout", "message": message}
    return {"code": "failed", "message": message}


class Failure(Exception):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


try:
    import frida
except ImportError as e:  # reported on hello, so the server names the missing package
    frida = None
    _import_error = str(e)


class Session:
    def __init__(self, agent_path):
        self.agent_path = agent_path
        self.device = None
        self.session = None
        self.script = None
        self.pid = None
        self.spawned = False
        self.spawn_retried = None  # why the first start was ended and tried again
        self.suspended = False
        self.exited = False
        self.ended = threading.Event()  # the process is gone
        self.closing = False
        self.exit_released = False  # an exit_status was answered: the process is past the script's last hook
        self.exit_begun = threading.Event()
        self.released_at = 0.0  # when a resume last let threads go from their stops
        self.held = set()
        self.loading = set()  # threads held at the load of a deferred module or the compile of a watched method
        self.lock = threading.Lock()
        self.user_scripts = {}
        self.children = {}  # pid of each held child to its path
        self.forks = {}  # pid of each fork followed to its exec (outside Windows) to its session
        # Pid of each child resumed with hold to the session whose script holds it, and, once released, to that session.
        self.holds = {}
        self.handed = {}
        self.child_names = None  # lower-case image names (with or without extension) to hold; None holds every child

    def on_message(self, message, data):
        if message.get("type") == "error":
            emit({"event": "script_error", "message": message.get("description"), "stack": message.get("stack")})
            return
        payload = message.get("payload") or {}
        kind = payload.pop("type", "message")
        if kind == "stop" and not payload.get("counted"):
            with self.lock:
                self.held.add(payload.get("tid"))
            if data:
                payload["stack"] = data.hex()
        elif kind in ("module", "compiled") and payload.get("held"):
            with self.lock:
                self.loading.add(payload.get("tid"))
        if kind == "exit_status":
            self.exit_begun.set()
        ack = kind in ("exception", "exit_status") and payload.pop("ack", False)
        payload["event"] = kind
        emit(payload)
        with self.lock:
            # once a close begins it answers what is awaited itself, so it knows whether an exit was let through
            if not ack or self.closing or self.script is None:
                return
            if kind == "exit_status":
                self.exit_released = True
            self.script.post({"type": "%s-%d" % ("exception" if kind == "exception" else "exit", payload.get("tid"))})

    def on_output(self, pid, fd, data):
        if pid == self.pid and data:
            text = data[:OUTPUT_CHUNK].decode("utf-8", "replace")
            emit({"event": "output", "stream": "stdout" if fd == 1 else "stderr", "text": text, "bytes": len(data)})

    def on_child_added(self, child):
        # Frida's signal thread must not wait on a call that needs it: the attach and resume run on a thread of their own
        threading.Thread(target=self.child_added, args=(child,), daemon=True).start()

    def child_added(self, child):
        origin = str(child.origin)
        with self.lock:
            fork = self.forks.pop(child.pid, None) if origin == "exec" else None
            nested = origin != "exec" and child.parent_pid in self.forks
        if nested:  # a fork's own child, before the fork ran a program: not followed
            self.resume_quietly(child.pid)
            return
        parent = child.parent_pid
        if origin == "exec" and fork is None and parent == child.pid:
            # posix_spawn and vfork run the program with no fork event: the exec names the child as its own parent
            parent = parent_of(child.pid)
        if fork is not None:
            self.detach_quietly(fork)
        elif parent != self.pid:
            if origin == "exec" and parent_of(child.pid) is not None:
                self.resume_quietly(child.pid)  # an exec in another process's tree is not followed, nor left held
            return
        elif origin == "fork":
            # a fork names no program until its exec: it is followed there, and held (or not) as the program it runs
            session = None
            try:
                session = self.device.attach(child.pid)
                session.enable_child_gating()
                with self.lock:
                    if not self.closing:
                        self.forks[child.pid], session = session, None
            except (frida.InvalidOperationError, frida.ProcessNotFoundError, frida.PermissionDeniedError):
                pass
            if session is not None:  # the close began meanwhile: the fork runs on unobserved
                self.detach_quietly(session)
            self.resume_quietly(child.pid)
            return
        # a program that starts a copy of itself runs /proc/self/exe: the image the link names is the program's own
        path = image_of(child.pid) or child.path or (child.argv[0] if child.argv else child.identifier) or ""
        name = path.replace("\\", "/").rsplit("/", 1)[-1].lower()
        held = self.child_names is None or name in self.child_names or name.rsplit(".", 1)[0] in self.child_names
        if held:
            with self.lock:
                held = not self.closing
                if held:
                    self.children[child.pid] = path
        emit({"event": "child", "pid": child.pid, "parentPid": self.pid, "path": path, "argv": list(child.argv or []),
              "origin": origin, "held": held})
        if not held:
            self.resume_quietly(child.pid)

    def resume_quietly(self, pid):
        try:
            self.device.resume(pid)
        except (frida.InvalidOperationError, frida.ProcessNotFoundError):
            pass

    @staticmethod
    def detach_quietly(session):
        try:
            session.detach()
        except frida.InvalidOperationError:
            pass

    def resume_child(self, args):
        self.require()
        pid = int(args["pid"])
        with self.lock:
            path = self.children.pop(pid, None)
            hold = self.holds.pop(pid, None)
        held = path is not None
        if hold is not None and args.get("hold"):
            # Asked again after another worker's attach failed: the child stays held for the next attach.
            with self.lock:
                self.holds[pid] = hold
            return {"resumed": True, "held": hold[2].is_set()}
        if hold is not None:
            self.release_hold(pid, hold, bool(args.get("keep")))
            return {"resumed": True}
        if held and args.get("hold"):
            try:
                hold, reached = self.hold_at_code(pid)
            except BaseException:
                with self.lock:
                    self.children[pid] = path
                raise
            with self.lock:
                self.holds[pid] = hold
            return {"resumed": True, "held": reached}
        if held:
            if args.get("stopped"):
                # The gate's ptrace hold keeps another worker from attaching, and a child held at its exec has no libc
                # to load an agent with: an attach here runs it until its libraries are loaded, and it leaves the gate
                # stopped by SIGSTOP for the next worker's attach.
                self.device.attach(pid).detach()
                os.kill(pid, signal.SIGSTOP)
            self.device.resume(pid)
        return {"resumed": held}

    def hold_at_code(self, pid):
        """Lets a gated child run held at its first instruction in the main module; returns (session, reached)."""
        # The gate's ptrace hold keeps another worker from attaching, and a SIGSTOP hold is lost when an attach to it
        # fails under load; a thread held by a script leaves the child attachable while it waits.
        # Workaround for frida/frida-core#1270, tested on Frida 17.24.3.
        session = self.device.attach(pid)
        try:
            reached, released = threading.Event(), threading.Event()
            script = session.create_script(HOLD_AT_CODE)
            script.on("message", lambda m, d: {"held": reached, "released": released}.get(m.get("payload"), threading.Event()).set())
            script.load()
        except BaseException:
            self.detach_quietly(session)
            raise
        self.device.resume(pid)
        return (session, script, reached, released), reached.wait(HOLD_WAIT)

    def release_hold(self, pid, hold, keep):
        session, script, reached, released = hold
        try:
            script.post({"type": "release"})
        except frida.InvalidOperationError:
            pass
        # Unload only once the held thread has left the wait: an unload while it is still there can end the child.
        if reached.is_set():
            released.wait(HOLD_WAIT)
        try:
            script.unload()
        except frida.InvalidOperationError:
            pass
        if not keep:
            self.detach_quietly(session)
            return
        # Every Frida agent patches exit, abort, sigaction and the loader's notification point, and one that leaves
        # before an agent that came later stops the later agent's hooks there: the session stays until drop_child.
        # Workaround for frida/frida-core#1271, tested on Frida 17.24.3.
        with self.lock:
            self.handed[pid] = session
        session.on("detached", lambda reason, crash: self.handed.pop(pid, None))

    def drop_child(self, args):
        with self.lock:
            session = self.handed.pop(int(args["pid"]), None)
            kept = len(self.handed)
        if session is not None:
            self.detach_quietly(session)
        return {"dropped": session is not None, "kept": kept}

    def resume_children(self, keep_handed=False):
        with self.lock:
            pids = list(self.children)
            forks = list(self.forks.values())
            holds = list(self.holds.items())
            handed = [] if keep_handed else list(self.handed.values())
            self.children.clear()
            self.forks.clear()
            self.holds.clear()
            if not keep_handed:
                self.handed.clear()
        for pid in pids:
            self.resume_quietly(pid)
        for fork in forks:
            self.detach_quietly(fork)
        for pid, hold in holds:
            self.release_hold(pid, hold, keep=False)
        for session in handed:
            self.detach_quietly(session)

    def on_detached(self, reason, crash):
        self.exited = str(reason) == "process-terminated"
        if self.exited:
            self.ended.set()
        emit({"event": "exit", "reason": str(reason), "crash": None if crash is None else str(crash.summary)})

    def open(self, args):
        if self.session is not None:
            raise Failure("invalid_argument", "this worker already holds a session")
        self.device = frida.get_local_device()
        if args.get("spawn"):
            argv = [args["spawn"]] + list(args.get("arguments") or [])
            # The program's stdio is piped through Frida: on our stdout it could write protocol lines.
            self.device.on("output", self.on_output)
            # The worker's TEMP is its own (Frida unpacks helpers there); the program gets the user's.
            env = {k: args[k.lower()] for k in ("TEMP", "TMP") if args.get(k.lower())}
            # W^X keeps .NET JIT code in a shared memory view that hooks cannot write; the caller may still turn it back on.
            env["DOTNET_EnableWriteXorExecute"] = "0"
            env.update({k: v for k, v in (args.get("environment") or {}).items() if v is not None})
            self.pid = self.spawn(argv, env, args.get("cwd"))
            self.spawned = True
            self.suspended = True
        else:
            target = args.get("attach")
            if isinstance(target, str) and not target.isdigit():
                try:
                    target = self.device.get_process(target).pid
                except frida.ProcessNotFoundError as e:
                    raise Failure("not_found", str(e))
            self.pid = int(target)
            # a child another worker's gate let go stopped (resume_child stopped): the first resume continues it
            self.suspended = bool(args.get("stopped"))
        # a program started here is ended on any failure from here on: nothing else would end it
        try:
            try:
                self.session = self.device.attach(self.pid)
            except (frida.ProcessNotFoundError, frida.PermissionDeniedError) as e:
                raise Failure("not_found" if isinstance(e, frida.ProcessNotFoundError) else "access_denied", str(e))
            self.session.on("detached", self.on_detached)
            children = args.get("children")
            if children is not None:
                names = [str(n).lower() for n in (children.get("names") or []) if n]
                self.child_names = set(names) if names else None
                self.device.on("child-added", self.on_child_added)
                self.session.enable_child_gating()
            with open(self.agent_path, "r", encoding="utf-8") as f:
                source = f.read()
            self.script = self.session.create_script(source)
            self.script.on("message", self.on_message)
            self.script.load()
            if children is not None:
                self.script.exports_sync.follow_children()
            result = self.script.exports_sync.info()
        except BaseException:
            if self.session is not None:
                try:
                    self.session.detach()
                except frida.InvalidOperationError:
                    pass
            self.end_spawned()
            self.script = self.session = None
            raise
        result["suspended"] = self.suspended
        if self.spawn_retried:
            result["spawn_retried"] = self.spawn_retried
        return result

    def spawn(self, argv, env, cwd):
        """Starts argv suspended; a start Frida timed out on is ended and tried once more (seen on macOS ARM64)."""
        before = descendants(os.getpid())
        try:
            return self.device.spawn(argv, stdio="pipe", env=env or None, cwd=cwd or None)
        except frida.ExecutableNotFoundError as e:
            raise Failure("not_found", str(e))
        # Frida 17.24.3 gives a macOS start 10 s (frida-core darwin helper,
        # prepare_target; source-derived). Seen in CI runs; not reproduced
        # standalone in 400 starts on macos-latest, so no upstream report.
        except frida.TimedOutError as e:
            after = descendants(os.getpid())
            if before is None or after is None:
                raise
            # Frida's own helpers stay; the rest is the half-started program.
            left = sorted(pid for pid, name in after.items() if pid not in before and "frida" not in os.path.basename(name).lower())
            for pid in left:
                try:
                    os.kill(pid, signal.SIGKILL)
                except OSError:
                    pass
            ended = "ended process%s %s" % ("es" if len(left) > 1 else "", ", ".join(map(str, left))) if left else "found no half-started process"
            self.spawn_retried = "%s; %s and started the program again" % (e, ended)
        try:
            return self.device.spawn(argv, stdio="pipe", env=env or None, cwd=cwd or None)
        except frida.ExecutableNotFoundError as e:
            raise Failure("not_found", str(e))

    def load_script(self, args):
        # a script the user supplied (the server allows it only with --live-scripting); its messages become events
        self.require()
        sid = args["id"]
        if sid in self.user_scripts:
            raise Failure("invalid_argument", "script %s is already loaded" % sid)
        try:
            script = self.session.create_script(args["source"], name=sid)
        except frida.InvalidArgumentError as e:  # the source does not compile
            raise Failure("invalid_argument", str(e))

        thrown = []

        def on_message(message, data):
            if message.get("type") == "error":
                thrown.append(message.get("description"))
                emit({"event": "user_script", "script": sid, "error": message.get("description"), "stack": message.get("stack")})
            else:
                emit({"event": "user_script", "script": sid, "payload": message.get("payload"), "bytes": len(data) if data else 0})

        script.on("message", on_message)
        script.load()
        # A top-level exception arrives as a message, before the reply of a round
        # trip through the script's own channel, so the load reply can name it.
        script.list_exports_sync()
        self.user_scripts[sid] = script
        return {"loaded": sid, "error": thrown[0] if thrown else None}

    def unload_script(self, args):
        script = self.user_scripts.pop(args["id"], None)
        if script is None:
            return {"unloaded": False}
        try:
            script.unload()
        except frida.InvalidOperationError:
            pass
        return {"unloaded": True}

    def require(self):
        if self.script is None:
            raise Failure("invalid_argument", "no session is open")
        return self.script.exports_sync

    def resume(self, args):
        self.require()
        thread = args.get("thread")
        with self.lock:
            targets = [t for t in self.held if thread is None or t == thread]
            self.held.difference_update(targets)
        for tid in targets:
            self.script.post({"type": "resume-%d" % tid})
        if targets:
            self.released_at = time.monotonic()
        started = self.suspended and thread is None
        if started:
            self.device.resume(self.pid)
            self.suspended = False
        return {"resumed": targets, "started": started}

    def release_load(self, args):
        self.require()
        tid = args.get("thread")
        with self.lock:
            held = tid in self.loading
            self.loading.discard(tid)
        if held:
            self.script.post({"type": "load-%d" % tid})
        return {"released": held}

    def end_spawned(self):
        if self.spawned and self.pid is not None:
            try:
                self.device.kill(self.pid)
            except frida.InvalidOperationError:
                pass

    def close(self, args):
        for sid in list(self.user_scripts):
            try:
                self.unload_script({"id": sid})
            except Exception:
                pass
        with self.lock:
            self.closing = True
            released = self.exit_released
        if self.script is not None and released:
            # the process is exiting past the last hook: a call into the script or its unload would block on the
            # process's shutdown, which waits on Frida; the exit finishes on its own
            self.ended.wait(10)
            self.script = self.session = None
        if self.script is not None:
            try:
                with self.lock:
                    held = list(self.held)
                    loading = list(self.loading)
                    self.held.clear()
                    self.loading.clear()
                for tid in held:
                    self.script.post({"type": "resume-%d" % tid})
                for tid in loading:
                    self.script.post({"type": "load-%d" % tid})
                # A teardown racing the exit of a thread let go from its stop just
                # now hangs or faults the program: give the exit a moment to
                # begin, so closeBegin reports it exiting. A start or a resume
                # that let no thread go closes at once. Workaround for
                # frida/frida-gum#1192 (17.24.0 to 17.24.3) and #1194 (17.23.3
                # to 17.24.3).
                if held or loading or time.monotonic() - self.released_at < EXIT_GRACE:
                    self.exit_begun.wait(EXIT_GRACE)
                # replies still in flight (a stop, an exit or a fault the worker has not read yet) never come after the unload
                exiting = False
                try:
                    state = self.script.exports_sync.close_begin()
                    for reply in state["awaited"]:
                        self.script.post({"type": reply})
                    exiting = state["exiting"]
                except (frida.InvalidOperationError, frida.core.RPCException):
                    pass
                # an exit finishes on its own; an unload during it blocks the process's exit and itself
                if exiting:
                    self.ended.wait(10)
                    self.script = self.session = None
                else:
                    self.script.unload()
            except frida.InvalidOperationError:
                pass
        # a held child never stays suspended: it runs on, unobserved unless a session of its own holds it
        self.resume_children(bool(args.get("keep_handed")))
        if self.session is not None:
            try:
                self.session.detach()
            except frida.InvalidOperationError:
                pass
        ended = False
        if args.get("end", self.spawned):
            ended = self.spawned and not self.exited
            self.end_spawned()
        elif self.suspended and not self.exited:
            try:
                self.device.resume(self.pid)
            except frida.InvalidOperationError:
                pass
        self.script = self.session = None
        self.suspended = False
        return {"ended": ended, "kept": len(self.handed)}


def set_each(agent, points):
    """Sets each point in turn; a refused point reports its error, as a set request would, and the rest go on."""
    results = []
    for p in points:
        try:
            agent.set(p["id"], p["address"], bool(p.get("bare", False)), int(p.get("limit", 0)))
            results.append({"id": p["id"], "ok": True})
        except Failure as e:
            results.append({"id": p["id"], "ok": False, "error": {"code": e.code, "message": str(e)}})
        except Exception as e:  # frida errors carry their own message
            results.append({"id": p["id"], "ok": False, "error": {"code": "failed", "message": "%s: %s" % (type(e).__name__, e)}})
    return results


def handle(state, op, args):
    if op == "hello":
        if frida is None:
            raise Failure("provider_unavailable", "the frida package is not installed for this Python (" + _import_error + ")")
        return {"frida": frida.__version__, "python": sys.version.split()[0]}
    if frida is None:
        raise Failure("provider_unavailable", "the frida package is not installed for this Python")
    if op == "open":
        return state.open(args)
    if op == "info":
        return state.require().info()
    if op == "set":
        return state.require().set(args["id"], args["address"], bool(args.get("bare", False)), int(args.get("limit", 0)))
    if op == "set_many":
        return {"results": set_each(state.require(), args["points"])}
    if op == "clear":
        return state.require().clear(args["id"])
    if op == "watch":
        return state.require().watch(args["id"], args["address"], args["args"], int(args["perSecond"]))
    if op == "unwatch":
        return state.require().unwatch(args["id"])
    if op == "defer_module":
        return state.require().defer_module(args["name"])
    if op == "undefer_module":
        return state.require().undefer_module(args["name"])
    if op == "watch_jit":
        return state.require().watch_jit(args["il"])
    if op == "count_jit":
        return state.require().count_jit(args["run"], args["ils"])
    if op == "release_load":
        return state.release_load(args)
    if op == "load_script":
        return state.load_script(args)
    if op == "unload_script":
        return state.unload_script(args)
    if op == "export":
        return {"address": state.require().export_of(args["module"], args["name"])}
    if op == "read":
        data = state.require().read(args["address"], int(args["length"]))
        return {"bytes": None if data is None else bytes(data).hex()}
    if op == "resume":
        return state.resume(args)
    if op == "resume_child":
        return state.resume_child(args)
    if op == "drop_child":
        return state.drop_child(args)
    if op == "close":
        return state.close(args)
    if op == "cancel":
        return {}
    raise Failure("invalid_argument", "unknown op " + op)


def main():
    state = Session(sys.argv[1])
    emit({"event": "ready"})
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        req = json.loads(line)
        rid, op = req.get("id"), req.get("op")
        result = None
        try:
            result = handle(state, op, req.get("args") or {})
            emit({"id": rid, "ok": True, "result": result})
        except Failure as e:
            emit({"id": rid, "ok": False, "error": {"code": e.code, "message": str(e)}})
        except Exception as e:  # frida errors carry their own message
            emit({"id": rid, "ok": False, "error": error_of(e)})
        # A close that keeps handed sessions leaves the worker serving drop_child until a close keeps none.
        if op == "close" and not (result or {}).get("kept"):
            break
    try:
        state.close({})
    except Exception:
        pass


if __name__ == "__main__":
    main()
