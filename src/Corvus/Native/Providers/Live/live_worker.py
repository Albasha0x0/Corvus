"""Session worker: a local program observed through Frida, on the worker protocol (one JSON object per line).

Ops: hello; open {attach, stopped | spawn, arguments, cwd, temp, tmp, children}; info; set {id, address}; clear {id}; watch {id, address, args,
perSecond}; unwatch {id}; defer_module {name}; undefer_module {name}; release_load {thread}; load_script {id, source};
unload_script {id}; read {address, length}; resume {thread}; resume_child {pid, stopped}; close.
Events: ready, stop (with stack: the bytes from the stack pointer up, outside Windows), calls, module, thread, exception, exit_status, output, exit, script_error, user_script, child.
A program started here stays suspended until the first resume; close resumes every held thread, and ends the
program only when this worker started it. A module named by defer_module holds its loading thread (module event with
held) until release_load; a fatal exception event, and exit_status {code}, hold their thread until the
worker has read them.
With children {names} on open, a program the process starts is held at its start (Frida's child gating) and reported
as a child event; one whose image name is not in names (when given) is resumed at once. resume_child lets a held child
run, or with stopped (Linux) leaves it stopped for open {attach, stopped} in another worker; close resumes
every child still held.
"""
import json
import os
import signal
import sys
import threading

_out = threading.Lock()
OUTPUT_CHUNK = 4096  # bytes of one program output chunk kept in its event


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


def emit(obj):
    line = json.dumps(obj, ensure_ascii=True, separators=(",", ":"))
    with _out:
        sys.stdout.write(line + "\n")
        sys.stdout.flush()


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
        self.suspended = False
        self.exited = False
        self.ended = threading.Event()  # the process is gone
        self.closing = False
        self.exit_released = False  # an exit_status was answered: the process is past the script's last hook
        self.held = set()
        self.loading = set()  # threads held at the load of a deferred module or the compile of a watched method
        self.lock = threading.Lock()
        self.user_scripts = {}
        self.children = {}  # pid of each held child to its path
        self.forks = {}  # pid of each fork followed to its exec (outside Windows) to its session
        self.child_names = None  # lower-case image names (with or without extension) to hold; None holds every child

    def on_message(self, message, data):
        if message.get("type") == "error":
            emit({"event": "script_error", "message": message.get("description"), "stack": message.get("stack")})
            return
        payload = message.get("payload") or {}
        kind = payload.pop("type", "message")
        if kind == "stop":
            with self.lock:
                self.held.add(payload.get("tid"))
            if data:
                payload["stack"] = data.hex()
        elif kind in ("module", "compiled") and payload.get("held"):
            with self.lock:
                self.loading.add(payload.get("tid"))
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
            held = self.children.pop(pid, None) is not None
        if held:
            if args.get("stopped"):
                # The gate's ptrace hold keeps another worker from attaching, and a child held at its exec has no libc
                # to load an agent with: an attach here runs it until its libraries are loaded, and it leaves the gate
                # stopped by SIGSTOP for the next worker's attach.
                self.device.attach(pid).detach()
                os.kill(pid, signal.SIGSTOP)
            self.device.resume(pid)
        return {"resumed": held}

    def resume_children(self):
        with self.lock:
            pids = list(self.children)
            forks = list(self.forks.values())
            self.children.clear()
            self.forks.clear()
        for pid in pids:
            self.resume_quietly(pid)
        for fork in forks:
            self.detach_quietly(fork)

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
            try:
                self.pid = self.device.spawn(argv, stdio="pipe", env=env or None, cwd=args.get("cwd") or None)
            except frida.ExecutableNotFoundError as e:
                raise Failure("not_found", str(e))
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
        return result

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

        def on_message(message, data):
            if message.get("type") == "error":
                emit({"event": "user_script", "script": sid, "error": message.get("description"), "stack": message.get("stack")})
            else:
                emit({"event": "user_script", "script": sid, "payload": message.get("payload"), "bytes": len(data) if data else 0})

        script.on("message", on_message)
        script.load()
        self.user_scripts[sid] = script
        return {"loaded": sid}

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
        self.resume_children()
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
        return {"ended": ended}


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
        return state.require().set(args["id"], args["address"], bool(args.get("bare", False)))
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
    if op == "read":
        data = state.require().read(args["address"], int(args["length"]))
        return {"bytes": None if data is None else bytes(data).hex()}
    if op == "resume":
        return state.resume(args)
    if op == "resume_child":
        return state.resume_child(args)
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
        try:
            result = handle(state, op, req.get("args") or {})
            emit({"id": rid, "ok": True, "result": result})
        except Failure as e:
            emit({"id": rid, "ok": False, "error": {"code": e.code, "message": str(e)}})
        except Exception as e:  # frida errors carry their own message
            emit({"id": rid, "ok": False, "error": {"code": "failed", "message": "%s: %s" % (type(e).__name__, e)}})
        if op == "close":
            break
    try:
        state.close({})
    except Exception:
        pass


if __name__ == "__main__":
    main()
