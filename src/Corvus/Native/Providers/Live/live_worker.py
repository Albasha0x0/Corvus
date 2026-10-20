"""Session worker: a local program observed through Frida, on the worker protocol (one JSON object per line).

Ops: hello; open {attach | spawn, arguments, cwd, temp, tmp}; info; set {id, address}; clear {id}; watch {id, address, args,
perSecond}; unwatch {id}; defer_module {name}; undefer_module {name}; release_load {thread}; load_script {id, source};
unload_script {id}; read {address, length}; resume {thread}; close.
Events: ready, stop (with stack: the bytes from the stack pointer up, outside Windows), calls, module, thread, exception, exit_status, output, exit, script_error, user_script.
A program started here stays suspended until the first resume; close resumes every held thread, and ends the
program only when this worker started it. A module named by defer_module holds its loading thread (module event with
held) until release_load; a fatal exception event, and exit_status {code} (outside Windows), hold their thread until the
worker has read them.
"""
import json
import sys
import threading

_out = threading.Lock()
OUTPUT_CHUNK = 4096  # bytes of one program output chunk kept in its event


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
        self.held = set()
        self.loading = set()  # threads held at the load of a deferred module
        self.lock = threading.Lock()
        self.user_scripts = {}

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
        elif kind == "module" and payload.get("held"):
            with self.lock:
                self.loading.add(payload.get("tid"))
        ack = kind in ("exception", "exit_status") and payload.pop("ack", False)
        payload["event"] = kind
        emit(payload)
        if ack and self.script is not None:
            self.script.post({"type": "%s-%d" % ("exception" if kind == "exception" else "exit", payload.get("tid"))})

    def on_output(self, pid, fd, data):
        if pid == self.pid and data:
            text = data[:OUTPUT_CHUNK].decode("utf-8", "replace")
            emit({"event": "output", "stream": "stdout" if fd == 1 else "stderr", "text": text, "bytes": len(data)})

    def on_detached(self, reason, crash):
        self.exited = str(reason) == "process-terminated"
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
        try:
            self.session = self.device.attach(self.pid)
        except (frida.ProcessNotFoundError, frida.PermissionDeniedError) as e:
            self.end_spawned()
            raise Failure("not_found" if isinstance(e, frida.ProcessNotFoundError) else "access_denied", str(e))
        self.session.on("detached", self.on_detached)
        with open(self.agent_path, "r", encoding="utf-8") as f:
            source = f.read()
        self.script = self.session.create_script(source)
        self.script.on("message", self.on_message)
        self.script.load()
        result = self.script.exports_sync.info()
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
                self.script.unload()
            except frida.InvalidOperationError:
                pass
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
        return state.require().set(args["id"], args["address"])
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
