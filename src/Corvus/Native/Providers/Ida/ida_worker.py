# idalib worker.
# Protocol: one JSON object per line. Requests on stdin: {"id": n, "op": "...", "args": {...}}.
# Responses on stdout: {"id": n, "ok": true, "result": ...} or {"id": n, "ok": false, "error": {"code": ..., "message": ...}}.
# A request may carry "timeout" (seconds); {"op": "cancel", "args": {"id": n}} stops request n. A stopped request answers
# with what it has, marked {"partial": reason, "next": cursor}, or with a timeout / cancelled error.
# Unsolicited lines: {"event": "progress", "id": n, "op": ..., "elapsed": seconds}.
# Anything IDA or Python prints goes to stderr: fd 1 is redirected there before idalib loads.
# Addresses on the wire are RVAs relative to the database image base.
import json
import os
import queue
import sys
import threading
import time
import traceback

PROTOCOL = 1

_proto = os.fdopen(os.dup(1), "w", encoding="utf-8", newline="\n")
os.dup2(2, 1)
sys.stdout = sys.stderr
sys.stdin.reconfigure(encoding="utf-8", errors="replace")
_write_lock = threading.Lock()


def send(obj):
    line = json.dumps(obj, ensure_ascii=True, separators=(",", ":"))
    with _write_lock:
        _proto.write(line + "\n")
        _proto.flush()


class WorkerError(Exception):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


class Request:
    # stop: None, "cancelled" (a cancel op) or "deadline" (the request's time limit, less a margin for the reply)
    def __init__(self, rid, op, args, timeout):
        self.id, self.op, self.args, self.timeout = rid, op, args, timeout
        self.start = self.deadline = None
        self.stop = None


_queue = queue.Queue()
_requests = {}  # id -> Request, queued or running
_current = None  # the Request running
_requests_lock = threading.Lock()


def read_requests():
    # stdin is read on its own thread so a cancel reaches the request it names while that request runs
    while True:
        line = sys.stdin.readline()
        if not line:
            _queue.put(None)  # parent closed the pipe or died
            return
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
            rid, op, args = req.get("id"), req.get("op"), req.get("args") or {}
            timeout = req.get("timeout")
        except (ValueError, AttributeError) as e:
            send({"id": None, "ok": False, "error": {"code": "invalid_argument", "message": "bad request line: %s" % e}})
            continue
        if op == "cancel":
            stop_request(args.get("id"), "cancelled")
            continue
        r = Request(rid, op, args, timeout if isinstance(timeout, (int, float)) and timeout > 0 else None)
        with _requests_lock:
            _requests[rid] = r
        _queue.put(r)


def stop_request(rid, reason):
    # Only flags the request: idalib's set_cancelled blocks when called off the main thread, so the main thread notices
    # through cancelled() in loops, the Hex-Rays stage hook and the script profile hook.
    with _requests_lock:
        r = _requests.get(rid)
        if r is not None and r.stop is None:
            r.stop = reason


def clear_cancel():
    # a script may have set IDA's cancel flag, which is sticky
    m = _ida
    if m is not None and m.ida_kernwin is not None:
        try:
            m.ida_kernwin.clr_cancelled()
        except BaseException:
            pass


def deadline():
    # absolute time.time() the running request must answer by, or None
    r = _current
    return r.deadline if r is not None else None


def cancelled():
    # whether the running request was cancelled or reached its deadline: long loops stop and return what they have
    r = _current
    if r is None:
        return False
    if r.stop is None and r.deadline is not None and time.time() >= r.deadline:
        stop_request(r.id, "deadline")
    return r.stop is not None


def stop_reason():
    r = _current
    return r.stop if r is not None else None


def stopped_error():
    r = _current
    seconds = time.time() - r.start
    if r.stop == "deadline":
        return WorkerError("timeout", "'%s' reached its time limit after %.1f s" % (r.op, seconds))
    return WorkerError("cancelled", "'%s' was cancelled after %.1f s" % (r.op, seconds))


def check_stop():
    if cancelled():
        raise stopped_error()


def partial(result, cursor):
    # marks a result cut short: why ("cancelled", "deadline" or "budget") and where to continue
    result["partial"] = stop_reason() or "budget"
    result["next"] = cursor
    return result


def heartbeat():
    while True:
        time.sleep(2.0)
        r = _current
        if r is not None and r.start is not None:
            send({"event": "progress", "id": r.id, "op": r.op, "elapsed": round(time.time() - r.start, 1)})


# idalib is loaded on the first request so that load and license failures come back as responses.
_ida = None
_state = {"open": False, "base": 0, "auto": True}


def ida():
    global _ida
    if _ida is not None:
        return _ida
    ida_dir = os.environ.get("IDADIR")
    if not ida_dir:
        raise WorkerError("provider_unavailable", "IDADIR is not set")
    sys.path.insert(0, os.path.join(ida_dir, "idalib", "python"))
    try:
        import idapro
    except BaseException as e:
        raise WorkerError("provider_unavailable", "idalib failed to load: %s" % (str(e).strip() or type(e).__name__))
    import ida_auto, ida_bytes, ida_entry, ida_funcs, ida_ida, ida_lines, ida_loader, ida_nalt, ida_name, ida_segment, ida_ua, ida_xref, idautils
    mods = dict(idapro=idapro, ida_auto=ida_auto, ida_bytes=ida_bytes, ida_entry=ida_entry, ida_funcs=ida_funcs,
                ida_ida=ida_ida, ida_lines=ida_lines, ida_loader=ida_loader, ida_nalt=ida_nalt, ida_name=ida_name,
                ida_segment=ida_segment, ida_ua=ida_ua, ida_xref=ida_xref, idautils=idautils)
    for optional in ("ida_hexrays", "ida_kernwin"):
        try:
            mods[optional] = __import__(optional)
        except BaseException:
            mods[optional] = None
    _ida = type("Ida", (), mods)
    batch_mode()
    return _ida


def batch_mode():
    # no dialog may wait for an answer that never comes: IDA takes the default of every question
    try:
        import idc
        idc.batch(1)
    except BaseException:
        pass


def need_open():
    if not _state["open"]:
        raise WorkerError("invalid_argument", "no database is open")
    return ida()


def ea_of(args, key="rva"):
    rva = args.get(key)
    if not isinstance(rva, int) or rva < 0:
        raise WorkerError("invalid_argument", "%s must be a non-negative integer" % key)
    return _state["base"] + rva


def rva_of(ea):
    r = ea - _state["base"]
    return r if 0 <= r <= 0xFFFFFFFF else None


def func_at(m, ea):
    f = m.ida_funcs.get_func(ea)
    if f is None and not _state["auto"] and m.ida_funcs.add_func(ea):
        f = m.ida_funcs.get_func(ea)  # without auto-analysis, functions are made where they are asked for
    if f is None:
        raise WorkerError("not_found", "no function contains rva 0x%X" % (ea - _state["base"]))
    return f


_stop_hooks = None


def hexrays_ready(m):
    global _stop_hooks
    hr = m.ida_hexrays
    try:
        ready = hr is not None and bool(hr.init_hexrays_plugin())
    except BaseException:
        return False
    if ready and _stop_hooks is None:
        # every decompilation checks at each stage whether its request was cancelled or reached its deadline
        class StopHooks(hr.Hexrays_Hooks):
            def _check(self, *unused):
                return hr.MERR_CANCELED if cancelled() else 0

            microcode = preoptimized = locopt = prealloc = glbopt = _check

        _stop_hooks = StopHooks()
        _stop_hooks.hook()
    return ready


def op_hello(args):
    m = ida()
    v = m.idapro.get_library_version()
    return {"protocol": PROTOCOL, "version": "%d.%d.%d" % v if v else None, "python": sys.version.split()[0],
            "pid": os.getpid()}


def op_open(args):
    m = ida()
    if _state["open"]:
        raise WorkerError("invalid_argument", "a database is already open")
    idb = args["idb"]
    reuse = os.path.isfile(idb)
    path = idb if reuse else args["input"]
    extra = list(args.get("ida_args") or [])
    if not reuse:
        extra.insert(0, "-o" + idb)
    cmdline = " ".join(quote_arg(a) for a in extra) or None
    start = time.time()
    _state["auto"] = args.get("auto", True) is not False
    rc = m.idapro.open_database(path, _state["auto"], cmdline)
    if rc != 0:
        raise WorkerError("provider_unavailable", "open_database returned %d for %s (%d characters; database %s, %d characters)"
                          % (rc, path, len(path), idb, len(idb)))
    _state["open"] = True
    batch_mode()
    if _state["auto"]:
        m.ida_auto.auto_wait()
    _state["base"] = m.ida_nalt.get_imagebase()
    ftype = m.ida_ida.inf_get_filetype()
    if ftype not in (m.ida_ida.f_PE, m.ida_ida.f_ELF, m.ida_ida.f_MACHO):
        raise WorkerError("unsupported", "IDA loaded the file with a loader other than its PE, ELF or Mach-O loader (file type %d, processor %s)"
                          % (ftype, m.ida_ida.inf_get_procname()))
    sha = args.get("sha256") or ""
    if reuse:
        rename_legacy_nodes()
    if reuse and sha:
        node = stamp_node(False)
        made_from = node.hashstr_buf(INPUT_STAMP) if node is not None else None
        if isinstance(made_from, bytes):
            made_from = made_from.decode("ascii", "replace")
        if made_from != sha:
            m.idapro.close_database(False)
            _state["open"] = False
            raise WorkerError("malformed_input", "the saved database %s was made from other input (%s, expected %s)"
                              % (idb, made_from or "no input stamp", sha))
    if not reuse:
        if sha:
            stamp_node(True).hashset_buf(INPUT_STAMP, sha)
        # IDA writes the packed .i64 only on save; persist the analysis now so a crash does not discard it.
        m.ida_loader.save_database(m.ida_loader.get_path(m.ida_loader.PATH_TYPE_IDB), 0)
    return info(m, reuse, time.time() - start)


INPUT_STAMP = "input"  # SHA-256 of the input the database was made from


def info(m, reused, seconds):
    return {"imagebase": _state["base"], "bits": 64 if m.ida_ida.inf_is_64bit() else (32 if m.ida_ida.inf_is_32bit_exactly() else 16),
            "processor": m.ida_ida.inf_get_procname(), "functions": m.ida_funcs.get_func_qty(),
            "decompiler": hexrays_ready(m), "reused": reused, "seconds": round(seconds, 3),
            "idb": m.ida_loader.get_path(m.ida_loader.PATH_TYPE_IDB), "filetype": file_type_name(m)}


def file_type_name(m):
    t = m.ida_ida.inf_get_filetype()
    return {m.ida_ida.f_PE: "pe", m.ida_ida.f_ELF: "elf", m.ida_ida.f_MACHO: "macho"}.get(t, "other")


def is_thumb(m, ea):
    # 32-bit ARM: the T segment register is 1 in Thumb code
    if m.ida_ida.inf_get_procname().lower() != "arm" or m.ida_ida.inf_is_64bit():
        return False
    try:
        import ida_idp, ida_segregs
        return ida_segregs.get_sreg(ea, ida_idp.str2reg("T")) == 1
    except BaseException:
        return False


def quote_arg(a):
    return '"%s"' % a if (" " in a or "\t" in a) and not a.startswith('"') else a


def op_rebase(args):
    m = need_open()
    target = args["imagebase"]
    delta = target - _state["base"]
    if delta != 0:
        rc = m.ida_segment.rebase_program(delta, m.ida_segment.MSF_FIXONCE)
        if rc != 0:
            raise WorkerError("failed", "rebase_program returned %d" % rc)
        m.ida_auto.auto_wait()
    _state["base"] = m.ida_nalt.get_imagebase()
    return {"imagebase": _state["base"]}


def op_functions(args):
    # [start, end, name, flags (1 thunk, 2 library, 4 thumb, 8 typed)] plus, with refs, the number of code references to the
    # start; from rva start when given. Stopped early: {rows, partial, next} where next is the start rva of the following call.
    m = need_open()
    import ida_typeinf
    refs = bool(args.get("refs"))
    start = args.get("start")
    out = []
    for ea in m.idautils.Functions(_state["base"] + start if isinstance(start, int) else None):
        if out and len(out) % 64 == 0 and cancelled() and rva_of(ea) is not None:
            return partial({"rows": out}, rva_of(ea))
        f = m.ida_funcs.get_func(ea)
        start, end = rva_of(f.start_ea), rva_of(f.end_ea)
        if start is None or end is None:
            continue
        flags = (1 if f.flags & m.ida_funcs.FUNC_THUNK else 0) | (2 if f.flags & m.ida_funcs.FUNC_LIB else 0) | (4 if is_thumb(m, f.start_ea) else 0) \
            | (8 if m.ida_nalt.get_tinfo(ida_typeinf.tinfo_t(), f.start_ea) else 0)
        row = [start, end, m.ida_funcs.get_func_name(f.start_ea) or "", flags]
        if refs:
            row.append(sum(1 for _ in m.idautils.CodeRefsTo(f.start_ea, 0)))
        out.append(row)
    return out


def line_addresses(m, cf, line):
    # ctree items are tagged COLOR_ON COLOR_ADDR <16 hex digits of the item index>.
    tag = m.ida_lines.SCOLOR_ON + m.ida_lines.SCOLOR_ADDR
    items = cf.treeitems
    lowest = None
    i = line.find(tag)
    while i >= 0:
        digits = line[i + 2:i + 2 + m.ida_lines.COLOR_ADDR_SIZE]
        try:
            anchor = int(digits, 16)
        except ValueError:
            anchor = -1
        if 0 <= anchor < len(items) and (anchor & 0xC0000000) == 0:
            ea = items[anchor].ea
            if ea != m.idautils.ida_idaapi.BADADDR and (lowest is None or ea < lowest):
                lowest = ea
        i = line.find(tag, i + 2)
    return lowest


def op_decompile(args):
    m = need_open()
    ea = ea_of(args)
    f = func_at(m, ea)
    if not hexrays_ready(m):
        raise WorkerError("unsupported", "the Hex-Rays decompiler for %s (%d-bit) is not available: not installed or not licensed"
                          % (m.ida_ida.inf_get_procname(), 64 if m.ida_ida.inf_is_64bit() else 32))
    hf = m.ida_hexrays.hexrays_failure_t()
    try:
        cf = m.ida_hexrays.decompile(f.start_ea, hf, m.ida_hexrays.DECOMP_NO_WAIT)
    except m.ida_hexrays.DecompilationFailure as e:
        raise WorkerError("failed", "decompilation failed at 0x%X: %s" % (rva_of(hf.errea) or 0, str(e).strip() or hf.desc()))
    if cf is None:
        raise WorkerError("failed", "decompilation failed: %s" % hf.desc())
    text_lines = []
    addresses = []
    for n, sl in enumerate(cf.get_pseudocode()):
        text_lines.append(m.ida_lines.tag_remove(sl.line))
        ea_line = line_addresses(m, cf, sl.line)
        if ea_line is not None and rva_of(ea_line) is not None:
            addresses.append([n, rva_of(ea_line)])
    return {"start": rva_of(f.start_ea), "name": m.ida_funcs.get_func_name(f.start_ea) or "",
            "text": "\n".join(text_lines), "lines": addresses}


def op_disasm(args):
    m = need_open()
    f = func_at(m, ea_of(args))
    limit = int(args.get("limit") or 200000)
    insns = []
    for head in m.idautils.FuncItems(f.start_ea):
        if len(insns) >= limit:
            break
        size = m.ida_bytes.get_item_size(head)
        raw = m.ida_bytes.get_bytes(head, size) or b""
        text = m.ida_lines.generate_disasm_line(head, m.ida_lines.GENDSM_REMOVE_TAGS) or ""
        cmt = m.ida_bytes.get_cmt(head, False) or m.ida_bytes.get_cmt(head, True)
        insns.append([rva_of(head), raw.hex(), text, cmt])
    return {"start": rva_of(f.start_ea), "end": rva_of(f.end_ea), "name": m.ida_funcs.get_func_name(f.start_ea) or "",
            "insns": insns, "truncated": len(insns) >= limit}


def op_disasm_range(args):
    # count items from rva in address order, whether or not a function contains them
    m = need_open()
    ea = ea_of(args)
    count = max(1, min(int(args.get("count") or 100), 200000))
    badaddr = m.idautils.ida_idaapi.BADADDR
    max_ea = m.ida_ida.inf_get_max_ea()
    insns = []
    while len(insns) < count and ea != badaddr and ea < max_ea and m.ida_bytes.is_loaded(ea):
        if insns and len(insns) % 1024 == 0 and cancelled():
            return {"insns": insns, "truncated": True, "partial": stop_reason()}
        end = m.ida_bytes.get_item_end(ea)
        size = end - ea if end > ea else 1
        raw = m.ida_bytes.get_bytes(ea, size) or b""
        text = m.ida_lines.generate_disasm_line(ea, m.ida_lines.GENDSM_REMOVE_TAGS) or ""
        cmt = m.ida_bytes.get_cmt(ea, False) or m.ida_bytes.get_cmt(ea, True)
        if rva_of(ea) is None:
            break
        insns.append([rva_of(ea), raw.hex(), text, cmt])
        ea += size
    return {"insns": insns, "truncated": len(insns) >= count}


def switch_row(m, ea, si):
    # a recognized switch: its values per target (from IDA's case calculation), default, tables and bias
    import ida_xref, ida_idaapi
    bad = ida_idaapi.BADADDR
    cases = []
    try:
        res = ida_xref.calc_switch_cases(ea, si)
    except Exception:
        res = None
    if res is not None:
        for i in range(len(res.targets)):
            t = rva_of(res.targets[i])
            values = [int(v) for v in res.cases[i]] if i < len(res.cases) else []
            if t is not None and values:
                cases.append([t, values])
    indirect = si.is_indirect()
    return {"jump": rva_of(ea), "cases": cases,
            "default": rva_of(si.defjump) if si.defjump != bad else None,
            "table": rva_of(si.jumps) if si.jumps not in (bad, 0) else None,
            "entry_size": si.get_jtable_element_size(),
            "entries": si.jcases if indirect else si.get_jtable_size(),
            "index_table": rva_of(si.values) if indirect and si.values not in (bad, 0) else None,
            "index_entries": si.get_jtable_size() if indirect else None,
            "bias": int(si.ind_lowcase if indirect else (0 if si.is_sparse() else si.lowcase))}


def op_blocks(args):
    # basic blocks of the function containing rva: [start, end, instructions, kind, successors, switch, switch details or None]
    m = need_open()
    import ida_gdl, ida_nalt
    f = func_at(m, ea_of(args))
    kinds = {}
    for k in ("normal", "indjump", "ret", "cndret", "noret", "enoret", "extern", "error"):
        kinds[getattr(ida_gdl, "fcb_" + k)] = k
    fc = ida_gdl.FlowChart(f, flags=ida_gdl.FC_NOEXT)
    blocks = []
    tails = set()
    for b in fc:
        if rva_of(b.start_ea) is None or rva_of(b.end_ea) is None:
            continue
        heads = [h for h in m.idautils.Heads(b.start_ea, b.end_ea) if m.ida_bytes.is_code(m.ida_bytes.get_flags(h))]
        last = heads[-1] if heads else b.start_ea
        succs = []
        for s in b.succs():
            if rva_of(s.start_ea) is not None:
                succs.append(rva_of(s.start_ea))
        # flow leaving the function (tail calls): code references from the last instruction to other functions
        for x in m.idautils.XrefsFrom(last, 0):
            if x.iscode and x.type in (m.ida_xref.fl_JF, m.ida_xref.fl_JN):
                g = m.ida_funcs.get_func(x.to)
                if (g is None or g.start_ea != f.start_ea) and rva_of(x.to) is not None:
                    tails.add(rva_of(x.to))
        si = ida_nalt.get_switch_info(last)
        blocks.append([rva_of(b.start_ea), rva_of(b.end_ea), len(heads), kinds.get(b.type, "normal"), succs, si is not None,
                       switch_row(m, last, si) if si is not None else None])
    return {"start": rva_of(f.start_ea), "name": m.ida_funcs.get_func_name(f.start_ea) or "", "blocks": blocks,
            "tail_calls": sorted(tails)}


def xref_kind(m, x):
    t = x.type
    x_ = m.ida_xref
    if x.iscode:
        if t in (x_.fl_CF, x_.fl_CN):
            return "call"
        if t in (x_.fl_JF, x_.fl_JN):
            return "jump"
        return "code"
    return {x_.dr_O: "offset", x_.dr_W: "write", x_.dr_R: "read", x_.dr_T: "text", x_.dr_I: "info"}.get(t, "data")


def xref_row(m, x):
    if x.iscode and x.type == m.ida_xref.fl_F:
        return None
    frm, to = rva_of(x.frm), rva_of(x.to)
    if frm is None or to is None:
        return None
    f = m.ida_funcs.get_func(x.frm)
    return [frm, to, xref_kind(m, x), rva_of(f.start_ea) if f else None]


def op_xrefs_to(args):
    m = need_open()
    rows = (xref_row(m, x) for x in m.idautils.XrefsTo(ea_of(args), 0))
    return [r for r in rows if r is not None]


def op_xrefs_from(args):
    m = need_open()
    ea = ea_of(args)
    heads = [ea]
    if args.get("function"):
        heads = list(m.idautils.FuncItems(func_at(m, ea).start_ea))
    out = []
    for h in heads:
        for x in m.idautils.XrefsFrom(h, 0):
            r = xref_row(m, x)
            if r is not None:
                out.append(r)
    return out


DIRTY_LIMIT = 512  # more changed addresses than this clear every cached function


def changed(m, eas=None):
    # Hex-Rays caches pseudocode per function; names and comments must show in the next decompilation. With eas, only the
    # functions holding or referencing them are decompiled again.
    if not hexrays_ready(m):
        return
    hr = m.ida_hexrays
    if eas is None or len(eas) > DIRTY_LIMIT:
        hr.clear_cached_cfuncs()
        return
    dirty = set()
    for ea in eas:
        for at in [ea] + [x.frm for x in m.idautils.XrefsTo(ea, 0)]:
            f = m.ida_funcs.get_func(at)
            if f is not None:
                dirty.add(f.start_ea)
        if len(dirty) > DIRTY_LIMIT:
            hr.clear_cached_cfuncs()
            return
    for f in dirty:
        hr.mark_cfunc_dirty(f, False)


def op_set_name(args):
    m = need_open()
    ea = ea_of(args)
    name = args.get("name") or ""
    if name:
        other = m.ida_name.get_name_ea(m.idautils.ida_idaapi.BADADDR, name)
        if other != m.idautils.ida_idaapi.BADADDR and other != ea:
            raise WorkerError("conflict", "the name %s is already used at rva 0x%X" % (name, rva_of(other) or 0))
    if not m.ida_name.set_name(ea, name, m.ida_name.SN_NOWARN):
        raise WorkerError("invalid_argument", "IDA rejected the name %r at rva 0x%X" % (name, args["rva"]))
    changed(m, [ea])
    return {"name": m.ida_name.get_name(ea) or ""}


def op_set_comment(args):
    m = need_open()
    ea = ea_of(args)
    repeatable = bool(args.get("repeatable"))
    if not m.ida_bytes.set_cmt(ea, args.get("text") or "", repeatable):
        raise WorkerError("invalid_argument", "IDA rejected the comment at rva 0x%X" % args["rva"])
    changed(m, [ea])
    return {"comment": m.ida_bytes.get_cmt(ea, repeatable) or ""}


def op_sync_patches(args):
    # INativeDecompilerProvider.SyncPatchesAsync; items: [[rva, hex bytes]].
    m = need_open()
    start = time.time()
    badaddr = m.idautils.ida_idaapi.BADADDR
    base = _state["base"]
    desired = {}
    for item in args.get("items") or []:
        data = bytes.fromhex(item[1])
        for i, b in enumerate(data):
            desired[base + item[0] + i] = b
    current = {}

    def visit(ea, fpos, org, val):
        current[ea] = org
        return 0

    m.ida_bytes.visit_patched_bytes(0, badaddr, visit)
    touched = set()
    reverted = patched = 0
    for ea, org in current.items():
        if ea not in desired or desired[ea] == org:
            if m.ida_bytes.revert_byte(ea):
                reverted += 1
                touched.add(ea)
    missing = []
    for ea, b in sorted(desired.items()):
        if not m.ida_bytes.is_loaded(ea):
            missing.append(ea - base)
            continue
        if m.ida_bytes.get_byte(ea) == b:
            continue
        if m.ida_bytes.get_original_byte(ea) == b:
            m.ida_bytes.revert_byte(ea)
            reverted += 1
        else:
            m.ida_bytes.patch_byte(ea, b)
            patched += 1
        touched.add(ea)
    mismatches = [ea - base for ea, b in desired.items() if m.ida_bytes.is_loaded(ea) and m.ida_bytes.get_byte(ea) != b]
    # coalesce touched bytes into ranges, then decode the code in them again
    ranges = []
    for ea in sorted(touched):
        if ranges and ea <= ranges[-1][1]:
            ranges[-1][1] = ea + 1
        else:
            ranges.append([ea, ea + 1])
    # functions that held patched code, remembered in the database: a patch can end a function (IDA deletes it when the
    # new code no longer forms one), and reverting the bytes must bring it back
    node = stamp_node(True)
    remembered = node.hashstr_buf(PATCH_FUNCTIONS) or ""
    if isinstance(remembered, bytes):
        remembered = remembered.decode("ascii", "replace")
    functions = set(int(x, 16) + base for x in remembered.split(",") if x)
    for lo, hi in ranges:
        seg = m.ida_segment.getseg(lo)
        if seg is None or not (seg.perm & m.ida_segment.SEGPERM_EXEC or seg.type == m.ida_segment.SEG_CODE):
            continue
        f = m.ida_funcs.get_func(lo)
        head = m.ida_bytes.get_item_head(lo)
        end = m.ida_bytes.get_item_end(hi - 1)
        if f is not None:
            functions.add(f.start_ea)
        m.ida_bytes.del_items(head, m.ida_bytes.DELIT_SIMPLE, end - head)
        ea = head
        while ea < end:
            n = m.ida_ua.create_insn(ea)
            ea += n if n > 0 else 1
        m.ida_auto.auto_mark_range(head, end, m.ida_auto.AU_USED)
    m.ida_auto.auto_wait()
    for fs in functions:
        f = m.ida_funcs.get_func(fs)
        if f is None:
            m.ida_funcs.add_func(fs, badaddr)
        elif f.start_ea == fs:
            m.ida_funcs.reanalyze_function(f, f.start_ea, f.end_ea, False)
    m.ida_auto.auto_wait()
    still = []
    m.ida_bytes.visit_patched_bytes(0, badaddr, lambda ea, fpos, org, val: still.append(ea) or 1)
    node.hashset_buf(PATCH_FUNCTIONS, ",".join("%X" % (fs - base) for fs in sorted(functions)) if still else "")
    changed(m)
    return {"patched": patched, "reverted": reverted, "ranges": len(ranges), "functions": len(functions),
            "missing": missing[:20], "missing_count": len(missing), "mismatches": mismatches[:20],
            "mismatch_count": len(mismatches), "seconds": round(time.time() - start, 3)}


PATCH_FUNCTIONS = "patch_functions"


def c_ident(text):
    out = []
    for ch in text:
        out.append(ch if (ch.isalnum() and ord(ch) < 128) or ch == "_" else "_")
    s = "".join(out).strip("_") or "x"
    return "_" + s if s[0].isdigit() else s


def op_apply_types(args):
    # decls: C declarations (parse_decls); prototypes: [[rva, C declaration]] applied to functions;
    # classes (C++ with vftables): {"ptr": 4|8, "classes": [{"name", "vftables": [[offset, vftable rva, [slot rvas]]],
    #   "bases": [[name, offset]]}], "methods": [[rva, class name]]}: a <name>_vftable struct per vftable (slot function
    #   pointers typed from the target's type when it has one), a <name> struct (vftable pointers at their subobject
    #   offsets, base subobjects there), the vftables typed, and the methods' first argument set to <name>*.
    # Addresses the user typed (apply_user_types) keep their type.
    m = need_open()
    import ida_typeinf as ti
    import idc
    start = time.time()
    til = ti.get_idati()
    result = {"decl_errors": 0, "typed": 0, "type_failures": 0, "failures": [], "structs": 0, "vftables_typed": 0, "methods_typed": 0}
    decls = args.get("decls")
    if decls:
        result["decl_errors"] = idc.parse_decls(decls, idc.PT_SILENT)
    for rva, decl in args.get("prototypes") or []:
        if user_typed(rva):
            continue
        ea = _state["base"] + rva
        if m.ida_funcs.get_func(ea) is None:
            m.ida_funcs.add_func(ea, m.idautils.ida_idaapi.BADADDR)
        if ti.apply_cdecl(til, ea, decl, ti.TINFO_DEFINITE):
            result["typed"] += 1
        else:
            result["type_failures"] += 1
            if len(result["failures"]) < 20:
                result["failures"].append("rva 0x%X: %s" % (rva, decl))
    model = args.get("classes")
    if model:
        apply_classes(m, ti, til, model, result)
    if decls or model:
        reapply_user_decls()
    changed(m)
    key = args.get("stamp_key")
    if key:
        stamp_node(True).hashset_buf(key, args.get("stamp") or "")
    if args.get("save"):
        if not m.ida_loader.save_database(m.ida_loader.get_path(m.ida_loader.PATH_TYPE_IDB), 0):
            raise WorkerError("io_error", "save_database failed")
    result["seconds"] = round(time.time() - start, 3)
    return result


def apply_classes(m, ti, til, model, result):
    import idc
    base = _state["base"]
    ptr_bits = 8 * int(model.get("ptr") or 8)
    classes = model.get("classes") or []

    def named(name):
        t = ti.tinfo_t()
        return t if t.get_named_type(til, name) else None

    def pointer_to(t):
        p = ti.tinfo_t()
        p.create_ptr(t)
        return p

    def void_ptr():
        return pointer_to(ti.tinfo_t(ti.BT_VOID))

    def define(name, members, size_bytes=None):
        udt = ti.udt_type_data_t()
        for mname, offset_bytes, mtype in members:
            u = ti.udm_t()
            u.name = mname
            u.type = mtype
            u.offset = offset_bytes * 8
            u.size = mtype.get_size() * 8
            udt.push_back(u)
        t = ti.tinfo_t()
        t.create_udt(udt, ti.BTF_STRUCT)
        return t.set_named_type(til, name, ti.NTF_REPLACE) == ti.TERR_OK

    # forward declarations, so pointers to every class resolve
    forward = "".join("struct %s; struct %s_vftable;" % (c["name"], c["name"]) for c in classes)
    if forward:
        result["decl_errors"] += idc.parse_decls(forward, idc.PT_SILENT)
    # methods: first argument becomes a pointer to the class (functions without a type of their own only)
    skips = result.setdefault("method_skips", {})

    def skip(reason):
        skips[reason] = skips.get(reason, 0) + 1

    deadline = time.time() + float(model.get("method_seconds") or 15)
    for rva, cname in model.get("methods") or []:
        ea = base + rva
        cls = named(cname)
        f = m.ida_funcs.get_func(ea)
        # library code (_purecall and the like) and thunks are not the class's own
        if cls is None:
            skip("no_class_type")
            continue
        if f is None or f.start_ea != ea or f.flags & (m.ida_funcs.FUNC_LIB | m.ida_funcs.FUNC_THUNK):
            skip("not_own_function")
            continue
        # a type set on purpose (PDB, user, a pushed prototype) is kept
        if m.ida_nalt.is_userti(ea):
            skip("typed")
            continue
        ftif = ti.tinfo_t()
        if not m.ida_nalt.get_tinfo(ftif, ea) and ti.guess_tinfo(ftif, ea) != ti.GUESS_FUNC_OK:
            # the decompiler's view of the function gives its arguments; bounded per batch, the rest are typed when asked for
            if time.time() > deadline:
                skip("deferred")
                continue
            if not hexrays_ready(m):
                skip("no_type")
                continue
            try:
                cf = m.ida_hexrays.decompile(ea, m.ida_hexrays.hexrays_failure_t(), m.ida_hexrays.DECOMP_NO_WAIT)
            except m.ida_hexrays.DecompilationFailure:
                cf = None
            if cf is None or not cf.get_func_type(ftif):
                skip("no_type")
                continue
        ftd = ti.func_type_data_t()
        if not ftif.is_func() or not ftif.get_func_details(ftd):
            skip("no_arguments")
            continue
        if ftd.size() == 0:
            # a method that does not use this still receives it
            arg = ti.funcarg_t()
            arg.type = pointer_to(cls)
            ftd.push_back(arg)
        ftd[0].type = pointer_to(cls)
        ftd[0].name = "this"
        typed = ti.tinfo_t()
        if typed.create_func(ftd) and ti.apply_tinfo(ea, typed, ti.TINFO_DEFINITE):
            result["methods_typed"] += 1
            if hexrays_ready(m):
                m.ida_hexrays.mark_cfunc_dirty(ea, False)
        else:
            skip("rejected")
    # vftable structs (slots typed from their targets), then class structs
    for c in classes:
        cname = c["name"]
        vmembers = {}
        for offset, vrva, slots in c.get("vftables") or []:
            used = set()
            members = []
            for i, target in enumerate(slots):
                ea = base + target
                mname = c_ident(m.ida_name.get_short_name(ea) or m.ida_funcs.get_func_name(ea) or "") if m.ida_funcs.get_func(ea) else ""
                if not mname or mname in used or len(mname) > 120:
                    mname = "slot_%d" % i
                used.add(mname)
                ftif = ti.tinfo_t()
                have = m.ida_nalt.get_tinfo(ftif, ea) or ti.guess_tinfo(ftif, ea) == ti.GUESS_FUNC_OK
                members.append((mname, i * ptr_bits // 8, pointer_to(ftif) if have and ftif.is_func() else void_ptr()))
            vname = cname + "_vftable" if offset == 0 else "%s_vftable_%X" % (cname, offset)
            if members and define(vname, members):
                result["structs"] += 1
                vt = named(vname)
                vmembers[offset] = vt
                if vt is not None and not user_typed(vrva) and ti.apply_tinfo(base + vrva, vt, ti.TINFO_DEFINITE):
                    result["vftables_typed"] += 1
        members = []
        taken = set()
        for offset, vt in sorted(vmembers.items()):
            members.append(("__vftable" if offset == 0 else "__vftable_%X" % offset, offset, pointer_to(vt)))
            taken.add(offset)
        for bname, offset in c.get("bases") or []:
            bt = named(bname)
            if bt is None or offset in taken or offset < 0:
                continue
            # a base subobject at its offset; its own vftable pointer is part of it
            members = [x for x in members if x[1] != offset]
            members.append(("__base_" + bname, offset, bt))
            taken.add(offset)
        members.sort(key=lambda x: x[1])
        clean = []
        end = 0
        for x in members:
            if x[1] >= end:
                clean.append(x)
                end = x[1] + max(1, x[2].get_size())
        if clean and define(cname, clean):
            result["structs"] += 1


def op_virtual_targets(args):
    # What IDA knows about the call instructions at sites (rvas) in functions (rvas), within seconds:
    # [site, "xref", target]: IDA's code references from the call instruction to a function;
    # [site, "vftable", struct name, member offset]: Hex-Rays shows the call through a member of a vftable struct type
    #   (<class>_vftable or <class>_vftable_<offset>, as apply_types defines them);
    # [site, "direct", target]: Hex-Rays resolved the call to a function;
    # [site, "other", expression kind]: Hex-Rays shows the call through an untyped pointer.
    m = need_open()
    base = _state["base"]
    sites = set(base + r for r in args.get("sites") or [] if isinstance(r, int) and r >= 0)
    deadline = time.time() + float(args.get("seconds") or 60)
    rows = []
    for ea in sorted(sites):
        for x in m.idautils.XrefsFrom(ea, 0):
            if x.iscode and x.type in (m.ida_xref.fl_CN, m.ida_xref.fl_CF):
                g = m.ida_funcs.get_func(x.to)
                if g is not None and g.start_ea == x.to and rva_of(x.to) is not None:
                    rows.append([rva_of(ea), "xref", rva_of(x.to)])
    decompiled, failed, skipped = 0, [], 0
    if not hexrays_ready(m):
        return {"rows": rows, "decompiled": 0, "failed": [], "skipped": len(args.get("functions") or []), "decompiler": False}
    hr = m.ida_hexrays

    class Calls(hr.ctree_visitor_t):
        def __init__(self):
            hr.ctree_visitor_t.__init__(self, hr.CV_FAST)

        def visit_expr(self, e):
            if e.op != hr.cot_call or e.ea not in sites:
                return 0
            x = e.x
            while x.op == hr.cot_cast:
                x = x.x
            if x.op in (hr.cot_memptr, hr.cot_memref):
                t = x.x.type
                if x.op == hr.cot_memptr:
                    t = t.get_pointed_object()
                rows.append([rva_of(e.ea), "vftable", t.get_type_name() or t.dstr(), int(x.m)])
            elif x.op == hr.cot_obj and rva_of(x.obj_ea) is not None:
                rows.append([rva_of(e.ea), "direct", rva_of(x.obj_ea)])
            else:
                rows.append([rva_of(e.ea), "other", x.opname])
            return 0

    resume = None
    for rva in args.get("functions") or []:
        if time.time() > deadline or cancelled():
            skipped += 1
            resume = rva if resume is None else resume
            continue
        try:
            cf = hr.decompile(base + rva, hr.hexrays_failure_t(), hr.DECOMP_NO_WAIT)
        except hr.DecompilationFailure as e:
            failed.append([rva, (str(e).strip() or "failed")[:200]])
            continue
        if cf is None:
            failed.append([rva, "failed"])
            continue
        decompiled += 1
        Calls().apply_to(cf.body, None)
    result = {"rows": rows, "decompiled": decompiled, "failed": failed, "skipped": skipped, "decompiler": True}
    return partial(result, resume) if resume is not None else result


USER_NODE = "$ corvus user types"  # altval(rva) = 1: a type set by the user; blob 'D': the user's declarations


def user_node(create):
    import ida_netnode
    n = ida_netnode.netnode(USER_NODE, 0, create)
    return n if n != ida_netnode.BADNODE else None


def user_typed(rva):
    n = user_node(False)
    return n is not None and n.altval(rva) == 1


def parse_type(ti, text, function):
    # A C type ("int[4]", "struct Foo *") or a declaration ("int __fastcall f(Foo *this, int n)"); None when it does not parse.
    text = text.strip().rstrip(";").strip()
    if not function:
        t = ti.tinfo_t()
        if t.get_named_type(None, text):
            return t
    # an abstract type gets a declarator name where C wants it: "int[4]" -> "int x[4]", "int (*)(int)" -> "int (*x)(int)"
    named = text.replace("(*)", "(*__parsed_x)", 1) if "(*)" in text else \
        text[:text.index("[")] + " __parsed_x" + text[text.index("["):] if "[" in text else text + " __parsed_x"
    for candidate in (text + ";", named + ";"):
        for flags in (ti.PT_SIL, ti.PT_SIL | ti.PT_TYP):
            t = ti.tinfo_t()
            try:
                if ti.parse_decl(t, None, candidate, flags) is not None and not t.empty():
                    return t
            except BaseException:
                pass
    return None


def type_text(ti, tif, name):
    return ti.print_tinfo("", 0, 0, ti.PRTYPE_1LINE, tif, name or "", "") or str(tif)


def apply_user_type(m, ti, rva, decl):
    # [kind, rva, target, applied, error, resolved, stack, text]
    ea = _state["base"] + rva
    if not m.ida_bytes.is_loaded(ea):
        return ["type", rva, decl, False, "rva 0x%X is not in the image" % rva, None, None, None]
    node = user_node(True)
    f = m.ida_funcs.get_func(ea)
    function = f is not None and f.start_ea == ea
    if f is not None and not function and m.ida_bytes.is_code(m.ida_bytes.get_flags(ea)):
        return ["type", rva, decl, False, "rva 0x%X is inside the function at rva 0x%X: pass the function's start" % (rva, rva_of(f.start_ea) or 0),
                None, None, None]
    name = m.ida_name.get_name(ea) or ""
    if not decl:
        m.ida_nalt.del_tinfo(ea)
        node.altdel(rva)
        if function and hexrays_ready(m):
            m.ida_hexrays.mark_cfunc_dirty(ea, False)
        return ["type", rva, "", True, None, None, None, None]
    tif = parse_type(ti, decl, function)
    if tif is None:
        return ["type", rva, decl, False, "the type does not parse (types it names must be declared first)", None, None, None]
    if function and not tif.is_func():
        return ["type", rva, decl, False, "rva 0x%X starts a function: give a prototype such as 'int __fastcall f(int a)'" % rva, None, None, None]
    if not ti.apply_tinfo(ea, tif, ti.TINFO_DEFINITE):
        return ["type", rva, decl, False, "IDA did not apply the type at rva 0x%X" % rva, None, None, None]
    node.altset(rva, 1)
    if function and hexrays_ready(m):
        m.ida_hexrays.mark_cfunc_dirty(ea, False)
    got = ti.tinfo_t()
    m.ida_nalt.get_tinfo(got, ea)
    return ["type", rva, decl, True, None, None, None, type_text(ti, got, name if function else "")]


def decompile_function(m, ea):
    # (cfunc, None) or (None, reason)
    if not hexrays_ready(m):
        return None, "the Hex-Rays decompiler is not available"
    try:
        cf = m.ida_hexrays.decompile(ea, m.ida_hexrays.hexrays_failure_t(), m.ida_hexrays.DECOMP_NO_WAIT)
    except m.ida_hexrays.DecompilationFailure as e:
        return None, "decompilation failed: %s" % (str(e).strip() or "unknown reason")
    return (cf, None) if cf is not None else (None, "decompilation failed")


def find_lvar(lvars, local, stack, name):
    # by stack offset (stable over renames), else the name it had when first edited, else the name it got
    if stack is not None:
        for v in lvars:
            if v.is_stk_var() and v.get_stkoff() == stack:
                return v
    for wanted in (local, name):
        if wanted:
            for v in lvars:
                if v.name == wanted:
                    return v
    return None


def apply_local(m, ti, rva, local, stack, name, typ):
    # Hex-Rays user lvar settings through modify_user_lvar_info (lvar_saved_info_t keyed by the variable's locator)
    hr = m.ida_hexrays
    f = m.ida_funcs.get_func(_state["base"] + rva)
    if f is None:
        return ["local", rva, local, False, "no function contains rva 0x%X" % rva, None, stack, None]
    rva = rva_of(f.start_ea)
    cf, why = decompile_function(m, f.start_ea)
    if cf is None:
        return ["local", rva, local, False, why, None, stack, None]
    lvars = list(cf.get_lvars())
    lv = find_lvar(lvars, local, stack, name)
    if lv is None:
        known = ", ".join(v.name for v in lvars if v.name)
        return ["local", rva, local, False, "the function has no local %s (locals: %s)" % (local, known[:400]), None, stack, None]
    resolved = lv.name
    stk = lv.get_stkoff() if lv.is_stk_var() else None
    if name and name != lv.name and any(v.name == name for v in lvars):
        return ["local", rva, local, False, "the function already has a local named %s" % name, resolved, stk, None]
    tif = None
    if typ:
        tif = parse_type(ti, typ, False)
        if tif is None:
            return ["local", rva, local, False, "the type does not parse (types it names must be declared first)", resolved, stk, None]
    if name:
        s = hr.lvar_saved_info_t()
        s.ll = lv
        s.name = name
        if not hr.modify_user_lvar_info(f.start_ea, hr.MLI_NAME, s):
            return ["local", rva, local, False, "Hex-Rays did not rename %s" % resolved, resolved, stk, None]
    if tif is not None:
        s = hr.lvar_saved_info_t()
        s.ll = lv
        s.type = tif
        if not hr.modify_user_lvar_info(f.start_ea, hr.MLI_TYPE, s):
            return ["local", rva, local, False, "Hex-Rays did not retype %s" % resolved, resolved, stk, None]
    hr.mark_cfunc_dirty(f.start_ea, False)
    cf, why = decompile_function(m, f.start_ea)
    now = find_lvar(list(cf.get_lvars()), resolved, stk, name) if cf is not None else None
    if now is None:
        return ["local", rva, local, False, why or "the local is gone after the edit", resolved, stk, None]
    if tif is not None and str(now.type()) != str(tif) and not now.type().equals_to(tif):
        return ["local", rva, local, False, "Hex-Rays kept %s as %s (it did not accept %s)" % (now.name, now.type(), typ), resolved, stk, None]
    return ["local", rva, local, True, None, resolved, stk, "%s %s" % (now.type(), now.name)]


class FrameMember:
    # a copy: udm_t proxies die with their udt_type_data_t
    def __init__(self, index, u):
        import ida_typeinf as ti
        self.index, self.name, self.offset, self.size, self.type = index, u.name, u.offset // 8, u.size // 8, ti.tinfo_t(u.type)


def frame_members(m, f):
    # (frame tinfo, [FrameMember]) without gaps; frame offsets count from the frame's lowest address
    import ida_frame
    import ida_typeinf as ti
    frame = ti.tinfo_t()
    if not ida_frame.get_func_frame(frame, f):
        return None, []
    udt = ti.udt_type_data_t()
    frame.get_udt_details(udt)
    return frame, [FrameMember(i, u) for i, u in enumerate(udt) if not u.is_gap()]


def frame_kind(f, frame, i, offset):
    import ida_frame
    if ida_frame.is_special_frame_member(frame.get_udm_tid(i)):
        return "special"
    return "arg" if ida_frame.is_funcarg_off(f, offset) else "local"


def op_frame(args):
    # members: [offset, name, type, size, kind (local, arg, special)];
    # locals: [name, type, location, stack offset or null, argument, user name, user type]
    m = need_open()
    import ida_frame
    f = func_at(m, ea_of(args))
    frame, members = frame_members(m, f)
    out = {"start": rva_of(f.start_ea), "name": m.ida_funcs.get_func_name(f.start_ea) or "", "frame_size": f.frsize, "saved_regs": f.frregs,
           "retaddr": ida_frame.frame_off_retaddr(f) if frame is not None else 0, "members": [], "locals": [], "decompile_error": None}
    for u in members:
        out["members"].append([u.offset, u.name, str(u.type), u.size, frame_kind(f, frame, u.index, u.offset)])
    cf, why = decompile_function(m, f.start_ea)
    if cf is None:
        out["decompile_error"] = why
    else:
        hr = m.ida_hexrays
        for v in cf.get_lvars():
            if v.is_stk_var():
                where = "stack"
            elif v.is_reg_var():
                where = hr.get_mreg_name(v.get_reg1(), v.width) or "register"
            else:
                where = ""
            out["locals"].append([v.name, str(v.type()), where, v.get_stkoff() if v.is_stk_var() else None, bool(v.is_arg_var),
                                  bool(v.has_user_name), bool(v.has_user_type)])
    return out


def apply_stack(m, ti, rva, offset, name, typ):
    # IDA 9 frames: rename in place; a new type replaces the member (delete, then define_stkvar at the frame-base offset)
    import ida_frame
    f = m.ida_funcs.get_func(_state["base"] + rva)
    target = "+0x%X" % offset
    if f is None:
        return ["stack", rva, target, False, "no function contains rva 0x%X" % rva, None, offset, None]
    rva = rva_of(f.start_ea)
    frame, members = frame_members(m, f)
    if frame is None:
        return ["stack", rva, target, False, "the function has no stack frame", None, offset, None]
    u = next((x for x in members if x.offset == offset), None)
    if u is not None and frame_kind(f, frame, u.index, offset) == "special":
        return ["stack", rva, target, False, "+0x%X is %s (return address or saved registers)" % (offset, u.name), u.name, offset, None]
    if name and any(x.name == name and x.offset != offset for x in members):
        return ["stack", rva, target, False, "the frame already has a member named %s" % name, u.name if u else None, offset, None]
    old = u.name if u is not None else None
    remember_stack_original(rva, offset, u)
    retaddr = ida_frame.frame_off_retaddr(f)
    if typ:
        tif = parse_type(ti, typ, False)
        if tif is None:
            return ["stack", rva, target, False, "the type does not parse (types it names must be declared first)", old, offset, None]
    elif u is not None:
        tif = u.type
    else:
        return ["stack", rva, target, False, "no stack member at +0x%X: give a type to create one" % offset, None, offset, None]
    if u is not None and not typ:
        ok = frame.rename_udm(u.index, name) == ti.TERR_OK
    else:
        default = ("var_%X" % (retaddr - offset)) if offset < retaddr else ("arg_%X" % (offset - ida_frame.frame_off_args(f)))
        if u is not None:
            ida_frame.delete_frame_members(f, offset, offset + max(1, u.size))
        ok = ida_frame.define_stkvar(f, name or old or default, offset - retaddr, tif)
        if not ok and u is not None:
            ida_frame.define_stkvar(f, old, offset - retaddr, u.type)
    if not ok:
        return ["stack", rva, target, False, "IDA did not change the stack member at +0x%X" % offset, old, offset, None]
    if hexrays_ready(m):
        m.ida_hexrays.mark_cfunc_dirty(f.start_ea, False)
    _, now = frame_members(m, f)
    got = [x for x in now if x.offset == offset]
    return ["stack", rva, target, True, None, old, offset, "%s %s" % (got[0].type, got[0].name) if got else None]


def parse_decls_reporting(text):
    # (errors, error messages, declared type names). On Windows the kernel's parse_decls runs through ctypes with a printer
    # that collects IDA's messages; elsewhere idc.parse_decls, with names found in the text.
    import idc
    import ida_typeinf as ti
    if os.name == "nt":
        try:
            import ctypes
            kernel = ctypes.CDLL("ida")
            kernel.parse_decls.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_void_p, ctypes.c_int]
            kernel.parse_decls.restype = ctypes.c_int
            lines = []

            @ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_char_p, ctypes.c_char_p)
            def printer(fmt, arg):
                lines.append((fmt or b"").replace(b"%s", arg or b"").decode("utf-8", "replace"))
                return 0

            # the kernel takes HTI flags, not PT ones (PT_EMPTY is HTI_PAK2): HTI_EXT prints the "// struct tag" lines, packing stays the default
            errors = kernel.parse_decls(None, text.encode("utf-8"), printer, ti.HTI_EXT)
            names = []
            for line in lines:
                for prefix in ("// struct tag: '", "// typedef: "):
                    if line.startswith(prefix):
                        names.append(line[len(prefix):].split("'")[0].split(" =")[0].strip())
            return errors, [l.strip() for l in lines if not l.startswith("//")], names
        except (OSError, AttributeError):
            pass
    import re
    errors = idc.parse_decls(text, idc.PT_SILENT | idc.PT_REPLACE)
    names = re.findall(r"\b(?:struct|union|enum|class)\s+([A-Za-z_]\w*)\s*[{:]", text)
    names += re.findall(r"\btypedef\b[^;{]*?\b([A-Za-z_]\w*)\s*(?:\[[^;]*\])?\s*;", text)
    return errors, [], names


def type_kind(ti, t):
    if t.is_enum():
        return "enum"
    if t.is_typedef():
        return "typedef"
    if t.is_func():
        return "func"
    if t.is_udt():
        return "union" if t.is_union() else "struct"
    return "other"


def type_members(ti, t, limit):
    # the first limit members: struct / union [offset, name, type, size]; enum [value, name, null, 0]
    out = []
    if t.is_udt():
        udt = ti.udt_type_data_t()
        t.get_udt_details(udt)
        for u in udt:
            if len(out) >= limit:
                break
            if not u.is_gap():
                out.append([u.offset // 8, u.name, str(u.type), u.size // 8])
    elif t.is_enum():
        edt = ti.enum_type_data_t()
        t.get_enum_details(edt)
        for e in edt:
            if len(out) >= limit:
                break
            out.append([e.value, e.name, None, 0])
    return out


def op_types(args):
    # named local types: rows [name, kind, size, members, first members (members > 0)]. filter: case-insensitive substring;
    # pattern: a regex (flags: i, m, s); kind also ptr (resolves to a pointer) and udt (struct or union); sort: ordinal (default), name, size
    need_open()
    import ida_typeinf as ti
    import re
    til = ti.get_idati()
    wanted = (args.get("filter") or "").lower()
    pattern = None
    if args.get("pattern"):
        flags = 0
        for f in args.get("flags") or "":
            flags |= {"i": re.IGNORECASE, "m": re.MULTILINE, "s": re.DOTALL}.get(f, 0)
        try:
            pattern = re.compile(args["pattern"], flags)
        except re.error as e:
            raise WorkerError("invalid_argument", "invalid regex: %s" % e)
    kind = args.get("kind") or None
    sort = args.get("sort") or "ordinal"
    descending = bool(args.get("descending"))
    member_limit = max(0, min(4096, int(args.get("members") or 0)))
    offset, limit = max(0, int(args.get("offset") or 0)), max(1, int(args.get("limit") or 200))
    found = []
    for ordinal in range(1, ti.get_ordinal_limit(til)):
        t = ti.tinfo_t()
        if not t.get_numbered_type(til, ordinal):
            continue
        name = t.get_type_name()
        if not name or (wanted and wanted not in name.lower()) or (pattern is not None and not pattern.search(name)):
            continue
        k = type_kind(ti, t)
        if kind and not (t.is_ptr() if kind == "ptr" else t.is_udt() if kind == "udt" else k == kind):
            continue
        size = t.get_size()
        found.append((ordinal, name, k, size if size != ti.BADSIZE else -1, t))
    if sort == "name":
        found.sort(key=lambda r: r[1].lower(), reverse=descending)
    elif sort == "size":
        found.sort(key=lambda r: r[3], reverse=descending)
    elif descending:
        found.reverse()
    rows = []
    for ordinal, name, k, size, t in found[offset:offset + limit]:
        row = [name, k, size, t.get_udt_nmembers() if t.is_udt() else (t.get_enum_nmembers() if t.is_enum() else 0)]
        if member_limit:
            row.append(type_members(ti, t, member_limit))
        rows.append(row)
    return {"total": len(found), "rows": rows}


def op_type(args):
    # one named type: its C declaration, alignment and packing and, for a struct or union, members
    # [offset, name, type, size, bit offset in the storage unit or null, bit width or null, comment or null]
    need_open()
    import ida_typeinf as ti
    name = args.get("name") or ""
    t = ti.tinfo_t()
    if not name or not t.get_named_type(ti.get_idati(), name):
        raise WorkerError("not_found", "no type named %s" % name)
    members = []
    packed = False
    if t.is_udt():
        udt = ti.udt_type_data_t()
        t.get_udt_details(udt)
        packed = bool(udt.taudt_bits & ti.TAUDT_UNALIGNED)
        for u in udt:
            if u.is_gap():
                continue
            cmt = u.cmt or None
            bf = ti.bitfield_type_data_t()
            if u.is_bitfield() and u.type.get_bitfield_details(bf) and bf.nbytes:
                unit = (u.offset // 8) // bf.nbytes * bf.nbytes
                members.append([unit, u.name, str(u.type), bf.nbytes, u.offset - unit * 8, bf.width, cmt])
            else:
                members.append([u.offset // 8, u.name, str(u.type), u.size // 8, None, None, cmt])
    decl = ti.print_tinfo("", 0, 0, ti.PRTYPE_MULTI | ti.PRTYPE_TYPE | ti.PRTYPE_DEF | ti.PRTYPE_SEMI, t, name, "") or str(t)
    size = t.get_size()
    return {"name": name, "kind": type_kind(ti, t), "size": size if size != ti.BADSIZE else -1, "decl": decl, "members": members,
            "align": t.get_alignment(), "packed": packed}


def op_field_xrefs(args):
    # References to a struct member: IDA's references to the member (operands typed as struct offsets), then member accesses
    # in the pseudocode of functions whose prototype names the type (typed this / arguments) plus the functions given,
    # within seconds. rows: [rva, kind (operand, read, write, address), function rva or null]
    m = need_open()
    import ida_typeinf as ti
    t, tname = None, None
    for candidate in args.get("types") or []:
        c = ti.tinfo_t()
        if c.get_named_type(None, candidate) and c.is_udt():
            t, tname = c, candidate
            break
    if t is None:
        raise WorkerError("not_found", "no struct or union named %s" % " or ".join(args.get("types") or []))
    udt = ti.udt_type_data_t()
    t.get_udt_details(udt)
    members = [(i, u.name, u.offset // 8, u.size // 8, str(u.type)) for i, u in enumerate(udt) if not u.is_gap()]
    member, offset = args.get("member"), args.get("offset")
    hit = [x for x in members if (member is not None and x[1] == member) or (member is None and x[2] <= offset < x[2] + max(1, x[3]))]
    if not hit:
        raise WorkerError("not_found", "%s has no member %s (members: %s)" % (tname, member if member is not None else "at +0x%X" % offset,
                                                                         ", ".join("%s +0x%X" % (x[1], x[2]) for x in members[:60])))
    idx, mname, moff, msize, mtype = hit[0]
    names = {tname, t.get_type_name() or tname, t.get_final_type_name() or tname}
    rows, seen = [], set()

    def add(ea, kind):
        if (ea, kind) in seen or rva_of(ea) is None:
            return
        seen.add((ea, kind))
        f = m.ida_funcs.get_func(ea)
        rows.append([rva_of(ea), kind, rva_of(f.start_ea) if f else None])

    tid = t.get_udm_tid(idx)
    funcs = set()
    if tid != m.idautils.ida_idaapi.BADADDR:
        for x in m.idautils.XrefsTo(tid, 0):
            add(x.frm, "operand")
            f = m.ida_funcs.get_func(x.frm)
            if f is not None:
                funcs.add(f.start_ea)
    def names_struct(a):
        while a.is_ptr() or a.is_array():
            a = a.get_pointed_object() if a.is_ptr() else a.get_array_element()
        return a.get_type_name() in names or a.get_final_type_name() in names

    for ea in m.idautils.Functions():
        ftif, ftd = ti.tinfo_t(), ti.func_type_data_t()
        if m.ida_nalt.get_tinfo(ftif, ea) and ftif.get_func_details(ftd) and (names_struct(ftd.rettype) or any(names_struct(a.type) for a in ftd)):
            funcs.add(ea)
    funcs.update(_state["base"] + r for r in args.get("functions") or [])
    if args.get("all_from") is not None:
        # every function from that rva on (scope all, resumed where the last call stopped)
        first = _state["base"] + int(args["all_from"])
        funcs.update(ea for ea in m.idautils.Functions() if ea >= first)
    result = {"type": tname, "member": mname, "offset": moff, "size": msize, "member_type": mtype, "rows": rows, "candidates": len(funcs),
              "scanned": 0, "skipped": 0, "failed": 0, "decompiler": hexrays_ready(m)}
    if not result["decompiler"]:
        result["skipped"] = len(funcs)
        return result
    hr = m.ida_hexrays

    class Members(hr.ctree_visitor_t):
        def __init__(self):
            hr.ctree_visitor_t.__init__(self, hr.CV_PARENTS)

        def visit_expr(self, e):
            if e.op in (hr.cot_memptr, hr.cot_memref) and e.m == moff:
                obj = e.x.type.get_pointed_object() if e.op == hr.cot_memptr else e.x.type
                if obj.get_type_name() in names or obj.get_final_type_name() in names:
                    p = self.parent_expr()
                    kind = "read"
                    if p is not None and p.op == hr.cot_ref:
                        kind = "address"
                    elif p is not None and hr.cot_asg <= p.op <= hr.cot_asgumod and p.x == e:
                        kind = "write"
                    add(self.address(e), kind)
            return 0

        def address(self, e):
            # the nearest item up the tree that has an address
            bad = m.idautils.ida_idaapi.BADADDR
            if e.ea != bad:
                return e.ea
            for i in range(len(self.parents) - 1, -1, -1):
                if self.parents[i].ea != bad:
                    return self.parents[i].ea
            return bad

    deadline = time.time() + float(args.get("seconds") or 30)
    resume = None
    for ea in sorted(funcs):
        if time.time() > deadline or cancelled():
            result["skipped"] += 1
            resume = ea if resume is None else resume
            continue
        cf, why = decompile_function(m, ea)
        if cf is None:
            result["failed"] += 1
            continue
        result["scanned"] += 1
        Members().apply_to(cf.body, None)
    rows.sort(key=lambda r: (r[0], r[1]))
    return partial(result, rva_of(resume)) if resume is not None else result


def reapply_user_decls():
    # the user's declarations (blob 'D' of USER_NODE) win over recovered types of the same name
    n = user_node(False)
    blob = n.getblob(0, "D") if n is not None else None
    if blob:
        import idc
        idc.parse_decls(blob.decode("utf-8", "replace"), idc.PT_SILENT | idc.PT_REPLACE)
    reapply_user_type_edits()
    reapply_user_enums()
    reapply_user_fields()


def op_apply_user_types(args):
    # decls: [C declarations]; types: [[rva, C type or prototype; "" clears]]; stack: [[function, offset, name, type]];
    # locals: [[function, local, stack offset or null, name, type]]. Items report [kind, rva, target, applied, error, resolved, stack, text].
    m = need_open()
    import ida_typeinf as ti
    start = time.time()
    result = {"decl_errors": 0, "decl_messages": [], "declared": [], "items": []}
    decls = [d.strip() for d in args.get("decls") or [] if d and d.strip()]
    if decls:
        node = user_node(True)
        kept = node.getblob(0, "D")
        kept = kept.decode("utf-8", "replace") if kept else ""
        for d in decls:
            errors, messages, names = parse_decls_reporting(d)
            result["decl_errors"] += errors
            result["decl_messages"] += messages[:50 - len(result["decl_messages"])]
            for n in names:
                if n not in result["declared"]:
                    result["declared"].append(n)
            if errors == 0 and d not in kept:
                kept += d + "\n"
        node.setblob(kept.encode("utf-8"), 0, "D")
    result["items"] += apply_edits_before(m, ti, args)
    for rva, decl in args.get("types") or []:
        result["items"].append(apply_user_type(m, ti, rva, decl or ""))
    for rva, offset, name, typ in args.get("stack") or []:
        result["items"].append(apply_stack(m, ti, rva, offset, name, typ))
    for rva, local, stack, name, typ in args.get("locals") or []:
        result["items"].append(apply_local(m, ti, rva, local, stack, name, typ))
    result["items"] += apply_edits_after(m, ti, args)
    changed(m)
    key = args.get("stamp_key")
    if key:
        stamp_node(True).hashset_buf(key, args.get("stamp") or "")
    if args.get("save"):
        if not m.ida_loader.save_database(m.ida_loader.get_path(m.ida_loader.PATH_TYPE_IDB), 0):
            raise WorkerError("io_error", "save_database failed")
    result["seconds"] = round(time.time() - start, 3)
    return result


STAMP_NODE = "$ corvus stamps"

# Migration only: the nodes' names before the rename; a database saved then has them renamed when opened.
LEGACY_NODES = (("$ netdecompilermcp user types", USER_NODE), ("$ netdecompilermcp stamps", STAMP_NODE))


def rename_legacy_nodes():
    import ida_netnode
    for old, new in LEGACY_NODES:
        n = ida_netnode.netnode(old, 0, False)
        if n != ida_netnode.BADNODE and ida_netnode.netnode(new, 0, False) == ida_netnode.BADNODE:
            n.rename(new)


def stamp_node(create):
    import ida_netnode
    n = ida_netnode.netnode(STAMP_NODE, 0, create)
    return n if n != ida_netnode.BADNODE else None


def op_apply_names(args):
    # items: [[rva, name or null, comment or null, make_function, comment kind (optional: eol, pre, plate)]]; empty name/comment removes it.
    m = need_open()
    start = time.time()
    badaddr = m.idautils.ida_idaapi.BADADDR
    flags = m.ida_name.SN_NOWARN | m.ida_name.SN_NOCHECK | m.ida_name.SN_FORCE
    named = name_failures = commented = created = 0
    failures = []
    touched = []
    for item in args.get("items") or []:
        rva, name, comment, make_function = item[0], item[1], item[2], item[3]
        kind = item[4] if len(item) > 4 else None
        ea = _state["base"] + rva
        touched.append(ea)
        f = m.ida_funcs.get_func(ea)
        if make_function and f is None:
            if m.ida_funcs.add_func(ea, badaddr):
                created += 1
                f = m.ida_funcs.get_func(ea)
        if name is not None:
            if m.ida_name.set_name(ea, name, flags if name else m.ida_name.SN_NOWARN):
                named += 1
            else:
                name_failures += 1
                if len(failures) < 20:
                    failures.append("rva 0x%X: %s" % (rva, name))
        if comment is not None:
            if kind is not None:
                ok = put_comment_kind(m, f, ea, comment, kind)
            elif f is not None and f.start_ea == ea:
                ok = m.ida_funcs.set_func_cmt(f, comment, True)
            else:
                ok = m.ida_bytes.set_cmt(ea, comment, True)
            if ok:
                commented += 1
    changed(m, None if created else touched)
    key = args.get("stamp_key")
    if key:
        n = stamp_node(True)
        n.hashset_buf(key, args.get("stamp") or "")
    if args.get("save"):
        if not m.ida_loader.save_database(m.ida_loader.get_path(m.ida_loader.PATH_TYPE_IDB), 0):
            raise WorkerError("io_error", "save_database failed")
    return {"named": named, "name_failures": name_failures, "commented": commented, "functions_created": created,
            "seconds": round(time.time() - start, 3), "failures": failures}


PDB_NODE = "$ pdb"
PDB_CC_USER_WITH_DATA = 3  # pdb plugin: load the file named in the node ("File > Load file > PDB file")


def op_load_pdb(args):
    # INativeDecompilerProvider.LoadPdbAsync, through IDA's PDB plugin.
    m = need_open()
    import ida_netnode
    import ida_typeinf as ti
    start = time.time()
    path = args.get("path")
    if not isinstance(path, str) or not os.path.isfile(path):
        raise WorkerError("not_found", "no PDB file at %r" % path)
    til = ti.get_idati()
    before = ti.get_ordinal_limit(til)
    node = ida_netnode.netnode(PDB_NODE, 0, True)
    analysis = node.altval(0) == 1
    result = {"loaded": False, "from_analysis": False, "plugin": True, "types_before": before}
    if args.get("trust_analysis") and analysis:
        result["loaded"] = result["from_analysis"] = True
    else:
        node.altset(0, _state["base"])
        node.supset(0, path)
        ran = m.ida_loader.load_and_run_plugin("pdb", PDB_CC_USER_WITH_DATA)
        result["plugin"] = bool(ran)
        result["loaded"] = bool(ran) and node.altval(0) == 1
        m.ida_auto.auto_wait()
    result["types_after"] = ti.get_ordinal_limit(til)
    if result["loaded"]:
        stamps = stamp_node(True)
        stamps.hashdel("names")
        stamps.hashdel("user_types")  # the PDB's prototypes may replace the user's: push them again
        key = args.get("stamp_key")
        if key:
            stamps.hashset_buf(key, args.get("stamp") or "")
        changed(m)
        if not m.ida_loader.save_database(m.ida_loader.get_path(m.ida_loader.PATH_TYPE_IDB), 0):
            raise WorkerError("io_error", "save_database failed")
    result["seconds"] = round(time.time() - start, 3)
    return result


_py_globals = None
PY_MODULES = ("idaapi", "idc", "idautils", "ida_auto", "ida_bytes", "ida_entry", "ida_frame", "ida_funcs", "ida_gdl", "ida_hexrays", "ida_ida",
              "ida_lines", "ida_loader", "ida_nalt", "ida_name", "ida_netnode", "ida_segment", "ida_typeinf", "ida_ua", "ida_xref")


def clip(text, limit=200000):
    return text if text is None or len(text) <= limit else text[:limit] + "\n[clipped at %d characters]" % limit


def op_python(args):
    # Runs code with IDAPython modules imported and `base` (the image base) set; globals persist between calls (reset clears
    # them). The value of a final expression is returned, with stdout and stderr; an exception comes back as its traceback.
    global _py_globals
    m = need_open()
    import ast
    import io
    if _py_globals is None or args.get("reset"):
        g = {"__builtins__": __builtins__, "__name__": "__user_script__"}
        for name in PY_MODULES:
            try:
                g[name] = __import__(name)
            except BaseException:
                pass
        _py_globals = g
    g = _py_globals
    g["base"] = _state["base"]
    out, err = io.StringIO(), io.StringIO()
    saved = sys.stdout, sys.stderr
    value = error = None
    def stop_hook(frame, event, arg):
        # Never raise inside the worker's own callbacks (the Hex-Rays stop hook): a C caller swallows the error and
        # Python drops the profiler with it, leaving the script unchecked until the cancel grace kills the worker.
        if frame.f_code.co_filename != __file__ and cancelled():
            raise stopped_error()

    try:
        sys.stdout, sys.stderr = out, err
        sys.setprofile(stop_hook)  # a script that calls functions stops on cancel or at the deadline
        tree = ast.parse(args.get("code") or "", "<ida_python>", "exec")
        last = tree.body.pop() if tree.body and isinstance(tree.body[-1], ast.Expr) else None
        exec(compile(tree, "<ida_python>", "exec"), g)
        if last is not None:
            v = eval(compile(ast.Expression(last.value), "<ida_python>", "eval"), g)
            value = None if v is None else repr(v)
    except BaseException:
        error = traceback.format_exc(limit=8)
    finally:
        sys.setprofile(None)
        sys.stdout, sys.stderr = saved
    changed(m)
    check_stop()
    return {"result": clip(value), "stdout": clip(out.getvalue()), "stderr": clip(err.getvalue()), "error": clip(error)}


def op_get_stamp(args):
    need_open()
    n = stamp_node(False)
    value = n.hashstr_buf(args["key"]) if n is not None else None
    if isinstance(value, bytes):
        value = value.decode("utf-8", "replace")
    return {"stamp": value or None}


def op_save(args):
    m = need_open()
    if not m.ida_loader.save_database(m.ida_loader.get_path(m.ida_loader.PATH_TYPE_IDB), 0):
        raise WorkerError("io_error", "save_database failed")
    return {}


def op_close(args):
    if _state["open"]:
        ida().idapro.close_database(bool(args.get("save", True)))
        _state["open"] = False
    return {}


INSN_OPERAND_TYPES = {1: "register", 2: "memory", 3: "memory", 4: "memory", 5: "immediate", 6: "far_branch", 7: "near_branch"}


def insn_operand(m, ida_idp, insn, ea, i, op, feature, width):
    o = {"index": i, "kind": INSN_OPERAND_TYPES.get(op.type, "other"),
         "text": m.ida_lines.tag_remove(m.ida_ua.print_operand(ea, i) or ""), "size": m.ida_ua.get_dtype_size(op.dtype)}
    use = feature & getattr(ida_idp, "CF_USE%d" % (i + 1), 0)
    chg = feature & getattr(ida_idp, "CF_CHG%d" % (i + 1), 0)
    o["access"] = "read_write" if use and chg else "write" if chg else "read" if use else "none"
    if op.type == m.ida_ua.o_reg:
        o["register"] = ida_idp.get_reg_name(op.reg, o["size"] or width)
    elif op.type in (m.ida_ua.o_phrase, m.ida_ua.o_displ):
        if m.ida_ida.inf_get_procname() == "metapc" and op.specflag1:
            # x86 SIB byte in specflag2; REX.X / REX.B in insnpref on x64
            rex = insn.insnpref if m.ida_ida.inf_is_64bit() else 0
            sib = op.specflag2
            base, index = (sib & 7) | (8 if rex & 1 else 0), ((sib >> 3) & 7) | (8 if rex & 2 else 0)
            if index != 4:
                o["index_register"] = ida_idp.get_reg_name(index, width)
                o["scale"] = 1 << ((sib >> 6) & 3)
            if not ((base & 7) == 5 and op.type == m.ida_ua.o_phrase):
                o["base"] = ida_idp.get_reg_name(base, width)
        else:
            o["base"] = ida_idp.get_reg_name(op.reg, width)
        if op.type == m.ida_ua.o_displ:
            d = op.addr
            o["displacement"] = d - (1 << 64) if d >= 1 << 63 else d
    elif op.type == m.ida_ua.o_mem:
        o["target"] = rva_of(op.addr)
    elif op.type == m.ida_ua.o_imm:
        o["value"] = op.value
    elif op.type in (m.ida_ua.o_near, m.ida_ua.o_far):
        o["target"] = rva_of(op.addr)
    return o


def insn_decode(m, ea):
    import ida_idp
    insn = m.ida_ua.insn_t()
    size = m.ida_ua.decode_insn(insn, ea)
    if size <= 0:
        return None
    feature = insn.get_canon_feature()
    width = 8 if m.ida_ida.inf_is_64bit() else 4
    ops = []
    for i in range(8):
        op = insn.ops[i]
        if op.type == m.ida_ua.o_void:
            break
        ops.append(insn_operand(m, ida_idp, insn, ea, i, op, feature, width))
    target = next((o.get("target") for o in ops if o["kind"] == "near_branch"), None)
    if ida_idp.is_ret_insn(insn):
        flow = "return"
    elif feature & ida_idp.CF_CALL:
        flow = "call" if target is not None else "indirect_call"
    elif target is not None:
        flow = "jump" if feature & ida_idp.CF_STOP else "conditional_jump"
    elif feature & ida_idp.CF_JUMP:
        flow = "indirect_jump"
    elif feature & ida_idp.CF_STOP:
        flow = "trap"
    else:
        flow = "next"
    fallthrough = None if flow in ("return", "jump", "indirect_jump", "trap") else rva_of(ea + size)
    if flow in ("call", "indirect_call") and m.ida_bytes.is_code(m.ida_bytes.get_flags(ea)) \
            and not any(x.type == m.ida_xref.fl_F for x in m.idautils.XrefsFrom(ea, 0)):
        fallthrough = None  # a call IDA knows does not return
    raw = m.ida_bytes.get_bytes(ea, size) or b""
    refs = [r for r in (xref_row(m, x) for x in m.idautils.XrefsFrom(ea, 0)) if r is not None]
    return {"size": size, "bytes": raw.hex(), "text": m.ida_lines.generate_disasm_line(ea, m.ida_lines.GENDSM_REMOVE_TAGS) or "",
            "mnemonic": insn.get_canon_mnem() or "", "operands": ops, "flow": flow, "target": target, "fallthrough": fallthrough,
            "references": [[r[1], r[2]] for r in refs]}


def insn_data(m, head):
    f = m.ida_bytes.get_flags(head)
    end = m.ida_bytes.get_item_end(head)
    name = m.ida_name.get_name(head) or ""
    if m.ida_bytes.is_strlit(f):
        raw = m.ida_bytes.get_strlit_contents(head, -1, m.ida_nalt.get_str_type(head)) or b""
        return "string", end, '"%s"' % raw.decode("utf-8", "replace")[:120]
    if m.ida_bytes.is_off0(f):
        width = end - head
        value = m.ida_bytes.get_qword(head) if width == 8 else m.ida_bytes.get_dword(head)
        return "pointer", end, "pointer to %s" % (m.ida_name.get_name(value) or "0x%X" % value)
    if m.ida_bytes.is_struct(f):
        return "struct", end, name
    for test, kind in ((m.ida_bytes.is_byte, "byte"), (m.ida_bytes.is_word, "word"), (m.ida_bytes.is_dword, "dword"), (m.ida_bytes.is_qword, "qword")):
        if test(f):
            return kind, end, name
    return "data", end, name


def op_insn(args):
    # what is at rva and the items after it: status, item head and extent, decoded operands, flow and references
    m = need_open()
    ea = ea_of(args)
    count = max(1, min(int(args.get("count") or 1), 64))
    items = []
    n = 0
    while n < count:
        rva = rva_of(ea)
        if rva is None or not m.ida_bytes.is_loaded(ea):
            items.append({"rva": rva_of(ea) or 0, "status": "unmapped"})
            break
        head = m.ida_bytes.get_item_head(ea)
        hf = m.ida_bytes.get_flags(head)
        func = m.ida_funcs.get_func(ea)
        item = {"rva": rva, "head": rva_of(head), "function": rva_of(func.start_ea) if func else None}
        items.append(item)
        if not (m.ida_bytes.is_code(hf) and head != ea):
            n += 1
        if m.ida_bytes.is_code(hf):
            if head != ea:
                item["status"] = "mid_instruction"
                item["end"] = rva_of(m.ida_bytes.get_item_end(head))
                if count == 1:
                    break
                ea = head  # a walk starts at the covering instruction
                continue
            decoded = insn_decode(m, ea)
            if decoded is None:
                item["status"] = "invalid"
                break
            item["status"] = "decoded" if func else "not_in_function"
            item["insn"] = decoded
            ea += decoded["size"]
        elif m.ida_bytes.is_data(hf):
            kind, end, text = insn_data(m, head)
            item.update({"status": "data", "kind": kind, "end": rva_of(end), "text": text})
            ea = end
        else:
            decoded = insn_decode(m, ea)
            if decoded is None:
                item["status"] = "invalid"
                break
            item["status"] = "not_in_function"
            item["note"] = "bytes IDA has not defined as code or data"
            item["insn"] = decoded
            ea += decoded["size"]
    return {"items": items}


def op_sleep(args):
    # Test hook: holds the worker busy; stops early on cancel or at the deadline unless ignore_cancel.
    seconds = float(args.get("seconds") or 0)
    if args.get("ignore_cancel"):
        time.sleep(seconds)
        return {"slept": seconds}
    start = time.time()
    while time.time() - start < seconds:
        if cancelled():
            return partial({"slept": round(time.time() - start, 3)}, None)
        time.sleep(0.05)
    return {"slept": seconds}


# ---- user edits beyond types (apply_user_types): enum members, analysis, stack deletes, operand display ----

DATA_SIZES = {"byte": 1, "word": 2, "dword": 4, "qword": 8, "float": 4, "double": 8}


def apply_edits_before(m, ti, args):
    # type_edits (when given, the whole kept list): [[name, new name or null]]; enums: [[enum, member, value or null]]; fields;
    # analysis: [[rva, kind, end or null, type or null]] in the order made
    items = apply_type_edits(m, ti, args["type_edits"]) if args.get("type_edits") is not None else []
    items += [apply_enum_member(m, ti, e[0], e[1], e[2]) for e in args.get("enums") or []]
    items += apply_fields(m, ti, args.get("fields") or [])
    items += apply_clears(m, ti, args)
    return items + [apply_analysis(m, ti, a[0], a[1], a[2], a[3]) for a in args.get("analysis") or []]


def apply_edits_after(m, ti, args):
    # stack_deletes: [[function, offset]]; operands: [[rva, operand, display, detail or null]]
    items = [apply_stack_delete(m, rva, offset) for rva, offset in args.get("stack_deletes") or []]
    return items + [apply_operand(m, ti, o[0], o[1], o[2], o[3]) for o in args.get("operands") or []]


def user_enums():
    # blob 'E' of USER_NODE: {"enum::member": value or null}, applied again after declarations replace enums
    n = user_node(False)
    blob = n.getblob(0, "E") if n is not None else None
    return json.loads(blob.decode("utf-8")) if blob else {}


def reapply_user_enums():
    edits = user_enums()
    if edits:
        m = ida()
        import ida_typeinf as ti
        for key, value in edits.items():
            enum, _, member = key.partition("::")
            edit_enum_member(m, ti, enum, member, value)


def apply_enum_member(m, ti, enum, member, value):
    item = edit_enum_member(m, ti, enum, member, value)
    if item[3]:
        edits = user_enums()
        edits[item[2]] = value
        user_node(True).setblob(json.dumps(edits).encode("utf-8"), 0, "E")
    return item


def edit_enum_member(m, ti, enum, member, value):
    # adds, changes or (value None) removes a member; a missing enum is created
    target = "%s::%s" % (enum, member)

    def item(applied, error, text=None):
        return ["enum", 0, target, applied, error, None, None, text]

    t = ti.tinfo_t()
    if not t.get_named_type(None, enum):
        if value is None:
            return item(True, None, "no enum %s" % enum)
        t = ti.tinfo_t()
        if not t.create_enum(ti.enum_type_data_t()) or t.set_named_type(None, enum) != ti.TERR_OK:
            return item(False, "IDA did not create the enum %s" % enum)
        t = ti.tinfo_t()
        t.get_named_type(None, enum)
    elif not t.is_enum():
        return item(False, "%s is a %s, not an enum" % (enum, type_kind(ti, t)))
    idx, _ = t.get_edm(member)
    try:
        if value is None:
            if idx >= 0 and t.del_edm(idx) != ti.TERR_OK:
                return item(False, "IDA did not remove %s" % target)
            return item(True, None, "removed")
        code = t.edit_edm(idx, value, ti.DEFMASK64, 0) if idx >= 0 else t.add_edm(member, value)
        if code != ti.TERR_OK:
            return item(False, "IDA refused %s = %d: %s" % (target, value, ti.tinfo_errstr(code)))
    except ValueError as e:
        return item(False, "IDA refused %s = %d: %s" % (target, value, e))
    return item(True, None, "%s = 0x%X" % (target, value & 0xFFFFFFFFFFFFFFFF))


def apply_stack_delete(m, rva, offset):
    import ida_frame
    target = "+0x%X" % offset
    f = m.ida_funcs.get_func(_state["base"] + rva)
    if f is None:
        return ["stack_delete", rva, target, False, "no function contains rva 0x%X" % rva, None, offset, None]
    rva = rva_of(f.start_ea)
    frame, members = frame_members(m, f)
    u = next((x for x in members if x.offset == offset), None)
    if u is None:
        return ["stack_delete", rva, target, True, None, None, offset, "no member at %s" % target]
    if frame_kind(f, frame, u.index, offset) == "special":
        return ["stack_delete", rva, target, False, "%s is %s (return address or saved registers)" % (target, u.name), u.name, offset, None]
    if not ida_frame.delete_frame_members(f, offset, offset + max(1, u.size)):
        return ["stack_delete", rva, target, False, "IDA did not delete the stack member at %s" % target, u.name, offset, None]
    if hexrays_ready(m):
        m.ida_hexrays.mark_cfunc_dirty(f.start_ea, False)
    return ["stack_delete", rva, target, True, None, u.name, offset, "deleted"]


def apply_operand(m, ti, rva, n, display, detail):
    # set_op_type: numeric formats, offset, stack variable, enum member, struct offset ("Name" or "Name+0x10"), default
    import idc
    b = m.ida_bytes
    ea = _state["base"] + rva
    target = "operand %d %s%s" % (n, display, " " + detail if detail else "")

    def item(applied, error):
        text = m.ida_lines.generate_disasm_line(ea, m.ida_lines.GENDSM_REMOVE_TAGS) if applied else None
        return ["operand", rva, target, applied, error, None, n, text]

    if not b.is_loaded(ea) or not b.is_code(b.get_flags(ea)) or b.get_item_head(ea) != ea:
        return item(False, "no instruction starts at rva 0x%X" % rva)
    insn = m.ida_ua.insn_t()
    if m.ida_ua.decode_insn(insn, ea) <= 0 or not 0 <= n < 8 or insn.ops[n].type == m.ida_ua.o_void:
        return item(False, "the instruction at rva 0x%X has no operand %d" % (rva, n))
    formats = {"hex": b.op_hex, "dec": b.op_dec, "oct": b.op_oct, "bin": b.op_bin, "char": b.op_chr, "stack": b.op_stkvar,
               "default": b.clr_op_type}
    if display in formats:
        ok = formats[display](ea, n)
    elif display == "offset":
        ok = idc.op_plain_offset(ea, n, 0)
    elif display == "enum":
        tid = idc.get_enum(detail or "")
        if tid == m.idautils.ida_idaapi.BADADDR:
            return item(False, "no enum named %s (declare_native_types declares one)" % detail)
        ok = b.op_enum(ea, n, tid, 0)
    elif display == "struct":
        name, _, delta = (detail or "").partition("+")
        t = ti.tinfo_t()
        if not t.get_named_type(None, name.strip()) or not t.is_udt():
            return item(False, "no struct named %s" % name.strip())
        try:
            off = int(delta.strip(), 0) if delta.strip() else 0
        except ValueError:
            return item(False, "the struct delta %r is not a number" % delta)
        ok = idc.op_stroff(ea, n, t.get_tid(), off)
    else:
        return item(False, "unknown operand display %r" % display)
    if not ok:
        return item(False, "IDA did not show operand %d at rva 0x%X as %s" % (n, rva, display))
    f = m.ida_funcs.get_func(ea)
    if f is not None and hexrays_ready(m):
        m.ida_hexrays.mark_cfunc_dirty(f.start_ea, False)
    return item(True, None)


def data_spec(text):
    # ("dword", 8) for "dword[8]"; (text, None) without a count
    t = text.strip()
    if t.endswith("]") and "[" in t:
        try:
            n = int(t[t.rindex("[") + 1:-1].strip(), 0)
            if n > 0:
                return t[:t.rindex("[")].strip(), n
        except ValueError:
            pass
    return t, None


def make_data(m, ti, ea, end, typ):
    # (applied, error)
    b = m.ida_bytes
    badaddr = m.idautils.ida_idaapi.BADADDR
    base, count = data_spec(typ)
    low = base.lower()
    if low in ("string", "string16"):
        width = 1 if low == "string" else 2
        length = count * width if count else (end - ea if end else 0)
        b.del_items(ea, b.DELIT_SIMPLE, max(length, 1))
        strtype = m.ida_nalt.STRTYPE_C if width == 1 else m.ida_nalt.STRTYPE_C_16
        return (True, None) if b.create_strlit(ea, length, strtype) else (False, "IDA did not make a string at rva 0x%X" % rva_of(ea))
    if low in DATA_SIZES:
        total = DATA_SIZES[low] * (count or 1)
        flag = {"byte": b.byte_flag, "word": b.word_flag, "dword": b.dword_flag, "qword": b.qword_flag, "float": b.float_flag,
                "double": b.double_flag}[low]()
        b.del_items(ea, b.DELIT_SIMPLE, total)
        return (True, None) if b.create_data(ea, flag, total, badaddr) else (False, "IDA did not make %s at rva 0x%X" % (typ, rva_of(ea)))
    tif = parse_type(ti, typ, False)
    if tif is None:
        return False, "the type does not parse (types it names must be declared first)"
    size = tif.get_size()
    if size in (0, ti.BADSIZE):
        return False, "%s has no size" % typ
    b.del_items(ea, b.DELIT_SIMPLE, size)
    if not ti.apply_tinfo(ea, tif, ti.TINFO_DEFINITE):
        return False, "IDA did not apply %s at rva 0x%X" % (typ, rva_of(ea))
    if b.get_item_size(ea) != size and tif.is_udt():
        b.create_struct(ea, size, tif.get_tid())
    user_node(True).altset(rva_of(ea), 1)
    return True, None


def item_text(m, ea):
    # what the database holds at ea now: "dword[4], 16 bytes", "code, 5 bytes"
    import idc
    b = m.ida_bytes
    f = b.get_flags(ea)
    size = b.get_item_size(ea)
    if b.is_code(f):
        return "code, %d bytes" % size
    if not b.is_data(f):
        return "unknown bytes"
    t = idc.get_type(ea)
    if not t:
        for test, name, width in ((b.is_strlit, "string", 0), (b.is_float, "float", 4), (b.is_double, "double", 8), (b.is_byte, "byte", 1),
                                  (b.is_word, "word", 2), (b.is_dword, "dword", 4), (b.is_qword, "qword", 8)):
            if test(f):
                t = name + ("[%d]" % (size // width) if width and size > width else "")
                break
    return "%s%s, %d bytes" % (t or "data", " (offset)" if b.is_off0(f) else "", size)


def apply_analysis(m, ti, rva, kind, end, typ):
    # [kind, rva, target, applied, error, resolved, stack, text]
    b = m.ida_bytes
    ea = _state["base"] + rva
    end_ea = _state["base"] + end if end is not None else None
    target = kind + (" " + typ if typ else "") + (" to 0x%X" % end if end is not None else "")

    def item(applied, error, text=None):
        return ["analysis", rva, target, applied, error, None, None, text]

    if not b.is_loaded(ea) or (end_ea is not None and (end_ea <= ea or not b.is_loaded(end_ea - 1))):
        return item(False, "rva 0x%X%s is not in the image" % (rva, "" if end is None else "-0x%X" % end))
    if kind == "undefine":
        # at a function start without an end: the whole function
        f = m.ida_funcs.get_func(ea)
        start = ea if end_ea is not None else b.get_item_head(ea)
        if f is not None and f.start_ea == ea:
            if end_ea is None:
                end_ea = f.end_ea
            m.ida_funcs.del_func(ea)
        n = end_ea - start if end_ea is not None else max(1, b.get_item_size(start))
        b.del_items(start, b.DELIT_EXPAND, n)
        return item(True, None, "%d byte(s) undefined" % n)
    if kind == "code":
        if b.is_code(b.get_flags(ea)) and b.get_item_head(ea) == ea and end_ea is None:
            return item(True, None, "already code")
        stop = end_ea if end_ea is not None else ea + 1
        b.del_items(ea, b.DELIT_SIMPLE, stop - ea)
        count, at = 0, ea
        while at < stop:
            n = m.ida_ua.create_insn(at)
            if n <= 0:
                break
            count, at = count + 1, at + n
        if count == 0:
            return item(False, "the bytes at rva 0x%X do not decode as an instruction" % rva)
        if end_ea is None:
            m.ida_auto.auto_make_code(ea)
            m.ida_auto.auto_wait()
        return item(True, None, "%d instruction(s) to rva 0x%X" % (count, rva_of(at)) if end_ea is not None else "code from rva 0x%X" % rva)
    if kind == "function":
        f = m.ida_funcs.get_func(ea)
        if f is not None and f.start_ea == ea:
            if end_ea is not None and f.end_ea != end_ea and not m.ida_funcs.set_func_end(ea, end_ea):
                return item(False, "IDA did not move the end of the function at rva 0x%X" % rva)
        elif f is not None:
            return item(False, "rva 0x%X is inside the function at rva 0x%X" % (rva, rva_of(f.start_ea) or 0))
        else:
            if end_ea is None and not b.is_code(b.get_flags(ea)):
                m.ida_auto.auto_make_code(ea)  # decode the flow first so the function gets its extent
                m.ida_auto.auto_wait()
            if not m.ida_funcs.add_func(ea, end_ea if end_ea is not None else m.idautils.ida_idaapi.BADADDR):
                return item(False, "IDA did not make a function at rva 0x%X" % rva)
        m.ida_auto.auto_wait()
        f = m.ida_funcs.get_func(ea)
        if hexrays_ready(m):
            m.ida_hexrays.mark_cfunc_dirty(ea, False)
        return item(True, None, "function %s, rva 0x%X-0x%X" % (m.ida_funcs.get_func_name(ea) or "", rva, rva_of(f.end_ea) or 0))
    if kind == "data":
        if not typ:
            return item(False, "data needs a type")
        ok, error = make_data(m, ti, ea, end_ea, typ)
        return item(True, None, item_text(m, ea)) if ok else item(False, error)
    return item(False, "unknown analysis edit %r" % kind)


# ---- type renames, deletions and struct members (apply_user_types) ----

def user_type_edits():
    # blob 'R' of USER_NODE: [[name, new name or null]], applied again after declarations
    n = user_node(False)
    blob = n.getblob(0, "R") if n is not None else None
    return json.loads(blob.decode("utf-8")) if blob else []


def apply_type_edits(m, ti, edits):
    # the kept list becomes the edits that applied
    items = [edit_type(m, ti, name, new_name) for name, new_name in edits]
    kept = [e for e, i in zip(edits, items) if i[3]]
    user_node(True).setblob(json.dumps(kept).encode("utf-8"), 0, "R")
    return items


def reapply_user_type_edits():
    edits = user_type_edits()
    if edits:
        import ida_typeinf as ti
        m = ida()
        for name, new_name in edits:
            edit_type(m, ti, name, new_name)


def edit_type(m, ti, name, new_name):
    # renames or (new_name None) deletes a named type; a type already gone is no change, and a rename onto an existing
    # type deletes the old one (a declaration made it again)
    def item(applied, error, text):
        return ["type_edit", 0, name, applied, error, None, None, text]

    t = ti.tinfo_t()
    if not t.get_named_type(None, name):
        return item(True, None, "no type %s" % name)
    if new_name is not None and not ti.tinfo_t().get_named_type(None, new_name):
        code = t.rename_type(new_name)
        if code != ti.TERR_OK:
            return item(False, "IDA did not rename %s: %s" % (name, ti.tinfo_errstr(code)), None)
        rekey_kept_members(name, new_name)
        return item(True, None, "renamed %s to %s" % (name, new_name))
    if not ti.del_named_type(None, name, ti.NTF_TYPE):
        return item(False, "IDA did not delete %s" % name, None)
    if new_name is None:
        rekey_kept_members(name, None)
    return item(True, None, "deleted %s" % name if new_name is None else "%s exists; deleted %s" % (new_name, name))


def rekey_kept_members(name, new_name):
    # the kept enum and struct member edits of a renamed type follow it; a deleted type's are dropped
    prefix = name + "::"
    for tag, edits in (("E", user_enums()), ("F", user_fields())):
        if any(k.startswith(prefix) for k in edits):
            moved = {}
            for k, v in edits.items():
                if not k.startswith(prefix):
                    moved[k] = v
                elif new_name is not None:
                    moved[new_name + "::" + k[len(prefix):]] = v
            user_node(True).setblob(json.dumps(moved).encode("utf-8"), 0, tag)


def user_fields():
    # blob 'F' of USER_NODE: {"type::member or @0xoffset": [name, offset, type or null]} in the order made, applied again after declarations
    n = user_node(False)
    blob = n.getblob(0, "F") if n is not None else None
    return json.loads(blob.decode("utf-8")) if blob else {}


def apply_fields(m, ti, fields):
    # fields: [[type, member name or null, offset or null, type or null]]
    items = []
    for tname, name, offset, typ in fields:
        item = edit_field(m, ti, tname, name, offset, typ)
        if item[3]:
            kept = user_fields()
            key = "%s::%s" % (tname, name if name else "@0x%X" % offset)
            kept.pop(key, None)
            kept[key] = [name, offset, typ]
            user_node(True).setblob(json.dumps(kept).encode("utf-8"), 0, "F")
        items.append(item)
    return items


def reapply_user_fields():
    kept = user_fields()
    if kept:
        import ida_typeinf as ti
        m = ida()
        for key, (name, offset, typ) in kept.items():
            edit_field(m, ti, key.partition("::")[0], name, offset, typ)


def edit_field(m, ti, tname, name, offset, typ):
    # a member by name, else by offset: typ None removes it; else it is retyped in place (and renamed), or placed at offset
    # (moving a named member there; overlapped members are replaced), or appended
    target = "%s.%s" % (tname, name if name else "+0x%X" % offset)

    def item(applied, error, text=None):
        return ["field", 0, target, applied, error, None, offset, text]

    t = ti.tinfo_t()
    if not t.get_named_type(None, tname):
        return item(False, "no struct or union named %s" % tname)
    if not t.is_udt():
        return item(False, "%s is a %s, not a struct or union" % (tname, type_kind(ti, t)))
    udt = ti.udt_type_data_t()
    t.get_udt_details(udt)
    idx = t.get_udm(name)[0] if name else -1
    if idx < 0 and offset is not None:
        idx = next((i for i, u in enumerate(udt) if not u.is_gap() and u.offset // 8 == offset), -1)
    if typ is None:
        if idx < 0:
            return item(True, None, "no member %s" % target)
        old = udt[idx].name
        code = t.del_udm(idx)
        if code != ti.TERR_OK:
            return item(False, "IDA did not remove %s: %s" % (old, ti.tinfo_errstr(code)))
        return item(True, None, "removed %s" % old)
    ft = parse_type(ti, typ, False)
    if ft is None:
        return item(False, "the type %r does not parse (types it names must be declared first)" % typ)
    try:
        if idx >= 0 and (offset is None or t.is_union() or udt[idx].offset // 8 == offset):
            code = t.set_udm_type(idx, ft, ti.ETF_MAY_DESTROY)
            if code == ti.TERR_OK and name and udt[idx].name != name:
                code = t.rename_udm(idx, name)
        else:
            if idx >= 0:
                t.del_udm(idx)
                t = ti.tinfo_t()
                t.get_named_type(None, tname)
            at = 0 if t.is_union() else offset if offset is not None else t.get_size()
            code = t.add_udm(name or "field_%X" % at, ft, at * 8, ti.ETF_MAY_DESTROY)
    except ValueError as e:
        return item(False, "IDA refused %s: %s" % (target, e))
    if code != ti.TERR_OK:
        return item(False, "IDA refused %s: %s" % (target, ti.tinfo_errstr(code)))
    t = ti.tinfo_t()
    t.get_named_type(None, tname)
    i, u = t.get_udm(name) if name else (-1, None)
    if u is None:
        t.get_udt_details(udt)
        u = next((x for x in udt if not x.is_gap() and x.offset // 8 == offset), None)
    return item(True, None, "%s.%s: %s at +0x%X" % (tname, u.name, type_text(ti, u.type, ""), u.offset // 8) if u is not None else target)


# ---- clearing user edits, pseudocode comments, type guesses ----

def stack_original_key(rva, offset):
    return "stk:%X:%d" % (rva, offset)


def remember_stack_original(rva, offset, u):
    # the member IDA had before the first user edit at this offset ("" when there was none), so a clear restores it
    node = user_node(True)
    key = stack_original_key(rva, offset)
    if node.hashstr_buf(key) is None:
        node.hashset_buf(key, json.dumps([u.name, str(u.type)] if u is not None else None))


def apply_clears(m, ti, args):
    # local_clears: [[function, local, stack offset or null, name]]; stack_clears: [[function, offset]]
    items = [clear_local(m, c[0], c[1], c[2], c[3]) for c in args.get("local_clears") or []]
    return items + [clear_stack(m, ti, c[0], c[1]) for c in args.get("stack_clears") or []]


def clear_local(m, rva, local, stack, name):
    # drops the variable's saved user settings (name, type, comment): Hex-Rays shows its own again
    hr = m.ida_hexrays
    f = m.ida_funcs.get_func(_state["base"] + rva)
    if f is None:
        return ["local_clear", rva, local, False, "no function contains rva 0x%X" % rva, None, stack, None]
    rva = rva_of(f.start_ea)
    cf, why = decompile_function(m, f.start_ea)
    if cf is None:
        return ["local_clear", rva, local, False, why, None, stack, None]
    lv = find_lvar(list(cf.get_lvars()), local, stack, name)
    if lv is None:
        return ["local_clear", rva, local, True, None, None, stack, "no such local; nothing to clear"]
    resolved = lv.name
    stk = lv.get_stkoff() if lv.is_stk_var() else None
    loc = hr.lvar_locator_t(lv.location, lv.defea)  # a copy: lv dies with its cfunc
    info = hr.lvar_uservec_t()
    if hr.restore_user_lvar_settings(info, f.start_ea):
        kept = [hr.lvar_saved_info_t(x) for x in info.lvvec if not x.ll == loc]
        if len(kept) != info.lvvec.size():
            info.lvvec.clear()
            for x in kept:
                info.lvvec.push_back(x)
            hr.save_user_lvar_settings(f.start_ea, info)
    hr.mark_cfunc_dirty(f.start_ea, False)
    cf, why = decompile_function(m, f.start_ea)
    now = next((v for v in cf.get_lvars() if loc == v), None) if cf is not None else None
    return ["local_clear", rva, local, True, None, resolved, stk, "%s %s" % (now.type(), now.name) if now is not None else "cleared"]


def clear_stack(m, ti, rva, offset):
    # restores the member IDA had before the first user edit; without that record the default name is given back and the type kept
    import ida_frame
    target = "+0x%X" % offset
    f = m.ida_funcs.get_func(_state["base"] + rva)
    if f is None:
        return ["stack_clear", rva, target, False, "no function contains rva 0x%X" % rva, None, offset, None]
    rva = rva_of(f.start_ea)
    frame, members = frame_members(m, f)
    if frame is None:
        return ["stack_clear", rva, target, False, "the function has no stack frame", None, offset, None]
    u = next((x for x in members if x.offset == offset), None)
    if u is not None and frame_kind(f, frame, u.index, offset) == "special":
        return ["stack_clear", rva, target, False, "%s is %s (return address or saved registers)" % (target, u.name), u.name, offset, None]
    node = user_node(True)
    key = stack_original_key(rva, offset)
    saved = node.hashstr_buf(key)
    retaddr = ida_frame.frame_off_retaddr(f)
    default = ("var_%X" % (retaddr - offset)) if offset < retaddr else ("arg_%X" % (offset - ida_frame.frame_off_args(f)))
    old = u.name if u is not None else None
    note = None
    if saved is not None:
        original = json.loads(saved)
        if u is not None:
            ida_frame.delete_frame_members(f, offset, offset + max(1, u.size))
        if original is not None:
            tif = parse_type(ti, original[1], False) or (u.type if u is not None else None)
            if tif is None or not ida_frame.define_stkvar(f, original[0], offset - retaddr, tif):
                return ["stack_clear", rva, target, False, "IDA did not restore %s at %s" % (original[0], target), old, offset, None]
        node.hashdel(key)
    elif u is not None:
        if u.name != default and frame.rename_udm(u.index, default) != ti.TERR_OK:
            return ["stack_clear", rva, target, False, "IDA did not rename %s back to %s" % (u.name, default), old, offset, None]
        note = "IDA's original type is not recorded; the type is kept"
    if hexrays_ready(m):
        m.ida_hexrays.mark_cfunc_dirty(f.start_ea, False)
    _, now = frame_members(m, f)
    got = [x for x in now if x.offset == offset]
    text = ("%s %s" % (got[0].type, got[0].name)) if got else "no member"
    return ["stack_clear", rva, target, True, None, old, offset, text + ("; " + note if note else "")]


def put_comment_kind(m, f, ea, comment, kind):
    # eol: the regular comment; pre: anterior lines; plate: the function comment at a function start, else anterior lines
    import ida_lines
    if kind == "eol":
        return m.ida_bytes.set_cmt(ea, comment, False)
    if kind == "plate" and f is not None and f.start_ea == ea:
        return m.ida_funcs.set_func_cmt(f, comment, False)
    ida_lines.delete_extra_cmts(ea, ida_lines.E_PREV)
    for i, line in enumerate(comment.split("\n") if comment else []):
        ida_lines.update_extra_cmt(ea, ida_lines.E_PREV + i, line)
    return True


def pseudo_anchors(cf, ea):
    # the statements made from ea, else from the nearest lower address that generated code (innermost first)
    eamap = cf.get_eamap()
    key = ea if ea in eamap else max([k for k in eamap.keys() if k <= ea], default=None)
    if key is None:
        return []
    out = []
    for insn in eamap[key]:
        if insn.ea not in out:
            out.append(insn.ea)
    return out


def comment_shown(m, cf, text):
    first = text.split("\n")[0].strip()
    return any(first in m.ida_lines.tag_remove(sl.line) for sl in cf.get_pseudocode())


def placement_key(rva):
    return "pc:%X" % rva


def drop_placement(m, func_ea, rva):
    # removes the comment placed for rva (its statement and placement are kept in USER_NODE)
    hr = m.ida_hexrays
    node = user_node(True)
    kept = node.hashstr_buf(placement_key(rva))
    if kept is None:
        return
    node.hashdel(placement_key(rva))
    ea, itp = (int(x) for x in kept.split(":"))
    cmts = hr.restore_user_cmts(func_ea)
    if cmts is None:
        return
    for key in [k for k in cmts.keys() if k.ea == ea and k.itp == itp]:
        cmts.erase(cmts.find(key))
    hr.save_user_cmts(func_ea, cmts)


def set_pseudo_comment(m, rva, text):
    # [rva, applied, anchor rva, error]: each statement made from the address and placement (ITP_SEMI..) in turn until the
    # comment is neither orphaned nor hidden; the placement is kept so a later change replaces exactly that comment
    hr = m.ida_hexrays
    ea = _state["base"] + rva
    f = m.ida_funcs.get_func(ea)
    if f is None:
        return [rva, False, None, "no function contains rva 0x%X" % rva]
    drop_placement(m, f.start_ea, rva)
    hr.mark_cfunc_dirty(f.start_ea, False)
    cf, why = decompile_function(m, f.start_ea)
    if cf is None:
        return [rva, False, None, why]
    anchors = pseudo_anchors(cf, ea)
    if not anchors:
        return [rva, False, None, "no pseudocode is generated at or before rva 0x%X" % rva]
    if not text:
        return [rva, True, rva_of(anchors[0]), None]
    cmts = cf.user_cmts
    tl = hr.treeloc_t()
    for target in anchors:
        tl.ea = target
        for itp in range(hr.ITP_SEMI, hr.ITP_COLON):
            tl.itp = itp
            if cmts is not None and cmts.find(tl) != cmts.end():
                continue  # another comment holds this place
            cf.set_user_cmt(tl, text)
            cf.refresh_func_ctext()
            if not cf.has_orphan_cmts() and comment_shown(m, cf, text):
                cf.save_user_cmts()
                user_node(True).hashset_buf(placement_key(rva), "%d:%d" % (target, itp))
                hr.mark_cfunc_dirty(f.start_ea, False)
                return [rva, True, rva_of(target), None]
            cf.set_user_cmt(tl, "")
            cf.refresh_func_ctext()
    hr.mark_cfunc_dirty(f.start_ea, False)
    return [rva, False, rva_of(anchors[0]), "Hex-Rays found no place for a comment at rva 0x%X" % rva_of(anchors[0])]


SIZE_TYPES = {1: "uint8_t", 2: "uint16_t", 4: "uint32_t", 8: "uint64_t"}


def op_type_guess(args):
    # {type, method, confidence}: at a function start the decompiler's prototype, else IDA's guess, else the type
    # applied there, else one from the item's size; nothing is applied
    m = need_open()
    import ida_typeinf as ti
    ea = ea_of(args)
    f = m.ida_funcs.get_func(ea)
    name = m.ida_name.get_name(ea) or ""
    if f is not None and f.start_ea == ea:
        cf, _ = decompile_function(m, ea)
        if cf is not None:
            t = ti.tinfo_t()
            if cf.get_func_type(t):
                return {"type": type_text(ti, t, name), "method": "decompiler", "confidence": "high"}
    t = ti.tinfo_t()
    if ti.guess_tinfo(t, ea) == ti.GUESS_FUNC_OK and not t.empty():
        return {"type": type_text(ti, t, name if t.is_func() else ""), "method": "ida", "confidence": "high"}
    t = ti.tinfo_t()
    if m.ida_nalt.get_tinfo(t, ea):
        return {"type": type_text(ti, t, name if t.is_func() else ""), "method": "existing", "confidence": "high"}
    size = m.ida_bytes.get_item_size(ea) if m.ida_bytes.is_loaded(ea) else 0
    if size > 0 and not m.ida_bytes.is_code(m.ida_bytes.get_flags(ea)):
        return {"type": SIZE_TYPES.get(size, "uint8_t[%d]" % size), "method": "size", "confidence": "low"}
    return {"type": None, "method": None, "confidence": "none"}


def op_pseudo_comments(args):
    # items: [[rva, text; "" removes]]
    m = need_open()
    if not hexrays_ready(m):
        raise WorkerError("unsupported", "the Hex-Rays decompiler is not available")
    return {"items": [set_pseudo_comment(m, rva, text or "") for rva, text in args.get("items") or []]}


OPS = {"hello": op_hello, "open": op_open, "rebase": op_rebase, "functions": op_functions, "decompile": op_decompile,
       "disasm": op_disasm, "disasm_range": op_disasm_range, "blocks": op_blocks, "xrefs_to": op_xrefs_to, "xrefs_from": op_xrefs_from, "set_name": op_set_name,
       "set_comment": op_set_comment, "apply_names": op_apply_names, "get_stamp": op_get_stamp, "save": op_save,
       "sync_patches": op_sync_patches, "apply_types": op_apply_types, "load_pdb": op_load_pdb, "virtual_targets": op_virtual_targets,
       "apply_user_types": op_apply_user_types, "frame": op_frame, "types": op_types, "type": op_type, "field_xrefs": op_field_xrefs,
       "python": op_python, "close": op_close, "sleep": op_sleep, "insn": op_insn}
OPS.update({"pseudo_comments": op_pseudo_comments, "type_guess": op_type_guess})


def op_decompile_many(args):
    # the function containing each rva, in order; each item within seconds_per_item, all within budget_seconds.
    # Hex-Rays has no timeout: the deadline is checked at every optimization stage and cancels the decompilation there.
    m = need_open()
    if not hexrays_ready(m):
        raise WorkerError("unsupported", "the Hex-Rays decompiler for %s (%d-bit) is not available: not installed or not licensed"
                          % (m.ida_ida.inf_get_procname(), 64 if m.ida_ida.inf_is_64bit() else 32))
    hr = m.ida_hexrays
    per_item = max(1.0, float(args.get("seconds_per_item") or 60))
    budget = max(1.0, float(args.get("budget_seconds") or 600))
    start = time.time()
    deadline = [start + per_item]

    class Deadline(hr.Hexrays_Hooks):
        def _check(self, *unused):
            return hr.MERR_CANCELED if time.time() > deadline[0] else 0

        microcode = preoptimized = locopt = prealloc = glbopt = _check

    hooks = Deadline()
    hooks.hook()
    items = []
    try:
        for rva in args.get("rvas") or []:
            now = time.time()
            if now - start >= budget or cancelled():
                items.append({"rva": rva, "status": "skipped"})
                continue
            deadline[0] = min(now + per_item, start + budget)
            try:
                item = op_decompile({"rva": rva})
                item.update({"rva": rva, "status": "ok"})
            except WorkerError as e:
                late = time.time() > deadline[0]
                item = {"rva": rva, "status": "error", "code": "timeout" if late else e.code,
                        "message": "not decompiled within %g s" % per_item if late else str(e)}
            items.append(item)
    finally:
        hooks.unhook()
    return partial({"items": items}, None) if stop_reason() else {"items": items}


OPS["decompile_many"] = op_decompile_many


class _Slicer:
    # Value slices over Hex-Rays microcode at MMAT_LVARS (cfunc.mba): a local's definitions backward (the one before the
    # use in its block, else all of them), its uses forward. Reply shape shared with the Ghidra worker's value_slice.
    COPIES = ("m_mov", "m_xdu", "m_xds", "m_low")
    JUMPS = ("m_jcnd", "m_jnz", "m_jz", "m_jae", "m_jb", "m_ja", "m_jbe", "m_jg", "m_jge", "m_jl", "m_jle",
             "m_setnz", "m_setz", "m_setae", "m_setb", "m_seta", "m_setbe", "m_setg", "m_setge", "m_setl", "m_setle")

    def __init__(self, m, cf, max_nodes):
        self.m, self.hr, self.mba = m, m.ida_hexrays, cf.mba
        hr = self.hr
        self.copies = {getattr(hr, n) for n in self.COPIES}
        self.jumps = {getattr(hr, n) for n in self.JUMPS}
        self.calls = {hr.m_call, hr.m_icall}
        self.max = max(1, min(int(max_nodes), 2000))
        self.nodes, self.edges = [], []
        self.truncated = False
        self.variable = None
        self.lvars = self.mba.vars
        self.args = list(self.mba.argidx)
        self.insns = []  # (block, position, top-level instruction)
        for b in range(self.mba.qty):
            ins, i = self.mba.get_mblock(b).head, 0
            while ins:
                self.insns.append((b, i, ins))
                ins, i = ins.next, i + 1
        self.used = {}

    def node(self, kind, ea, text, why, **extra):
        if len(self.nodes) >= self.max:
            self.truncated = True
            return -1
        n = {"kind": kind, "rva": (rva_of(ea) or 0) if ea is not None else 0, "text": text, "why": why}
        n.update({k: v for k, v in extra.items() if v is not None})
        self.nodes.append(n)
        return len(self.nodes) - 1

    def edge(self, a, b, kind):
        if a >= 0 and b >= 0:
            self.edges.append([a, b, kind])

    def result(self):
        return {"nodes": self.nodes, "edges": self.edges, "truncated": self.truncated, "note": None, "variable": self.variable}

    def name(self, idx):
        return self.lvars[idx].name if 0 <= idx < self.lvars.size() else "v%d" % idx

    def target(self, value):
        # an image address the constant names, as an RVA
        m = self.m
        return rva_of(value) if m.ida_bytes.is_loaded(value) and m.ida_segment.getseg(value) is not None else None

    def nested(self, ins):
        # ins and the instructions nested in its operands
        yield ins
        for op in (ins.l, ins.r, ins.d):
            yield from self.nested_mop(op)

    def nested_mop(self, op):
        hr = self.hr
        if op.t == hr.mop_d:
            yield from self.nested(op.d)
        elif op.t == hr.mop_f:
            for a in op.f.args:
                yield from self.nested_mop(a)

    def call_at(self, ea):
        for b, i, top in self.insns:
            for ins in self.nested(top):
                if ins.ea == ea and ins.opcode in self.calls:
                    return b, i, top, ins
        return None

    def top_at(self, ea):
        for b, i, top in self.insns:
            if top.ea == ea:
                return b, i, top
        return None

    def defs(self, idx):
        hr = self.hr
        return [(b, i, ins) for b, i, ins in self.insns if ins.d.t == hr.mop_l and ins.d.l.idx == idx and ins.opcode not in self.calls]

    # backward

    def back_mop(self, op, at, stack, depth=0):
        hr = self.hr
        if len(self.nodes) >= self.max:
            self.truncated = True
            return -1
        if depth > 48:
            return self.node("unknown", None, "?", "derivation deeper than 48 steps")
        t = op.t
        if t == hr.mop_n:
            v = op.nnn.value
            # a number is an address only where something is defined (images based at 0 make every small number loaded)
            m = self.m
            named = v >= 0x10000 and (m.ida_name.get_name(v) or m.ida_bytes.is_strlit(m.ida_bytes.get_flags(v)))
            tg = self.target(v) if op.size >= 4 and named else None
            if tg is not None and v:
                return self.node("address", None, "0x%X" % v, "constant", target=tg)
            return self.node("constant", None, "0x%X" % v, "constant", value=v)
        if t == hr.mop_a:
            inner = op.a
            if inner.t == hr.mop_v and rva_of(inner.g) is not None:
                return self.node("address", None, "&0x%X" % inner.g, "address", target=rva_of(inner.g))
            if inner.t in (hr.mop_l, hr.mop_S):
                return self.node("stack_address", None, "&" + inner.dstr(), "address of a local")
            return self.node("unknown", None, "?", "address of " + inner.dstr())
        if t == hr.mop_v:
            return self.node("global", op.g, "[0x%X]" % op.g, "global variable", target=rva_of(op.g))
        if t == hr.mop_l:
            return self.back_lvar(op.l.idx, at, stack, depth)
        if t == hr.mop_d:
            return self.back_insn(op.d, at, stack, depth)
        return self.node("unknown", None, "?", op.dstr())

    def back_lvar(self, idx, at, stack, depth):
        if idx in stack:
            return self.node("loop", None, "loop-carried value", "%s depends on itself" % self.name(idx))
        defs = self.defs(idx)
        before = [d for d in defs if at is not None and d[0] == at[0] and d[1] < at[1]]
        reaching = [max(before, key=lambda d: d[1])] if before else defs
        alts = [("def", d) for d in reaching]
        if not before and idx in self.args:
            alts.insert(0, ("param", self.args.index(idx)))
        if not alts:
            return self.node("unknown", None, "?", "no definition of " + self.name(idx))
        stack = stack | {idx}

        def one(alt):
            if alt[0] == "param":
                return self.node("parameter", self.mba.entry_ea, "parameter %d" % (alt[1] + 1), self.name(idx), index=alt[1])
            b, i, ins = alt[1]
            return self.back_def(ins, (b, i), stack, depth + 1)

        if len(alts) == 1:
            return one(alts[0])
        merge = self.node("merge", None, "%d values" % len(alts), self.name(idx) + " has several definitions", derived=len(alts) > 8 or None)
        for alt in alts[:8]:
            c = one(alt)
            self.edge(c, merge, "loop" if c >= 0 and self.nodes[c]["kind"] == "loop" else "merge")
        return merge

    def back_def(self, ins, at, stack, depth):
        if ins.opcode in self.copies:
            c = self.back_mop(ins.l, at, stack, depth)
            if c >= 0 and not self.nodes[c].get("rva"):
                self.nodes[c]["rva"] = rva_of(ins.ea) or 0
                self.nodes[c]["why"] = ins.dstr()
            return c
        return self.back_insn(ins, at, stack, depth)

    def back_insn(self, ins, at, stack, depth):
        hr = self.hr
        op = ins.opcode
        if op in self.copies:
            return self.back_mop(ins.l, at, stack, depth + 1)
        if op in self.calls:
            return self.node("call_result", ins.ea, "result of the call", ins.dstr(), site=rva_of(ins.ea))
        if op == hr.m_ldx:
            g = self.fixed(ins.r)
            if g is not None:
                return self.node("global", ins.ea, "[0x%X]" % g, ins.dstr(), target=rva_of(g))
            base, off = ins.r, 0
            if base.t == hr.mop_d and base.d.opcode == hr.m_add and base.d.r.t == hr.mop_n:
                base, off = base.d.l, base.d.r.nnn.value
            f = self.node("field", ins.ea, "field +0x%X" % off, ins.dstr(), value=off)
            self.edge(self.back_mop(base, at, stack, depth + 1), f, "field")
            return f
        if op in (hr.m_add, hr.m_sub, hr.m_or, hr.m_and, hr.m_xor) and ins.l.t == hr.mop_n and ins.r.t == hr.mop_n:
            a, b = ins.l.nnn.value, ins.r.nnn.value
            v = {hr.m_add: a + b, hr.m_sub: a - b, hr.m_or: a | b, hr.m_and: a & b}.get(op, a ^ b) & ((1 << (8 * max(1, ins.d.size))) - 1)
            return self.node("constant", ins.ea, "0x%X" % v, ins.dstr(), value=v)
        return self.node("unknown", ins.ea, "?", "computed: " + ins.dstr())

    def fixed(self, op):
        # a pointer that is a fixed address
        hr = self.hr
        if op.t == hr.mop_a and op.a.t == hr.mop_v:
            return op.a.g
        if op.t == hr.mop_n and self.target(op.nnn.value) is not None:
            return op.nnn.value
        if op.t == hr.mop_d and op.d.opcode in self.copies:
            return self.fixed(op.d.l)
        return None

    # forward

    def holds(self, op, idx):
        # "direct" when op is the local (through copies), "derived" when computed from it, else None
        hr = self.hr
        if op.t == hr.mop_l:
            return "direct" if op.l.idx == idx else None
        if op.t == hr.mop_d:
            ins = op.d
            if ins.opcode in self.calls or ins.opcode == hr.m_ldx:
                return None
            if ins.opcode in self.copies:
                return self.holds(ins.l, idx)
            if self.holds(ins.l, idx) or self.holds(ins.r, idx):
                return "derived"
        return None

    def use(self, origin, kind, ins, text, path, derived, **extra):
        key = (kind, ins.ea, extra.get("index"))
        if key in self.used:
            return
        n = self.node(kind, ins.ea, text, path + ins.dstr(), site=rva_of(ins.ea), derived=bool(derived) or None, **extra)
        if n >= 0:
            self.used[key] = n
            self.edge(origin, n, "use")

    def callee(self, call):
        hr, m = self.hr, self.m
        if call.opcode == hr.m_call and call.l.t == hr.mop_v:
            return m.ida_funcs.get_func_name(call.l.g) or m.ida_name.get_name(call.l.g) or "0x%X" % call.l.g, rva_of(call.l.g)
        return None, None

    def forward(self, idx, origin):
        hr = self.hr
        work, seen = [(idx, False, "")], set()
        while work and not self.truncated:
            v, derived, path = work.pop(0)
            if v in seen:
                continue
            seen.add(v)
            for b, i, top in self.insns:
                for ins in self.nested(top):
                    op = ins.opcode
                    if op in self.calls and ins.d.t == hr.mop_f:
                        name, tg = self.callee(ins)
                        for k, a in enumerate(ins.d.f.args):
                            h = self.holds(a, v)
                            if h:
                                self.use(origin, "argument", ins, "argument %d%s" % (k + 1, " of " + name if name else ""), path, derived or h == "derived",
                                         index=k, callee=name, target=tg)
                        if op == hr.m_icall and self.holds(ins.r, v):
                            self.use(origin, "call_target", ins, "called", path, derived)
                    elif op == hr.m_stx:
                        if self.holds(ins.l, v):
                            g = self.fixed(ins.d)
                            if g is not None:
                                self.use(origin, "store", ins, "stored to [0x%X]" % g, path, derived, target=rva_of(g))
                            else:
                                self.use(origin, "field_store", ins, "stored through a pointer", path, derived)
                        if self.holds(ins.d, v):
                            self.use(origin, "dereference", ins, "points to the store", path, derived)
                    elif op == hr.m_ldx and self.holds(ins.r, v):
                        self.use(origin, "dereference", ins, "points to the load", path, derived)
                    elif op in self.jumps:
                        side = ins.r if self.holds(ins.l, v) else ins.l if self.holds(ins.r, v) else None
                        if side is not None:
                            value = side.nnn.value if side.t == hr.mop_n else None
                            self.use(origin, "compare", ins, ins.dstr(), path, derived, value=value)
                    elif op in (hr.m_jtbl, hr.m_ijmp) and (self.holds(ins.l, v) or self.holds(ins.d, v)):
                        self.use(origin, "switch", ins, "selects the jump target", path, derived)
                # assignments of top-level instructions carry the value on
                if top.opcode in self.calls or top.opcode in (hr.m_stx, hr.m_ldx) or top.opcode in self.jumps:
                    continue
                h = self.holds(top.l, v) or self.holds(top.r, v)
                if not h:
                    continue
                d = derived or h == "derived" or top.opcode not in self.copies
                if top.d.t == hr.mop_l:
                    nxt = top.d.l.idx
                    if nxt == self.mba.retvaridx:
                        self.use(origin, "return", top, "returned", path, d)
                    else:
                        work.append((nxt, d, path + top.dstr() + " -> "))
                elif top.d.t == hr.mop_v:
                    self.use(origin, "store", top, "stored to [0x%X]" % top.d.g, path, d, target=rva_of(top.d.g))

    def locals_in(self, op, out):
        hr = self.hr
        if op.t == hr.mop_l:
            out.add(op.l.idx)
        elif op.t == hr.mop_d:
            for o in (op.d.l, op.d.r, op.d.d):
                self.locals_in(o, out)
        elif op.t == hr.mop_f:
            for a in op.f.args:
                self.locals_in(a, out)

    def lvar_of_register(self, ea, name):
        # the local the register holds at ea: one living in it that the instruction uses, the only local it uses,
        # a call result read just after the call (the result register), or the latest definition of one living in it
        import ida_idp
        hr = self.hr
        reg = ida_idp.str2reg(name)
        if reg is None or reg < 0:
            return None
        mreg = hr.reg2mreg(reg)
        cands = {i for i in range(self.lvars.size()) if self.lvars[i].location.is_reg1() and self.lvars[i].location.reg1() == mreg}
        used = set()
        for b, i, top in self.insns:
            if top.ea == ea:
                for op in (top.l, top.r) if top.d.t == hr.mop_l else (top.l, top.r, top.d):
                    self.locals_in(op, used)
        if used & cands:
            return min(used & cands)
        if len(used) == 1:
            return next(iter(used))
        if mreg == hr.reg2mreg(ida_idp.str2reg("rax" if self.m.ida_ida.inf_is_64bit() else "eax")):
            prior = [top for b, i, top in self.insns if top.ea < ea and top.d.t == hr.mop_l and top.l.t == hr.mop_d and top.l.d.opcode in self.calls]
            if prior:
                last = max(prior, key=lambda t: t.ea)
                if last.d.l.idx in used or not used:
                    return last.d.l.idx
        best = None
        for c in cands:
            for b, i, ins in self.defs(c):
                if ins.ea <= ea and (best is None or ins.ea > best[0]):
                    best = (ins.ea, c)
        return best[1] if best else (min(cands) if cands else None)


def op_value_slice(args):
    # per-function value slice from Hex-Rays microcode (see _Slicer)
    m = need_open()
    if not hexrays_ready(m):
        raise WorkerError("unsupported", "the Hex-Rays decompiler is not available: not installed or not licensed")
    hr = m.ida_hexrays
    f = func_at(m, ea_of(args, "function"))
    failure = hr.hexrays_failure_t()
    try:
        cf = hr.decompile(f.start_ea, failure, hr.DECOMP_NO_WAIT)
    except hr.DecompilationFailure as e:
        raise WorkerError("failed", "decompilation failed: %s" % (str(e).strip() or failure.desc()))
    if cf is None:
        raise WorkerError("failed", "decompilation failed: %s" % failure.desc())
    s = _Slicer(m, cf, args.get("max_nodes") or 256)
    seed, ea, index = args.get("seed"), ea_of(args), int(args.get("index", -1))
    forward = args.get("direction") == "forward"
    if seed == "argument":
        found = s.call_at(ea)
        if found is None:
            raise WorkerError("not_found", "no call at rva 0x%X in the microcode" % rva_of(ea))
        b, i, top, call = found
        callargs = list(call.d.f.args) if call.d.t == hr.mop_f else []
        if not 0 <= index < len(callargs):
            raise WorkerError("not_found", "the call passes %d arguments, not %d" % (len(callargs), index + 1))
        arg = callargs[index]
        if forward:
            origin = s.node("origin", ea, "argument %d at the call" % (index + 1), "")
            name, tg = s.callee(call)
            s.use(origin, "argument", call, "argument %d%s" % (index + 1, " of " + name if name else ""), "", False, index=index, callee=name, target=tg)
            if arg.t == hr.mop_l:
                s.variable = s.name(arg.l.idx)
                s.forward(arg.l.idx, origin)
        else:
            if arg.t == hr.mop_l:
                s.variable = s.name(arg.l.idx)
            s.back_mop(arg, (b, i), frozenset())
    elif seed == "parameter":
        if not 0 <= index < len(s.args):
            raise WorkerError("not_found", "the function has %d parameters, not %d" % (len(s.args), index + 1))
        idx = s.args[index]
        s.variable = s.name(idx)
        if forward:
            s.forward(idx, s.node("origin", f.start_ea, s.name(idx) + " at entry", ""))
        else:
            s.node("parameter", f.start_ea, "parameter %d" % (index + 1), s.name(idx), index=index)
    elif seed == "result":
        if not forward:
            s.node("call_result", ea, "result of the call", "", site=rva_of(ea))
        else:
            origin = s.node("origin", ea, "result of the call", "")
            found = s.call_at(ea)
            if found is not None and found[2].d.t == hr.mop_l:
                s.variable = s.name(found[2].d.l.idx)
                s.forward(found[2].d.l.idx, origin)
    elif seed == "returns":
        r = s.mba.retvaridx
        if r < 0:
            s.node("unknown", f.start_ea, "?", "the function returns nothing")
        else:
            s.variable = s.name(r)
            s.back_lvar(r, None, frozenset(), 0)
    elif seed == "stored":
        top = s.top_at(ea)
        if top is None or not (top[2].opcode == hr.m_stx or top[2].opcode in s.copies and top[2].d.t == hr.mop_v):
            raise WorkerError("not_found", "no store at rva 0x%X in the microcode" % rva_of(ea))
        s.back_mop(top[2].l, (top[0], top[1]), frozenset())
    elif seed == "loaded":
        top = s.top_at(ea)
        if top is None or top[2].d.t != hr.mop_l:
            raise WorkerError("not_found", "no load into a local at rva 0x%X in the microcode" % rva_of(ea))
        idx = top[2].d.l.idx
        s.variable = s.name(idx)
        s.forward(idx, s.node("origin", ea, "loaded value", ""))
    elif seed == "location":
        result = (args.get("register") or "").lower() in ("rax", "eax") and not forward
        call = next((c for b, i, top in s.insns for c in s.nested(top)
                     if c.opcode in s.calls and c.ea + m.ida_bytes.get_item_size(c.ea) == ea), None) if result else None
        if call is not None:
            # the result register read right after the call holds its result, whatever local the microcode folded it into
            s.node("call_result", call.ea, "result of the call", call.dstr(), site=rva_of(call.ea))
            return s.result()
        idx = s.lvar_of_register(ea, args.get("register") or "")
        if idx is None:
            raise WorkerError("not_found", "no decompiler local lives in %s at rva 0x%X" % (args.get("register"), rva_of(ea)))
        s.variable = s.name(idx)
        if forward:
            s.forward(idx, s.node("origin", ea, "%s (%s) at the instruction" % (args.get("register"), s.name(idx)), ""))
        else:
            top = s.top_at(ea)
            s.back_lvar(idx, (top[0], top[1]) if top else None, frozenset(), 0)
    else:
        raise WorkerError("invalid_argument", "unknown seed '%s'" % seed)
    return s.result()


OPS["value_slice"] = op_value_slice


# ---- query surface: pseudocode references ----

_STR_CODECS = {0: "utf-8", 1: "utf-16-le", 2: "utf-32-le"}


def ref_string(m, ea):
    # the text of a string literal item at ea, else None
    import ida_bytes
    if not ida_bytes.is_strlit(ida_bytes.get_flags(ea)):
        return None
    strtype = m.ida_nalt.get_str_type(ea)
    if strtype is None or strtype < 0:
        strtype = m.ida_nalt.STRTYPE_C
    raw = ida_bytes.get_strlit_contents(ea, -1, strtype)
    if not raw:
        return None
    return raw.decode(_STR_CODECS.get(strtype & 3, "utf-8"), errors="replace")[:400]


def op_decompile_refs(args):
    # objects the pseudocode of the function at rva names (globals, functions, strings, imports), in first-use order:
    # rows [rva, name, string or null, uses, function start (bool)]
    m = need_open()
    f = func_at(m, ea_of(args))
    cf, why = decompile_function(m, f.start_ea)
    if cf is None:
        raise WorkerError("failed", why)
    hr = m.ida_hexrays
    order, uses = [], {}

    class Objects(hr.ctree_visitor_t):
        def __init__(self):
            hr.ctree_visitor_t.__init__(self, hr.CV_FAST)

        def visit_expr(self, e):
            if e.op == hr.cot_obj and e.obj_ea != m.idautils.ida_idaapi.BADADDR:
                if e.obj_ea not in uses:
                    order.append(e.obj_ea)
                uses[e.obj_ea] = uses.get(e.obj_ea, 0) + 1
            return 0

    Objects().apply_to(cf.body, None)
    rows = []
    for ea in order:
        rva = rva_of(ea)
        if rva is None:
            continue
        callee = m.ida_funcs.get_func(ea)
        rows.append([rva, m.ida_name.get_ea_name(ea) or "", ref_string(m, ea), uses[ea], bool(callee and callee.start_ea == ea)])
    return {"start": rva_of(f.start_ea), "refs": rows}


OPS["decompile_refs"] = op_decompile_refs


# ---- Database export ----

def op_save_as(args):
    # A packed, compressed copy of the open database at a new path for the IDA GUI. Never DBFL_KILL: it deletes the
    # unpacked working files the open database still runs on. The worker keeps saving to its own path.
    m = need_open()
    loader = m.ida_loader
    path = os.path.abspath(args["path"])
    current = loader.get_path(loader.PATH_TYPE_IDB)
    if os.path.normcase(path) == os.path.normcase(os.path.abspath(current)):
        raise WorkerError("invalid_argument", "that is the worker's own database")
    if not loader.save_database(path, loader.DBFL_COMP):
        raise WorkerError("io_error", "save_database failed for %s" % path)
    if os.path.normcase(loader.get_path(loader.PATH_TYPE_IDB)) != os.path.normcase(current):
        loader.set_path(loader.PATH_TYPE_IDB, current)
    return {"path": path, "size": os.path.getsize(path)}


OPS["save_as"] = op_save_as


# ---- engine read views; rows shared with the Ghidra worker's InfoOps ----

def op_image_info(args):
    m = need_open()
    import ida_typeinf
    v = m.idapro.get_library_version()
    bits = 64 if m.ida_ida.inf_is_64bit() else (32 if m.ida_ida.inf_is_32bit_exactly() else 16)
    entries = []
    for i in range(min(m.ida_entry.get_entry_qty(), 64)):
        r = rva_of(m.ida_entry.get_entry(m.ida_entry.get_entry_ordinal(i)))
        if r is not None:
            entries.append(r)
    externals = [0]

    def count(ea, name, ordinal):
        externals[0] += 1
        return True

    for i in range(m.ida_nalt.get_import_module_qty()):
        m.ida_nalt.enum_import_names(i, count)
    blocks = []
    for n in range(m.ida_segment.get_segm_qty()):
        seg = m.ida_segment.getnseg(n)
        perm = seg.perm
        perms = ("r" if perm & m.ida_segment.SEGPERM_READ else "-") + ("w" if perm & m.ida_segment.SEGPERM_WRITE else "-") + \
                ("x" if perm & m.ida_segment.SEGPERM_EXEC else "-")
        blocks.append([m.ida_segment.get_segm_name(seg) or "", seg.start_ea, seg.end_ea - seg.start_ea, perms,
                       bool(m.ida_bytes.is_loaded(seg.start_ea))])
    md5 = m.ida_nalt.retrieve_input_file_md5()
    sha = m.ida_nalt.retrieve_input_file_sha256()
    return {"version": "%d.%d.%d" % v if v else "", "processor": m.ida_ida.inf_get_procname(),
            "language": "%s:%s:%d" % (m.ida_ida.inf_get_procname(), "BE" if m.ida_ida.inf_is_be() else "LE", bits),
            "compiler": ida_typeinf.get_compiler_name(m.ida_ida.inf_get_cc_id()) or None, "format": file_type_name(m),
            "pointer_size": bits // 8, "endian": "big" if m.ida_ida.inf_is_be() else "little", "functions": m.ida_funcs.get_func_qty(),
            "external_functions": externals[0], "entry_points": entries, "md5": md5.hex() if md5 else None, "sha256": sha.hex() if sha else None,
            "blocks": blocks, "changed": None, "analysis": "complete" if m.ida_auto.auto_is_ok() else "running"}


def op_defined_data(args):
    # data items in address order: total, rows [rva, size, type, label or null, value text or null, is string] up to max
    m = need_open()
    import ida_typeinf
    limit = int(args.get("max") or 200000)
    rows, total = [], 0
    for n in range(m.ida_segment.get_segm_qty()):
        seg = m.ida_segment.getnseg(n)
        ea = seg.start_ea
        while ea != m.idautils.ida_idaapi.BADADDR and ea < seg.end_ea:
            flags = m.ida_bytes.get_flags(ea)
            if m.ida_bytes.is_data(flags) and rva_of(ea) is not None:
                total += 1
                if len(rows) < limit:
                    size = m.ida_bytes.get_item_size(ea)
                    tif = ida_typeinf.tinfo_t()
                    typ = str(tif) if m.ida_nalt.get_tinfo(tif, ea) else data_flag_type(m, flags, size)
                    label = m.ida_name.get_name(ea) if m.ida_bytes.has_user_name(flags) or m.ida_bytes.has_auto_name(flags) else None
                    text = without_comment(m.ida_lines.tag_remove(m.ida_lines.generate_disasm_line(ea, 0) or "")).strip()
                    rows.append([rva_of(ea), size, typ, label or None, text[:120] + ("..." if len(text) > 120 else "") if text else None,
                                 bool(m.ida_bytes.is_strlit(flags))])
            ea = m.ida_bytes.next_head(ea, seg.end_ea)
    return {"total": total, "rows": rows}


def without_comment(line):
    # the listing line up to its comment (a ';' outside quotes)
    quote = None
    for i, c in enumerate(line):
        if quote:
            if c == quote:
                quote = None
        elif c in "'\"":
            quote = c
        elif c == ";":
            return line[:i]
    return line


def data_flag_type(m, flags, size):
    b = m.ida_bytes
    for test, name, unit in ((b.is_byte, "byte", 1), (b.is_word, "word", 2), (b.is_dword, "dword", 4), (b.is_qword, "qword", 8),
                             (b.is_oword, "oword", 16), (b.is_float, "float", 4), (b.is_double, "double", 8), (b.is_strlit, "string", 0),
                             (b.is_struct, "struct", 0), (b.is_align, "align", 0)):
        if test(flags):
            return name if unit == 0 or size <= unit else "%s[%d]" % (name, size // unit)
    return "data"


STRTYPE_NAMES = {0: "C", 1: "C_16", 2: "C_32"}


def op_defined_strings(args):
    # string literal items in address order: rows [rva, size, type, text] up to max
    m = need_open()
    limit = int(args.get("max") or 200000)
    rows = []
    for n in range(m.ida_segment.get_segm_qty()):
        seg = m.ida_segment.getnseg(n)
        ea = seg.start_ea
        while ea != m.idautils.ida_idaapi.BADADDR and ea < seg.end_ea and len(rows) < limit:
            if m.ida_bytes.is_strlit(m.ida_bytes.get_flags(ea)) and rva_of(ea) is not None:
                strtype = m.ida_nalt.get_str_type(ea)
                width = strtype & 3 if strtype is not None and strtype >= 0 else 0
                raw = m.ida_bytes.get_strlit_contents(ea, -1, strtype if strtype is not None and strtype >= 0 else 0) or b""
                text = raw.decode("utf-8", "replace")
                rows.append([rva_of(ea), m.ida_bytes.get_item_size(ea), STRTYPE_NAMES.get(width, "C"), text[:400]])
            ea = m.ida_bytes.next_head(ea, seg.end_ea)
    return {"rows": rows}


def cc_name(cc):
    import ida_typeinf as t
    names = {t.CM_CC_CDECL: "__cdecl", t.CM_CC_ELLIPSIS: "__cdecl", t.CM_CC_STDCALL: "__stdcall", t.CM_CC_PASCAL: "__pascal",
             t.CM_CC_FASTCALL: "__fastcall", t.CM_CC_THISCALL: "__thiscall", t.CM_CC_SPECIAL: "__usercall", t.CM_CC_SPECIALE: "__usercall",
             t.CM_CC_SPECIALP: "__usercall"}
    return names.get(cc & t.CM_CC_MASK)


def argloc_text(m, loc, size):
    import ida_idp
    if loc.is_reg1():
        return ida_idp.get_reg_name(loc.reg1(), max(1, size))
    if loc.is_reg2():
        return "%s:%s" % (ida_idp.get_reg_name(loc.reg1(), max(1, size // 2)), ida_idp.get_reg_name(loc.reg2(), max(1, size // 2)))
    if loc.is_stkoff():
        return "stack[0x%X]" % loc.stkoff()
    return "scattered" if loc.is_scattered() else "unknown"


def op_function_info(args):
    # the function containing rva as IDA records it; field names match the Ghidra worker's function_info
    m = need_open()
    import ida_typeinf
    f = func_at(m, ea_of(args))
    ea = f.start_ea
    tif, ftd = ida_typeinf.tinfo_t(), ida_typeinf.func_type_data_t()
    typed = m.ida_nalt.get_tinfo(tif, ea) and tif.get_func_details(ftd)
    if not typed:
        # IDA's guess, as the decompiler would start from
        typed = ida_typeinf.guess_tinfo(tif, ea) != ida_typeinf.GUESS_FUNC_FAILED and tif.get_func_details(ftd)
    params = []
    if typed:
        for a in ftd:
            params.append([a.name or "", str(a.type), argloc_text(m, a.argloc, a.type.get_size())])
    ranges = [[rva_of(s), rva_of(e)] for s, e in m.idautils.Chunks(ea) if rva_of(s) is not None and rva_of(e) is not None]
    target = None
    if f.flags & m.ida_funcs.FUNC_THUNK:
        t, _ = m.ida_funcs.calc_thunk_func_target(f)
        if t != m.idautils.ida_idaapi.BADADDR:
            target = t
    proto = ida_typeinf.print_type(ea, ida_typeinf.PRTYPE_1LINE) if typed else None
    cc = ftd.get_cc() if typed else None
    result = {"start": rva_of(ea), "name": m.ida_funcs.get_func_name(ea) or "", "namespace": None, "prototype": proto,
              "convention": cc_name(cc) if cc is not None else None,
              "signature_source": ("user" if m.ida_nalt.is_userti(ea) else "guessed") if typed else None, "ranges": ranges,
              "external": False, "noreturn": bool(f.flags & m.ida_funcs.FUNC_NORET), "library": bool(f.flags & m.ida_funcs.FUNC_LIB),
              "stack_purge": f.argsize, "params": params, "return_type": str(ftd.rettype) if typed else None,
              "return_storage": argloc_text(m, ftd.retloc, ftd.rettype.get_size()) if typed and not ftd.rettype.is_void() else None,
              "varargs": bool(typed and ftd.is_vararg_cc())}
    if target is not None:
        result["thunk_target"] = rva_of(target)
        result["thunk_name"] = m.ida_name.get_name(target) or None
    return result


OPS["defined_data"] = op_defined_data
OPS["function_info"] = op_function_info
OPS["defined_strings"] = op_defined_strings
OPS["image_info"] = op_image_info


# ---- analysis control: analyzer flags, reanalysis, function candidates, marks ----

_ANALYZER_FLAGS = [
    ("AF_CODE", "trace execution flow"), ("AF_MARKCODE", "mark typical code sequences as code"), ("AF_JUMPTBL", "locate and create jump tables"),
    ("AF_PURDAT", "control flow to data segment is ignored"), ("AF_USED", "analyze and create all xrefs"), ("AF_UNK", "delete instructions with no xrefs"),
    ("AF_PROCPTR", "create function if data xref data->code32 exists"), ("AF_PROC", "create functions if call is present"),
    ("AF_FTAIL", "create function tails"), ("AF_LVAR", "create stack variables"), ("AF_STKARG", "propagate stack argument information"),
    ("AF_REGARG", "propagate register argument information"), ("AF_TRACE", "trace stack pointer"), ("AF_VERSP", "perform full SP-analysis"),
    ("AF_ANORET", "perform no-return analysis"), ("AF_MEMFUNC", "try to guess member function types"), ("AF_TRFUNC", "truncate functions upon code deletion"),
    ("AF_STRLIT", "create string literal if data xref exists"), ("AF_CHKUNI", "check for unicode strings"), ("AF_FIXUP", "create offsets and segments using fixup info"),
    ("AF_DREFOFF", "create offset if data xref to seg32 exists"), ("AF_IMMOFF", "convert 32bit instruction operand to offset"),
    ("AF_DATOFF", "automatically convert data to offsets"), ("AF_FLIRT", "use flirt signatures"), ("AF_SIGCMT", "append a signature name comment for recognized anonymous library functions"),
    ("AF_SIGMLT", "allow recognition of several copies of the same function"), ("AF_HFLIRT", "automatically hide library functions"),
    ("AF_JFUNC", "rename jump functions as j_..."), ("AF_NULLSUB", "rename empty functions as nullsub_..."), ("AF_DODATA", "coagulate data segs at the final pass"),
    ("AF_DOCODE", "coagulate code segs at the final pass"), ("AF_FINAL", "final pass of analysis"),
    ("AF2_DOEH", "handle EH information"), ("AF2_DORTTI", "handle RTTI information"), ("AF2_MACRO", "try to combine several instructions into a macro"),
    ("AF2_MERGESTR", "merge string literals created using data xrefs"),
]


def _analyzer_bit(name):
    import ida_ida
    bit = getattr(ida_ida, name, None)
    if bit is None:
        return None, None
    return bit, (ida_ida.inf_get_af2, ida_ida.inf_set_af2) if name.startswith("AF2_") else (ida_ida.inf_get_af, ida_ida.inf_set_af)


def op_analyzers(args):
    # IDA's analysis flags as options: {options: [[name, "bool", "true"|"false", description]]}
    need_open()
    rows = []
    for name, description in _ANALYZER_FLAGS:
        bit, accessors = _analyzer_bit(name)
        if bit is not None:
            rows.append([name, "bool", "true" if accessors[0]() & bit else "false", description])
    return {"options": rows}


def _set_analyzer(name, value, warnings):
    bit, accessors = _analyzer_bit(name.strip().upper())
    if bit is None:
        warnings.append("unknown analysis option '%s'" % name)
        return
    text = str(value).strip().lower()
    if text not in ("true", "false", "1", "0", "on", "off"):
        warnings.append("analysis option '%s' = '%s': not true or false" % (name, value))
        return
    get, set_ = accessors
    set_(get() | bit if text in ("true", "1", "on") else get() & ~bit)


def op_reanalyze(args):
    # plans [start, end) or the whole database for analysis again and waits for the queue within budget_seconds; options
    # [[flag, value]] apply to this run only. Saved. complete: the queue ran empty; the rest runs on the next wait.
    m = need_open()
    import ida_ida
    start = time.time()
    budget = max(1.0, float(args.get("budget_seconds") or 600))
    before = m.ida_funcs.get_func_qty()
    saved = (ida_ida.inf_get_af(), ida_ida.inf_get_af2())
    warnings = []
    for name, value in args.get("options") or []:
        _set_analyzer(name, value, warnings)
    if args.get("start") is not None:
        lo = ea_of(args, "start")
        hi = ea_of(args, "end") if args.get("end") is not None else lo + 1
    else:
        lo, hi = ida_ida.inf_get_min_ea(), ida_ida.inf_get_max_ea()
    try:
        m.ida_auto.plan_range(lo, hi)
        step = 0x100000
        ea = lo
        while ea < hi and time.time() - start < budget:
            m.ida_auto.auto_wait_range(ea, min(hi, ea + step))
            ea += step
        if time.time() - start < budget and not m.ida_auto.auto_is_ok():
            m.ida_auto.auto_wait()
        complete = bool(m.ida_auto.auto_is_ok())
    finally:
        ida_ida.inf_set_af(saved[0])
        ida_ida.inf_set_af2(saved[1])
    if hexrays_ready(m):
        m.ida_hexrays.clear_cached_cfuncs()
    op_save({})
    return {"complete": complete, "before": before, "after": m.ida_funcs.get_func_qty(), "warnings": warnings,
            "seconds": round(time.time() - start, 3)}


def op_function_candidates(args):
    # runs of code items in no function, in address order, over at most max_scan code items: rows
    # [start, end (exclusive), instructions, call refs, jump refs, data refs] to the run's start; scanned, truncated
    m = need_open()
    import ida_bytes, ida_xref
    limit = max(1, int(args.get("max_scan") or 2000000))
    calls = (ida_xref.fl_CF, ida_xref.fl_CN)
    jumps = (ida_xref.fl_JF, ida_xref.fl_JN)
    rows, scanned, truncated = [], 0, False
    run = None  # [start, end, count]

    def close():
        if run is None or rva_of(run[0]) is None or rva_of(run[1]) is None:
            return
        c = j = d = 0
        for x in m.idautils.XrefsTo(run[0], 0):
            if x.type in calls:
                c += 1
            elif x.type in jumps:
                j += 1
            elif not x.iscode:
                d += 1
        rows.append([rva_of(run[0]), rva_of(run[1]), run[2], c, j, d])

    for seg_ea in m.idautils.Segments():
        seg = m.ida_segment.getseg(seg_ea)
        if seg is None or not (seg.perm & m.ida_segment.SEGPERM_EXEC or seg.type == m.ida_segment.SEG_CODE):
            continue
        for head in m.idautils.Heads(seg.start_ea, seg.end_ea):
            if not ida_bytes.is_code(ida_bytes.get_flags(head)):
                close()
                run = None
                continue
            if scanned >= limit:
                truncated = True
                break
            scanned += 1
            if m.ida_funcs.get_func(head) is not None:
                close()
                run = None
            elif run is not None and run[1] == head:
                run[1] = head + ida_bytes.get_item_size(head)
                run[2] += 1
            else:
                close()
                run = [head, head + ida_bytes.get_item_size(head), 1]
        close()
        run = None
        if truncated:
            break
    return {"rows": rows, "scanned": scanned, "truncated": truncated}


MARK_PREFIX = "Corvus: "
# Migration only: the marks' prefix before the rename; such marks are replaced like ours.
LEGACY_MARK_PREFIX = "NDM: "


def op_set_marks(args):
    # replaces the marked positions titled with MARK_PREFIX with items [[rva, text]] and records the stamp (stamp_key, stamp).
    # Removing a slot (mark_position at BADADDR) shifts the later ones down, so slots are cleared from the top.
    m = need_open()
    import ida_idc, ida_moves
    badaddr = m.idautils.ida_idaapi.BADADDR
    used = 0
    while used < ida_moves.MAX_MARK_SLOT and ida_idc.get_marked_pos(used) != badaddr:
        used += 1
    removed = 0
    for slot in range(used - 1, -1, -1):
        if (ida_idc.get_mark_comment(slot) or "").startswith((MARK_PREFIX, LEGACY_MARK_PREFIX)):
            ida_idc.mark_position(badaddr, 0, 0, 0, slot, "")
            removed += 1
    slot = used - removed
    placed, failures = 0, []
    for rva, text in args.get("items") or []:
        ea = _state["base"] + rva
        if slot >= ida_moves.MAX_MARK_SLOT:
            failures.append("0x%X: all %d marked positions are in use" % (rva, ida_moves.MAX_MARK_SLOT))
            continue
        if not m.ida_bytes.is_mapped(ea):
            failures.append("0x%X: not mapped" % rva)
            continue
        ida_idc.mark_position(ea, 0, 0, 0, slot, MARK_PREFIX + text)
        slot += 1
        placed += 1
    if args.get("stamp_key"):
        stamp_node(True).hashset_buf(args["stamp_key"], args.get("stamp") or "")
    changed(m)
    return {"set": placed, "removed": removed, "failed": len(failures), "failures": failures}


OPS["analyzers"] = op_analyzers
OPS["function_candidates"] = op_function_candidates
OPS["reanalyze"] = op_reanalyze
OPS["set_marks"] = op_set_marks


def op_classes(args):
    # C++ classes among the local types: structs IDA marks as C++ objects, or with base classes or a vftable pointer.
    # rows [name, size, vftable rva or null, slots, [[base, offset, virtual]], functions named Class::*]
    need_open()
    import ida_typeinf as ti
    import re
    m = ida()
    til = ti.get_idati()
    rows = []
    for ordinal in range(1, ti.get_ordinal_limit(til)):
        t = ti.tinfo_t()
        if not t.get_numbered_type(til, ordinal) or not t.is_struct() or t.is_vftable():
            continue
        name = t.get_type_name()
        udt = ti.udt_type_data_t()
        if not name or not t.get_udt_details(udt):
            continue
        bases, vptr = [], None
        for u in udt:
            if u.is_baseclass():
                bases.append([u.type.get_type_name() or str(u.type), u.offset // 8, bool(u.is_virtbase())])
            elif u.name.startswith("__base_") and u.type.is_udt():  # the RTTI push's base subobjects
                bases.append([u.type.get_type_name() or u.name[7:], u.offset // 8, False])
            elif vptr is None and (u.is_vftable() or u.name in ("__vftable", "_vptr", "vfptr")):
                vptr = u
        if not (t.is_cpp_struct() or bases or vptr is not None):
            continue
        vftable, slots = None, 0
        if vptr is not None and vptr.type.is_ptr():
            table = vptr.type.get_pointed_object()
            table_name = table.get_type_name()
            if table.is_udt():
                slots = table.get_udt_nmembers()
            vord = ti.get_type_ordinal(til, table_name) if table_name else 0
            ea = ti.get_vftable_ea(vord) if vord else m.idautils.ida_idaapi.BADADDR
            if ea not in (0, m.idautils.ida_idaapi.BADADDR):
                vftable = rva_of(ea)
        rows.append([name, t.get_size(), vftable, slots, bases, 0])
    counts = {}
    for ea in m.idautils.Functions():
        short = m.ida_name.get_short_name(ea) or ""
        paren = short.find("(")
        cut = short.rfind("::", 0, paren if paren >= 0 else len(short))
        if cut > 0:
            owner = short[:cut]
            # also under the identifier the RTTI push names the class struct with
            for key in {owner, re.sub(r"[^0-9A-Za-z_]", "_", owner.replace("::", "__"))}:
                counts[key] = counts.get(key, 0) + 1
    for row in rows:
        row[5] = counts.get(row[0], 0)
    return {"rows": rows}


OPS["classes"] = op_classes


def watch_parent(parent):
    # POSIX has no job object: exit when the server dies, even while a request runs (stdin EOF is only seen between requests)
    try:
        import ctypes
        import signal
        if sys.platform.startswith("linux"):
            ctypes.CDLL(None, use_errno=True).prctl(1, signal.SIGKILL)  # PR_SET_PDEATHSIG
    except BaseException:
        pass
    while True:
        time.sleep(1.0)
        if os.getppid() != parent:
            os._exit(3)


def main():
    global _current
    if os.name != "nt":
        parent = os.getppid()
        try:
            os.setsid()
        except OSError:
            pass
        threading.Thread(target=watch_parent, args=(parent,), daemon=True).start()
    threading.Thread(target=heartbeat, daemon=True).start()
    threading.Thread(target=read_requests, daemon=True).start()
    send({"event": "ready", "protocol": PROTOCOL, "pid": os.getpid()})
    while True:
        r = _queue.get()
        if r is None:
            break
        fn = OPS.get(r.op)
        with _requests_lock:
            r.start = time.time()
            if r.timeout is not None:
                # answer before the server's limit: the margin carries a partial result back in time
                r.deadline = r.start + max(0.1, r.timeout - min(5.0, max(0.25, r.timeout * 0.1)))
            _current = r
        try:
            if fn is None:
                raise WorkerError("invalid_argument", "unknown op %r" % r.op)
            if r.stop is not None:
                raise stopped_error()  # cancelled while queued
            clear_cancel()
            send({"id": r.id, "ok": True, "result": fn(r.args)})
        except WorkerError as e:
            send({"id": r.id, "ok": False, "error": {"code": e.code, "message": str(e)}})
        except BaseException as e:
            if r.stop is not None:
                stopped = stopped_error()
                send({"id": r.id, "ok": False, "error": {"code": stopped.code, "message": "%s (%s)" % (stopped, e)}})
            else:
                sys.stderr.write(traceback.format_exc())
                sys.stderr.flush()
                send({"id": r.id, "ok": False, "error": {"code": "failed", "message": "%s: %s" % (type(e).__name__, e)}})
        finally:
            with _requests_lock:
                _current = None
                _requests.pop(r.id, None)
            clear_cancel()
        if r.op == "close":
            break
    if _state["open"]:
        try:
            ida().idapro.close_database(False)
        except BaseException:
            pass
    _proto.flush()
    os._exit(0)


if __name__ == "__main__":
    main()
