# idalib worker for NetDecompilerMcp.
# Protocol: one JSON object per line. Requests on stdin: {"id": n, "op": "...", "args": {...}}.
# Responses on stdout: {"id": n, "ok": true, "result": ...} or {"id": n, "ok": false, "error": {"code": ..., "message": ...}}.
# Unsolicited lines: {"event": "progress", "op": ..., "elapsed": seconds}.
# Anything IDA or Python prints goes to stderr: fd 1 is redirected there before idalib loads.
# Addresses on the wire are RVAs relative to the database image base.
import json
import os
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
_busy = None  # (op, start time) while a request runs


def send(obj):
    line = json.dumps(obj, ensure_ascii=True, separators=(",", ":"))
    with _write_lock:
        _proto.write(line + "\n")
        _proto.flush()


class WorkerError(Exception):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


def heartbeat():
    while True:
        time.sleep(2.0)
        busy = _busy
        if busy is not None:
            send({"event": "progress", "op": busy[0], "elapsed": round(time.time() - busy[1], 1)})


# idalib is loaded on the first request so that load and license failures come back as responses.
_ida = None
_state = {"open": False, "base": 0}


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
    try:
        import ida_hexrays
        mods["ida_hexrays"] = ida_hexrays
    except BaseException:
        mods["ida_hexrays"] = None
    _ida = type("Ida", (), mods)
    return _ida


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
    if f is None:
        raise WorkerError("not_found", "no function contains rva 0x%X" % (ea - _state["base"]))
    return f


def hexrays_ready(m):
    hr = m.ida_hexrays
    try:
        return hr is not None and bool(hr.init_hexrays_plugin())
    except BaseException:
        return False


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
    rc = m.idapro.open_database(path, True, cmdline)
    if rc != 0:
        raise WorkerError("provider_unavailable", "open_database returned %d for %s" % (rc, path))
    _state["open"] = True
    m.ida_auto.auto_wait()
    _state["base"] = m.ida_nalt.get_imagebase()
    ftype = m.ida_ida.inf_get_filetype()
    if ftype != m.ida_ida.f_PE:
        raise WorkerError("unsupported", "IDA loaded the file with a loader other than its PE loader (file type %d, processor %s)"
                          % (ftype, m.ida_ida.inf_get_procname()))
    if not reuse:
        # IDA writes the packed .i64 only on save; persist the analysis now so a crash does not discard it.
        m.ida_loader.save_database(m.ida_loader.get_path(m.ida_loader.PATH_TYPE_IDB), 0)
    return info(m, reuse, time.time() - start)


def info(m, reused, seconds):
    return {"imagebase": _state["base"], "bits": 64 if m.ida_ida.inf_is_64bit() else (32 if m.ida_ida.inf_is_32bit_exactly() else 16),
            "processor": m.ida_ida.inf_get_procname(), "functions": m.ida_funcs.get_func_qty(),
            "decompiler": hexrays_ready(m), "reused": reused, "seconds": round(seconds, 3),
            "idb": m.ida_loader.get_path(m.ida_loader.PATH_TYPE_IDB)}


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
    # [start, end, name, flags (1 thunk, 2 library)] plus, with refs, the number of code references to the start
    m = need_open()
    refs = bool(args.get("refs"))
    out = []
    for ea in m.idautils.Functions():
        f = m.ida_funcs.get_func(ea)
        start, end = rva_of(f.start_ea), rva_of(f.end_ea)
        if start is None or end is None:
            continue
        flags = (1 if f.flags & m.ida_funcs.FUNC_THUNK else 0) | (2 if f.flags & m.ida_funcs.FUNC_LIB else 0)
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


def op_blocks(args):
    # basic blocks of the function containing rva: [start, end, instructions, kind, successors, switch]
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
        switch = ida_nalt.get_switch_info(last) is not None
        blocks.append([rva_of(b.start_ea), rva_of(b.end_ea), len(heads), kinds.get(b.type, "normal"), succs, switch])
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


def changed(m):
    # Hex-Rays caches pseudocode per function; names and comments must show in the next decompilation.
    if hexrays_ready(m):
        m.ida_hexrays.clear_cached_cfuncs()


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
    changed(m)
    return {"name": m.ida_name.get_name(ea) or ""}


def op_set_comment(args):
    m = need_open()
    ea = ea_of(args)
    repeatable = bool(args.get("repeatable"))
    if not m.ida_bytes.set_cmt(ea, args.get("text") or "", repeatable):
        raise WorkerError("invalid_argument", "IDA rejected the comment at rva 0x%X" % args["rva"])
    changed(m)
    return {"comment": m.ida_bytes.get_cmt(ea, repeatable) or ""}


def op_sync_patches(args):
    # Makes the database's patched bytes exactly items ([[rva, hex bytes]]): bytes patched before and not wanted now are
    # reverted to their original values, wanted bytes patched; code in the touched ranges is decoded again and its
    # functions reanalyzed. Reports the wanted bytes that could not be set (mismatches) or are not in the database (missing).
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
                if vt is not None and ti.apply_tinfo(base + vrva, vt, ti.TINFO_DEFINITE):
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


STAMP_NODE = "$ netdecompilermcp stamps"


def stamp_node(create):
    import ida_netnode
    n = ida_netnode.netnode(STAMP_NODE, 0, create)
    return n if n != ida_netnode.BADNODE else None


def op_apply_names(args):
    # items: [[rva, name or null, comment or null, make_function]]; empty name/comment removes it.
    m = need_open()
    start = time.time()
    badaddr = m.idautils.ida_idaapi.BADADDR
    flags = m.ida_name.SN_NOWARN | m.ida_name.SN_NOCHECK | m.ida_name.SN_FORCE
    named = name_failures = commented = created = 0
    failures = []
    for item in args.get("items") or []:
        rva, name, comment, make_function = item[0], item[1], item[2], item[3]
        ea = _state["base"] + rva
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
            if f is not None and f.start_ea == ea:
                ok = m.ida_funcs.set_func_cmt(f, comment, True)
            else:
                ok = m.ida_bytes.set_cmt(ea, comment, True)
            if ok:
                commented += 1
    changed(m)
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
    # IDA's PDB plugin on an explicit file: its types, prototypes and names go into the database.
    # trust_analysis: when IDA's own PDB load during auto-analysis succeeded, record the stamp without loading again.
    # On success the stamp is recorded under stamp_key, the names stamp is dropped (the PDB's names replace pushed ones,
    # so they are pushed again) and the database is saved.
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
        key = args.get("stamp_key")
        if key:
            stamps.hashset_buf(key, args.get("stamp") or "")
        changed(m)
        if not m.ida_loader.save_database(m.ida_loader.get_path(m.ida_loader.PATH_TYPE_IDB), 0):
            raise WorkerError("io_error", "save_database failed")
    result["seconds"] = round(time.time() - start, 3)
    return result


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


def op_sleep(args):
    # Test hook: holds the worker busy.
    time.sleep(float(args.get("seconds") or 0))
    return {}


OPS = {"hello": op_hello, "open": op_open, "rebase": op_rebase, "functions": op_functions, "decompile": op_decompile,
       "disasm": op_disasm, "disasm_range": op_disasm_range, "blocks": op_blocks, "xrefs_to": op_xrefs_to, "xrefs_from": op_xrefs_from, "set_name": op_set_name,
       "set_comment": op_set_comment, "apply_names": op_apply_names, "get_stamp": op_get_stamp, "save": op_save,
       "sync_patches": op_sync_patches, "apply_types": op_apply_types, "load_pdb": op_load_pdb, "close": op_close, "sleep": op_sleep}


def main():
    global _busy
    if os.name != "nt":
        try:
            os.setsid()
        except OSError:
            pass
    threading.Thread(target=heartbeat, daemon=True).start()
    send({"event": "ready", "protocol": PROTOCOL, "pid": os.getpid()})
    while True:
        line = sys.stdin.readline()
        if not line:
            break  # parent closed the pipe or died
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
            rid = req.get("id")
            op = req.get("op")
            args = req.get("args") or {}
        except (ValueError, AttributeError) as e:
            send({"id": None, "ok": False, "error": {"code": "invalid_argument", "message": "bad request line: %s" % e}})
            continue
        fn = OPS.get(op)
        if fn is None:
            send({"id": rid, "ok": False, "error": {"code": "invalid_argument", "message": "unknown op %r" % op}})
            continue
        _busy = (op, time.time())
        try:
            send({"id": rid, "ok": True, "result": fn(args)})
        except WorkerError as e:
            send({"id": rid, "ok": False, "error": {"code": e.code, "message": str(e)}})
        except BaseException as e:
            sys.stderr.write(traceback.format_exc())
            sys.stderr.flush()
            send({"id": rid, "ok": False, "error": {"code": "failed", "message": "%s: %s" % (type(e).__name__, e)}})
        finally:
            _busy = None
        if op == "close":
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
