# idalib worker for NetDecompilerMcp.
# Protocol: one JSON object per line. Requests on stdin: {"id": n, "op": "...", "args": {...}}.
# Responses on stdout: {"id": n, "ok": true, "result": ...} or {"id": n, "ok": false, "error": {"code": ..., "message": ...}}.
# Unsolicited lines: {"event": "progress", "op": ..., "elapsed": seconds}.
# Anything IDA or Python prints goes to stderr: fd 1 is redirected there before idalib loads.
# Addresses on the wire are RVAs relative to the database image base.
# The user type, local, stack frame, member reference, declaration and Python ops adapt code from mrexodia/ida-pro-mcp
# (MIT, Copyright (c) 2025 Duncan Ogilvie); see THIRD-PARTY-NOTICES.md.
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
    sha = args.get("sha256") or ""
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

    for rva in args.get("functions") or []:
        if time.time() > deadline:
            skipped += 1
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
    return {"rows": rows, "decompiled": decompiled, "failed": failed, "skipped": skipped, "decompiler": True}


USER_NODE = "$ netdecompilermcp user types"  # altval(rva) = 1: a type set by the user; blob 'D': the user's declarations


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
    named = text.replace("(*)", "(*__ndm_x)", 1) if "(*)" in text else \
        text[:text.index("[")] + " __ndm_x" + text[text.index("["):] if "[" in text else text + " __ndm_x"
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

            errors = kernel.parse_decls(None, text.encode("utf-8"), printer, ti.PT_SIL | ti.PT_EMPTY | ti.PT_TYP)
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


def op_types(args):
    # named local types: rows [name, kind, size, members]; filter is a case-insensitive substring
    need_open()
    import ida_typeinf as ti
    til = ti.get_idati()
    wanted = (args.get("filter") or "").lower()
    kind = args.get("kind") or None
    offset, limit = max(0, int(args.get("offset") or 0)), max(1, int(args.get("limit") or 200))
    rows, total = [], 0
    for ordinal in range(1, ti.get_ordinal_limit(til)):
        t = ti.tinfo_t()
        if not t.get_numbered_type(til, ordinal):
            continue
        name = t.get_type_name()
        if not name or (wanted and wanted not in name.lower()):
            continue
        k = type_kind(ti, t)
        if kind and k != kind:
            continue
        total += 1
        if offset < total <= offset + limit:
            rows.append([name, k, t.get_size() if t.get_size() != ti.BADSIZE else -1, t.get_udt_nmembers() if t.is_udt() else (t.get_enum_nmembers() if t.is_enum() else 0)])
    return {"total": total, "rows": rows}


def op_type(args):
    # one named type: its C declaration and, for a struct or union, members [offset, name, type, size]
    need_open()
    import ida_typeinf as ti
    name = args.get("name") or ""
    t = ti.tinfo_t()
    if not name or not t.get_named_type(ti.get_idati(), name):
        raise WorkerError("not_found", "no type named %s" % name)
    members = []
    if t.is_udt():
        udt = ti.udt_type_data_t()
        t.get_udt_details(udt)
        for u in udt:
            if not u.is_gap():
                members.append([u.offset // 8, u.name, str(u.type), u.size // 8])
    decl = ti.print_tinfo("", 0, 0, ti.PRTYPE_MULTI | ti.PRTYPE_TYPE | ti.PRTYPE_DEF | ti.PRTYPE_SEMI, t, name, "") or str(t)
    size = t.get_size()
    return {"name": name, "kind": type_kind(ti, t), "size": size if size != ti.BADSIZE else -1, "decl": decl, "members": members}


def reapply_user_decls():
    # the user's declarations (blob 'D' of USER_NODE) win over recovered types of the same name
    n = user_node(False)
    blob = n.getblob(0, "D") if n is not None else None
    if blob:
        import idc
        idc.parse_decls(blob.decode("utf-8", "replace"), idc.PT_SILENT | idc.PT_REPLACE)


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
    for rva, decl in args.get("types") or []:
        result["items"].append(apply_user_type(m, ti, rva, decl or ""))
    for rva, offset, name, typ in args.get("stack") or []:
        result["items"].append(apply_stack(m, ti, rva, offset, name, typ))
    for rva, local, stack, name, typ in args.get("locals") or []:
        result["items"].append(apply_local(m, ti, rva, local, stack, name, typ))
    changed(m)
    key = args.get("stamp_key")
    if key:
        stamp_node(True).hashset_buf(key, args.get("stamp") or "")
    if args.get("save"):
        if not m.ida_loader.save_database(m.ida_loader.get_path(m.ida_loader.PATH_TYPE_IDB), 0):
            raise WorkerError("io_error", "save_database failed")
    result["seconds"] = round(time.time() - start, 3)
    return result


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
       "sync_patches": op_sync_patches, "apply_types": op_apply_types, "load_pdb": op_load_pdb, "virtual_targets": op_virtual_targets,
       "apply_user_types": op_apply_user_types, "frame": op_frame, "types": op_types, "type": op_type, "close": op_close, "sleep": op_sleep}


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
    global _busy
    if os.name != "nt":
        parent = os.getppid()
        try:
            os.setsid()
        except OSError:
            pass
        threading.Thread(target=watch_parent, args=(parent,), daemon=True).start()
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
