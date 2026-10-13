# Guide: idapython

<!-- Generated from src/Corvus/Mcp/Guide.cs; run the tests with CORVUS_UPDATE_DOCS=1 to update. -->

ida_python: IDAPython in the image's IDA worker (idalib, headless). Off unless the server runs with --ida-scripting.
Environment: idaapi, idc, idautils and the ida_* modules (auto, bytes, entry, frame, funcs, gdl, hexrays, ida, lines, loader,
nalt, name, netnode, segment, typeinf, ua, xref) are imported. base is
the image base: IDA works in VAs (ea = base + rva); the other tools take either form. Globals persist between calls
(reset=true clears them). The last line, when an expression, is the result (its repr); print() goes to stdout. Output is
clipped at maxOutput per stream: return counts or slices of large lists, or page with an offset global.
The database: names, comments and types set with the other tools are pushed before the script runs. Script changes are not
journaled: a worker restart (crash, time limit) loses them unless persist=true saves the database; names and comments that
should survive and reach other tools and new builds belong in rename_native / comment_native / set_native_type instead.
Time: each call has the request limit (CORVUS_ENGINE_REQUEST_TIMEOUT, default 120 s). At the limit or on cancel the script
stops between Python statements (loops included); a native call (auto_wait, a decompilation) finishes first, and a worker
that does not answer within the grace is restarted from the saved database. Dialogs never wait: batch mode is on.
Quick reference (ea is a VA):
  functions: idautils.Functions(); ida_funcs.get_func(ea) (start_ea, end_ea, flags); ida_funcs.get_func_name(ea)
  names: ida_name.get_name(ea); ida_name.set_name(ea, "n", ida_name.SN_NOWARN); ida_name.get_name_ea(idaapi.BADADDR, "n")
  references: idautils.XrefsTo(ea, 0) / XrefsFrom(ea, 0) (x.frm, x.to, x.type, x.iscode); idautils.CodeRefsTo(ea, 0)
  bytes and items: ida_bytes.get_bytes(ea, n), .get_qword, .get_dword, .get_flags(ea), .is_code / .is_data / .is_strlit,
    .next_head(ea, end), .get_strlit_contents(ea, -1, ida_nalt.STRTYPE_C); idautils.Heads(start, end)
  disassembly: idc.generate_disasm_line(ea, 0); ida_ua.insn_t() with ida_ua.decode_insn(insn, ea); idc.print_operand(ea, n)
  pseudocode: cf = ida_hexrays.decompile(ea); str(cf); walk cf.body with a ida_hexrays.ctree_visitor_t (visit_expr, op cot_call)
  types: t = ida_typeinf.tinfo_t(); ida_nalt.get_tinfo(t, ea); ida_typeinf.apply_cdecl(ida_typeinf.get_idati(), ea, "int f(int);");
    idc.parse_decls("struct S { int a; };", 0); ida_typeinf.print_type(ea, ida_typeinf.PRTYPE_1LINE)
  segments: idautils.Segments(); ida_segment.getseg(ea) (name via ida_segment.get_segm_name, perm, start_ea, end_ea)
  comments: ida_bytes.set_cmt(ea, "text", False); ida_funcs.set_func_cmt(f, "text", True)
  analysis: ida_auto.plan_range(start, end); ida_auto.auto_wait() (blocks until done; reanalyze_native has a budget)
Prefer the typed tools for what they cover (find_xrefs, decompile_native, search_instructions, list_globals): they page,
merge the server's names and keep edits; use scripts for what they do not. get_engine_status (engine toolset) shows the
engine's own view of the database: language, compiler, entry points, memory blocks.
