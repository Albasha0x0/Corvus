using System.Text;
using System.Text.Json;
using NetDecompilerMcp.Core;

namespace NetDecompilerMcp.Native.Annotations;

/// <summary>Renders the saved names, comments and user types of an image as an IDAPython / Ghidra script or JSON (Ghidra: names and comments). Addresses are
/// RVAs, rebased to the database's own image base at run time, so the script applies regardless of where the image
/// is loaded.</summary>
public static class AnnotationExport
{
    private static readonly JsonSerializerOptions IndentedJson = new() { WriteIndented = true };

    public enum Format { Ida, Ghidra, Json, Header }

    public static Format ParseFormat(string? format) => (format ?? "json").Trim().ToLowerInvariant() switch
    {
        "ida" or "idapython" or "idc" => Format.Ida,
        "ghidra" => Format.Ghidra,
        "json" or "" => Format.Json,
        "header" or "h" => Format.Header,
        _ => throw new ToolError(ErrorCode.InvalidArgument, $"Unknown format '{format}'.", "use ida, ghidra, json or header"),
    };

    public static string Render(NativeAnnotations ann, Format format) => format switch
    {
        Format.Ida => Ida(ann),
        Format.Ghidra => Ghidra(ann),
        _ => Json(ann),
    };

    public static string Extension(Format format) => format switch { Format.Ida => ".py", Format.Ghidra => ".java", Format.Header => ".h", _ => ".json" };

    private static string Ida(NativeAnnotations ann)
    {
        var sb = new StringBuilder();
        sb.AppendLine("# IDAPython: apply names and comments exported from NetDecompilerMcp.");
        sb.AppendLine($"# Source: {ann.FilePath}  sha256 {ann.Sha256}");
        sb.AppendLine("import idaapi, idc");
        sb.AppendLine("base = idaapi.get_imagebase()");
        foreach (var (rva, name) in ann.Names())
            sb.AppendLine($"idc.set_name(base + 0x{rva:X}, {Py(name)}, idc.SN_NOWARN)");
        foreach (var (rva, comment) in ann.Comments())
            sb.AppendLine($"idc.set_cmt(base + 0x{rva:X}, {Py(comment)}, 0)");
        var types = ann.UserTypes;
        if (!types.IsEmpty)
        {
            sb.Append(IdaTypeHelpers);
            foreach (var d in types.Declarations) sb.AppendLine($"ndm_declare({Py(d)})");
            var batch = types.ToBatch();
            foreach (var e in batch.EnumMembers)
                sb.AppendLine($"ndm_enum({Py(e.Enum)}, {Py(e.Member)}, {(e.Value is { } v ? v.ToString(System.Globalization.CultureInfo.InvariantCulture) : "None")})");
            foreach (var a in types.Analysis)
                sb.AppendLine($"ndm_analysis(0x{a.Rva:X}, {Py(a.Kind)}, {(a.End is { } e ? $"0x{e:X}" : "None")}, {PyOrNone(a.Type)})");
            foreach (var (rva, t) in types.Types.OrderBy(t => t.Key)) sb.AppendLine($"ndm_type(0x{rva:X}, {Py(t)})");
            foreach (var s in batch.StackVars.Where(s => !s.Delete))
                sb.AppendLine($"ndm_stack(0x{s.Function:X}, {s.Offset}, {PyOrNone(s.Name)}, {PyOrNone(s.Type)})");
            foreach (var l in types.Locals.OrderBy(l => l.Key).SelectMany(l => l.Value))
                sb.AppendLine($"ndm_local(0x{l.Function:X}, {Py(l.Local)}, {(l.Stack is { } k ? k.ToString(System.Globalization.CultureInfo.InvariantCulture) : "None")}, {PyOrNone(l.Name)}, {PyOrNone(l.Type)})");
            foreach (var s in batch.StackVars.Where(s => s.Delete))
                sb.AppendLine($"ndm_stack_delete(0x{s.Function:X}, {s.Offset})");
            foreach (var o in types.Operands.OrderBy(o => o.Key).Select(o => o.Value))
                sb.AppendLine(FormattableString.Invariant($"ndm_operand(0x{o.Rva:X}, {o.Operand}, {Py(o.Display)}, {PyOrNone(o.Detail)})"));
            sb.AppendLine("if ndm_failed: print('NetDecompilerMcp: not applied: ' + '; '.join(ndm_failed))");
        }
        sb.AppendLine($"print('NetDecompilerMcp: applied {ann.NameCount} name(s), {ann.CommentCount} comment(s) and {types.Count} user type(s)')");
        return sb.ToString();
    }

    // Mirrors the worker's apply_user_types (Native/Providers/Ida/ida_worker.py) for a database outside the server.
    private const string IdaTypeHelpers = """
        import ida_auto, ida_bytes, ida_frame, ida_funcs, ida_hexrays, ida_nalt, ida_typeinf, ida_ua
        ndm_failed = []
        def ndm_data(ea, stop, text):
            base_t, n = text.strip(), None
            if base_t.endswith("]") and "[" in base_t:
                try: n, base_t = int(base_t[base_t.rindex("[") + 1:-1], 0), base_t[:base_t.rindex("[")].strip()
                except ValueError: n = None
            low = base_t.lower()
            if low in ("string", "string16"):
                w = 1 if low == "string" else 2
                length = n * w if n else (stop - ea if stop else 0)
                ida_bytes.del_items(ea, ida_bytes.DELIT_SIMPLE, max(length, 1))
                return ida_bytes.create_strlit(ea, length, ida_nalt.STRTYPE_C if w == 1 else ida_nalt.STRTYPE_C_16)
            sizes = {"byte": (1, ida_bytes.byte_flag), "word": (2, ida_bytes.word_flag), "dword": (4, ida_bytes.dword_flag), "qword": (8, ida_bytes.qword_flag),
                     "float": (4, ida_bytes.float_flag), "double": (8, ida_bytes.double_flag)}
            if low in sizes:
                total = sizes[low][0] * (n or 1)
                ida_bytes.del_items(ea, ida_bytes.DELIT_SIMPLE, total)
                return ida_bytes.create_data(ea, sizes[low][1](), total, idaapi.BADADDR)
            t = ndm_parse(text)
            if t is None: return False
            ida_bytes.del_items(ea, ida_bytes.DELIT_SIMPLE, max(1, t.get_size()))
            return ida_typeinf.apply_tinfo(ea, t, ida_typeinf.TINFO_DEFINITE)
        def ndm_analysis(rva, kind, end, text):
            ea = base + rva
            stop = base + end if end is not None else None
            f = ida_funcs.get_func(ea)
            if kind == "undefine":
                if f is not None and f.start_ea == ea:
                    stop = stop or f.end_ea
                    ida_funcs.del_func(ea)
                ok = ida_bytes.del_items(ea, ida_bytes.DELIT_EXPAND, (stop - ea) if stop else 1)
            elif kind == "code":
                ida_bytes.del_items(ea, ida_bytes.DELIT_SIMPLE, (stop - ea) if stop else 1)
                at = ea
                while at < (stop or ea + 1):
                    n = ida_ua.create_insn(at)
                    if n <= 0: break
                    at += n
                ok = at > ea
                if ok and stop is None: ida_auto.auto_make_code(ea); ida_auto.auto_wait()
            elif kind == "function":
                if f is not None and f.start_ea == ea: ok = stop is None or ida_funcs.set_func_end(ea, stop)
                else: ok = ida_funcs.add_func(ea, stop if stop is not None else idaapi.BADADDR)
            else:
                ok = ndm_data(ea, stop, text or "")
            if not ok: ndm_failed.append('%s 0x%X' % (kind, rva))
        def ndm_enum(enum, member, value):
            t = ida_typeinf.tinfo_t()
            if not t.get_named_type(None, enum):
                if value is None: return
                t.create_enum(ida_typeinf.enum_type_data_t()); t.set_named_type(None, enum)
                t = ida_typeinf.tinfo_t(); t.get_named_type(None, enum)
            idx, _ = t.get_edm(member)
            try:
                if value is None: ok = idx < 0 or t.del_edm(idx) == 0
                else: ok = (t.edit_edm(idx, value, ida_typeinf.DEFMASK64, 0) if idx >= 0 else t.add_edm(member, value)) == 0
            except ValueError: ok = False
            if not ok: ndm_failed.append('enum %s::%s' % (enum, member))
        def ndm_stack_delete(rva, offset):
            f = ida_funcs.get_func(base + rva)
            frame = ida_typeinf.tinfo_t()
            if f is None or not ida_frame.get_func_frame(frame, f): ndm_failed.append('stack 0x%X' % rva); return
            udt = ida_typeinf.udt_type_data_t()
            frame.get_udt_details(udt)
            u = next((m for m in udt if m.offset // 8 == offset and not m.is_gap()), None)
            if u and not ida_frame.delete_frame_members(f, offset, offset + max(1, u.size // 8)): ndm_failed.append('stack 0x%X+%d' % (rva, offset))
        def ndm_operand(rva, n, display, detail):
            ea = base + rva
            if display == "enum": ok = ida_bytes.op_enum(ea, n, idc.get_enum(detail), 0)
            elif display == "struct":
                name, _, delta = detail.partition("+")
                t = ida_typeinf.tinfo_t()
                ok = t.get_named_type(None, name.strip()) and idc.op_stroff(ea, n, t.get_tid(), int(delta.strip() or "0", 0))
            elif display == "offset": ok = idc.op_plain_offset(ea, n, 0)
            else: ok = {"hex": ida_bytes.op_hex, "dec": ida_bytes.op_dec, "oct": ida_bytes.op_oct, "bin": ida_bytes.op_bin, "char": ida_bytes.op_chr,
                        "stack": ida_bytes.op_stkvar}[display](ea, n)
            if not ok: ndm_failed.append('operand %d at 0x%X' % (n, rva))
        def ndm_parse(text):
            text = text.strip().rstrip(";").strip()
            named = text.replace("(*)", "(*__ndm_x)", 1) if "(*)" in text else \
                text[:text.index("[")] + " __ndm_x" + text[text.index("["):] if "[" in text else text + " __ndm_x"
            for c in (text + ";", named + ";"):
                for f in (ida_typeinf.PT_SIL, ida_typeinf.PT_SIL | ida_typeinf.PT_TYP):
                    t = ida_typeinf.tinfo_t()
                    if ida_typeinf.parse_decl(t, None, c, f) is not None and not t.empty():
                        return t
            t = ida_typeinf.tinfo_t()
            return t if t.get_named_type(None, text) else None
        def ndm_declare(text):
            if idc.parse_decls(text, idc.PT_SILENT | idc.PT_REPLACE): ndm_failed.append('declarations ' + text[:40])
        def ndm_type(rva, text):
            t = ndm_parse(text)
            if t is None or not ida_typeinf.apply_tinfo(base + rva, t, ida_typeinf.TINFO_DEFINITE): ndm_failed.append('type 0x%X' % rva)
        def ndm_stack(rva, offset, name, text):
            f = ida_funcs.get_func(base + rva)
            frame = ida_typeinf.tinfo_t()
            if f is None or not ida_frame.get_func_frame(frame, f): ndm_failed.append('stack 0x%X' % rva); return
            udt = ida_typeinf.udt_type_data_t()
            frame.get_udt_details(udt)
            u = next((m for m in udt if m.offset // 8 == offset and not m.is_gap()), None)
            t = ndm_parse(text) if text else (ida_typeinf.tinfo_t(u.type) if u else None)
            if t is None: ndm_failed.append('stack 0x%X+%d' % (rva, offset)); return
            old = u.name if u else 'var_%X' % offset
            if u: ida_frame.delete_frame_members(f, offset, offset + max(1, u.size // 8))
            if not ida_frame.define_stkvar(f, name or old, offset - ida_frame.frame_off_retaddr(f), t):
                ndm_failed.append('stack 0x%X+%d' % (rva, offset))
        def ndm_local(rva, local, stack, name, text):
            ea = base + rva
            cf = ida_hexrays.decompile(ea) if ida_hexrays.init_hexrays_plugin() else None
            lvars = list(cf.get_lvars()) if cf else []
            lv = next((v for v in lvars if stack is not None and v.is_stk_var() and v.get_stkoff() == stack), None) \
                or next((v for v in lvars if v.name == local), None) or next((v for v in lvars if name and v.name == name), None)
            if lv is None: ndm_failed.append('local %s at 0x%X' % (local, rva)); return
            if name:
                s = ida_hexrays.lvar_saved_info_t(); s.ll = lv; s.name = name
                ida_hexrays.modify_user_lvar_info(ea, ida_hexrays.MLI_NAME, s)
            if text:
                t = ndm_parse(text)
                s = ida_hexrays.lvar_saved_info_t(); s.ll = lv
                if t is not None: s.type = t
                if t is None or not ida_hexrays.modify_user_lvar_info(ea, ida_hexrays.MLI_TYPE, s): ndm_failed.append('local %s type at 0x%X' % (local, rva))

        """;

    private static string PyOrNone(string? s) => s == null ? "None" : Py(s);

    private static string Ghidra(NativeAnnotations ann)
    {
        var sb = new StringBuilder();
        sb.AppendLine("// Ghidra script: apply names and comments exported from NetDecompilerMcp.");
        sb.AppendLine($"// Source: {ann.FilePath}  sha256 {ann.Sha256}");
        sb.AppendLine("// @category NetDecompilerMcp");
        if (ann.UserTypes.Count > 0) sb.AppendLine($"// {ann.UserTypes.Count} user type(s) (declarations, enum members, analysis edits, prototypes, locals, stack variables, operand formats) are in the IDA and JSON exports only.");
        sb.AppendLine("import ghidra.app.script.GhidraScript;");
        sb.AppendLine("import ghidra.program.model.address.Address;");
        sb.AppendLine("import ghidra.program.model.symbol.SourceType;");
        sb.AppendLine("public class ApplyAnnotations extends GhidraScript {");
        sb.AppendLine("  public void run() throws Exception {");
        sb.AppendLine("    Address base = currentProgram.getImageBase();");
        foreach (var (rva, name) in ann.Names())
            sb.AppendLine($"    createLabel(base.add(0x{rva:X}L), {Java(name)}, true, SourceType.USER_DEFINED);");
        foreach (var (rva, comment) in ann.Comments())
            sb.AppendLine($"    setPlateComment(base.add(0x{rva:X}L), {Java(comment)});");
        sb.AppendLine($"    println(\"NetDecompilerMcp: applied {ann.NameCount} name(s) and {ann.CommentCount} comment(s)\");");
        sb.AppendLine("  }");
        sb.AppendLine("}");
        return sb.ToString();
    }

    private static string Json(NativeAnnotations ann)
    {
        var doc = new
        {
            path = ann.FilePath,
            sha256 = ann.Sha256,
            imageBase = ann.ImageBase,
            names = ann.Names().Select(n => new { rva = n.Rva, name = n.Name }),
            comments = ann.Comments().Select(c => new { rva = c.Rva, comment = c.Comment }),
            declarations = ann.UserTypes.Declarations,
            types = ann.UserTypes.Types.OrderBy(t => t.Key).Select(t => new { rva = t.Key, type = t.Value }),
            stackVars = ann.UserTypes.StackVars.OrderBy(s => s.Key).SelectMany(s => s.Value)
                .Select(s => new { function = s.Function, offset = s.Offset, name = s.Name, type = s.Type, delete = s.Delete }),
            locals = ann.UserTypes.Locals.OrderBy(l => l.Key).SelectMany(l => l.Value)
                .Select(l => new { function = l.Function, local = l.Local, stack = l.Stack, name = l.Name, type = l.Type }),
            analysis = ann.UserTypes.Analysis.Select(a => new { rva = a.Rva, kind = a.Kind, end = a.End, type = a.Type }),
            operands = ann.UserTypes.Operands.OrderBy(o => o.Key).Select(o => new { rva = o.Value.Rva, operand = o.Value.Operand, display = o.Value.Display, detail = o.Value.Detail }),
            enumMembers = ann.UserTypes.ToBatch().EnumMembers.Select(e => new { @enum = e.Enum, member = e.Member, value = e.Value }),
        };
        return JsonSerializer.Serialize(doc, IndentedJson);
    }

    private static string Py(string s) => "\"" + s.Replace("\\", "\\\\").Replace("\"", "\\\"").Replace("\n", "\\n").Replace("\r", "") + "\"";
    private static string Java(string s) => Py(s);
}
