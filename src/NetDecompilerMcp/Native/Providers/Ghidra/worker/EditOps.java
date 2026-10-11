// The user's analysis edits (code, functions, data, undefined ranges) and operand display formats as apply_user_types
// items. The operations follow mrexodia/ida-pro-mcp's define_code / define_func / undefine / make_data / set_op_type (MIT)
// on Ghidra's listing; see THIRD-PARTY-NOTICES.md.
package ndm.ghidra;

import java.util.Set;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonNull;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CallDepthChangeInfo;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DWordDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.DoubleDataType;
import ghidra.program.model.data.EnumDataType;
import ghidra.program.model.data.FloatDataType;
import ghidra.program.model.data.QWordDataType;
import ghidra.program.model.data.TerminatedStringDataType;
import ghidra.program.model.data.TerminatedUnicodeDataType;
import ghidra.program.model.data.WordDataType;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.CodeUnitFormat;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.Equate;
import ghidra.program.model.symbol.EquateTable;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SourceType;

/** Edits made inside {@link TypeOps#applyUserTypes}, so they share its transaction, stamp and save. */
final class EditOps {
    private EditOps() {
    }

    /** Program option: the user's enum member edits as JSON {"enum::member": value or null}, applied again after declarations. */
    static final String USER_ENUMS = "ndm_user_enums";

    /**
     * Edits applied after the declarations and before the types: enums [[enum, member, value or null]], then analysis
     * [[rva, kind, end or null, type or null]] in the order made.
     */
    static void before(Worker w, Worker.Request r, JsonArray items) throws Exception {
        for (JsonElement e : Worker.array(r.args, "enums")) {
            JsonArray m = e.getAsJsonArray();
            Long value = m.get(2).isJsonNull() ? null : m.get(2).getAsLong();
            JsonArray item = enumMember(w, m.get(0).getAsString(), m.get(1).getAsString(), value);
            if (item.get(3).getAsBoolean()) {
                JsonObject kept = userEnums(w);
                if (value == null) kept.add(item.get(2).getAsString(), JsonNull.INSTANCE);
                else kept.addProperty(item.get(2).getAsString(), value);
                w.program.getOptions(Worker.STAMPS).setString(USER_ENUMS, kept.toString());
            }
            items.add(item);
        }
        FrameOps.clears(w, r, items);
        for (JsonElement e : Worker.array(r.args, "analysis")) {
            JsonArray a = e.getAsJsonArray();
            long rva = a.get(0).getAsLong();
            String kind = a.get(1).getAsString();
            try {
                items.add(analysis(w, r, rva, kind, a.get(2).isJsonNull() ? null : a.get(2).getAsLong(), a.get(3).isJsonNull() ? null : a.get(3).getAsString()));
            }
            catch (ghidra.util.exception.CancelledException c) {
                throw c;
            }
            catch (Exception x) {
                items.add(item(rva, kind, false, "Ghidra refused the edit: " + x.getMessage(), null));
            }
        }
    }

    private static JsonObject userEnums(Worker w) {
        String kept = w.program.getOptions(Worker.STAMPS).getString(USER_ENUMS, "");
        return kept == null || kept.isEmpty() ? new JsonObject() : JsonParser.parseString(kept).getAsJsonObject();
    }

    /** The user's enum member edits again, after declarations replaced the enums. */
    static void reapplyEnums(Worker w) {
        for (var entry : userEnums(w).entrySet()) {
            String key = entry.getKey();
            int sep = key.indexOf("::");
            if (sep > 0) enumMember(w, key.substring(0, sep), key.substring(sep + 2), entry.getValue().isJsonNull() ? null : entry.getValue().getAsLong());
        }
    }

    /** Adds, changes or (null value) removes an enum member; a missing enum is created (4 bytes). */
    static JsonArray enumMember(Worker w, String enumName, String member, Long value) {
        String target = enumName + "::" + member;
        DataTypeManager dtm = w.program.getDataTypeManager();
        DataType dt = TypeOps.parseType(w, enumName);
        if (dt != null && !(dt instanceof ghidra.program.model.data.Enum))
            return FrameOps.item("enum", 0, target, false, enumName + " is a " + TypeOps.kind(dt) + ", not an enum", null, null, null);
        if (dt == null) {
            if (value == null) return FrameOps.item("enum", 0, target, true, null, null, null, "no enum " + enumName);
            dt = dtm.addDataType(new EnumDataType(CategoryPath.ROOT, enumName, 4, dtm), DataTypeConflictHandler.DEFAULT_HANDLER);
        }
        var en = (ghidra.program.model.data.Enum) dt;
        try {
            if (en.contains(member)) en.remove(member);
            if (value == null) return FrameOps.item("enum", 0, target, true, null, null, null, "removed");
            en.add(member, value);
        }
        catch (IllegalArgumentException e) {
            return FrameOps.item("enum", 0, target, false, "Ghidra refused " + target + ": " + e.getMessage(), null, null, null);
        }
        return FrameOps.item("enum", 0, target, true, null, null, null, target + " = 0x" + hex(value));
    }

    /** Edits applied after the locals: stack_deletes [[function, offset]], then operands [[rva, operand, display, detail or null]]. */
    static void after(Worker w, Worker.Request r, JsonArray items) throws Exception {
        for (JsonElement e : Worker.array(r.args, "stack_deletes")) {
            JsonArray s = e.getAsJsonArray();
            items.add(stackDelete(w, s.get(0).getAsLong(), s.get(1).getAsInt()));
        }
        for (JsonElement e : Worker.array(r.args, "operands")) {
            JsonArray o = e.getAsJsonArray();
            long rva = o.get(0).getAsLong();
            int n = o.get(1).getAsInt();
            String display = o.get(2).getAsString();
            String detail = o.get(3).isJsonNull() ? null : o.get(3).getAsString();
            try {
                items.add(operand(w, r, rva, n, display, detail));
            }
            catch (ghidra.util.exception.CancelledException c) {
                throw c;
            }
            catch (Exception x) {
                items.add(FrameOps.item("operand", rva, "operand " + n + " " + display, false, "Ghidra refused the edit: " + x.getMessage(), null, n, null));
            }
        }
    }

    private static String hex(long v) {
        return Long.toHexString(v).toUpperCase();
    }

    /** Removes the stack frame member at a frame offset; the return address slot is refused, a missing member is no change. */
    static JsonArray stackDelete(Worker w, long rva, int offset) {
        String target = "+0x" + Integer.toHexString(offset).toUpperCase();
        Function f = w.program.getFunctionManager().getFunctionContaining(w.space().getAddress(w.base + rva));
        if (f == null) return FrameOps.item("stack_delete", rva, target, false, "no function contains rva 0x" + hex(rva), null, offset, null);
        rva = w.rva(f.getEntryPoint());
        var sf = f.getStackFrame();
        int at = offset + FrameOps.low(sf);
        if (FrameOps.returnAddressOnStack(w) && at >= sf.getReturnAddressOffset() && at < sf.getReturnAddressOffset() + w.program.getDefaultPointerSize())
            return FrameOps.item("stack_delete", rva, target, false, target + " is the return address", "__return_address", offset, null);
        ghidra.program.model.listing.Variable v = sf.getVariableContaining(at);
        if (v == null || v.getStackOffset() != at) return FrameOps.item("stack_delete", rva, target, true, null, null, offset, "no member at " + target);
        String old = v.getName();
        sf.clearVariable(at);
        return FrameOps.item("stack_delete", rva, target, true, null, old, offset, "deleted");
    }

    /**
     * An operand's display: numeric formats and enum members as equates (the decompiler shows them too), offset as a memory
     * reference, stack as a stack reference at the stack depth there; default removes the user's equates and references.
     */
    static JsonArray operand(Worker w, Worker.Request r, long rva, int n, String display, String detail) throws Exception {
        String target = "operand " + n + " " + display + (detail != null ? " " + detail : "");
        Address a = w.space().getAddress(w.base + rva);
        Instruction ins = w.program.getMemory().contains(a) ? w.program.getListing().getInstructionAt(a) : null;
        if (ins == null) return operandItem(rva, n, target, false, "no instruction starts at rva 0x" + hex(rva), null);
        if (n < 0 || n >= ins.getNumOperands()) return operandItem(rva, n, target, false, "the instruction at rva 0x" + hex(rva) + " has no operand " + n, null);
        EquateTable equates = w.program.getEquateTable();
        ReferenceManager refs = w.program.getReferenceManager();
        Scalar scalar = ins.getScalar(n);
        if (scalar == null)
            for (Object o : ins.getOpObjects(n))
                if (o instanceof Scalar s) scalar = s;
        String error = null;
        switch (display) {
            case "default": {
                for (Equate eq : equates.getEquates(a, n)) {
                    eq.removeReference(a, n);
                    if (eq.getReferenceCount() == 0) equates.removeEquate(eq.getName());
                }
                for (Reference ref : refs.getReferencesFrom(a, n))
                    if (ref.getSource() == SourceType.USER_DEFINED) refs.delete(ref);
                break;
            }
            case "hex", "dec", "oct", "bin", "char", "enum": {
                if (scalar == null) return operandItem(rva, n, target, false, "operand " + n + " has no constant", null);
                long v = scalar.getValue();
                String name;
                if (display.equals("enum")) {
                    DataType dt = detail != null ? TypeOps.parseType(w, detail) : null;
                    if (!(dt instanceof ghidra.program.model.data.Enum en))
                        return operandItem(rva, n, target, false, "no enum named " + detail + " (declare_native_types declares one)", null);
                    name = ghidra.program.database.symbol.EquateManager.formatNameForEquate(en.getUniversalID(), v);
                }
                else name = switch (display) {
                    case "hex" -> "0x" + Long.toHexString(scalar.getUnsignedValue()).toUpperCase();
                    case "dec" -> Long.toString(scalar.getSignedValue());
                    case "oct" -> "0" + Long.toOctalString(scalar.getUnsignedValue());
                    case "bin" -> "0b" + Long.toBinaryString(scalar.getUnsignedValue());
                    default -> v >= 0x20 && v < 0x7F ? "'" + (char) v + "'" : null;
                };
                if (name == null) return operandItem(rva, n, target, false, "0x" + hex(v) + " is not a printable character", null);
                for (Equate eq : equates.getEquates(a, n)) eq.removeReference(a, n);
                Equate eq = equates.getEquate(name);
                if (eq == null) eq = equates.createEquate(name, v);
                else if (eq.getValue() != v) return operandItem(rva, n, target, false, "the equate " + name + " already stands for 0x" + hex(eq.getValue()), null);
                eq.addReference(a, n);
                break;
            }
            case "offset": {
                if (scalar == null) return operandItem(rva, n, target, false, "operand " + n + " has no constant", null);
                Address to = w.space().getAddress(scalar.getUnsignedValue());
                if (!w.program.getMemory().contains(to)) return operandItem(rva, n, target, false, "0x" + hex(scalar.getUnsignedValue()) + " is not an address in the image", null);
                Reference ref = refs.addMemoryReference(a, to, RefType.DATA, SourceType.USER_DEFINED, n);
                refs.setPrimary(ref, true);
                break;
            }
            case "stack": {
                Function f = w.program.getFunctionManager().getFunctionContaining(a);
                Register sp = w.program.getCompilerSpec().getStackPointer();
                if (f == null || scalar == null || !java.util.Arrays.asList(ins.getOpObjects(n)).contains(sp))
                    return operandItem(rva, n, target, false, "operand " + n + " is not a stack pointer access in a function", null);
                int depth = new CallDepthChangeInfo(f, r.monitor).getDepth(a);
                if (depth == Function.UNKNOWN_STACK_DEPTH_CHANGE || depth == Function.INVALID_STACK_DEPTH_CHANGE)
                    return operandItem(rva, n, target, false, "Ghidra does not know the stack depth at rva 0x" + hex(rva), null);
                refs.addStackReference(a, n, depth + (int) scalar.getSignedValue(), RefType.DATA, SourceType.USER_DEFINED);
                break;
            }
            case "struct":
                error = "Ghidra's listing has no struct offset display; type the pointer register's variable with set_native_local instead";
                break;
            default:
                error = "unknown operand display '" + display + "'";
        }
        if (error != null) return operandItem(rva, n, target, false, error, null);
        return operandItem(rva, n, target, true, null, CodeUnitFormat.DEFAULT.getRepresentationString(ins));
    }

    private static JsonArray operandItem(long rva, int n, String target, boolean applied, String error, String text) {
        return FrameOps.item("operand", rva, target, applied, error, null, n, text);
    }

    static JsonArray analysis(Worker w, Worker.Request r, long rva, String kind, Long end, String type) throws Exception {
        String target = kind + (type != null ? " " + type : "") + (end != null ? " to 0x" + hex(end) : "");
        Address a = w.space().getAddress(w.base + rva);
        Address last = end != null && end > rva ? w.space().getAddress(w.base + end - 1) : null;
        var memory = w.program.getMemory();
        if (!memory.contains(a) || (end != null && (last == null || !memory.contains(last))))
            return item(rva, target, false, "rva 0x" + hex(rva) + (end != null ? "-0x" + hex(end) : "") + " is not in the image", null);
        Listing listing = w.program.getListing();
        var functions = w.program.getFunctionManager();
        switch (kind) {
            case "undefine": {
                // at a function start without an end: the whole function
                Function f = functions.getFunctionAt(a);
                if (last == null && f != null) last = f.getBody().getMaxAddress();
                if (f != null) functions.removeFunction(a);
                if (last == null) {
                    CodeUnit cu = listing.getCodeUnitContaining(a);
                    a = cu != null ? cu.getMinAddress() : a;
                    last = cu != null ? cu.getMaxAddress() : a;
                }
                listing.clearCodeUnits(a, last, false);
                return item(rva, target, true, null, (last.subtract(a) + 1) + " byte(s) undefined");
            }
            case "code": {
                if (last == null && listing.getInstructionAt(a) != null) return item(rva, target, true, null, "already code");
                listing.clearCodeUnits(a, last != null ? last : a, false);
                var cmd = new DisassembleCommand(a, last != null ? new AddressSet(a, last) : null, true);
                cmd.applyTo(w.program, r.monitor);
                if (listing.getInstructionAt(a) == null) return item(rva, target, false, "the bytes at rva 0x" + hex(rva) + " do not decode as an instruction", null);
                return item(rva, target, true, null, cmd.getDisassembledAddressSet().getNumAddresses() + " byte(s) of code");
            }
            case "function": {
                Function f = functions.getFunctionAt(a);
                if (f != null) {
                    if (last != null && !f.getBody().getMaxAddress().equals(last)) f.setBody(new AddressSet(a, last));
                }
                else if (functions.getFunctionContaining(a) != null)
                    return item(rva, target, false, "rva 0x" + hex(rva) + " is inside the function at rva 0x" + hex(w.rva(functions.getFunctionContaining(a).getEntryPoint())), null);
                else {
                    if (listing.getInstructionAt(a) == null) new DisassembleCommand(a, last != null ? new AddressSet(a, last) : null, true).applyTo(w.program, r.monitor);
                    var cmd = new CreateFunctionCmd(null, a, last != null ? new AddressSet(a, last) : null, SourceType.USER_DEFINED);
                    if (!cmd.applyTo(w.program, r.monitor) || functions.getFunctionAt(a) == null)
                        return item(rva, target, false, "Ghidra did not make a function at rva 0x" + hex(rva) + ": " + cmd.getStatusMsg(), null);
                }
                f = functions.getFunctionAt(a);
                return item(rva, target, true, null, "function " + f.getName() + ", rva 0x" + hex(rva) + "-0x" + hex(CodeOps.end(w, f)));
            }
            case "data": {
                if (type == null || type.isBlank()) return item(rva, target, false, "data needs a type", null);
                DataType dt = dataType(w, type);
                if (dt == null) return item(rva, target, false, "the type does not parse (types it names must be declared first)", null);
                int length = dt.getLength();
                if (length <= 0 && end != null) length = (int) (end - rva);
                if (length > 0) listing.clearCodeUnits(a, a.add(length - 1), false);
                else listing.clearCodeUnits(a, a, false);
                try {
                    Data d = DataUtilities.createData(w.program, a, dt, length > 0 ? length : -1, DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA);
                    if (!BUILTIN.contains(baseName(type))) {
                        // recovered types leave a user-typed global alone
                        Set<Long> user = TypeOps.userTyped(w);
                        user.add(rva);
                        TypeOps.setUserTyped(w, user);
                    }
                    return item(rva, target, true, null, d.getDataType().getDisplayName() + ", " + d.getLength() + " bytes");
                }
                catch (Exception e) {
                    return item(rva, target, false, "Ghidra did not make " + type + " at rva 0x" + hex(rva) + ": " + e.getMessage(), null);
                }
            }
            default:
                return item(rva, target, false, "unknown analysis edit '" + kind + "'", null);
        }
    }

    private static final Set<String> BUILTIN = Set.of("byte", "word", "dword", "qword", "float", "double", "string", "string16");

    /** The count of "dword[8]", or null without one. */
    private static Integer count(String text) {
        String t = text.trim();
        if (!t.endsWith("]") || t.indexOf('[') <= 0) return null;
        try {
            int n = Integer.decode(t.substring(t.lastIndexOf('[') + 1, t.length() - 1).trim());
            return n > 0 ? n : null;
        }
        catch (NumberFormatException e) {
            return null; // a C array such as "char[LEN]" parses as a whole
        }
    }

    private static String baseName(String text) {
        String t = text.trim();
        return (count(t) != null ? t.substring(0, t.lastIndexOf('[')).trim() : t).toLowerCase();
    }

    /** byte, word, dword, qword, float, double, string, string16 or a C type, each with an optional [count]. */
    static DataType dataType(Worker w, String text) {
        Integer count = count(text);
        String t = count != null ? text.trim().substring(0, text.trim().lastIndexOf('[')).trim() : text.trim();
        DataType base;
        switch (t.toLowerCase()) {
            case "byte": base = ByteDataType.dataType; break;
            case "word": base = WordDataType.dataType; break;
            case "dword": base = DWordDataType.dataType; break;
            case "qword": base = QWordDataType.dataType; break;
            case "float": base = FloatDataType.dataType; break;
            case "double": base = DoubleDataType.dataType; break;
            case "string":
                if (count != null) return new ArrayDataType(ghidra.program.model.data.CharDataType.dataType, count, 1);
                return TerminatedStringDataType.dataType;
            case "string16":
                if (count != null) return new ArrayDataType(ghidra.program.model.data.WideChar16DataType.dataType, count, 2);
                return TerminatedUnicodeDataType.dataType;
            default:
                base = TypeOps.parseType(w, t);
        }
        if (base == null) return null;
        return count != null ? new ArrayDataType(base, count, base.getLength()) : base;
    }

    private static JsonArray item(long rva, String target, boolean applied, String error, String text) {
        return FrameOps.item("analysis", rva, target, applied, error, null, null, text);
    }
}
