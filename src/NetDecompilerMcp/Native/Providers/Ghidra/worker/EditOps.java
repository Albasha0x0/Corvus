// The user's analysis edits (code, functions, data, undefined ranges) as apply_user_types items. The operations follow
// mrexodia/ida-pro-mcp's define_code / define_func / undefine / make_data (MIT) on Ghidra's listing; see THIRD-PARTY-NOTICES.md.
package ndm.ghidra;

import java.util.Set;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.DWordDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.DoubleDataType;
import ghidra.program.model.data.FloatDataType;
import ghidra.program.model.data.QWordDataType;
import ghidra.program.model.data.TerminatedStringDataType;
import ghidra.program.model.data.TerminatedUnicodeDataType;
import ghidra.program.model.data.WordDataType;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.symbol.SourceType;

/** Edits made inside {@link TypeOps#applyUserTypes}, so they share its transaction, stamp and save. */
final class EditOps {
    private EditOps() {
    }

    /** Edits applied after the declarations and before the types: analysis [[rva, kind, end or null, type or null]] in the order made. */
    static void before(Worker w, Worker.Request r, JsonArray items) throws Exception {
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

    private static String hex(long v) {
        return Long.toHexString(v).toUpperCase();
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
