// Decompiler variables are renamed and retyped through HighFunctionDBUtil.updateDBVariable.
package corvus.ghidra;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonNull;
import com.google.gson.JsonObject;

import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.StackFrame;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.HighFunctionDBUtil.ReturnCommitOption;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.util.FillOutStructureHelper;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.Undefined;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.LocalSymbolMap;
import ghidra.program.model.symbol.SourceType;

/**
 * Stack frames and decompiler locals. Frame offsets count from the frame's lowest address (the bottom of the locals),
 * as the IDA worker reports them; Ghidra's stack offsets are relative to the stack pointer at entry.
 */
final class FrameOps {
    private FrameOps() {
    }

    /** The stack offset of the frame's lowest address. */
    static int low(StackFrame sf) {
        return sf.growsNegative() ? -sf.getLocalSize() : 0;
    }

    /** Whether the return address is on the stack at entry (x86), so its slot is listed and refused for edits. */
    static boolean returnAddressOnStack(Worker w) {
        return w.program.getLanguage().getProcessor().toString().equalsIgnoreCase("x86");
    }

    private static String kind(StackFrame sf, int stackOffset) {
        return sf.isParameterOffset(stackOffset) ? "arg" : "local";
    }

    /**
     * members [offset, name, type, size, kind (local, arg, special)]; locals [name, type, location, stack offset or
     * null, argument, user name, user type]; Ghidra keeps saved registers among the locals, so saved_regs is 0.
     */
    static JsonElement frame(Worker w, Worker.Request r) throws Exception {
        Function f = CodeOps.functionAt(w, w.addr(r.args, "rva"));
        StackFrame sf = f.getStackFrame();
        int low = low(sf);
        JsonArray members = new JsonArray();
        boolean retaddr = returnAddressOnStack(w);
        int ret = sf.getReturnAddressOffset();
        int ptr = w.program.getDefaultPointerSize();
        boolean listedReturn = false;
        for (Variable v : sf.getStackVariables()) {
            int off = v.getStackOffset();
            if (retaddr && !listedReturn && off > ret) {
                members.add(member(ret - low, "__return_address", "void *", ptr, "special"));
                listedReturn = true;
            }
            members.add(member(off - low, v.getName(), v.getDataType().getDisplayName(), v.getLength(), kind(sf, off)));
            if (retaddr && off == ret) listedReturn = true;
        }
        if (retaddr && !listedReturn) members.add(member(ret - low, "__return_address", "void *", ptr, "special"));
        JsonObject o = new JsonObject();
        o.addProperty("start", w.rva(f.getEntryPoint()));
        o.addProperty("name", f.getName());
        o.addProperty("frame_size", sf.getLocalSize());
        o.addProperty("saved_regs", 0);
        o.addProperty("retaddr", ret - low);
        o.add("members", members);
        JsonArray locals = new JsonArray();
        o.add("locals", locals);
        o.add("decompile_error", JsonNull.INSTANCE);
        if (r.args.has("locals") && !r.args.get("locals").getAsBoolean()) return o;
        HighFunction hf;
        try {
            hf = high(w, f, r);
        }
        catch (Worker.WorkerError e) {
            o.addProperty("decompile_error", e.getMessage());
            return o;
        }
        for (Iterator<HighSymbol> it = hf.getLocalSymbolMap().getSymbols(); it.hasNext();) {
            HighSymbol s = it.next();
            VariableStorage storage = s.getStorage();
            JsonArray row = new JsonArray();
            row.add(s.getName());
            row.add(s.getDataType().getDisplayName());
            row.add(storage.isStackStorage() ? "stack" : storage.isRegisterStorage() ? storage.getRegister().getName() : "");
            if (storage.isStackStorage()) row.add(storage.getStackOffset() - low);
            else row.add(JsonNull.INSTANCE);
            row.add(s.isParameter());
            row.add(s.isNameLocked());
            row.add(s.isTypeLocked());
            locals.add(row);
        }
        return o;
    }

    private static JsonArray member(int offset, String name, String type, int size, String kind) {
        JsonArray m = new JsonArray();
        m.add(offset);
        m.add(name);
        m.add(type);
        m.add(size);
        m.add(kind);
        return m;
    }

    private static HighFunction high(Worker w, Function f, Worker.Request r) throws Exception {
        if (!Worker.decompilerPresent()) throw new Worker.WorkerError("unsupported", "Ghidra's native decompiler is not available");
        DecompileResults res = CodeOps.results(w, f, w.decompileTimeout, r.monitor);
        if (res.getHighFunction() == null) throw new Worker.WorkerError("failed", "decompiling " + f.getName() + " gave no variables");
        return res.getHighFunction();
    }

    /** [kind, rva, target, applied, error, resolved, stack, text]. */
    static JsonArray item(String kind, long rva, String target, boolean applied, String error, String resolved, Integer stack, String text) {
        JsonArray a = new JsonArray();
        a.add(kind);
        a.add(rva);
        a.add(target);
        a.add(applied);
        if (error == null) a.add(JsonNull.INSTANCE);
        else a.add(error);
        if (resolved == null) a.add(JsonNull.INSTANCE);
        else a.add(resolved);
        if (stack == null) a.add(JsonNull.INSTANCE);
        else a.add(stack);
        if (text == null) a.add(JsonNull.INSTANCE);
        else a.add(text);
        return a;
    }

    /**
     * Names and/or types the stack frame member at a frame offset; a type at an offset without a member creates one.
     * The return address slot is refused.
     */
    static JsonArray applyStack(Worker w, long rva, int offset, String name, String type) {
        String target = "+0x" + Integer.toHexString(offset).toUpperCase();
        Function f = w.program.getFunctionManager().getFunctionContaining(w.space().getAddress(w.base + rva));
        if (f == null) return item("stack", rva, target, false, "no function contains rva 0x" + Long.toHexString(rva).toUpperCase(), null, offset, null);
        rva = w.rva(f.getEntryPoint());
        StackFrame sf = f.getStackFrame();
        int at = offset + low(sf);
        int ptr = w.program.getDefaultPointerSize();
        if (returnAddressOnStack(w) && at >= sf.getReturnAddressOffset() && at < sf.getReturnAddressOffset() + ptr)
            return item("stack", rva, target, false, target + " is the return address", "__return_address", offset, null);
        Variable existing = null;
        for (Variable v : sf.getStackVariables())
            if (v.getStackOffset() == at) existing = v;
        String old = existing != null ? existing.getName() : null;
        rememberOriginal(w, rva, offset, existing);
        if (name != null)
            for (Variable v : f.getAllVariables())
                if (v.getName().equals(name) && v != existing)
                    return item("stack", rva, target, false, "the function already has a variable named " + name, old, offset, null);
        DataType dt;
        if (type != null) {
            dt = TypeOps.parseType(w, type);
            if (dt == null) return item("stack", rva, target, false, "the type does not parse (types it names must be declared first)", old, offset, null);
        }
        else if (existing != null) dt = existing.getDataType();
        else return item("stack", rva, target, false, "no stack member at " + target + ": give a type to create one", null, offset, null);
        try {
            if (existing != null && type == null) existing.setName(name, SourceType.USER_DEFINED);
            else {
                String use = name != null ? name : old != null ? old : (at < 0 ? "local_" : "param_") + Integer.toHexString(Math.abs(at));
                DataType oldType = existing != null ? existing.getDataType() : null;
                if (existing != null) sf.clearVariable(at);
                try {
                    sf.createVariable(use, at, dt, SourceType.USER_DEFINED);
                }
                catch (Exception e) {
                    if (oldType != null) sf.createVariable(old, at, oldType, SourceType.USER_DEFINED);
                    throw e;
                }
            }
        }
        catch (Exception e) {
            return item("stack", rva, target, false, "Ghidra did not change the stack member at " + target + ": " + e.getMessage(), old, offset, null);
        }
        for (Variable v : f.getStackFrame().getStackVariables())
            if (v.getStackOffset() == at)
                return item("stack", rva, target, true, null, old, offset, v.getDataType().getDisplayName() + " " + v.getName());
        return item("stack", rva, target, false, "the stack member is gone after the edit", old, offset, null);
    }

    /**
     * The struct a pointer local is used as, from its loads and stores (Ghidra's FillOutStructureHelper), as a C
     * declaration other engines parse too: undefinedN become plain integer types, gaps become char arrays. Nothing in the
     * program changes; the tool declares the struct and retypes the local as kept edits. Args: rva, local, stack, name.
     */
    static JsonElement inferStruct(Worker w, Worker.Request r) throws Exception {
        long rva = r.args.get("rva").getAsLong();
        String local = r.args.get("local").getAsString(), name = r.args.get("name").getAsString();
        Integer stack = r.args.has("stack") && !r.args.get("stack").isJsonNull() ? r.args.get("stack").getAsInt() : null;
        Function f = w.program.getFunctionManager().getFunctionAt(w.space().getAddress(w.base + rva));
        if (f == null) throw new Worker.WorkerError("not_found", "no function at rva 0x" + Long.toHexString(rva).toUpperCase());
        HighFunction hf = high(w, f, r);
        HighSymbol s = find(hf, low(f.getStackFrame()), local, stack, null);
        if (s == null || s.getHighVariable() == null) throw new Worker.WorkerError("not_found", f.getName() + " has no local '" + local + "'");
        long deadline = System.nanoTime() + w.decompileTimeout * 1_000_000_000L;
        DecompInterface d = w.decompilers.acquire(deadline);
        Structure st;
        try {
            st = new FillOutStructureHelper(w.program, r.monitor).processStructure(s.getHighVariable(), f, true, false, d);
        }
        finally {
            w.decompilers.release(d);
        }
        if (st == null || st.getNumDefinedComponents() == 0)
            throw new Worker.WorkerError("not_found", local + " in " + f.getName() + " is not used as a pointer to fields");
        StringBuilder sb = new StringBuilder("struct ").append(name).append(" {\n");
        int at = 0, fields = 0;
        for (DataTypeComponent c : st.getDefinedComponents()) {
            if (c.getOffset() < at) continue;
            if (c.getOffset() > at) sb.append("  char gap_").append(Integer.toHexString(at).toUpperCase()).append('[').append(c.getOffset() - at).append("];\n");
            String field = c.getFieldName() != null ? c.getFieldName() : "field_0x" + Integer.toHexString(c.getOffset());
            sb.append("  ").append(cType(c.getDataType())).append(' ').append(field).append(";\n");
            at = c.getOffset() + c.getLength();
            fields++;
        }
        if (st.getLength() > at) sb.append("  char gap_").append(Integer.toHexString(at).toUpperCase()).append('[').append(st.getLength() - at).append("];\n");
        sb.append("};");
        JsonObject o = new JsonObject();
        o.addProperty("declaration", sb.toString());
        o.addProperty("fields", fields);
        o.addProperty("size", st.getLength());
        o.addProperty("local", s.getName());
        return o;
    }

    /** A C spelling of a field type that another engine parses. */
    private static String cType(DataType dt) {
        if (dt instanceof Pointer p) return p.getDataType() == null || p.getDataType() instanceof Undefined ? "void *" : cType(p.getDataType()) + " *";
        if (dt instanceof Undefined || dt.getName().startsWith("undefined"))
            return switch (dt.getLength()) {
                case 1 -> "unsigned char";
                case 2 -> "unsigned short";
                case 4 -> "unsigned int";
                case 8 -> "unsigned long long";
                default -> "char[" + dt.getLength() + "]";
            };
        return dt.getDisplayName();
    }

    /** A decompiler local by stack offset (stable over renames), else by the name it had when first edited, else by the name it got. */
    private static HighSymbol find(HighFunction hf, int low, String local, Integer stack, String name) {
        List<HighSymbol> all = new ArrayList<>();
        hf.getLocalSymbolMap().getSymbols().forEachRemaining(all::add);
        if (stack != null)
            for (HighSymbol s : all)
                if (s.getStorage().isStackStorage() && s.getStorage().getStackOffset() - low == stack) return s;
        for (String wanted : new String[] { local, name })
            if (wanted != null)
                for (HighSymbol s : all)
                    if (s.getName().equals(wanted)) return s;
        return null;
    }

    /** A symbol's identity that survives renames of the others: its storage and first use. */
    private static String pin(HighSymbol s) {
        return s.getStorage() + "@" + s.getPCAddress();
    }

    /**
     * The pins of the variables that locals [[function, local, stack, name, type]] name, taken before any edit: Ghidra
     * renumbers its default names (iVar2 becomes iVar1) once another local is named. Null where not found.
     */
    static String[] pins(Worker w, Worker.Request r, JsonArray locals) throws Exception {
        String[] out = new String[locals.size()];
        java.util.Map<Function, HighFunction> seen = new java.util.HashMap<>();
        w.decompilers.flush();
        for (int i = 0; i < locals.size(); i++) {
            JsonArray l = locals.get(i).getAsJsonArray();
            Function f = w.program.getFunctionManager().getFunctionContaining(w.space().getAddress(w.base + l.get(0).getAsLong()));
            if (f == null) continue;
            HighFunction hf = seen.get(f);
            if (hf == null && !seen.containsKey(f)) {
                try {
                    hf = high(w, f, r);
                }
                catch (Worker.WorkerError e) {
                    hf = null;
                }
                seen.put(f, hf);
            }
            if (hf == null) continue;
            HighSymbol s = find(hf, low(f.getStackFrame()), l.get(1).getAsString(), l.get(2).isJsonNull() ? null : l.get(2).getAsInt(),
                l.get(3).isJsonNull() ? null : l.get(3).getAsString());
            if (s != null) out[i] = pin(s);
        }
        return out;
    }

    /**
     * Whether a parameter edit needs the decompiler's parameters committed first: when the database has another count or
     * storage, committing only the edited one would lock a prototype that drops the others.
     */
    private static boolean paramsDiffer(HighSymbol s, HighFunction hf) {
        if (!s.isParameter()) return false;
        Parameter[] db = hf.getFunction().getParameters();
        LocalSymbolMap map = hf.getLocalSymbolMap();
        if (map.getNumParams() != db.length) return true;
        for (int i = 0; i < db.length; i++) {
            HighSymbol p = map.getParamSymbol(i);
            if (p.getCategoryIndex() != i || p.getStorage().compareTo(db[i].getVariableStorage()) != 0) return true;
        }
        return false;
    }

    static JsonArray applyLocal(Worker w, Worker.Request r, long rva, String local, Integer stack, String name, String type) throws Exception {
        return applyLocal(w, r, rva, local, stack, name, type, null);
    }

    /** Renames and/or retypes a decompiler local or parameter (found by its pin when given); the decompiler's view after the edit is the check. */
    static JsonArray applyLocal(Worker w, Worker.Request r, long rva, String local, Integer stack, String name, String type, String pinned) throws Exception {
        Function f = w.program.getFunctionManager().getFunctionContaining(w.space().getAddress(w.base + rva));
        if (f == null) return item("local", rva, local, false, "no function contains rva 0x" + Long.toHexString(rva).toUpperCase(), null, stack, null);
        rva = w.rva(f.getEntryPoint());
        int low = low(f.getStackFrame());
        w.decompilers.flush();
        HighFunction hf;
        try {
            hf = high(w, f, r);
        }
        catch (Worker.WorkerError e) {
            return item("local", rva, local, false, e.getMessage(), null, stack, null);
        }
        HighSymbol s = null;
        if (pinned != null)
            for (Iterator<HighSymbol> it = hf.getLocalSymbolMap().getSymbols(); it.hasNext() && s == null;) {
                HighSymbol x = it.next();
                if (pin(x).equals(pinned)) s = x;
            }
        if (s == null) s = find(hf, low, local, stack, name);
        if (s == null) {
            StringBuilder known = new StringBuilder();
            hf.getLocalSymbolMap().getSymbols().forEachRemaining(x -> known.append(known.length() > 0 ? ", " : "").append(x.getName()));
            return item("local", rva, local, false, "the function has no local " + local + " (locals: " + TypeOps.clip(known.toString(), 400) + ")", null, stack, null);
        }
        String resolved = s.getName();
        Integer stk = s.getStorage().isStackStorage() ? s.getStorage().getStackOffset() - low : null;
        // Such a symbol takes the edit without error and without effect.
        if (!s.isParameter() && (s.getHighVariable() == null || s.getStorage().isUnassignedStorage() || s.getStorage().isBadStorage()))
            return item("local", rva, local, false, resolved + " has no storage the decompiler uses; it is not in the pseudocode, so the edit would not take",
                resolved, stk, null);
        if (name != null && !name.equals(resolved)) {
            for (Iterator<HighSymbol> it = hf.getLocalSymbolMap().getSymbols(); it.hasNext();)
                if (it.next().getName().equals(name))
                    return item("local", rva, local, false, "the function already has a local named " + name, resolved, stk, null);
        }
        DataType dt = null;
        if (type != null) {
            dt = TypeOps.parseType(w, type);
            if (dt == null) return item("local", rva, local, false, "the type does not parse (types it names must be declared first)", resolved, stk, null);
        }
        try {
            if (paramsDiffer(s, hf)) HighFunctionDBUtil.commitParamsToDatabase(hf, false, ReturnCommitOption.NO_COMMIT, f.getSignatureSource());
            HighFunctionDBUtil.updateDBVariable(s, name, dt, SourceType.USER_DEFINED);
        }
        catch (Exception e) {
            return item("local", rva, local, false, "Ghidra did not change " + resolved + ": " + e.getMessage(), resolved, stk, null);
        }
        String before = pin(s);
        w.decompilers.flush();
        HighSymbol now = null;
        try {
            HighFunction after = high(w, f, r);
            // By pin first: other default names may be renumbered by the edit.
            for (Iterator<HighSymbol> it = after.getLocalSymbolMap().getSymbols(); it.hasNext() && now == null;) {
                HighSymbol x = it.next();
                if (pin(x).equals(before)) now = x;
            }
            if (now == null) now = find(after, low, name, stk, resolved);
        }
        catch (Worker.WorkerError e) {
            return item("local", rva, local, false, e.getMessage(), resolved, stk, null);
        }
        if (now == null) return item("local", rva, local, false, "the local is gone after the edit", resolved, stk, null);
        if (name != null && !now.getName().equals(name))
            return item("local", rva, local, false, "the decompiler kept the name " + now.getName() + "; the edit did not take", resolved, stk, null);
        if (dt != null && !now.getDataType().isEquivalent(dt))
            return item("local", rva, local, false, "the decompiler kept " + now.getName() + " as " + now.getDataType().getDisplayName() + " (it did not accept " + type + ")",
                resolved, stk, null);
        return item("local", rva, local, true, null, resolved, stk, now.getDataType().getDisplayName() + " " + now.getName());
    }

    // ---- clearing user edits ----

    private static String originalKey(long rva, int offset) {
        return "stack_original_" + Long.toHexString(rva) + "_" + offset;
    }

    /** The member Ghidra had before the first user edit at this offset ("null" when none), so a clear restores it. */
    private static void rememberOriginal(Worker w, long rva, int offset, Variable existing) {
        var options = w.program.getOptions(Worker.STAMPS);
        String key = originalKey(rva, offset);
        if (options.getString(key, null) != null) return;
        JsonArray v = new JsonArray();
        if (existing != null) {
            v.add(existing.getName());
            v.add(existing.getDataType().getDisplayName());
        }
        options.setString(key, existing == null ? "null" : v.toString());
    }

    /** Clears, before the other edits: local_clears [[function, local, stack offset or null, name]], stack_clears [[function, offset]]. */
    static void clears(Worker w, Worker.Request r, JsonArray items) throws Exception {
        for (JsonElement e : Worker.array(r.args, "local_clears")) {
            JsonArray l = e.getAsJsonArray();
            items.add(clearLocal(w, r, l.get(0).getAsLong(), l.get(1).getAsString(), l.get(2).isJsonNull() ? null : l.get(2).getAsInt(),
                l.get(3).isJsonNull() ? null : l.get(3).getAsString()));
        }
        for (JsonElement e : Worker.array(r.args, "stack_clears")) {
            JsonArray s = e.getAsJsonArray();
            items.add(clearStack(w, s.get(0).getAsLong(), s.get(1).getAsInt()));
        }
    }

    /** Drops the user's name and type of a decompiler local: a committed local is removed, a parameter gets its default name back. */
    static JsonArray clearLocal(Worker w, Worker.Request r, long rva, String local, Integer stack, String name) throws Exception {
        Function f = w.program.getFunctionManager().getFunctionContaining(w.space().getAddress(w.base + rva));
        if (f == null) return item("local_clear", rva, local, false, "no function contains rva 0x" + Long.toHexString(rva).toUpperCase(), null, stack, null);
        rva = w.rva(f.getEntryPoint());
        int low = low(f.getStackFrame());
        w.decompilers.flush();
        HighFunction hf;
        try {
            hf = high(w, f, r);
        }
        catch (Worker.WorkerError e) {
            return item("local_clear", rva, local, false, e.getMessage(), null, stack, null);
        }
        HighSymbol s = find(hf, low, local, stack, name);
        if (s == null) return item("local_clear", rva, local, true, null, null, stack, "no such local; nothing to clear");
        String resolved = s.getName();
        Integer stk = s.getStorage().isStackStorage() ? s.getStorage().getStackOffset() - low : null;
        try {
            if (s.isParameter()) {
                ghidra.program.model.listing.Parameter p = f.getParameter(s.getCategoryIndex());
                if (p != null) p.setName(null, SourceType.DEFAULT);
            }
            else if (s.getSymbol() != null && s.getSymbol().getObject() instanceof Variable v) f.removeVariable(v);
        }
        catch (Exception e) {
            return item("local_clear", rva, local, false, "Ghidra did not clear " + resolved + ": " + e.getMessage(), resolved, stk, null);
        }
        w.decompilers.flush();
        return item("local_clear", rva, local, true, null, resolved, stk, "cleared");
    }

    /** Restores the member Ghidra had before the first user edit; without that record the member is removed and the decompiler names it again. */
    static JsonArray clearStack(Worker w, long rva, int offset) {
        String target = "+0x" + Integer.toHexString(offset).toUpperCase();
        Function f = w.program.getFunctionManager().getFunctionContaining(w.space().getAddress(w.base + rva));
        if (f == null) return item("stack_clear", rva, target, false, "no function contains rva 0x" + Long.toHexString(rva).toUpperCase(), null, offset, null);
        rva = w.rva(f.getEntryPoint());
        StackFrame sf = f.getStackFrame();
        int at = offset + low(sf);
        if (returnAddressOnStack(w) && at >= sf.getReturnAddressOffset() && at < sf.getReturnAddressOffset() + w.program.getDefaultPointerSize())
            return item("stack_clear", rva, target, false, target + " is the return address", "__return_address", offset, null);
        Variable existing = sf.getVariableContaining(at);
        String old = existing != null && existing.getStackOffset() == at ? existing.getName() : null;
        var options = w.program.getOptions(Worker.STAMPS);
        String key = originalKey(rva, offset);
        String saved = options.getString(key, null);
        try {
            if (old != null) sf.clearVariable(at);
            if (saved != null && !saved.equals("null")) {
                JsonArray o = com.google.gson.JsonParser.parseString(saved).getAsJsonArray();
                DataType dt = TypeOps.parseType(w, o.get(1).getAsString());
                if (dt == null && existing != null) dt = existing.getDataType();
                if (dt != null) sf.createVariable(o.get(0).getAsString(), at, dt, SourceType.ANALYSIS);
            }
            if (saved != null) options.removeOption(key);
        }
        catch (Exception e) {
            return item("stack_clear", rva, target, false, "Ghidra did not restore the stack member at " + target + ": " + e.getMessage(), old, offset, null);
        }
        for (Variable v : f.getStackFrame().getStackVariables())
            if (v.getStackOffset() == at) return item("stack_clear", rva, target, true, null, old, offset, v.getDataType().getDisplayName() + " " + v.getName());
        return item("stack_clear", rva, target, true, null, old, offset, "no member");
    }
}
