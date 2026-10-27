// Value slices over the decompiler's high p-code: a value's derivation backward, its uses forward.
package corvus.ghidra;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.function.LongBinaryOperator;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionSignature;
import ghidra.program.model.pcode.DataTypeSymbol;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.pcode.LocalSymbolMap;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.Symbol;

/** Per-function value slices in the reply shape of the IDA worker's value_slice; callers hold the read lock. */
final class SliceOps {
    private SliceOps() {
    }

    /** Args: function, seed, rva, direction, register, index, max_nodes, seconds. */
    static JsonElement valueSlice(Worker w, Worker.Request r) throws Exception {
        Function f = CodeOps.functionAt(w, w.addr(r.args, "function"));
        int seconds = (int) Math.ceil(r.args.has("seconds") ? r.args.get("seconds").getAsDouble() : w.decompileTimeout);
        DecompileResults res = CodeOps.results(w, f, Math.max(1, seconds), r.monitor);
        HighFunction hf = res.getHighFunction();
        if (hf == null) throw new Worker.WorkerError("failed", "no high function for " + f.getName());
        Slicer s = new Slicer(w, hf, r.args.has("max_nodes") ? r.args.get("max_nodes").getAsInt() : 256);
        String seed = r.args.get("seed").getAsString();
        boolean forward = "forward".equals(r.args.get("direction").getAsString());
        Address at = w.addr(r.args, "rva");
        int index = r.args.has("index") ? r.args.get("index").getAsInt() : -1;
        String register = r.args.has("register") && !r.args.get("register").isJsonNull() ? r.args.get("register").getAsString() : null;
        switch (seed) {
            case "argument" -> {
                PcodeOp call = s.callAt(at);
                if (call == null) throw new Worker.WorkerError("not_found", "no call at rva 0x" + Long.toHexString(w.rva(at)));
                if (index < 0 || index + 1 >= call.getNumInputs())
                    throw new Worker.WorkerError("not_found", "the call passes " + (call.getNumInputs() - 1) + " arguments, not " + (index + 1));
                Varnode v = call.getInput(index + 1);
                s.inferred(call);
                s.variable(v);
                if (forward) {
                    int origin = s.origin(at, "argument " + (index + 1) + " at the call");
                    s.use(origin, call, index + 1, "", false);
                    s.forward(v, origin);
                }
                else s.back(v);
            }
            case "parameter" -> {
                if (!forward) {
                    s.node("parameter", f.getEntryPoint(), "parameter " + (index + 1), "", n -> n.addProperty("index", index));
                    break;
                }
                HighSymbol p = index >= 0 && index < hf.getLocalSymbolMap().getNumParams() ? hf.getLocalSymbolMap().getParamSymbol(index) : null;
                if (p == null || p.getHighVariable() == null) throw new Worker.WorkerError("not_found", f.getName() + " has no parameter " + (index + 1));
                s.variable = p.getName();
                int origin = s.origin(f.getEntryPoint(), p.getName() + " at entry");
                for (Varnode v : p.getHighVariable().getInstances()) s.forward(v, origin);
            }
            case "result" -> {
                PcodeOp call = s.callAt(at);
                if (!forward) {
                    s.node("call_result", at, "result of the call", "", n -> n.addProperty("site", w.rva(at)));
                    break;
                }
                int origin = s.origin(at, "result of the call");
                if (call != null && call.getOutput() != null) {
                    s.variable(call.getOutput());
                    s.forward(call.getOutput(), origin);
                }
            }
            case "returns" -> {
                List<Varnode> values = new ArrayList<>();
                for (Iterator<PcodeOpAST> it = hf.getPcodeOps(); it.hasNext();) {
                    PcodeOp op = it.next();
                    if (op.getOpcode() == PcodeOp.RETURN && op.getNumInputs() > 1) values.add(op.getInput(1));
                }
                if (values.isEmpty()) s.node("unknown", f.getEntryPoint(), "no return value", "", null);
                else if (values.size() == 1) s.back(values.get(0));
                else {
                    int m = s.node("merge", f.getEntryPoint(), "returned at " + values.size() + " sites", "", null);
                    for (Varnode v : values) s.edge(s.back(v), m, "merge");
                }
            }
            case "stored" -> {
                Varnode value = null;
                for (PcodeOp op : s.opsAt(at)) {
                    if (op.getOpcode() == PcodeOp.STORE) value = op.getInput(2);
                    else if (op.getOutput() != null && op.getOutput().isAddress() && op.getNumInputs() > 0) value = op.getInput(0);
                    if (value != null) break;
                }
                if (value == null) throw new Worker.WorkerError("not_found", "no store at rva 0x" + Long.toHexString(w.rva(at)));
                s.back(value);
            }
            case "loaded" -> {
                Varnode loaded = null;
                for (PcodeOp op : s.opsAt(at))
                    if (op.getOutput() != null && (op.getOpcode() == PcodeOp.LOAD || op.getNumInputs() > 0 && op.getInput(0).isAddress())) {
                        loaded = op.getOutput();
                        break;
                    }
                if (loaded == null) throw new Worker.WorkerError("not_found", "no load at rva 0x" + Long.toHexString(w.rva(at)));
                s.variable(loaded);
                s.forward(loaded, s.origin(at, "loaded value"));
            }
            case "location" -> {
                if (register == null) throw new Worker.WorkerError("invalid_argument", "location needs a register");
                if (forward) {
                    Varnode out = null;
                    for (PcodeOp op : s.opsAt(at))
                        if (op.getOutput() != null && s.isRegister(op.getOutput(), register)) out = op.getOutput();
                    if (out == null) throw new Worker.WorkerError("not_found", register + " is not defined at rva 0x" + Long.toHexString(w.rva(at)) + " in the decompiler's view");
                    s.variable(out);
                    s.forward(out, s.origin(at, register + " at the instruction"));
                }
                else {
                    Varnode in = s.registerBefore(at, register);
                    if (in == null) throw new Worker.WorkerError("not_found", register + " is not used at rva 0x" + Long.toHexString(w.rva(at)) + " in the decompiler's view");
                    s.variable(in);
                    s.back(in);
                }
            }
            default -> throw new Worker.WorkerError("invalid_argument", "unknown seed '" + seed + "'");
        }
        return s.result();
    }

    /** Builds nodes and edges; node 0 is the root (the value backward, the origin forward). */
    private static final class Slicer {
        private final Worker w;
        private final HighFunction hf;
        private final int max;
        private final JsonArray nodes = new JsonArray();
        private final JsonArray edges = new JsonArray();
        private final Map<String, Integer> uses = new HashMap<>();
        private final Set<Long> inferredCalls = new TreeSet<>();
        private boolean truncated;
        String variable;

        Slicer(Worker w, HighFunction hf, int max) {
            this.w = w;
            this.hf = hf;
            this.max = Math.max(1, Math.min(max, 2000));
        }

        interface Extra {
            void add(JsonObject n);
        }

        int node(String kind, Address at, String text, String why, Extra extra) {
            if (nodes.size() >= max) {
                truncated = true;
                return -1;
            }
            JsonObject n = new JsonObject();
            n.addProperty("kind", kind);
            Long rva = at == null ? null : w.rva(at);
            n.addProperty("rva", rva == null ? 0 : rva);
            n.addProperty("text", text);
            n.addProperty("why", why);
            if (extra != null) extra.add(n);
            nodes.add(n);
            return nodes.size() - 1;
        }

        void edge(int from, int to, String kind) {
            if (from < 0 || to < 0) return;
            JsonArray e = new JsonArray();
            e.add(from);
            e.add(to);
            e.add(kind);
            edges.add(e);
        }

        void variable(Varnode v) {
            HighVariable h = v.getHigh();
            if (h != null && h.getName() != null) variable = h.getName();
        }

        JsonObject result() {
            JsonObject o = new JsonObject();
            o.add("nodes", nodes);
            o.add("edges", edges);
            o.addProperty("truncated", truncated);
            if (inferredCalls.isEmpty()) o.add("note", null);
            else {
                List<String> sites = new ArrayList<>();
                for (long rva : inferredCalls) sites.add(hex(rva));
                o.addProperty("note", "argument registers of the indirect call" + (sites.size() > 1 ? "s" : "") + " at " + String.join(", ", sites)
                    + " are inferred by the decompiler and can differ between runs");
            }
            if (variable == null) o.add("variable", null);
            else o.addProperty("variable", variable);
            return o;
        }

        List<PcodeOp> opsAt(Address a) {
            List<PcodeOp> list = new ArrayList<>();
            for (Iterator<PcodeOpAST> it = hf.getPcodeOps(a); it.hasNext();) list.add(it.next());
            return list;
        }

        /**
         * True when a CALLIND's signature does not declare every input it passes; the inferred argument registers can
         * differ between decompiler processes (NationalSecurityAgency/ghidra#10018, 12.0.4-12.1.4), so it is noted.
         */
        boolean inferred(PcodeOp call) {
            if (call.getOpcode() != PcodeOp.CALLIND) return false;
            FunctionSignature sig = signature(call);
            if (sig != null && !sig.hasVarArgs() && sig.getArguments().length >= call.getNumInputs() - 1) return false;
            Long rva = w.rva(call.getSeqnum().getTarget());
            if (rva != null) inferredCalls.add(rva);
            return true;
        }

        private FunctionSignature signature(PcodeOp call) {
            for (Symbol sym : w.program.getSymbolTable().getSymbols(call.getSeqnum().getTarget())) {
                DataTypeSymbol o = HighFunctionDBUtil.readOverride(sym);
                if (o != null) return (FunctionSignature) o.getDataType();
            }
            HighVariable h = call.getInput(0).getHigh();
            DataType t = h != null ? h.getDataType() : null;
            while (t instanceof TypeDef d) t = d.getBaseDataType();
            if (!(t instanceof ghidra.program.model.data.Pointer ptr)) return null;
            t = ptr.getDataType();
            while (t instanceof TypeDef d) t = d.getBaseDataType();
            return t instanceof FunctionSignature f ? f : null;
        }

        PcodeOp callAt(Address a) {
            for (PcodeOp op : opsAt(a)) if (op.getOpcode() == PcodeOp.CALL || op.getOpcode() == PcodeOp.CALLIND) return op;
            return null;
        }

        boolean isRegister(Varnode v, String name) {
            if (!v.isRegister()) return false;
            Register reg = w.program.getRegister(v.getAddress(), v.getSize());
            if (reg == null) reg = w.program.getRegister(v.getAddress());
            if (reg == null) return false;
            return reg.getName().equalsIgnoreCase(name) || reg.getBaseRegister().getName().equalsIgnoreCase(name)
                   || w.program.getRegister(name) instanceof Register r && r.getBaseRegister().equals(reg.getBaseRegister());
        }

        /** The register's value used at the address, or the latest definition of it before the address. */
        Varnode registerBefore(Address a, String name) {
            for (PcodeOp op : opsAt(a))
                for (Varnode in : op.getInputs()) if (isRegister(in, name)) return in;
            Varnode best = null;
            Address bestAt = null;
            for (Iterator<PcodeOpAST> it = hf.getPcodeOps(); it.hasNext();) {
                PcodeOp op = it.next();
                Address at = op.getSeqnum().getTarget();
                if (op.getOutput() != null && at.compareTo(a) < 0 && isRegister(op.getOutput(), name) && (bestAt == null || at.compareTo(bestAt) > 0)) {
                    best = op.getOutput();
                    bestAt = at;
                }
            }
            return best;
        }

        private Long addressOf(long value, int size) {
            if (size != w.program.getDefaultPointerSize() && size != 4) return null;
            try {
                Address a = w.space().getAddress(value);
                return w.program.getMemory().contains(a) ? w.rva(a) : null;
            }
            catch (RuntimeException e) {
                return null;
            }
        }

        private boolean defined(long value) {
            try {
                Address a = w.space().getAddress(value);
                return w.program.getSymbolTable().getPrimarySymbol(a) != null || w.program.getListing().getDefinedDataAt(a) != null;
            }
            catch (RuntimeException e) {
                return false;
            }
        }

        /** A pointer that is a fixed address: a constant, PTRSUB(0, c), or a copy or cast of one, within 8 steps. */
        private Long fixed(Varnode ptr) {
            Varnode cur = ptr;
            for (int step = 0; step < 8 && cur != null; step++) {
                if (cur.isConstant()) return addressOf(cur.getOffset(), cur.getSize());
                PcodeOp def = cur.getDef();
                if (def == null) return null;
                int op = def.getOpcode();
                if (op == PcodeOp.PTRSUB)
                    return isZero(def.getInput(0)) && def.getInput(1).isConstant() ? addressOf(def.getInput(1).getOffset(), w.program.getDefaultPointerSize()) : null;
                if (op != PcodeOp.COPY && op != PcodeOp.CAST) return null;
                cur = def.getInput(0);
            }
            return null;
        }

        private static boolean isZero(Varnode v) {
            return v.isConstant() && v.getOffset() == 0;
        }

        private static String hex(long v) {
            return "0x" + Long.toHexString(v).toUpperCase();
        }

        // Deeper derivations end in an unknown node.
        private static final int MAX_DERIVATION = 48;

        // A merge lists at most this many of its inputs.
        private static final int MAX_MERGE_INPUTS = 8;

        /** What the backward walk does with a defining op. */
        private enum Step { PASS, MERGE, CALL, LOAD, PTRSUB, FOLD, OPAQUE }

        private static final Set<Integer> PASS_THROUGH = Set.of(PcodeOp.COPY, PcodeOp.CAST, PcodeOp.INT_ZEXT, PcodeOp.INT_SEXT, PcodeOp.SUBPIECE, PcodeOp.INDIRECT);

        private static final Map<Integer, LongBinaryOperator> FOLDS = Map.of(
            PcodeOp.INT_ADD, (a, b) -> a + b, PcodeOp.INT_SUB, (a, b) -> a - b, PcodeOp.INT_OR, (a, b) -> a | b,
            PcodeOp.INT_AND, (a, b) -> a & b, PcodeOp.INT_XOR, (a, b) -> a ^ b);

        private static Step stepOf(PcodeOp def) {
            int op = def.getOpcode();
            if (PASS_THROUGH.contains(op)) return Step.PASS;
            if (FOLDS.containsKey(op)) return Step.FOLD;
            return switch (op) {
                case PcodeOp.MULTIEQUAL -> Step.MERGE;
                case PcodeOp.CALL, PcodeOp.CALLIND -> Step.CALL;
                case PcodeOp.LOAD -> Step.LOAD;
                case PcodeOp.PTRSUB -> Step.PTRSUB;
                default -> Step.OPAQUE;
            };
        }

        /** A loaded pointer: a fixed target, or a base plus a constant offset (0 when it has none). */
        private record Pointer(Long target, Varnode base, long offset) {
        }

        private Pointer pointer(Varnode ptr) {
            Long target = fixed(ptr);
            if (target != null) return new Pointer(target, null, 0);
            PcodeOp def = ptr.getDef();
            if (def != null && (def.getOpcode() == PcodeOp.PTRSUB || def.getOpcode() == PcodeOp.INT_ADD) && def.getInput(1).isConstant())
                return new Pointer(null, def.getInput(0), def.getInput(1).getOffset());
            return new Pointer(null, ptr, 0);
        }

        /** The prototype parameter whose decompiler variable holds v: its index, or -1. */
        private int parameterIndex(Varnode v) {
            HighVariable high = v.getHigh();
            if (high == null) return -1;
            LocalSymbolMap symbols = hf.getLocalSymbolMap();
            for (int i = 0; i < symbols.getNumParams(); i++) {
                HighSymbol p = symbols.getParamSymbol(i);
                if (p != null && p.getHighVariable() == high) return i;
            }
            return -1;
        }

        private final Set<Integer> loops = new HashSet<>();

        /** The derivation of v as nodes; returns its node, -1 past the node budget. */
        int back(Varnode v) {
            return derive(v, new ArrayDeque<>(), 0);
        }

        // Ops on the path from the root are not entered again: a value that reaches one is loop-carried.
        private int derive(Varnode v, ArrayDeque<PcodeOp> path, int depth) {
            if (nodes.size() >= max) {
                truncated = true;
                return -1;
            }
            if (depth > MAX_DERIVATION) return node("unknown", null, "?", "derivation deeper than " + MAX_DERIVATION + " steps", null);
            if (v.isConstant()) return constant(v.getOffset(), v.getSize());
            PcodeOp def = v.getDef();
            if (def == null) return source(v);
            Address at = def.getSeqnum().getTarget();
            if (path.contains(def)) {
                int id = node("loop", at, "loop-carried value", def.toString(), null);
                loops.add(id);
                return id;
            }
            path.push(def);
            try {
                return derived(def, at, path, depth);
            }
            finally {
                path.pop();
            }
        }

        private int constant(long c, int size) {
            // A number is an address only where something is defined: images based at 0 map every small number.
            Long target = c != 0 && Long.compareUnsigned(c, 0x10000) >= 0 && defined(c) ? addressOf(c, size) : null;
            if (target != null) return node("address", null, hex(c), "constant", n -> n.addProperty("target", target));
            return node("constant", null, hex(c), "constant", n -> n.add("value", Worker.u64(c)));
        }

        /** A value with no defining op: a global, a prototype parameter, or unknown. */
        private int source(Varnode v) {
            Long global = v.isAddress() ? w.rva(v.getAddress()) : null;
            if (global != null) return node("global", v.getAddress(), "[" + v.getAddress() + "]", "global variable", n -> n.addProperty("target", global));
            int index = parameterIndex(v);
            if (index >= 0) {
                String name = hf.getLocalSymbolMap().getParamSymbol(index).getName();
                return node("parameter", hf.getFunction().getEntryPoint(), "parameter " + (index + 1), name, n -> n.addProperty("index", index));
            }
            return node("unknown", null, "?", v.isInput() ? "incoming " + v + " (not a parameter of the prototype)" : "no definition of " + v, null);
        }

        private int derived(PcodeOp def, Address at, ArrayDeque<PcodeOp> path, int depth) {
            switch (stepOf(def)) {
                case PASS:
                    return derive(def.getInput(0), path, depth + 1);
                case MERGE: {
                    int inputs = def.getNumInputs();
                    int merge = node("merge", at, inputs + " values", def.toString(), n -> n.addProperty("derived", inputs > MAX_MERGE_INPUTS));
                    for (int i = 0; i < Math.min(inputs, MAX_MERGE_INPUTS); i++) {
                        int from = derive(def.getInput(i), path, depth + 1);
                        edge(from, merge, loops.contains(from) ? "loop" : "merge");
                    }
                    return merge;
                }
                case CALL:
                    return node("call_result", at, "result of the call", def.toString(), n -> n.addProperty("site", w.rva(at)));
                case LOAD: {
                    Pointer p = pointer(def.getInput(1));
                    if (p.target() != null) return node("global", at, "[" + hex(p.target()) + "]", def.toString(), n -> n.addProperty("target", p.target()));
                    long offset = p.offset();
                    int field = node("field", at, "field " + (offset < 0 ? "-" : "+") + hex(Math.abs(offset)), def.toString(), n -> n.add("value", Worker.u64(offset)));
                    edge(derive(p.base(), path, depth + 1), field, "field");
                    return field;
                }
                case PTRSUB: {
                    Varnode base = def.getInput(0), off = def.getInput(1);
                    if (isZero(base) && off.isConstant()) {
                        Long target = addressOf(off.getOffset(), w.program.getDefaultPointerSize());
                        if (target != null) return node("address", at, hex(off.getOffset()), def.toString(), n -> n.addProperty("target", target));
                    }
                    if (base.isRegister() && off.isConstant())
                        return node("stack_address", at, "&local " + hex(off.getOffset()), def.toString(), n -> n.add("value", Worker.u64(off.getOffset())));
                    return node("unknown", at, "?", "pointer arithmetic: " + def, null);
                }
                case FOLD:
                    if (def.getInput(0).isConstant() && def.getInput(1).isConstant()) {
                        long c = FOLDS.get(def.getOpcode()).applyAsLong(def.getInput(0).getOffset(), def.getInput(1).getOffset());
                        return node("constant", at, hex(c), def.toString(), n -> n.add("value", Worker.u64(c)));
                    }
                    return node("unknown", at, "?", "computed: " + def, null);
                default:
                    return node("unknown", at, "?", "computed: " + def, null);
            }
        }

        int origin(Address at, String text) {
            return node("origin", at, text, "", null);
        }

        /** A use of a value as input slot of op; registered once per op and slot. */
        void use(int origin, PcodeOp op, int slot, String why, boolean derived) {
            Address at = op.getSeqnum().getTarget();
            String key = op.getSeqnum() + ":" + slot;
            if (uses.containsKey(key)) return;
            int code = op.getOpcode();
            String kind;
            String text;
            Long target = null;
            String callee = null;
            int index = -1;
            Long value = null;
            boolean inferredSlot = false;
            switch (code) {
                case PcodeOp.CALL, PcodeOp.CALLIND -> {
                    if (code == PcodeOp.CALLIND && slot == 0) {
                        kind = "call_target";
                        text = "called";
                    }
                    else {
                        kind = "argument";
                        index = slot - 1;
                        if (code == PcodeOp.CALL) {
                            Address t = op.getInput(0).getAddress();
                            Function fn = w.program.getFunctionManager().getFunctionAt(t);
                            target = w.rva(t);
                            callee = fn != null ? fn.getName() : t.toString();
                        }
                        text = "argument " + slot + (callee != null ? " of " + callee : "");
                        inferredSlot = inferred(op);
                    }
                }
                case PcodeOp.STORE -> {
                    if (slot == 1) {
                        kind = "dereference";
                        text = "points to the store";
                    }
                    else {
                        Long g = fixed(op.getInput(1));
                        kind = g != null ? "store" : "field_store";
                        target = g;
                        text = g != null ? "stored to [" + hex(g) + "]" : "stored through a pointer";
                    }
                }
                case PcodeOp.LOAD -> {
                    kind = "dereference";
                    text = "points to the load";
                }
                case PcodeOp.RETURN -> {
                    kind = "return";
                    text = "returned";
                }
                case PcodeOp.BRANCHIND -> {
                    kind = "switch";
                    text = "selects the target of the indirect jump";
                }
                default -> {
                    kind = "compare";
                    Varnode other = op.getInput(slot == 0 ? 1 : 0);
                    value = other.isConstant() ? other.getOffset() : null;
                    text = op.getMnemonic().toLowerCase() + (value != null ? " " + hex(value) : "");
                }
            }
            final Long t = target, v = value;
            final String c = callee;
            final int k = index;
            final boolean marked = derived || inferredSlot;
            int id = node(kind, at, text, why.isEmpty() ? op.toString() : why + "; " + op, n -> {
                n.addProperty("site", w.rva(at));
                if (t != null) n.addProperty("target", t);
                if (c != null) n.addProperty("callee", c);
                if (k >= 0) n.addProperty("index", k);
                if (v != null) n.add("value", Worker.u64(v));
                if (marked) n.addProperty("derived", true);
            });
            if (id < 0) return;
            uses.put(key, id);
            edge(origin, id, "use");
        }

        /** Every use reachable from v through copies and arithmetic. */
        void forward(Varnode start, int origin) {
            ArrayDeque<Object[]> work = new ArrayDeque<>();
            Set<Varnode> seen = new HashSet<>();
            work.add(new Object[] { start, false, "" });
            while (!work.isEmpty() && !truncated) {
                Object[] item = work.poll();
                Varnode v = (Varnode) item[0];
                boolean derived = (Boolean) item[1];
                String path = (String) item[2];
                if (!seen.add(v)) continue;
                for (Iterator<PcodeOp> it = v.getDescendants(); it.hasNext();) {
                    PcodeOp op = it.next();
                    int slot = op.getSlot(v);
                    switch (op.getOpcode()) {
                        case PcodeOp.CALL, PcodeOp.CALLIND, PcodeOp.STORE, PcodeOp.LOAD, PcodeOp.RETURN, PcodeOp.BRANCHIND,
                             PcodeOp.INT_EQUAL, PcodeOp.INT_NOTEQUAL, PcodeOp.INT_LESS, PcodeOp.INT_SLESS, PcodeOp.INT_LESSEQUAL, PcodeOp.INT_SLESSEQUAL ->
                            use(origin, op, slot, path, derived);
                        case PcodeOp.COPY, PcodeOp.CAST, PcodeOp.INT_ZEXT, PcodeOp.INT_SEXT, PcodeOp.SUBPIECE, PcodeOp.PIECE, PcodeOp.MULTIEQUAL, PcodeOp.INDIRECT -> {
                            if (op.getOutput() != null) work.add(new Object[] { op.getOutput(), derived, step(path, op) });
                        }
                        case PcodeOp.INT_ADD, PcodeOp.INT_SUB, PcodeOp.INT_MULT, PcodeOp.INT_AND, PcodeOp.INT_OR, PcodeOp.INT_XOR, PcodeOp.INT_LEFT,
                             PcodeOp.INT_RIGHT, PcodeOp.INT_SRIGHT, PcodeOp.PTRADD, PcodeOp.PTRSUB, PcodeOp.INT_NEGATE, PcodeOp.INT_2COMP -> {
                            if (op.getOutput() != null) work.add(new Object[] { op.getOutput(), true, step(path, op) });
                        }
                        default -> {
                        }
                    }
                }
            }
        }

        private static String step(String path, PcodeOp op) {
            String s = op.getMnemonic() + " @" + op.getSeqnum().getTarget();
            if (path.isEmpty()) return s;
            String[] parts = path.split(" -> ");
            return parts.length >= 6 ? "... -> " + parts[parts.length - 2] + " -> " + parts[parts.length - 1] + " -> " + s : path + " -> " + s;
        }
    }
}
