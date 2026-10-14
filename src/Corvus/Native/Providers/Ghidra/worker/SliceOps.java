// Value slices over the decompiler's high p-code: getDef() backward and getDescendants() forward, parameters through
// HighParam.getSlot(); credits in THIRD-PARTY-NOTICES.md.
package corvus.ghidra;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighParam;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.Varnode;

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
            o.add("note", null);
            if (variable == null) o.add("variable", null);
            else o.addProperty("variable", variable);
            return o;
        }

        List<PcodeOp> opsAt(Address a) {
            List<PcodeOp> list = new ArrayList<>();
            for (Iterator<PcodeOpAST> it = hf.getPcodeOps(a); it.hasNext();) list.add(it.next());
            return list;
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

        /** A pointer that is a fixed address: a constant, PTRSUB(0, c), or a copy or cast of one. */
        private Long fixed(Varnode ptr) {
            for (int depth = 0; depth < 8 && ptr != null; depth++) {
                if (ptr.isConstant()) return addressOf(ptr.getOffset(), ptr.getSize());
                PcodeOp def = ptr.getDef();
                if (def == null) return null;
                switch (def.getOpcode()) {
                    case PcodeOp.PTRSUB:
                        return def.getInput(0).isConstant() && def.getInput(0).getOffset() == 0 && def.getInput(1).isConstant()
                            ? addressOf(def.getInput(1).getOffset(), w.program.getDefaultPointerSize()) : null;
                    case PcodeOp.COPY:
                    case PcodeOp.CAST:
                        ptr = def.getInput(0);
                        break;
                    default:
                        return null;
                }
            }
            return null;
        }

        private static String hex(long v) {
            return "0x" + Long.toHexString(v).toUpperCase();
        }

        int back(Varnode v) {
            return back(v, new ArrayDeque<>(), 0);
        }

        private int back(Varnode v, ArrayDeque<PcodeOp> stack, int depth) {
            if (nodes.size() >= max) {
                truncated = true;
                return -1;
            }
            if (depth > 48) return node("unknown", null, "?", "derivation deeper than 48 steps", null);
            if (v.isConstant()) {
                long c = v.getOffset();
                // a number is an address only where something is defined (images based at 0 make every small number mapped)
                Long target = Long.compareUnsigned(c, 0x10000) >= 0 && defined(c) ? addressOf(c, v.getSize()) : null;
                if (target != null && c != 0) return node("address", null, hex(c), "constant", n -> n.addProperty("target", target));
                return node("constant", null, hex(c), "constant", n -> n.add("value", Worker.u64(c)));
            }
            PcodeOp def = v.getDef();
            if (def == null) {
                if (v.isAddress() && w.rva(v.getAddress()) != null)
                    return node("global", v.getAddress(), "[" + v.getAddress() + "]", "global variable", n -> n.addProperty("target", w.rva(v.getAddress())));
                if (v.getHigh() instanceof HighParam p)
                    return node("parameter", hf.getFunction().getEntryPoint(), "parameter " + (p.getSlot() + 1), p.getName(), n -> n.addProperty("index", p.getSlot()));
                return node("unknown", null, "?", v.isInput() ? "incoming " + v + " (not a parameter of the prototype)" : "no definition of " + v, null);
            }
            Address at = def.getSeqnum().getTarget();
            if (stack.contains(def)) return node("loop", at, "loop-carried value", def.toString(), null);
            stack.push(def);
            try {
                switch (def.getOpcode()) {
                    case PcodeOp.COPY:
                    case PcodeOp.CAST:
                    case PcodeOp.INT_ZEXT:
                    case PcodeOp.INT_SEXT:
                    case PcodeOp.SUBPIECE:
                    case PcodeOp.INDIRECT:
                        return back(def.getInput(0), stack, depth + 1);
                    case PcodeOp.MULTIEQUAL: {
                        int inputs = def.getNumInputs();
                        boolean cut = inputs > 8;
                        int m = node("merge", at, inputs + " values", def.toString(), n -> n.addProperty("derived", cut));
                        for (int i = 0; i < Math.min(inputs, 8); i++) {
                            int c = back(def.getInput(i), stack, depth + 1);
                            boolean loop = c >= 0 && "loop".equals(nodes.get(c).getAsJsonObject().get("kind").getAsString());
                            edge(c, m, loop ? "loop" : "merge");
                        }
                        return m;
                    }
                    case PcodeOp.CALL:
                    case PcodeOp.CALLIND:
                        return node("call_result", at, "result of the call", def.toString(), n -> n.addProperty("site", w.rva(at)));
                    case PcodeOp.LOAD: {
                        Varnode ptr = def.getInput(1);
                        Long g = fixed(ptr);
                        if (g != null) return node("global", at, "[" + hex(g) + "]", def.toString(), n -> n.addProperty("target", g));
                        Varnode base = ptr;
                        long off = 0;
                        PcodeOp pd = ptr.getDef();
                        if (pd != null && (pd.getOpcode() == PcodeOp.PTRSUB || pd.getOpcode() == PcodeOp.INT_ADD) && pd.getInput(1).isConstant()) {
                            base = pd.getInput(0);
                            off = pd.getInput(1).getOffset();
                        }
                        long offset = off;
                        int fnode = node("field", at, "field " + (offset < 0 ? "-" : "+") + hex(Math.abs(offset)), def.toString(), n -> n.add("value", Worker.u64(offset)));
                        edge(back(base, stack, depth + 1), fnode, "field");
                        return fnode;
                    }
                    case PcodeOp.PTRSUB: {
                        Varnode base = def.getInput(0), off = def.getInput(1);
                        if (base.isConstant() && base.getOffset() == 0 && off.isConstant()) {
                            Long target = addressOf(off.getOffset(), w.program.getDefaultPointerSize());
                            if (target != null) return node("address", at, hex(off.getOffset()), def.toString(), n -> n.addProperty("target", target));
                        }
                        if (base.isRegister() && off.isConstant())
                            return node("stack_address", at, "&local " + hex(off.getOffset()), def.toString(), n -> n.add("value", Worker.u64(off.getOffset())));
                        return node("unknown", at, "?", "pointer arithmetic: " + def, null);
                    }
                    case PcodeOp.INT_ADD:
                    case PcodeOp.INT_SUB:
                    case PcodeOp.INT_OR:
                    case PcodeOp.INT_AND:
                    case PcodeOp.INT_XOR:
                        if (def.getInput(0).isConstant() && def.getInput(1).isConstant()) {
                            long a = def.getInput(0).getOffset(), b = def.getInput(1).getOffset();
                            long c = switch (def.getOpcode()) {
                                case PcodeOp.INT_ADD -> a + b;
                                case PcodeOp.INT_SUB -> a - b;
                                case PcodeOp.INT_OR -> a | b;
                                case PcodeOp.INT_AND -> a & b;
                                default -> a ^ b;
                            };
                            return node("constant", at, hex(c), def.toString(), n -> n.add("value", Worker.u64(c)));
                        }
                        return node("unknown", at, "?", "computed: " + def, null);
                    default:
                        return node("unknown", at, "?", "computed: " + def, null);
                }
            }
            finally {
                stack.pop();
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
            int id = node(kind, at, text, why.isEmpty() ? op.toString() : why + "; " + op, n -> {
                n.addProperty("site", w.rva(at));
                if (t != null) n.addProperty("target", t);
                if (c != null) n.addProperty("callee", c);
                if (k >= 0) n.addProperty("index", k);
                if (v != null) n.add("value", Worker.u64(v));
                if (derived) n.addProperty("derived", true);
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
