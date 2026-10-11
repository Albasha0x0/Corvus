package corvus.ghidra;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.TreeSet;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonNull;
import com.google.gson.JsonObject;

import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.Array;
import ghidra.program.model.data.Composite;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;

/** References to a struct or union member (field_xrefs); callers hold the read lock. Rows match the IDA worker's. */
final class FieldOps {
    private FieldOps() {
    }

    private record Hit(String name, int offset, int size, String type) {
    }

    /**
     * The member of the first of types that exists, by name (member) or by an offset it covers: references to it inside
     * defined instances of the type, then PTRSUB accesses in the high p-code of the functions whose signature names the
     * type, the functions referencing an instance, and the functions given, within seconds. Rows [rva, read|write|address,
     * function rva or null].
     */
    static JsonElement fieldXrefs(Worker w, Worker.Request r) throws Exception {
        long deadline = System.nanoTime() + (long) ((r.args.has("seconds") ? r.args.get("seconds").getAsDouble() : 30) * 1e9);
        Composite type = null;
        String typeName = null;
        for (JsonElement e : Worker.array(r.args, "types")) {
            List<DataType> found = new ArrayList<>();
            w.program.getDataTypeManager().findDataTypes(e.getAsString(), found);
            for (DataType t : found)
                if (strip(t) instanceof Composite c) {
                    type = c;
                    typeName = e.getAsString();
                    break;
                }
            if (type != null) break;
        }
        if (type == null) {
            List<String> names = new ArrayList<>();
            for (JsonElement e : Worker.array(r.args, "types")) names.add(e.getAsString());
            throw new Worker.WorkerError("not_found", "no struct or union named " + String.join(" or ", names));
        }
        String member = r.args.has("member") && !r.args.get("member").isJsonNull() ? r.args.get("member").getAsString() : null;
        Integer offset = r.args.has("offset") && !r.args.get("offset").isJsonNull() ? r.args.get("offset").getAsInt() : null;
        Hit hit = null;
        List<String> listed = new ArrayList<>();
        for (DataTypeComponent c : type.getDefinedComponents()) {
            String name = c.getFieldName() != null ? c.getFieldName() : c.getDefaultFieldName();
            if (listed.size() < 60) listed.add(name + " +0x" + Integer.toHexString(c.getOffset()).toUpperCase());
            boolean match = member != null ? name.equals(member) : offset != null && c.getOffset() <= offset && offset < c.getOffset() + Math.max(1, c.getLength());
            if (match && hit == null) hit = new Hit(name, c.getOffset(), c.getLength(), c.getDataType().getDisplayName());
        }
        if (hit == null)
            throw new Worker.WorkerError("not_found", typeName + " has no member " + (member != null ? member : "at +0x" + Integer.toHexString(offset).toUpperCase())
                + " (members: " + String.join(", ", listed) + ")");

        JsonArray rows = new JsonArray();
        TreeSet<String> seen = new TreeSet<>();
        TreeSet<Long> functions = new TreeSet<>();
        // instances in memory: references into the member's bytes
        DataIterator it = w.program.getListing().getDefinedData(true);
        while (it.hasNext()) {
            r.monitor.checkCancelled();
            Data d = it.next();
            if (!sameType(d.getDataType(), type)) continue;
            Address at = d.getAddress().add(hit.offset);
            for (Reference ref : w.program.getReferenceManager().getReferencesTo(at)) {
                RefType t = ref.getReferenceType();
                Function f = add(w, rows, seen, ref.getFromAddress(), t.isWrite() ? "write" : t.isRead() ? "read" : "address");
                if (f != null) functions.add(f.getEntryPoint().getOffset() - w.base);
            }
        }
        for (Function f : w.program.getFunctionManager().getFunctions(true)) {
            if (namesType(f.getReturnType(), type)) functions.add(f.getEntryPoint().getOffset() - w.base);
            else
                for (Parameter p : f.getParameters())
                    if (namesType(p.getDataType(), type)) {
                        functions.add(f.getEntryPoint().getOffset() - w.base);
                        break;
                    }
        }
        for (JsonElement e : Worker.array(r.args, "functions")) functions.add(e.getAsLong());
        if (r.args.has("all_from") && !r.args.get("all_from").isJsonNull()) {
            // every function from that rva on (scope all, resumed where the last call stopped)
            long first = r.args.get("all_from").getAsLong();
            for (Function f : w.program.getFunctionManager().getFunctions(true))
                if (f.getEntryPoint().getOffset() - w.base >= first) functions.add(f.getEntryPoint().getOffset() - w.base);
        }

        int scanned = 0, failed = 0, skipped = 0;
        boolean decompiler = Worker.decompilerPresent();
        for (long rva : functions) {
            Function f = w.program.getFunctionManager().getFunctionAt(w.space().getAddress(w.base + rva));
            long left = deadline - System.nanoTime();
            if (!decompiler || left <= 0) {
                skipped++;
                continue;
            }
            if (f == null) {
                failed++;
                continue;
            }
            DecompileResults res;
            try {
                res = CodeOps.results(w, f, (int) Math.max(1, Math.min(w.decompileTimeout, left / 1_000_000_000L)), r.monitor);
            }
            catch (Worker.WorkerError ex) {
                failed++;
                continue;
            }
            HighFunction hf = res.getHighFunction();
            if (hf == null) {
                failed++;
                continue;
            }
            scanned++;
            for (Iterator<PcodeOpAST> ops = hf.getPcodeOps(); ops.hasNext();) {
                PcodeOp op = ops.next();
                if (op.getOpcode() != PcodeOp.PTRSUB || !op.getInput(1).isConstant() || op.getInput(1).getOffset() != hit.offset) continue;
                if (!pointsTo(op.getInput(0), type)) continue;
                add(w, rows, seen, op.getSeqnum().getTarget(), access(op.getOutput()));
            }
        }
        JsonObject o = new JsonObject();
        o.addProperty("type", type.getName());
        o.addProperty("member", hit.name);
        o.addProperty("offset", hit.offset);
        o.addProperty("size", hit.size);
        o.addProperty("member_type", hit.type);
        o.add("rows", sorted(rows));
        o.addProperty("candidates", functions.size());
        o.addProperty("scanned", scanned);
        o.addProperty("failed", failed);
        o.addProperty("skipped", skipped);
        o.addProperty("decompiler", decompiler);
        return o;
    }

    /**
     * write when the member's address (or an element or field address derived from it) is stored to, read when loaded from,
     * else address (passed on, taken).
     */
    private static String access(Varnode address) {
        boolean read = false;
        List<Varnode> work = new ArrayList<>();
        if (address != null) work.add(address);
        for (int depth = 0; depth < 4 && !work.isEmpty(); depth++) {
            List<Varnode> next = new ArrayList<>();
            for (Varnode v : work)
                for (Iterator<PcodeOp> uses = v.getDescendants(); uses.hasNext();) {
                    PcodeOp use = uses.next();
                    int code = use.getOpcode();
                    if (code == PcodeOp.STORE && use.getInput(1) == v) return "write";
                    if (code == PcodeOp.LOAD && use.getInput(1) == v) read = true;
                    else if ((code == PcodeOp.PTRADD || code == PcodeOp.PTRSUB || code == PcodeOp.INT_ADD || code == PcodeOp.CAST || code == PcodeOp.COPY)
                        && use.getInput(0) == v && use.getOutput() != null) next.add(use.getOutput());
                }
            work = next;
        }
        return read ? "read" : "address";
    }

    private static Function add(Worker w, JsonArray rows, TreeSet<String> seen, Address from, String kind) {
        Long rva = w.rva(from);
        if (rva == null || !seen.add(rva + kind)) return null;
        Function f = w.program.getFunctionManager().getFunctionContaining(from);
        JsonArray row = new JsonArray();
        row.add(rva);
        row.add(kind);
        Long start = f != null ? w.rva(f.getEntryPoint()) : null;
        if (start == null) row.add(JsonNull.INSTANCE);
        else row.add(start);
        rows.add(row);
        return f;
    }

    private static JsonArray sorted(JsonArray rows) {
        List<JsonArray> list = new ArrayList<>();
        for (JsonElement e : rows) list.add(e.getAsJsonArray());
        list.sort((a, b) -> a.get(0).getAsLong() != b.get(0).getAsLong() ? Long.compare(a.get(0).getAsLong(), b.get(0).getAsLong())
            : a.get(1).getAsString().compareTo(b.get(1).getAsString()));
        JsonArray out = new JsonArray();
        list.forEach(out::add);
        return out;
    }

    private static boolean pointsTo(Varnode v, Composite type) {
        HighVariable high = v.getHigh();
        DataType t = high != null ? strip(high.getDataType()) : null;
        return t instanceof Pointer p && sameType(p.getDataType(), type);
    }

    /** Whether t is the type, or a pointer, array or typedef down to it. */
    private static boolean namesType(DataType t, Composite type) {
        for (int i = 0; t != null && i < 8; i++) {
            t = strip(t);
            if (sameType(t, type)) return true;
            if (t instanceof Pointer p) t = p.getDataType();
            else if (t instanceof Array a) t = a.getDataType();
            else return false;
        }
        return false;
    }

    private static boolean sameType(DataType t, Composite type) {
        t = strip(t);
        return t != null && (t == type || t.isEquivalent(type) && t.getName().equals(type.getName()));
    }

    private static DataType strip(DataType t) {
        while (t instanceof TypeDef td) t = td.getBaseDataType();
        return t;
    }
}
