package ndm.ghidra;

import java.util.Iterator;
import java.util.TreeSet;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.Reference;

/** Call targets as the program and its decompiler see them; callers hold the read lock. */
final class CallOps {
    private CallOps() {
    }

    /**
     * What Ghidra knows about the call instructions at sites (rvas) in functions (rvas), within seconds. Rows:
     * [site, "xref", target]: a call reference to a function; [site, "vftable", struct, offset]: the decompiler loads
     * the target from a member of a struct reached through a pointer (a vftable as apply_types defines it);
     * [site, "direct", target]: the decompiler resolved the call to a function; [site, "other", how]: anything else.
     */
    static JsonElement virtualTargets(Worker w, Worker.Request r) throws Exception {
        long deadline = System.nanoTime() + (long) ((r.args.has("seconds") ? r.args.get("seconds").getAsDouble() : 60) * 1e9);
        FunctionManager fm = w.program.getFunctionManager();
        TreeSet<Long> sites = new TreeSet<>();
        for (JsonElement e : Worker.array(r.args, "sites")) sites.add(e.getAsLong());
        JsonArray rows = new JsonArray();
        for (long site : sites) {
            for (Reference ref : w.program.getReferenceManager().getReferencesFrom(w.space().getAddress(w.base + site))) {
                Long to = w.rva(ref.getToAddress());
                if (ref.getReferenceType().isCall() && to != null && fm.getFunctionAt(ref.getToAddress()) != null) rows.add(row(site, "xref", to));
            }
        }
        JsonObject o = new JsonObject();
        o.add("rows", rows);
        JsonArray failed = new JsonArray();
        int decompiled = 0, skipped = 0;
        if (!Worker.decompilerPresent()) {
            o.addProperty("decompiled", 0);
            o.add("failed", failed);
            o.addProperty("skipped", Worker.array(r.args, "functions").size());
            o.addProperty("decompiler", false);
            return o;
        }
        for (JsonElement e : Worker.array(r.args, "functions")) {
            long rva = e.getAsLong();
            long left = deadline - System.nanoTime();
            Function f = fm.getFunctionAt(w.space().getAddress(w.base + rva));
            if (left <= 0) {
                skipped++;
                continue;
            }
            if (f == null) {
                failed.add(failure(rva, "no function starts there"));
                continue;
            }
            DecompileResults res;
            try {
                res = CodeOps.results(w, f, (int) Math.max(1, Math.min(w.decompileTimeout, left / 1_000_000_000L)), r.monitor);
            }
            catch (Worker.WorkerError ex) {
                failed.add(failure(rva, ex.getMessage()));
                continue;
            }
            HighFunction hf = res.getHighFunction();
            if (hf == null) {
                failed.add(failure(rva, "no high function"));
                continue;
            }
            decompiled++;
            for (long site : sites) {
                Address a = w.space().getAddress(w.base + site);
                if (!f.getBody().contains(a)) continue;
                for (Iterator<PcodeOpAST> it = hf.getPcodeOps(a); it.hasNext();) {
                    PcodeOp op = it.next();
                    if (op.getOpcode() == PcodeOp.CALL) {
                        Address target = op.getInput(0).getAddress();
                        Long to = w.rva(target);
                        if (to != null && fm.getFunctionAt(target) != null) rows.add(row(site, "direct", to));
                    }
                    else if (op.getOpcode() == PcodeOp.CALLIND) rows.add(indirect(site, op.getInput(0)));
                }
            }
        }
        o.addProperty("decompiled", decompiled);
        o.add("failed", failed);
        o.addProperty("skipped", skipped);
        o.addProperty("decompiler", true);
        return o;
    }

    /** CALLIND(LOAD(base + offset)) with base a pointer to a struct: that struct's member; else how the target is computed. */
    private static JsonArray indirect(long site, Varnode target) {
        PcodeOp load = skipCasts(target);
        if (load == null || load.getOpcode() != PcodeOp.LOAD) return row(site, "other", load == null ? "unknown" : load.getMnemonic().toLowerCase());
        Varnode pointer = load.getInput(1);
        PcodeOp def = skipCasts(pointer);
        Varnode base = pointer;
        long offset = 0;
        if (def != null && (def.getOpcode() == PcodeOp.PTRSUB || def.getOpcode() == PcodeOp.INT_ADD) && def.getInput(1).isConstant()) {
            base = def.getInput(0);
            offset = def.getInput(1).getOffset();
        }
        Structure s = pointedStruct(base);
        if (s == null) return row(site, "other", "load");
        JsonArray row = new JsonArray();
        row.add(site);
        row.add("vftable");
        row.add(s.getName());
        row.add(offset);
        return row;
    }

    /** The defining op of a varnode, through casts and copies. */
    private static PcodeOp skipCasts(Varnode v) {
        PcodeOp def = v.getDef();
        while (def != null && (def.getOpcode() == PcodeOp.CAST || def.getOpcode() == PcodeOp.COPY)) def = def.getInput(0).getDef();
        return def;
    }

    private static Structure pointedStruct(Varnode v) {
        HighVariable high = v.getHigh();
        DataType t = high != null ? high.getDataType() : null;
        while (t instanceof TypeDef td) t = td.getBaseDataType();
        if (!(t instanceof Pointer p)) return null;
        DataType pointed = p.getDataType();
        while (pointed instanceof TypeDef td) pointed = td.getBaseDataType();
        return pointed instanceof Structure s ? s : null;
    }

    private static JsonArray row(long site, String kind, Object value) {
        JsonArray row = new JsonArray();
        row.add(site);
        row.add(kind);
        if (value instanceof Long l) row.add(l);
        else row.add(String.valueOf(value));
        return row;
    }

    private static JsonArray failure(long rva, String reason) {
        JsonArray row = new JsonArray();
        row.add(rva);
        row.add(reason == null ? "failed" : reason.length() > 200 ? reason.substring(0, 200) : reason);
        return row;
    }
}
