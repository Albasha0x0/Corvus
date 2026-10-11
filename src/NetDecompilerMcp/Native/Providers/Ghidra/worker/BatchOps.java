package ndm.ghidra;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import ghidra.program.model.listing.Function;

/** Requests over many functions with partial results; callers hold the read lock. */
final class BatchOps {
    private BatchOps() {
    }

    /**
     * The function containing each of rvas, in order: each within seconds_per_item, all within budget_seconds. Items:
     * {rva, status ok + the decompile fields} or {rva, status error, code, message} or {rva, status skipped}.
     */
    static JsonElement decompileMany(Worker w, Worker.Request r) throws Exception {
        double perItem = Math.max(1, r.args.has("seconds_per_item") ? r.args.get("seconds_per_item").getAsDouble() : 60);
        double budget = Math.max(1, r.args.has("budget_seconds") ? r.args.get("budget_seconds").getAsDouble() : 600);
        long start = System.nanoTime();
        JsonArray items = new JsonArray();
        for (JsonElement e : Worker.array(r.args, "rvas")) {
            r.monitor.checkCancelled();
            long rva = e.getAsLong();
            double left = budget - (System.nanoTime() - start) / 1e9;
            JsonObject item;
            if (left < 1) {
                item = new JsonObject();
                item.addProperty("status", "skipped");
            }
            else {
                try {
                    Function f = CodeOps.functionAt(w, w.space().getAddress(w.base + rva));
                    item = CodeOps.decompiled(w, f, (int) Math.max(1, Math.min(perItem, left)), r.monitor);
                    item.addProperty("status", "ok");
                }
                catch (Worker.WorkerError ex) {
                    item = new JsonObject();
                    item.addProperty("status", "error");
                    item.addProperty("code", ex.code);
                    item.addProperty("message", ex.getMessage());
                }
            }
            item.addProperty("rva", rva);
            items.add(item);
        }
        JsonObject o = new JsonObject();
        o.add("items", items);
        return o;
    }
}
