package ndm.ghidra;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicInteger;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import ghidra.program.model.listing.Function;
import ghidra.util.exception.CancelledException;

/** Requests over many functions with partial results; callers hold the read lock. */
final class BatchOps {
    private BatchOps() {
    }

    /**
     * The function containing each of rvas, in order: each within seconds_per_item, all within budget_seconds, run across
     * the decompiler pool (items start in order, one per free decompiler). Items: {rva, status ok + the decompile fields}
     * or {rva, status error, code, message} or {rva, status skipped}.
     */
    static JsonElement decompileMany(Worker w, Worker.Request r) throws Exception {
        double perItem = Math.max(1, r.args.has("seconds_per_item") ? r.args.get("seconds_per_item").getAsDouble() : 60);
        double budget = Math.max(1, r.args.has("budget_seconds") ? r.args.get("budget_seconds").getAsDouble() : 600);
        long start = System.nanoTime();
        JsonArray rvas = Worker.array(r.args, "rvas");
        JsonObject[] items = new JsonObject[rvas.size()];
        AtomicInteger next = new AtomicInteger();
        // The read lock held by this thread covers the helpers: they take no lock of their own.
        int threads = Math.max(1, Math.min(w.decompilers.size(), rvas.size()));
        ExecutorService pool = Executors.newFixedThreadPool(threads, t -> {
            Thread th = new Thread(t, "ndm decompile_many");
            th.setDaemon(true);
            return th;
        });
        try {
            List<Future<?>> running = new ArrayList<>();
            for (int k = 0; k < threads; k++)
                running.add(pool.submit(() -> {
                    for (int i; (i = next.getAndIncrement()) < items.length;)
                        items[i] = item(w, r, rvas.get(i).getAsLong(), perItem, budget - (System.nanoTime() - start) / 1e9);
                    return null;
                }));
            for (Future<?> f : running) f.get();
        }
        catch (java.util.concurrent.ExecutionException e) {
            if (e.getCause() instanceof Exception x) throw x;
            throw e;
        }
        finally {
            pool.shutdownNow();
        }
        JsonArray out = new JsonArray();
        for (JsonObject item : items) out.add(item);
        JsonObject o = new JsonObject();
        o.add("items", out);
        return r.stop != null ? r.partial(o, null) : o;
    }

    private static JsonObject item(Worker w, Worker.Request r, long rva, double perItem, double left) throws Exception {
        JsonObject item;
        if (left < 1 || r.stopped()) {
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
            catch (CancelledException ex) {
                item = new JsonObject();
                item.addProperty("status", "skipped");
            }
        }
        item.addProperty("rva", rva);
        return item;
    }
}
