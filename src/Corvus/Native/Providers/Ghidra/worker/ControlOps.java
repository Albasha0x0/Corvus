package corvus.ghidra;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Bookmark;
import ghidra.program.model.listing.BookmarkManager;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;

/** Function candidates and the server's bookmarks; callers hold the read lock (candidates) or the write lock (marks). */
final class ControlOps {
    /** Bookmark category of the server's marks. */
    static final String MARK_CATEGORY = "Corvus";

    // Migration only: the category before the rename; its bookmarks are replaced like ours.
    private static final String LEGACY_MARK_CATEGORY = "NDM";

    private ControlOps() {
    }

    /**
     * Runs of consecutive instructions in no function, in address order, scanning at most max_scan instructions: rows
     * [start, end (exclusive), instructions, call refs, jump refs, data refs] to the run's start; scanned, truncated.
     */
    static JsonElement functionCandidates(Worker w, Worker.Request r) throws Exception {
        int max = r.args.has("max_scan") ? Math.max(1, r.args.get("max_scan").getAsInt()) : 2_000_000;
        FunctionManager fm = w.program.getFunctionManager();
        ReferenceManager rm = w.program.getReferenceManager();
        JsonArray rows = new JsonArray();
        int scanned = 0;
        boolean truncated = false;
        Address start = null, last = null;
        int count = 0;
        InstructionIterator it = w.program.getListing().getInstructions(true);
        while (it.hasNext()) {
            r.monitor.checkCancelled();
            if (scanned >= max) {
                truncated = true;
                break;
            }
            Instruction ins = it.next();
            scanned++;
            boolean outside = fm.getFunctionContaining(ins.getMinAddress()) == null;
            if (outside && start != null && follows(last, ins.getMinAddress())) {
                last = ins.getMaxAddress();
                count++;
                continue;
            }
            if (start != null) row(w, rm, rows, start, last, count);
            start = null;
            if (outside) {
                start = ins.getMinAddress();
                last = ins.getMaxAddress();
                count = 1;
            }
        }
        if (start != null) row(w, rm, rows, start, last, count);
        JsonObject o = new JsonObject();
        o.add("rows", rows);
        o.addProperty("scanned", scanned);
        o.addProperty("truncated", truncated);
        return o;
    }

    private static boolean follows(Address last, Address next) {
        return last.getAddressSpace() == next.getAddressSpace() && next.getOffset() == last.getOffset() + 1;
    }

    private static void row(Worker w, ReferenceManager rm, JsonArray rows, Address start, Address last, int count) {
        Long rva = w.rva(start), end = w.rva(last);
        if (rva == null || end == null) return;
        int calls = 0, jumps = 0, data = 0;
        for (Reference ref : rm.getReferencesTo(start)) {
            RefType t = ref.getReferenceType();
            if (t.isCall()) calls++;
            else if (t.isJump()) jumps++;
            else if (t.isData()) data++;
        }
        JsonArray row = new JsonArray();
        row.add(rva);
        row.add(Math.min(end + 1, 0xFFFFFFFFL));
        row.add(count);
        row.add(calls);
        row.add(jumps);
        row.add(data);
        rows.add(row);
    }

    /**
     * Replaces the bookmarks of the server's category with items [[rva, text]] (Note bookmarks) and records the stamp
     * (stamp_key, stamp). Result: set, removed, failed, failures.
     */
    static JsonElement setMarks(Worker w, Worker.Request r) throws Exception {
        BookmarkManager bm = w.program.getBookmarkManager();
        List<Bookmark> old = new ArrayList<>();
        for (Iterator<Bookmark> it = bm.getBookmarksIterator(BookmarkType.NOTE); it.hasNext();) {
            Bookmark b = it.next();
            if (MARK_CATEGORY.equals(b.getCategory()) || LEGACY_MARK_CATEGORY.equals(b.getCategory())) old.add(b);
        }
        for (Bookmark b : old) bm.removeBookmark(b);
        int set = 0;
        JsonArray failures = new JsonArray();
        for (JsonElement e : Worker.array(r.args, "items")) {
            long rva = e.getAsJsonArray().get(0).getAsLong();
            String text = e.getAsJsonArray().get(1).getAsString();
            Address a = w.space().getAddress(w.base + rva);
            if (!w.program.getMemory().contains(a)) {
                failures.add("0x" + Long.toHexString(rva).toUpperCase() + ": not in memory");
                continue;
            }
            bm.setBookmark(a, BookmarkType.NOTE, MARK_CATEGORY, text);
            set++;
        }
        w.setStamp(r.args);
        JsonObject o = new JsonObject();
        o.addProperty("set", set);
        o.addProperty("removed", old.size());
        o.addProperty("failed", failures.size());
        o.add("failures", failures);
        return o;
    }
}
