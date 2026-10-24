package corvus.ghidra;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import java.math.BigInteger;

import ghidra.program.model.address.Address;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.reloc.Relocation;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.ContextChangeException;
import ghidra.program.model.listing.ProgramContext;
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

    /**
     * ranges: [[start, end (exclusive)]] of 32-bit ARM code in Thumb state. Sets the TMode context register there, so code
     * disassembled later (functions made on request without auto-analysis) decodes as Thumb; ranges already holding
     * instructions keep their state. {set, skipped}; set 0 when the language has no TMode register.
     */
    static JsonObject setThumb(Worker w, Worker.Request r) {
        ProgramContext context = w.program.getProgramContext();
        Register tmode = context.getRegister("TMode");
        int set = 0, skipped = 0;
        if (tmode != null)
            for (JsonElement e : Worker.array(r.args, "ranges")) {
                JsonArray x = e.getAsJsonArray();
                long start = x.get(0).getAsLong(), end = x.get(1).getAsLong();
                if (end <= start) continue;
                try {
                    context.setValue(tmode, w.space().getAddress(w.base + start), w.space().getAddress(w.base + end - 1), BigInteger.ONE);
                    set++;
                }
                catch (ContextChangeException ex) {
                    skipped++;
                }
            }
        JsonObject o = new JsonObject();
        o.addProperty("set", set);
        o.addProperty("skipped", skipped);
        return o;
    }

    private static final int MEMORY_MAX = 16 << 20;

    /**
     * The loaded, initialized bytes of [rva, rva + size) in address order: runs [rva, base64]; other bytes are gaps. With
     * page, pages [rva, length, digest] cut at multiples of page instead, the digest being the first 8 bytes of the
     * SHA-256 in hex.
     */
    static JsonObject memory(Worker w, Worker.Request r) throws Exception {
        long size = r.args.has("size") ? r.args.get("size").getAsLong() : 0;
        if (size <= 0 || size > MEMORY_MAX) throw new Worker.WorkerError("invalid_argument", "size must be 1 to " + MEMORY_MAX + " bytes");
        long from = w.addr(r.args, "rva").getOffset(), to = from + size; // exclusive
        int page = r.args.has("page") ? r.args.get("page").getAsInt() : 0;
        if (page < 0 || page > MEMORY_MAX) throw new Worker.WorkerError("invalid_argument", "page must be 0 to " + MEMORY_MAX + " bytes");
        java.security.MessageDigest sha = page > 0 ? java.security.MessageDigest.getInstance("SHA-256") : null;
        JsonArray runs = new JsonArray(), pages = new JsonArray();
        for (MemoryBlock b : w.program.getMemory().getBlocks()) {
            if (!b.isInitialized() || !b.isLoaded() || b.getStart().getAddressSpace() != w.space()) continue;
            long lo = Math.max(from, b.getStart().getOffset()), hi = Math.min(to, b.getEnd().getOffset() + 1);
            if (lo >= hi) continue;
            byte[] buf = new byte[(int) (hi - lo)];
            int got = b.getBytes(w.space().getAddress(lo), buf, 0, buf.length);
            Long rva = w.rva(w.space().getAddress(lo));
            if (rva == null || got <= 0) continue;
            if (sha != null) {
                for (long at = rva, end = rva + got; at < end;) {
                    long next = Math.min(end, (at / page + 1) * page);
                    sha.update(buf, (int) (at - rva), (int) (next - at));
                    JsonArray p = new JsonArray();
                    p.add(at);
                    p.add(next - at);
                    p.add(java.util.HexFormat.of().formatHex(sha.digest(), 0, 8));
                    pages.add(p);
                    at = next;
                }
                continue;
            }
            JsonArray run = new JsonArray();
            run.add(rva);
            run.add(java.util.Base64.getEncoder().encodeToString(got == buf.length ? buf : java.util.Arrays.copyOf(buf, got)));
            runs.add(run);
        }
        JsonObject o = new JsonObject();
        o.add(sha != null ? "pages" : "runs", sha != null ? pages : runs);
        return o;
    }

    /**
     * The relocations the loader recorded, at most max, in address order: rows [rva, length, type, symbol or null]. The
     * type names the relocation number and its status ("type 7, applied"). Ghidra keeps no patch record: patched is null.
     */
    static JsonObject fixups(Worker w, Worker.Request r) {
        int max = r.args.has("max") ? r.args.get("max").getAsInt() : 1_000_000;
        JsonArray rows = new JsonArray();
        boolean truncated = false;
        for (Iterator<Relocation> it = w.program.getRelocationTable().getRelocations(); it.hasNext();) {
            Relocation rel = it.next();
            Long rva = rel.getAddress().getAddressSpace() == w.space() ? w.rva(rel.getAddress()) : null;
            if (rva == null) continue;
            if (rows.size() >= max) {
                truncated = true;
                break;
            }
            JsonArray row = new JsonArray();
            row.add(rva);
            row.add(Math.max(1, rel.getLength()));
            row.add("type " + rel.getType() + ", " + rel.getStatus().name().toLowerCase(java.util.Locale.ROOT).replace('_', ' '));
            if (rel.getSymbolName() != null && !rel.getSymbolName().isEmpty()) row.add(rel.getSymbolName());
            else row.add(com.google.gson.JsonNull.INSTANCE);
            rows.add(row);
        }
        JsonObject o = new JsonObject();
        o.add("fixups", rows);
        o.add("patched", com.google.gson.JsonNull.INSTANCE);
        o.addProperty("truncated", truncated);
        return o;
    }
}
