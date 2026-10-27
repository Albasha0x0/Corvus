package corvus.ghidra;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryBlockSourceInfo;

/** Byte patches in the program; callers run them inside {@link Worker#write}. */
final class PatchOps {
    /** Program option: the RVAs whose bytes differ from the file because of a sync, as "rva:length" ranges. */
    private static final String PATCHED = "patched";
    /** Program option: entries of functions that held patched code, so a revert restores their bodies. */
    private static final String PATCH_FUNCTIONS = "patch_functions";

    private PatchOps() {
    }

    /**
     * Makes the synced patches exactly items [[rva, hex bytes]], restoring unwanted bytes; touched code is redecoded and its functions' bodies recomputed
     * without auto-analysis. Bytes outside initialized file-backed memory are missing.
     */
    static JsonObject sync(Worker w, Worker.Request r) throws Exception {
        long start = System.nanoTime();
        Memory mem = w.program.getMemory();
        TreeMap<Long, Byte> desired = new TreeMap<>();
        for (JsonElement e : Worker.array(r.args, "items")) {
            JsonArray item = e.getAsJsonArray();
            long rva = item.get(0).getAsLong();
            byte[] bytes = java.util.HexFormat.of().parseHex(item.get(1).getAsString());
            for (int i = 0; i < bytes.length; i++) desired.put(rva + i, bytes[i]);
        }
        Set<Long> previously = ranges(w.program.getOptions(Worker.STAMPS).getString(PATCHED, ""));

        // The plan: byte values to write, by rva.
        TreeMap<Long, Byte> plan = new TreeMap<>();
        List<Long> missing = new ArrayList<>();
        int patched = 0, reverted = 0;
        for (long rva : previously) {
            if (desired.containsKey(rva)) continue;
            Address a = w.space().getAddress(w.base + rva);
            Byte orig = original(mem, a);
            if (orig != null && mem.getByte(a) != orig) {
                plan.put(rva, orig);
                reverted++;
            }
        }
        for (Map.Entry<Long, Byte> d : desired.entrySet()) {
            Address a = w.space().getAddress(w.base + d.getKey());
            Byte orig = original(mem, a);
            if (orig == null) {
                missing.add(d.getKey());
                continue;
            }
            if (mem.getByte(a) == d.getValue()) continue;
            plan.put(d.getKey(), d.getValue());
            if (orig == (byte) d.getValue()) reverted++;
            else patched++;
        }

        // Contiguous ranges of the plan, widened to the code units they touch.
        Listing listing = w.program.getListing();
        FunctionManager fm = w.program.getFunctionManager();
        Set<Long> functions = new TreeSet<>(ranges(w.program.getOptions(Worker.STAMPS).getString(PATCH_FUNCTIONS, "")));
        List<long[]> runs = new ArrayList<>();
        for (long rva : plan.keySet()) {
            if (!runs.isEmpty() && runs.get(runs.size() - 1)[1] == rva) runs.get(runs.size() - 1)[1] = rva + 1;
            else runs.add(new long[] { rva, rva + 1 });
        }
        AddressSet code = new AddressSet();
        for (long[] run : runs) {
            Address lo = w.space().getAddress(w.base + run[0]);
            Address hi = w.space().getAddress(w.base + run[1] - 1);
            CodeUnit first = listing.getCodeUnitContaining(lo);
            CodeUnit last = listing.getCodeUnitContaining(hi);
            Address from = first != null ? first.getMinAddress() : lo;
            Address to = last != null ? last.getMaxAddress() : hi;
            for (var it = fm.getFunctionsOverlapping(new AddressSet(from, to)); it.hasNext();) {
                Long entry = w.rva(it.next().getEntryPoint());
                if (entry != null) functions.add(entry);
            }
            MemoryBlock block = mem.getBlock(lo);
            listing.clearCodeUnits(from, to, false);
            // The range's start only: flow decodes the rest; a start set would make every address an instruction.
            if (block != null && block.isExecute()) code.add(from);
        }
        for (Map.Entry<Long, Byte> p : plan.entrySet())
            mem.setByte(w.space().getAddress(w.base + p.getKey()), p.getValue());
        if (!code.isEmpty()) new DisassembleCommand(code, null, true).applyTo(w.program, r.monitor);
        for (long entry : functions) {
            Address a = w.space().getAddress(w.base + entry);
            Function f = fm.getFunctionAt(a);
            if (f != null) CreateFunctionCmd.fixupFunctionBody(w.program, f, r.monitor);
            else if (listing.getInstructionAt(a) != null) new CreateFunctionCmd(a).applyTo(w.program, r.monitor);
        }

        List<Long> mismatches = new ArrayList<>();
        for (Map.Entry<Long, Byte> d : desired.entrySet()) {
            Address a = w.space().getAddress(w.base + d.getKey());
            if (original(mem, a) != null && mem.getByte(a) != d.getValue()) mismatches.add(d.getKey());
        }
        // Record what differs from the file now.
        TreeSet<Long> now = new TreeSet<>();
        TreeSet<Long> candidates = new TreeSet<>(previously);
        candidates.addAll(desired.keySet());
        for (long rva : candidates) {
            Address a = w.space().getAddress(w.base + rva);
            Byte orig = original(mem, a);
            if (orig != null && mem.getByte(a) != orig) now.add(rva);
        }
        w.program.getOptions(Worker.STAMPS).setString(PATCHED, format(now));
        w.program.getOptions(Worker.STAMPS).setString(PATCH_FUNCTIONS, now.isEmpty() ? "" : format(functions));

        JsonObject o = new JsonObject();
        o.addProperty("patched", patched);
        o.addProperty("reverted", reverted);
        o.addProperty("ranges", runs.size());
        o.addProperty("functions", functions.size());
        o.add("missing", first20(missing));
        o.addProperty("missing_count", missing.size());
        o.add("mismatches", first20(mismatches));
        o.addProperty("mismatch_count", mismatches.size());
        o.addProperty("seconds", Math.round((System.nanoTime() - start) / 1e6) / 1000.0);
        return o;
    }

    /** The byte the file has at the address, or null where memory is not initialized from the file. */
    static Byte original(Memory mem, Address a) throws IOException {
        MemoryBlock block = mem.getBlock(a);
        if (block == null || !block.isInitialized()) return null;
        for (MemoryBlockSourceInfo info : block.getSourceInfos()) {
            if (!info.contains(a)) continue;
            Optional<FileBytes> bytes = info.getFileBytes();
            return bytes.isPresent() ? bytes.get().getOriginalByte(info.getFileBytesOffset(a)) : null;
        }
        return null;
    }

    private static JsonArray first20(List<Long> values) {
        JsonArray a = new JsonArray();
        for (int i = 0; i < Math.min(20, values.size()); i++) a.add(values.get(i));
        return a;
    }

    /** "rva:length,..." in hex to the set of RVAs it covers. */
    private static Set<Long> ranges(String text) {
        TreeSet<Long> set = new TreeSet<>();
        if (text == null || text.isEmpty()) return set;
        for (String part : text.split(",")) {
            int colon = part.indexOf(':');
            long rva = Long.parseLong(colon < 0 ? part : part.substring(0, colon), 16);
            long n = colon < 0 ? 1 : Long.parseLong(part.substring(colon + 1), 16);
            for (long i = 0; i < n; i++) set.add(rva + i);
        }
        return set;
    }

    private static String format(Set<Long> rvas) {
        StringBuilder sb = new StringBuilder();
        long runStart = -1, runEnd = -1;
        for (long rva : rvas) {
            if (rva == runEnd) {
                runEnd++;
                continue;
            }
            if (runStart >= 0) append(sb, runStart, runEnd);
            runStart = rva;
            runEnd = rva + 1;
        }
        if (runStart >= 0) append(sb, runStart, runEnd);
        return sb.toString();
    }

    private static void append(StringBuilder sb, long start, long end) {
        if (sb.length() > 0) sb.append(',');
        sb.append(Long.toHexString(start));
        if (end - start > 1) sb.append(':').append(Long.toHexString(end - start));
    }
}
