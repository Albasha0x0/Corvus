// A decompiler timeout is its own error, not a failure.
package ndm.ghidra;

import java.util.HexFormat;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonNull;
import com.google.gson.JsonObject;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.decompiler.ClangLine;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.component.DecompilerUtils;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockIterator;
import ghidra.program.model.block.CodeBlockReference;
import ghidra.program.model.block.CodeBlockReferenceIterator;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.CodeUnitFormat;
import ghidra.program.model.listing.CodeUnitIterator;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolType;
import ghidra.util.task.TaskMonitor;

/** Read operations; callers hold the read lock. Row shapes match the IDA worker's. */
final class CodeOps {
    private static final HexFormat HEX = HexFormat.of();

    private CodeOps() {
    }

    static Function functionAt(Worker w, Address a) {
        Function f = w.program.getFunctionManager().getFunctionContaining(a);
        if (f == null && w.noAuto) f = create(w, a);
        if (f == null) throw new Worker.WorkerError("not_found", "no function contains rva 0x" + Long.toHexString(a.getOffset() - w.base).toUpperCase());
        return f;
    }

    /** Without auto-analysis: disassembles from the address and makes a function there (as IDA's worker does). */
    private static synchronized Function create(Worker w, Address a) {
        int tx = w.program.startTransaction("function on request");
        try {
            if (w.program.getListing().getInstructionAt(a) == null) new DisassembleCommand(a, null, true).applyTo(w.program, TaskMonitor.DUMMY);
            new CreateFunctionCmd(a).applyTo(w.program, TaskMonitor.DUMMY);
            return w.program.getFunctionManager().getFunctionContaining(a);
        }
        finally {
            w.program.endTransaction(tx, true);
        }
    }

    /** Exclusive end of the body range holding the entry (the main chunk). */
    static long end(Worker w, Function f) {
        AddressRange range = f.getBody().getRangeContaining(f.getEntryPoint());
        Address max = range != null ? range.getMaxAddress() : f.getEntryPoint();
        return max.getOffset() + 1 - w.base;
    }

    /**
     * [start, end, name, flags (1 thunk, 8 typed: a signature not of default source), refs?]: refs counts code references to
     * the start; from rva start when given. Stopped early: {rows, partial, next} where next is the start rva of the following call.
     */
    static JsonElement functions(Worker w, Worker.Request r) throws Exception {
        boolean refs = r.args.has("refs") && r.args.get("refs").getAsBoolean();
        ReferenceManager rm = w.program.getReferenceManager();
        JsonArray out = new JsonArray();
        boolean from = r.args.has("start") && !r.args.get("start").isJsonNull();
        FunctionIterator functions = from ? w.program.getFunctionManager().getFunctions(w.addr(r.args, "start"), true)
            : w.program.getFunctionManager().getFunctions(true);
        for (Function f : functions) {
            Long start = w.rva(f.getEntryPoint());
            if (start == null) continue;
            if (out.size() > 0 && r.stopped()) {
                JsonObject o = new JsonObject();
                o.add("rows", out);
                return r.partial(o, start);
            }
            JsonArray row = new JsonArray();
            row.add(start);
            row.add(Math.min(end(w, f), 0xFFFFFFFFL));
            row.add(f.getName());
            row.add((f.isThunk() ? 1 : 0) | (f.getSignatureSource() != ghidra.program.model.symbol.SourceType.DEFAULT ? 8 : 0));
            if (refs) {
                int n = 0;
                for (Reference ref : rm.getReferencesTo(f.getEntryPoint()))
                    if (ref.getReferenceType().isFlow() && !ref.getReferenceType().isFallthrough()) n++;
                row.add(n);
            }
            out.add(row);
        }
        return out;
    }

    /** A pooled decompilation of the function within timeout seconds; a timeout or failure is a WorkerError. */
    static DecompileResults results(Worker w, Function f, int timeout, Worker.Monitor monitor) throws Exception {
        return results(w, f, timeout, 0, false, monitor).results();
    }

    record Outcome(DecompileResults results, boolean retried) {
    }

    /**
     * As {@link #results(Worker, Function, int, Worker.Monitor)}; with retrySeconds > 0 a timeout or a full response buffer
     * is tried once more within retrySeconds and twice the payload, on a fresh decompiler that is discarded afterwards.
     * failFirst (test hook) treats the first attempt as timed out without running it.
     */
    static Outcome results(Worker w, Function f, int timeout, int retrySeconds, boolean failFirst, Worker.Monitor monitor) throws Exception {
        DecompileResults res = failFirst ? null : run(w, f, timeout, 0, monitor);
        boolean timedOut = failFirst || res != null && res.isTimedOut();
        if (retrySeconds > 0 && !completed(res) && (timedOut || bufferFull(res))) {
            int payload = Math.max(1, w.decompilers.payloadMb) * 2;
            DecompileResults again = run(w, f, retrySeconds, payload, monitor);
            if (!completed(again)) {
                boolean late = again != null && again.isTimedOut();
                throw new Worker.WorkerError(late ? "timeout" : "failed", "decompiling " + f.getName() + " " +
                    (timedOut ? "did not finish within " + timeout + " s" : "exceeded the " + w.decompilers.payloadMb + " MB response limit") +
                    ", and a retry with " + retrySeconds + " s and " + payload + " MB " + (late ? "did not finish" : "failed: " + message(again)));
            }
            return new Outcome(again, true);
        }
        if (!completed(res)) {
            if (timedOut) throw new Worker.WorkerError("timeout", "decompiling " + f.getName() + " did not finish within " + timeout + " s");
            throw new Worker.WorkerError("failed", "decompiling " + f.getName() + " failed: " + message(res));
        }
        return new Outcome(res, false);
    }

    /** One attempt; payload 0 uses a pooled decompiler, otherwise a fresh one with that payload. */
    private static DecompileResults run(Worker w, Function f, int timeout, int payload, Worker.Monitor monitor) throws Exception {
        long deadline = System.nanoTime() + timeout * 1_000_000_000L;
        DecompInterface d = payload > 0 ? w.decompilers.acquireFresh(deadline, payload) : w.decompilers.acquire(deadline);
        DecompileResults res;
        try {
            int left = (int) Math.max(1, (deadline - System.nanoTime()) / 1_000_000_000L);
            res = d.decompileFunction(f, left, monitor);
        }
        finally {
            if (payload > 0) w.decompilers.discard(d);
            else w.decompilers.release(d);
        }
        monitor.checkCancelled();
        return res;
    }

    private static boolean completed(DecompileResults res) {
        return res != null && res.decompileCompleted() && res.getCCodeMarkup() != null;
    }

    private static String message(DecompileResults res) {
        String m = res == null ? "no result" : res.getErrorMessage();
        return m == null ? "" : m.trim();
    }

    /** The decompiler's answer did not fit its payload limit. */
    private static boolean bufferFull(DecompileResults res) {
        return res != null && message(res).toLowerCase().contains("buffer size exceeded");
    }

    static JsonElement decompile(Worker w, Worker.Request r) throws Exception {
        Function f = functionAt(w, w.addr(r.args, "rva"));
        int timeout = r.args.has("timeout") ? r.args.get("timeout").getAsInt() : w.decompileTimeout;
        int retry = r.args.has("retry_timeout") ? r.args.get("retry_timeout").getAsInt() : 0;
        boolean failFirst = r.args.has("fail_first") && r.args.get("fail_first").getAsBoolean();
        Outcome out = results(w, f, timeout, retry, failFirst, r.monitor);
        JsonObject o = text(w, f, out.results());
        if (out.retried()) o.addProperty("retried", true);
        return o;
    }

    static JsonObject decompiled(Worker w, Function f, int timeout, Worker.Monitor monitor) throws Exception {
        return text(w, f, results(w, f, timeout, monitor));
    }

    /** Pseudocode built from the decompiler's lines, each with the lowest address among its tokens. */
    private static JsonObject text(Worker w, Function f, DecompileResults res) {
        List<ClangLine> lines = DecompilerUtils.toLines(res.getCCodeMarkup());
        StringBuilder text = new StringBuilder();
        JsonArray addresses = new JsonArray();
        for (int i = 0; i < lines.size(); i++) {
            ClangLine line = lines.get(i);
            if (i > 0) text.append('\n');
            text.append(line.getIndentString());
            Long lowest = null;
            for (ClangToken t : line.getAllTokens()) {
                text.append(t.getText());
                Long a = w.rva(t.getMinAddress());
                if (a != null && (lowest == null || a < lowest)) lowest = a;
            }
            if (lowest != null) {
                JsonArray pair = new JsonArray();
                pair.add(i);
                pair.add(lowest);
                addresses.add(pair);
            }
        }
        JsonObject o = new JsonObject();
        o.addProperty("start", w.rva(f.getEntryPoint()));
        o.addProperty("name", f.getName());
        o.addProperty("text", text.toString());
        o.add("lines", addresses);
        return o;
    }

    private static JsonArray row(Worker w, CodeUnit cu) {
        JsonArray row = new JsonArray();
        row.add(w.rva(cu.getAddress()));
        byte[] bytes;
        try {
            bytes = cu.getBytes();
        }
        catch (MemoryAccessException e) {
            bytes = new byte[0];
        }
        row.add(HEX.formatHex(bytes));
        row.add(CodeUnitFormat.DEFAULT.getRepresentationString(cu));
        String comment = cu.getComment(CommentType.EOL);
        if (comment == null) comment = cu.getComment(CommentType.REPEATABLE);
        row.add(comment == null ? JsonNull.INSTANCE : new com.google.gson.JsonPrimitive(comment));
        return row;
    }

    static JsonElement disasm(Worker w, Worker.Request r) throws Exception {
        Function f = functionAt(w, w.addr(r.args, "rva"));
        int limit = r.args.has("limit") ? r.args.get("limit").getAsInt() : 200_000;
        JsonArray insns = new JsonArray();
        InstructionIterator it = w.program.getListing().getInstructions(f.getBody(), true);
        while (it.hasNext() && insns.size() < limit) {
            r.monitor.checkCancelled();
            Instruction insn = it.next();
            if (w.rva(insn.getAddress()) != null) insns.add(row(w, insn));
        }
        JsonObject o = new JsonObject();
        o.addProperty("start", w.rva(f.getEntryPoint()));
        o.addProperty("end", end(w, f));
        o.addProperty("name", f.getName());
        o.add("insns", insns);
        o.addProperty("truncated", insns.size() >= limit);
        return o;
    }

    /** count items from rva in address order (instructions, or data and undefined bytes), stopping at a gap. */
    static JsonElement disasmRange(Worker w, Worker.Request r) throws Exception {
        Address a = w.addr(r.args, "rva");
        int count = Math.max(1, Math.min(r.args.has("count") ? r.args.get("count").getAsInt() : 100, 200_000));
        Listing listing = w.program.getListing();
        JsonArray insns = new JsonArray();
        CodeUnit first = listing.getCodeUnitContaining(a);
        if (first != null && !first.getAddress().equals(a)) a = first.getAddress();
        CodeUnitIterator it = listing.getCodeUnits(a, true);
        Address expected = a;
        boolean cut = false;
        while (it.hasNext() && insns.size() < count) {
            if (insns.size() > 0 && r.stopped()) {
                cut = true;
                break;
            }
            CodeUnit cu = it.next();
            if (!cu.getAddress().equals(expected) || w.rva(cu.getAddress()) == null) break;
            insns.add(row(w, cu));
            expected = cu.getMaxAddress().next();
            if (expected == null) break;
        }
        JsonObject o = new JsonObject();
        o.add("insns", insns);
        o.addProperty("truncated", cut || insns.size() >= count);
        if (cut) o.addProperty("partial", r.stop != null ? r.stop : "cancelled");
        return o;
    }

    /** [start, end, instructions, kind, successors, switch] per basic block; jumps leaving the function are tail calls. */
    static JsonElement blocks(Worker w, Worker.Request r) throws Exception {
        Function f = functionAt(w, w.addr(r.args, "rva"));
        Listing listing = w.program.getListing();
        BasicBlockModel model = new BasicBlockModel(w.program);
        JsonArray blocks = new JsonArray();
        Set<Long> tails = new TreeSet<>();
        CodeBlockIterator it = model.getCodeBlocksContaining(f.getBody(), r.monitor);
        while (it.hasNext()) {
            CodeBlock b = it.next();
            Long start = w.rva(b.getMinAddress());
            Long last = w.rva(b.getMaxAddress());
            if (start == null || last == null) continue;
            int count = 0;
            InstructionIterator ii = listing.getInstructions(b, true);
            Instruction lastInsn = null;
            while (ii.hasNext()) {
                lastInsn = ii.next();
                count++;
            }
            Set<Long> succs = new LinkedHashSet<>();
            CodeBlockReferenceIterator dests = b.getDestinations(r.monitor);
            while (dests.hasNext()) {
                CodeBlockReference ref = dests.next();
                FlowType ft = ref.getFlowType();
                if (ft.isCall()) continue;
                Long to = w.rva(ref.getDestinationAddress());
                if (to == null) continue;
                if (f.getBody().contains(ref.getDestinationAddress())) succs.add(to);
                else if (ft.isJump()) tails.add(to);
            }
            FlowType flow = lastInsn != null ? lastInsn.getFlowType() : RefType.FALL_THROUGH;
            boolean isSwitch = lastInsn != null && flow.isComputed() && flow.isJump() && lastInsn.getFlows().length > 1;
            JsonArray row = new JsonArray();
            row.add(start);
            row.add(last + 1);
            row.add(count);
            row.add(kind(flow));
            JsonArray s = new JsonArray();
            for (Long x : succs) s.add(x);
            row.add(s);
            row.add(isSwitch);
            blocks.add(row);
        }
        JsonObject o = new JsonObject();
        o.addProperty("start", w.rva(f.getEntryPoint()));
        o.addProperty("name", f.getName());
        o.add("blocks", blocks);
        JsonArray t = new JsonArray();
        for (Long x : tails) t.add(x);
        o.add("tail_calls", t);
        return o;
    }

    /** Block end kinds in the IDA worker's terms. */
    private static String kind(FlowType flow) {
        if (flow.isCall() && flow.isTerminal()) return "noret";
        if (flow.isTerminal()) return flow.isConditional() ? "cndret" : "ret";
        if (flow.isComputed() && flow.isJump()) return "indjump";
        return "normal";
    }

    static String xrefKind(RefType t) {
        if (t.isCall()) return "call";
        if (t.isJump()) return "jump";
        if (t.isFlow()) return "code";
        if (t.isWrite()) return "write";
        if (t.isRead()) return "read";
        if (t == RefType.DATA) return "offset";
        return "data";
    }

    private static JsonArray xrefRow(Worker w, Reference ref) {
        if (ref.getReferenceType().isFallthrough()) return null;
        Long from = w.rva(ref.getFromAddress());
        Long to = w.rva(ref.getToAddress());
        if (from == null || to == null) return null;
        JsonArray row = new JsonArray();
        row.add(from);
        row.add(to);
        row.add(xrefKind(ref.getReferenceType()));
        Function f = w.program.getFunctionManager().getFunctionContaining(ref.getFromAddress());
        Long fs = f != null ? w.rva(f.getEntryPoint()) : null;
        if (fs == null) row.add(JsonNull.INSTANCE);
        else row.add(fs);
        return row;
    }

    static JsonElement xrefsTo(Worker w, Worker.Request r) throws Exception {
        JsonArray out = new JsonArray();
        for (Reference ref : w.program.getReferenceManager().getReferencesTo(w.addr(r.args, "rva"))) {
            r.monitor.checkCancelled();
            JsonArray row = xrefRow(w, ref);
            if (row != null) out.add(row);
        }
        return out;
    }

    static JsonElement xrefsFrom(Worker w, Worker.Request r) throws Exception {
        Address a = w.addr(r.args, "rva");
        ReferenceManager rm = w.program.getReferenceManager();
        JsonArray out = new JsonArray();
        if (r.args.has("function") && r.args.get("function").getAsBoolean()) {
            InstructionIterator it = w.program.getListing().getInstructions(functionAt(w, a).getBody(), true);
            while (it.hasNext()) {
                r.monitor.checkCancelled();
                for (Reference ref : rm.getReferencesFrom(it.next().getAddress())) {
                    JsonArray row = xrefRow(w, ref);
                    if (row != null) out.add(row);
                }
            }
        }
        else {
            for (Reference ref : rm.getReferencesFrom(a)) {
                JsonArray row = xrefRow(w, ref);
                if (row != null) out.add(row);
            }
        }
        return out;
    }

    /**
     * Names Ghidra has that are neither its defaults nor ours: functions and labels from the loader and analysis (IMPORTED,
     * ANALYSIS, including Function ID library names); USER_DEFINED names are what this server pushed. Rows [rva, name,
     * source (imported, analysis), function]; offset/limit page them, total counts all.
     */
    static JsonElement names(Worker w, Worker.Request r) throws Exception {
        int offset = Math.max(0, r.args.has("offset") ? r.args.get("offset").getAsInt() : 0);
        int limit = Math.max(1, r.args.has("limit") ? r.args.get("limit").getAsInt() : 50_000);
        JsonArray rows = new JsonArray();
        int total = 0;
        for (Symbol s : w.program.getSymbolTable().getAllSymbols(false)) {
            r.monitor.checkCancelled();
            SymbolType t = s.getSymbolType();
            SourceType src = s.getSource();
            if (t != SymbolType.FUNCTION && t != SymbolType.LABEL || !s.isPrimary() || s.isExternal()) continue;
            if (src != SourceType.IMPORTED && src != SourceType.ANALYSIS) continue;
            String name = s.getName(true);
            if (generated(name)) continue;
            Long rva = w.rva(s.getAddress());
            if (rva == null) continue;
            if (total++ < offset || rows.size() >= limit) continue;
            JsonArray row = new JsonArray();
            row.add(rva);
            row.add(name);
            row.add(src == SourceType.IMPORTED ? "imported" : "analysis");
            row.add(t == SymbolType.FUNCTION);
            rows.add(row);
        }
        JsonObject o = new JsonObject();
        o.addProperty("total", total);
        o.add("rows", rows);
        return o;
    }

    /** Names Ghidra generates that analysis records under its own source: switch tables, cases, strings, pointers. */
    private static final String[] GENERATED = { "FUN_", "LAB_", "DAT_", "PTR_", "thunk_FUN_", "switchD_", "caseD_", "switchdataD_", "s_", "u_" };

    private static boolean generated(String name) {
        for (String p : GENERATED)
            if (name.startsWith(p)) return true;
        return false;
    }
}
