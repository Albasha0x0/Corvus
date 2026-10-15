package corvus.ghidra;

import java.math.BigInteger;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.HexFormat;
import java.util.List;
import java.util.Locale;
import java.util.Set;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import ghidra.pcode.emu.PcodeEmulationCallbacks;
import ghidra.pcode.emu.PcodeEmulator;
import ghidra.pcode.emu.PcodeThread;
import ghidra.pcode.exec.PcodeArithmetic;
import ghidra.pcode.exec.PcodeArithmetic.Purpose;
import ghidra.pcode.exec.PcodeExecutorState;
import ghidra.pcode.exec.PcodeExecutorStatePiece;
import ghidra.pcode.exec.PcodeExecutorStatePiece.Reason;
import ghidra.pcode.exec.PcodeFrame;
import ghidra.pcode.exec.PcodeStateCallbacks;
import ghidra.pcode.exec.PcodeUseropLibrary;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Undefined;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.PrototypeModel;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.symbol.ExternalLocation;
import ghidra.program.model.symbol.ExternalReference;
import ghidra.program.model.symbol.Reference;

/**
 * Static p-code emulation over the open program. Memory is the program's bytes (copy on write) plus a private region
 * holding a stack and scratch buffers; any other address faults. Nothing from the program runs natively and there is no host I/O.
 */
final class EmuOps {
    /** Private region: stack in the low half, scratch buffers in the high half. */
    private static final long REGION = 0x200000, STACK = 0x100000;
    private static final int MAX_CALLS = 100, MAX_RANGES = 64, MAX_RANGE_BYTES = 4096, MAX_READ = 65536, MAX_CHUNK = 1 << 20;

    private EmuOps() {
    }

    /** A read of an address no block, region or initial write maps. */
    static final class Fault extends RuntimeException {
        final Address at;

        Fault(Address at, String message) {
            super(message);
            this.at = at;
        }
    }

    /** Memory and write tracking for one run. */
    private static final class Machine implements PcodeEmulationCallbacks<byte[]> {
        final Memory mem;
        final AddressSpace ram;
        final long regionBase, regionEnd;
        final AddressSet userMapped = new AddressSet();
        final AddressSet written = new AddressSet();
        boolean tracking;

        Machine(Program program, AddressSpace ram, long regionBase) {
            this.mem = program.getMemory();
            this.ram = ram;
            this.regionBase = regionBase;
            this.regionEnd = regionBase + REGION;
        }

        boolean inRegion(Address a) {
            return Long.compareUnsigned(a.getOffset(), regionBase) >= 0 && Long.compareUnsigned(a.getOffset(), regionEnd) < 0;
        }

        boolean mapped(Address a) {
            return a.getAddressSpace() == ram && (mem.getBlock(a) != null || inRegion(a) || userMapped.contains(a));
        }

        // Ghidra 12.0's callback, without the read's reason (12.1 added it); no @Override on either, so both versions compile.
        public <A, U> AddressSetView readUninitialized(PcodeThread<byte[]> thread, PcodeExecutorStatePiece<A, U> piece, AddressSetView set) {
            return readUninitialized(thread, piece, set, null);
        }

        public <A, U> AddressSetView readUninitialized(PcodeThread<byte[]> thread, PcodeExecutorStatePiece<A, U> piece, AddressSetView set, Reason reason) {
            if (set.isEmpty() || set.getMinAddress().getAddressSpace() != ram) return set;
            PcodeExecutorStatePiece<A, byte[]> bytes = PcodeStateCallbacks.checkValueDomain(piece, byte[].class);
            if (bytes == null) return set;
            AddressSet remains = new AddressSet();
            for (AddressRange range : set) {
                Address a = range.getMinAddress(), end = range.getMaxAddress();
                while (a != null && a.compareTo(end) <= 0) {
                    MemoryBlock b = mem.getBlock(a);
                    Address stop;
                    if (b != null) stop = min(end, b.getEnd());
                    else if (inRegion(a)) stop = min(end, ram.getAddress(regionEnd - 1));
                    else {
                        Address next = nextMapped(a, end);
                        // the decoder reads ahead, so only a data read faults
                        if (reason == Reason.EXECUTE_READ) throw new Fault(a, "read of unmapped memory at 0x" + Long.toHexString(a.getOffset()));
                        remains.add(a, next == null ? end : next.previous());
                        a = next;
                        continue;
                    }
                    if (stop.subtract(a) >= MAX_CHUNK) stop = a.add(MAX_CHUNK - 1);
                    byte[] data = new byte[(int) stop.subtract(a) + 1];
                    if (b != null && b.isInitialized()) {
                        try {
                            mem.getBytes(a, data);
                        }
                        catch (MemoryAccessException e) {
                            // unreadable bytes stay zero
                        }
                    }
                    bytes.setVarInternal(ram, a.getOffset(), data.length, data);
                    a = stop.equals(ram.getMaxAddress()) ? null : stop.next();
                }
            }
            return remains;
        }

        /** The first mapped address after a within end, or null. */
        private Address nextMapped(Address a, Address end) {
            Address best = null;
            var it = mem.getAddressRanges(a, true);
            while (it.hasNext()) {
                AddressRange r = it.next();
                if (r.getMinAddress().getAddressSpace() != ram) continue;
                if (r.getMinAddress().compareTo(a) > 0) {
                    best = r.getMinAddress();
                    break;
                }
            }
            Address region = ram.getAddress(regionBase);
            if (region.compareTo(a) > 0 && (best == null || region.compareTo(best) < 0)) best = region;
            return best != null && best.compareTo(end) <= 0 ? best : null;
        }

        /**
         * Undoes a run for the next one on the same emulator: image bytes it wrote are read again from the program, the
         * stack and scratch region and the memory= ranges are zeroed.
         */
        void reset(PcodeExecutorState<byte[]> shared) {
            for (AddressRange range : written) {
                for (Address a = range.getMinAddress(); a != null && a.compareTo(range.getMaxAddress()) <= 0; ) {
                    MemoryBlock b = mem.getBlock(a);
                    Address stop = min(range.getMaxAddress(), b != null ? b.getEnd() : range.getMaxAddress());
                    if (stop.subtract(a) >= MAX_CHUNK) stop = a.add(MAX_CHUNK - 1);
                    byte[] data = new byte[(int) stop.subtract(a) + 1];
                    if (b != null && b.isInitialized()) {
                        try {
                            mem.getBytes(a, data);
                        }
                        catch (MemoryAccessException e) {
                            // unreadable bytes stay zero
                        }
                    }
                    if (b != null) shared.setVar(ram, a.getOffset(), data.length, false, data);
                    a = stop.equals(ram.getMaxAddress()) ? null : stop.next();
                }
            }
            byte[] zeros = new byte[MAX_CHUNK];
            for (long at = regionBase; Long.compareUnsigned(at, regionEnd) < 0; at += MAX_CHUNK)
                shared.setVar(ram, at, (int) Math.min(MAX_CHUNK, regionEnd - at), false, zeros);
            for (AddressRange range : userMapped)
                for (Address a = range.getMinAddress(); a != null && a.compareTo(range.getMaxAddress()) <= 0; ) {
                    long n = Math.min(MAX_CHUNK, range.getMaxAddress().subtract(a) + 1);
                    shared.setVar(ram, a.getOffset(), (int) n, false, java.util.Arrays.copyOf(zeros, (int) n));
                    a = range.getMaxAddress().subtract(a) + 1 > n ? a.add(n) : null;
                }
            written.clear();
            userMapped.clear();
        }

        @Override
        public <A, U> void dataWritten(PcodeThread<byte[]> thread, PcodeExecutorStatePiece<A, U> piece, Address address, int length, U value) {
            if (!tracking || length <= 0 || address.getAddressSpace() != ram) return;
            try {
                written.add(address, address.add(length - 1));
            }
            catch (ghidra.program.model.address.AddressOutOfBoundsException e) {
                written.add(address, ram.getMaxAddress());
            }
        }

        @Override
        public boolean handleMissingUserop(PcodeThread<byte[]> thread, PcodeOp op, PcodeFrame frame, String opName, PcodeUseropLibrary<byte[]> library) {
            // bus locking has no effect on a single emulated thread
            return opName.equals("LOCK") || opName.equals("UNLOCK");
        }
    }

    private static Address min(Address a, Address b) {
        return a.compareTo(b) <= 0 ? a : b;
    }

    /**
     * Emulates from start until it returns to the sentinel return address, reaches a stop address, an instruction or time
     * budget, an unmodelled call, a fault or a cancel. Args: start (VA), registers [[name, value]], args [value], memory
     * [{va, bytes}], stops [VA], stubs [[name, 0xVA or * (any other call), value]], max_instructions,
     * seconds, trace, reads [{va or register, length}]; a value is {value: "0x.."} or {bytes: hex} (a pointer to a scratch copy).
     */
    static JsonElement emulate(Worker w, Worker.Request r) {
        return run(w, r, r.args, new Engine(w.program));
    }

    /** A machine and its emulator, kept for every set of a batch; each run gets a new thread. */
    private static final class Engine {
        final Machine m;
        final PcodeEmulator emu;
        final long regionBase;

        Engine(Program program) {
            AddressSpace ram = program.getAddressFactory().getDefaultAddressSpace();
            int ptr = ram.getPointerSize();
            if (ptr < 4) throw new Worker.WorkerError("unsupported", "emulation needs a 32- or 64-bit address space, not " + (ptr * 8) + "-bit");
            regionBase = pickRegion(program, ram, ptr);
            m = new Machine(program, ram, regionBase);
            emu = new PcodeEmulator(program.getLanguage(), m);
        }
    }

    /**
     * One run per argument set in candidates [[value]], each on a fresh emulator with the other args shared; seconds bounds
     * the whole batch, and sets left when it is spent answer stop "not_run".
     */
    static JsonElement emulateBatch(Worker w, Worker.Request r) {
        JsonObject a = r.args;
        double seconds = a.has("seconds") ? a.get("seconds").getAsDouble() : 10;
        long end = System.nanoTime() + (long) (seconds * 1e9);
        JsonArray out = new JsonArray();
        Engine engine = new Engine(w.program);
        boolean used = false;
        for (JsonElement set : a.getAsJsonArray("candidates")) {
            double left = (end - System.nanoTime()) / 1e9;
            if (left <= 0 || r.stopped()) {
                JsonObject skipped = new JsonObject();
                skipped.addProperty("stop", r.stopped() && !"deadline".equals(r.stop) ? "cancelled" : "not_run");
                out.add(skipped);
                continue;
            }
            JsonObject one = a.deepCopy();
            one.remove("candidates");
            one.add("args", set);
            one.addProperty("seconds", left);
            if (used) engine.m.reset(engine.emu.getSharedState());
            used = true;
            out.add(run(w, r, one, engine));
        }
        JsonObject o = new JsonObject();
        o.add("candidates", out);
        return o;
    }

    private static JsonObject run(Worker w, Worker.Request r, JsonObject a, Engine engine) {
        Program program = w.program;
        Language lang = program.getLanguage();
        AddressSpace ram = program.getAddressFactory().getDefaultAddressSpace();
        int ptr = ram.getPointerSize();
        if (ptr < 4) throw new Worker.WorkerError("unsupported", "emulation needs a 32- or 64-bit address space, not " + (ptr * 8) + "-bit");
        Address start = ram.getAddress(va(a.get("start").getAsString()));
        long maxIns = a.has("max_instructions") ? a.get("max_instructions").getAsLong() : 1_000_000;
        double seconds = a.has("seconds") ? a.get("seconds").getAsDouble() : 10;
        int traceMax = a.has("trace") ? a.get("trace").getAsInt() : 0;
        boolean x86 = lang.getProcessor().toString().equalsIgnoreCase("x86");

        long regionBase = engine.regionBase;
        Machine m = engine.m;
        PcodeEmulator emu = engine.emu;
        PcodeThread<byte[]> t = emu.newThread();
        PcodeArithmetic<byte[]> arith = emu.getArithmetic();
        PcodeExecutorState<byte[]> shared = emu.getSharedState();
        PcodeExecutorState<byte[]> state = t.getState();
        Register contextReg = lang.getContextBaseRegister();
        if (contextReg != null && contextReg != Register.NO_CONTEXT) {
            RegisterValue ctx = program.getProgramContext().getDisassemblyContext(start);
            if (ctx != null) t.overrideContext(ctx);
        }
        t.overrideCounter(start);

        // stack, sentinel return address and the scratch area
        long stackTop = regionBase + STACK;
        long sp = (stackTop - 0x1000) & ~0xFL;
        Address sentinel = ram.getAddress(regionBase + REGION);
        if (x86) {
            sp -= ptr;
            shared.setVar(ram, sp, ptr, false, arith.fromConst(sentinel.getOffset(), ptr));
        }
        else {
            Register link = firstRegister(lang, "lr", "x30", "ra");
            if (link != null) state.setVar(link, arith.fromConst(sentinel.getOffset(), link.getMinimumByteSize()));
            else sentinel = null;
        }
        Register spReg = program.getCompilerSpec().getStackPointer();
        state.setVar(spReg, arith.fromConst(sp, spReg.getMinimumByteSize()));
        long[] scratch = { stackTop + 0x1000 };
        JsonArray scratchOut = new JsonArray();

        Function startFn = program.getFunctionManager().getFunctionAt(start);
        PrototypeModel cc = startFn != null && startFn.getCallingConvention() != null ? startFn.getCallingConvention()
            : program.getCompilerSpec().getDefaultCallingConvention();
        DataType word = Undefined.getUndefinedDataType(ptr);
        VariableStorage returnStorage = cc != null ? cc.getReturnLocation(word, program) : null;
        Register returnReg = returnStorage != null ? returnStorage.getRegister() : null;

        if (a.has("memory")) for (JsonElement e : a.getAsJsonArray("memory")) {
            JsonObject o = e.getAsJsonObject();
            Address at = ram.getAddress(va(o.get("va").getAsString()));
            byte[] bytes = HexFormat.of().parseHex(o.get("bytes").getAsString());
            if (bytes.length == 0) continue;
            shared.setVar(ram, at.getOffset(), bytes.length, false, bytes);
            if (!m.mapped(at) || !m.mapped(at.add(bytes.length - 1))) m.userMapped.add(at, at.add(bytes.length - 1));
        }
        if (a.has("args")) {
            JsonArray args = a.getAsJsonArray("args");
            if (cc == null) throw new Worker.WorkerError("unsupported", "the program has no calling convention to place arguments");
            DataType[] types = new DataType[args.size() + 1];
            java.util.Arrays.fill(types, word);
            VariableStorage[] storage = cc.getStorageLocations(program, types, false);
            for (int i = 0; i < args.size(); i++) {
                BigInteger v = value(args.get(i).getAsJsonObject(), shared, ram, scratch, regionBase, scratchOut, "arg" + (i + 1));
                VariableStorage s = i + 1 < storage.length ? storage[i + 1] : null;
                if (s == null || s.isBadStorage() || s.isUnassignedStorage())
                    throw new Worker.WorkerError("unsupported", "the calling convention has no place for argument " + (i + 1));
                if (s.isRegisterStorage()) {
                    Register reg = s.getRegister();
                    state.setVar(reg, arith.fromConst(v, reg.getMinimumByteSize()));
                }
                else if (s.isStackStorage()) shared.setVar(ram, sp + s.getStackOffset(), s.size(), false, arith.fromConst(v, s.size()));
                else throw new Worker.WorkerError("unsupported", "argument " + (i + 1) + " is passed in " + s + ", which is not supported");
            }
        }
        if (a.has("registers")) for (JsonElement e : a.getAsJsonArray("registers")) {
            JsonArray pair = e.getAsJsonArray();
            String name = pair.get(0).getAsString();
            Register reg = register(lang, name);
            if (reg == null) throw new Worker.WorkerError("invalid_argument", "no register '" + name + "' in " + lang.getLanguageID());
            BigInteger v = value(pair.get(1).getAsJsonObject(), shared, ram, scratch, regionBase, scratchOut, name);
            state.setVar(reg, arith.fromConst(v, reg.getMinimumByteSize()));
        }
        Set<Address> stops = new HashSet<>();
        if (a.has("stops")) for (JsonElement e : a.getAsJsonArray("stops")) stops.add(ram.getAddress(va(e.getAsString())));
        List<String[]> stubs = new ArrayList<>();
        if (a.has("stubs")) for (JsonElement e : a.getAsJsonArray("stubs")) {
            JsonArray pair = e.getAsJsonArray();
            stubs.add(new String[] { pair.get(0).getAsString(), pair.get(1).getAsString() });
        }

        List<Register> shown = mainRegisters(lang, ptr);
        List<BigInteger> before = new ArrayList<>();
        for (Register reg : shown) before.add(read(state, arith, reg));

        // run
        m.tracking = true;
        long started = System.nanoTime();
        long deadline = started + (long) (seconds * 1e9);
        long executed = 0;
        String stop = null, detail = null;
        Address stopAt = null;
        ArrayDeque<String[]> trace = new ArrayDeque<>();
        JsonArray calls = new JsonArray();
        int callCount = 0;
        while (true) {
            Address pc = t.getCounter();
            if (sentinel != null && pc.equals(sentinel)) {
                stop = "returned";
                break;
            }
            if (executed > 0 && stops.contains(pc)) {
                stop = "stop_address";
                break;
            }
            if (executed >= maxIns) {
                stop = "instruction_budget";
                break;
            }
            if ((executed & 63) == 0 && r.stopped()) {
                stop = "deadline".equals(r.stop) ? "time_budget" : "cancelled";
                break;
            }
            if (System.nanoTime() - deadline >= 0) {
                stop = "time_budget";
                break;
            }
            if (!m.mapped(pc)) {
                stop = "unmapped_execute";
                detail = "execution reached unmapped address 0x" + Long.toHexString(pc.getOffset());
                break;
            }
            Instruction ins;
            try {
                t.stepPcodeOp(); // decodes without executing
                ins = t.getInstruction();
                if (traceMax > 0 && ins != null) {
                    if (trace.size() == traceMax) trace.removeFirst();
                    trace.addLast(new String[] { "0x" + Long.toHexString(pc.getOffset()), ins.toString() });
                }
                t.finishInstruction();
            }
            catch (RuntimeException e) {
                Fault f = fault(e);
                stopAt = pc;
                if (f != null) {
                    stop = "memory_fault";
                    detail = f.getMessage();
                }
                else {
                    stop = "error";
                    detail = message(e);
                }
                break;
            }
            executed++;
            if (ins == null || !ins.getFlowType().isCall()) continue;
            Address site = ins.getAddress(), target = t.getCounter(), fall = ins.getFallThrough();
            Callee c = callee(program, site, target);
            String stubValue = stub(stubs, c, target);
            // a call to the next instruction reads its own address and is never skipped
            String anyValue = stubValue == null && fall != null && !target.equals(fall) ? any(stubs) : null;
            String action;
            BigInteger result = null;
            if (stubValue != null || anyValue != null) {
                action = stubValue != null ? "stub" : "skip";
                result = new BigInteger(Long.toUnsignedString(va(stubValue != null ? stubValue : anyValue)));
            }
            else if (c.external || !m.mapped(target)) {
                stop = "unmodelled_call";
                stopAt = site;
                detail = "call at 0x" + Long.toHexString(site.getOffset()) + " to " + (c.name != null ? c.name : "0x" + Long.toHexString(target.getOffset())) +
                    (c.external ? " (outside the image)" : " (unmapped)") + ": stub it (stubs=NAME=VALUE, or *=VALUE for every call)";
                break;
            }
            else action = "into";
            if (result != null) {
                if (returnReg != null) state.setVar(returnReg, arith.fromConst(result, returnReg.getMinimumByteSize()));
                if (x86) {
                    long purge = c.function != null && c.function.getStackPurgeSize() > 0 && c.function.getStackPurgeSize() < 0x10000 ? c.function.getStackPurgeSize() : 0;
                    BigInteger spNow = read(state, arith, spReg);
                    state.setVar(spReg, arith.fromConst(spNow.add(BigInteger.valueOf(ptr + purge)), spReg.getMinimumByteSize()));
                }
                t.overrideCounter(fall);
            }
            if (callCount++ < MAX_CALLS) {
                JsonObject call = new JsonObject();
                call.addProperty("site", hex(site.getOffset()));
                call.addProperty("target", hex(target.getOffset()));
                call.addProperty("name", c.name);
                call.addProperty("action", action);
                call.addProperty("value", result == null ? null : "0x" + result.toString(16));
                calls.add(call);
            }
        }
        m.tracking = false;
        double elapsed = (System.nanoTime() - started) / 1e9;
        if (r.monitor.isCancelled() && "cancelled".equals(stop)) r.monitor.clearCanceled();

        JsonObject o = new JsonObject();
        o.addProperty("language", lang.getLanguageID().toString());
        o.addProperty("stop", stop);
        o.addProperty("detail", detail);
        Address pc = stopAt != null ? stopAt : t.getCounter();
        o.addProperty("pc", hex(pc.getOffset()));
        o.addProperty("where", where(program, pc));
        o.addProperty("instructions", executed);
        o.addProperty("seconds", Math.round(elapsed * 1000) / 1000.0);
        o.addProperty("return_register", returnReg != null ? returnReg.getName() : null);
        o.addProperty("return_value", returnReg != null ? hex(read(state, arith, returnReg)) : null);
        JsonArray regs = new JsonArray();
        for (int i = 0; i < shown.size(); i++) {
            BigInteger now = read(state, arith, shown.get(i));
            JsonArray row = new JsonArray();
            row.add(shown.get(i).getName());
            row.add(hex(now));
            row.add(!now.equals(before.get(i)));
            regs.add(row);
        }
        o.add("registers", regs);
        o.add("calls", calls);
        o.addProperty("call_count", callCount);
        o.add("scratch", scratchOut);
        o.addProperty("stack", hex(regionBase) + "-" + hex(stackTop));

        // written memory outside the stack
        AddressSet stack = new AddressSet(ram.getAddress(regionBase), ram.getAddress(stackTop - 1));
        o.addProperty("stack_bytes_written", m.written.intersect(stack).getNumAddresses());
        AddressSet data = m.written.subtract(stack);
        JsonArray written = new JsonArray();
        int ranges = 0;
        for (AddressRange range : data) {
            if (ranges++ >= MAX_RANGES) break;
            int len = (int) Math.min(range.getLength(), MAX_RANGE_BYTES);
            JsonObject row = new JsonObject();
            row.addProperty("va", hex(range.getMinAddress().getOffset()));
            row.addProperty("length", range.getLength());
            row.addProperty("bytes", HexFormat.of().formatHex(shared.getVar(ram, range.getMinAddress().getOffset(), len, false, Reason.INSPECT)));
            row.addProperty("where", where(program, range.getMinAddress()));
            written.add(row);
        }
        o.add("written", written);
        o.addProperty("written_ranges", data.getNumAddressRanges());

        JsonArray reads = new JsonArray();
        if (a.has("reads")) for (JsonElement e : a.getAsJsonArray("reads")) {
            JsonObject q = e.getAsJsonObject();
            JsonObject row = new JsonObject();
            int len = Math.max(1, Math.min(MAX_READ, q.get("length").getAsInt()));
            long at;
            if (q.has("register")) {
                String name = q.get("register").getAsString();
                Register reg = register(lang, name);
                if (reg == null) throw new Worker.WorkerError("invalid_argument", "no register '" + name + "' in " + lang.getLanguageID());
                at = read(state, arith, reg).longValue();
                row.addProperty("label", name);
            }
            else at = va(q.get("va").getAsString());
            row.addProperty("va", hex(at));
            Address from = ram.getAddress(at);
            boolean ok = true;
            for (long i = 0; i < len && ok; i += 0x1000) ok = m.mapped(from.add(i)) || m.written.contains(from.add(i));
            if (!ok || !m.mapped(from.add(len - 1)) && !m.written.contains(from.add(len - 1))) row.addProperty("error", "unmapped");
            else row.addProperty("bytes", HexFormat.of().formatHex(shared.getVar(ram, at, len, false, Reason.INSPECT)));
            reads.add(row);
        }
        o.add("reads", reads);
        JsonArray traceOut = new JsonArray();
        for (String[] s : trace) {
            JsonArray row = new JsonArray();
            row.add(s[0]);
            row.add(s[1]);
            traceOut.add(row);
        }
        o.add("trace", traceOut);
        return o;
    }

    /** A value: a number, or bytes copied to the scratch area whose address is the value. */
    private static BigInteger value(JsonObject v, PcodeExecutorState<byte[]> shared, AddressSpace ram, long[] scratch, long regionBase, JsonArray scratchOut,
        String label) {
        if (v.has("value")) return new BigInteger(Long.toUnsignedString(va(v.get("value").getAsString())));
        byte[] bytes = HexFormat.of().parseHex(v.get("bytes").getAsString());
        long at = scratch[0];
        long next = (at + bytes.length + 16 + 15) & ~0xFL;
        if (next > regionBase + REGION) throw new Worker.WorkerError("limit_exceeded", "scratch buffers exceed " + (REGION - STACK - 0x1000) + " bytes");
        if (bytes.length > 0) shared.setVar(ram, at, bytes.length, false, bytes);
        scratch[0] = next;
        JsonObject row = new JsonObject();
        row.addProperty("label", label);
        row.addProperty("va", hex(at));
        row.addProperty("length", bytes.length);
        scratchOut.add(row);
        return BigInteger.valueOf(at);
    }

    /** A free 2 MB range (plus the sentinel page) outside the program's memory. */
    private static long pickRegion(Program program, AddressSpace ram, int ptr) {
        long[] candidates = ptr >= 8 ? new long[] { 0x7ffe00000000L, 0x100000000000L, 0x10000000L }
            : new long[] { 0x7f000000L, 0x10000000L, 0x30000000L, 0x50000000L, 0xa0000000L };
        Memory mem = program.getMemory();
        for (long c : candidates) {
            try {
                if (!mem.intersects(ram.getAddress(c), ram.getAddress(c + REGION + 0xfff))) return c;
            }
            catch (ghidra.program.model.address.AddressOutOfBoundsException e) {
                // too high for this space
            }
        }
        throw new Worker.WorkerError("failed", "no free address range for the emulator's stack");
    }

    private record Callee(String name, boolean external, Function function) {
    }

    /** What a call reaches: the function at its target, else the call's references (an import slot), thunks followed. */
    private static Callee callee(Program p, Address site, Address target) {
        var fm = p.getFunctionManager();
        var rm = p.getReferenceManager();
        Function f = p.getMemory().contains(target) ? fm.getFunctionAt(target) : null;
        if (f == null) {
            for (Reference ref : rm.getReferencesFrom(site)) {
                if (ref instanceof ExternalReference er) return external(er.getExternalLocation());
                Address to = ref.getToAddress();
                if (!to.isMemoryAddress()) continue;
                Function g = fm.getFunctionAt(to);
                if (g != null) {
                    f = g;
                    break;
                }
                for (Reference inner : rm.getReferencesFrom(to)) {
                    if (inner instanceof ExternalReference er) return external(er.getExternalLocation());
                    Function h = inner.getToAddress().isMemoryAddress() ? fm.getFunctionAt(inner.getToAddress()) : null;
                    if (h != null) f = h;
                }
                if (f != null) break;
            }
        }
        if (f == null) return new Callee(null, false, null);
        if (f.isThunk() && f.getThunkedFunction(true) != null) f = f.getThunkedFunction(true);
        if (f.isExternal()) {
            ExternalLocation loc = f.getExternalLocation();
            return loc != null ? new Callee(label(loc), true, f) : new Callee(f.getName(), true, f);
        }
        return new Callee(f.getName(), false, f);
    }

    private static Callee external(ExternalLocation loc) {
        return new Callee(label(loc), true, loc.getFunction());
    }

    private static String label(ExternalLocation loc) {
        return loc.getLibraryName() + "!" + loc.getLabel();
    }

    /** The stub value for a callee: by 0x address, by name, or by library!name (".dll" optional, case ignored). */
    private static String stub(List<String[]> stubs, Callee c, Address target) {
        for (String[] s : stubs) {
            String key = s[0].trim();
            if (key.equals("*")) continue;
            if (key.toLowerCase(Locale.ROOT).startsWith("0x")) {
                try {
                    if (Long.parseUnsignedLong(key.substring(2), 16) == target.getOffset()) return s[1];
                }
                catch (NumberFormatException e) {
                    // a name after all
                }
            }
            if (c.name == null) continue;
            String name = c.name, label = name.contains("!") ? name.substring(name.indexOf('!') + 1) : name;
            if (key.contains("!")) {
                if (name.contains("!") && module(key).equals(module(name)) && key.substring(key.indexOf('!') + 1).equalsIgnoreCase(label)) return s[1];
            }
            else if (key.equalsIgnoreCase(label)) return s[1];
        }
        return null;
    }

    /** The value of the * stub, which answers every call no other stub names. */
    private static String any(List<String[]> stubs) {
        for (String[] s : stubs) if (s[0].trim().equals("*")) return s[1];
        return null;
    }

    private static String module(String qualified) {
        String m = qualified.substring(0, qualified.indexOf('!')).toLowerCase(Locale.ROOT);
        return m.endsWith(".dll") ? m.substring(0, m.length() - 4) : m;
    }

    private static Register firstRegister(Language lang, String... names) {
        for (String n : names) {
            Register reg = register(lang, n);
            if (reg != null) return reg;
        }
        return null;
    }

    private static Register register(Language lang, String name) {
        Register reg = lang.getRegister(name);
        if (reg == null) reg = lang.getRegister(name.toUpperCase(Locale.ROOT));
        if (reg == null) reg = lang.getRegister(name.toLowerCase(Locale.ROOT));
        return reg;
    }

    /** The general registers reported after the run. */
    private static List<Register> mainRegisters(Language lang, int ptr) {
        String proc = lang.getProcessor().toString().toLowerCase(Locale.ROOT);
        List<String> names = new ArrayList<>();
        if (proc.equals("x86") && ptr == 8) {
            names.addAll(List.of("RAX", "RBX", "RCX", "RDX", "RSI", "RDI", "RBP", "RSP"));
            for (int i = 8; i < 16; i++) names.add("R" + i);
            names.add("RIP");
        }
        else if (proc.equals("x86")) names.addAll(List.of("EAX", "EBX", "ECX", "EDX", "ESI", "EDI", "EBP", "ESP", "EIP"));
        else if (proc.equals("aarch64")) {
            for (int i = 0; i <= 30; i++) names.add("x" + i);
            names.addAll(List.of("sp", "pc"));
        }
        else if (proc.equals("arm")) {
            for (int i = 0; i <= 12; i++) names.add("r" + i);
            names.addAll(List.of("sp", "lr", "pc"));
        }
        List<Register> regs = new ArrayList<>();
        for (String n : names) {
            Register reg = register(lang, n);
            if (reg != null) regs.add(reg);
        }
        if (regs.isEmpty()) for (Register reg : lang.getRegisters()) {
            if (reg.isBaseRegister() && !reg.isHidden() && !reg.isProcessorContext() && reg.getMinimumByteSize() == ptr) regs.add(reg);
            if (regs.size() >= 48) break;
        }
        return regs;
    }

    private static BigInteger read(PcodeExecutorState<byte[]> state, PcodeArithmetic<byte[]> arith, Register reg) {
        return arith.toBigInteger(state.getVar(reg, Reason.INSPECT), Purpose.INSPECT);
    }

    private static Fault fault(Throwable e) {
        for (Throwable c = e; c != null; c = c.getCause()) if (c instanceof Fault f) return f;
        return null;
    }

    private static String message(Throwable e) {
        Throwable root = e;
        while (root.getCause() != null && root.getCause() != root) root = root.getCause();
        String m = root.getMessage() != null ? root.getMessage() : root.getClass().getSimpleName();
        return root == e ? m : m + " (" + e.getClass().getSimpleName() + ")";
    }

    private static String where(Program p, Address a) {
        if (!p.getMemory().contains(a)) return null;
        Function f = p.getFunctionManager().getFunctionContaining(a);
        if (f == null) return null;
        long off = a.subtract(f.getEntryPoint());
        return off == 0 ? f.getName() : f.getName() + "+0x" + Long.toHexString(off);
    }

    static long va(String s) {
        String t = s.trim().toLowerCase(Locale.ROOT);
        boolean negative = t.startsWith("-");
        if (negative) t = t.substring(1);
        long v = t.startsWith("0x") ? Long.parseUnsignedLong(t.substring(2), 16) : Long.parseUnsignedLong(t);
        return negative ? -v : v;
    }

    private static String hex(long v) {
        return "0x" + Long.toHexString(v);
    }

    private static String hex(BigInteger v) {
        return "0x" + v.toString(16);
    }
}
