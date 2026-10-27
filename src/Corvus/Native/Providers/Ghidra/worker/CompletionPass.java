package corvus.ghidra;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

import com.google.gson.JsonObject;

import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.services.Analyzer;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.classfinder.ClassSearcher;
import ghidra.util.task.TaskMonitor;

/**
 * Reruns the standard profile's capped analyzers at 60 s, plus stack analysis, in slices while the worker is idle.
 * A slice holds the read lock; a writer cancels it once GRACE old and it is redone. Slices are large: each starts decompilers.
 */
final class CompletionPass {
    static final String STAMP = "completion";
    // Stack is off in the first analysis when this pass follows (GhidraOptions.AnalyzerOptions).
    private static final Set<String> ANALYZERS = Set.of("Decompiler Parameter ID", "Decompiler Switch Analysis", "Call Convention ID", "Stack");
    private static final String TIMEOUT = ".Analysis Decompiler Timeout (sec)";
    private static final int SLICE = 64;
    private static final long IDLE_NANOS = 300_000_000L, GRACE_NANOS = 500_000_000L, SAVE_NANOS = 60_000_000_000L;

    private final Worker w;
    private final Program program;
    private volatile Worker.Monitor slice;
    private volatile long sliceStarted;
    private volatile long lastActivity = System.nanoTime();
    private volatile String state = "pending";
    private volatile int done, total;
    // Requests that arrived while a slice ran, and slices cancelled for a writer.
    private final AtomicInteger beside = new AtomicInteger(), yielded = new AtomicInteger();

    CompletionPass(Worker w, Program program) {
        this.w = w;
        this.program = program;
    }

    static boolean finished(Program p) {
        return "full".equals(p.getOptions(Worker.STAMPS).getString(STAMP, null));
    }

    /** A request arrived or ended: the next slice waits for the worker to be idle again. */
    void activity() {
        lastActivity = System.nanoTime();
    }

    /** A request arrived: as {@link #activity}, counting it when a slice is running beside it. */
    void arrived() {
        if (slice != null) beside.incrementAndGet();
        activity();
    }

    JsonObject status() {
        JsonObject o = new JsonObject();
        o.addProperty("state", state);
        o.addProperty("done", done);
        o.addProperty("total", total);
        o.addProperty("beside", beside.get());
        o.addProperty("yielded", yielded.get());
        return o;
    }

    void start() {
        Thread t = new Thread(this::run, "completion pass");
        t.setDaemon(true);
        t.setPriority(Thread.MIN_PRIORITY);
        t.start();
        Thread p = new Thread(this::preempter, "completion pass preemption");
        p.setDaemon(true);
        p.start();
    }

    private boolean over() {
        return state.equals("done") || state.equals("stopped") || state.startsWith("failed") || w.program != program;
    }

    /** Cancels a slice that a writer waits behind, once the slice is GRACE old. */
    private void preempter() {
        try {
            while (!over()) {
                Thread.sleep(20);
                Worker.Monitor m = slice;
                if (m != null && !m.isCancelled() && w.lock.hasQueuedThreads() && System.nanoTime() - sliceStarted >= GRACE_NANOS) {
                    m.cancel();
                    yielded.incrementAndGet();
                }
            }
        }
        catch (InterruptedException e) {
            // The worker is exiting.
        }
    }

    private boolean idleNow() {
        return w.running.isEmpty() && System.nanoTime() - lastActivity >= IDLE_NANOS;
    }

    private void run() {
        try {
            List<Analyzer> analyzers = new ArrayList<>();
            for (Analyzer a : ClassSearcher.getInstances(Analyzer.class))
                if (ANALYZERS.contains(a.getName())) analyzers.add(a);
            List<Address> entries = new ArrayList<>();
            w.lock.readLock().lock();
            try {
                if (w.program != program) return;
                for (Function f : program.getFunctionManager().getFunctions(true))
                    if (!f.isThunk() && !f.isExternal()) entries.add(f.getEntryPoint());
            }
            finally {
                w.lock.readLock().unlock();
            }
            total = entries.size();
            if (analyzers.isEmpty()) {
                state = "unavailable";
                return;
            }
            setTimeouts();
            state = "running";
            long saved = System.nanoTime();
            for (int i = 0; i < entries.size();) {
                if (w.program != program) return;
                if (!idleNow()) {
                    Thread.sleep(100);
                    continue;
                }
                int end = Math.min(entries.size(), i + SLICE);
                Boolean ran = slice(entries.subList(i, end), analyzers);
                if (ran == null) return;
                if (ran) done = i = end;
                if (System.nanoTime() - saved > SAVE_NANOS && idleNow()) {
                    save(false);
                    saved = System.nanoTime();
                }
            }
            save(true);
            state = "done";
        }
        catch (InterruptedException e) {
            state = "stopped";
        }
        catch (Exception e) {
            state = "failed: " + e;
            e.printStackTrace(System.err);
        }
    }

    private void setTimeouts() throws Exception {
        w.lock.writeLock().lock();
        try {
            if (w.program != program) return;
            int tx = program.startTransaction("completion pass options");
            try {
                var options = program.getOptions(Program.ANALYSIS_PROPERTIES);
                for (String name : ANALYZERS)
                    if (options.isRegistered(name + TIMEOUT)) options.setInt(name + TIMEOUT, 60);
                AutoAnalysisManager.getAnalysisManager(program).initializeOptions();
            }
            finally {
                program.endTransaction(tx, true);
            }
        }
        finally {
            w.lock.writeLock().unlock();
        }
    }

    /** One slice under the read lock: true when it finished, false when cancelled for a writer, null when the program closed. */
    private Boolean slice(List<Address> entries, List<Analyzer> analyzers) throws Exception {
        w.lock.readLock().lock();
        try {
            if (w.program != program) return null;
            Worker.Monitor m = new Worker.Monitor();
            sliceStarted = System.nanoTime();
            slice = m;
            int tx = program.startTransaction("completion pass");
            try {
                AutoAnalysisManager mgr = AutoAnalysisManager.getAnalysisManager(program);
                // Whole bodies: switch analysis looks at the jumps inside a function, not at its entry.
                AddressSet set = new AddressSet();
                for (Address a : entries)
                    if (program.getFunctionManager().getFunctionAt(a) instanceof Function f) set.add(f.getBody());
                for (Analyzer a : analyzers) mgr.scheduleOneTimeAnalysis(a, set);
                mgr.startAnalysis(m);
                return !m.isCancelled();
            }
            finally {
                program.endTransaction(tx, true);
                slice = null;
            }
        }
        finally {
            w.lock.readLock().unlock();
        }
    }

    private void save(boolean stamp) throws Exception {
        w.lock.writeLock().lock();
        try {
            if (w.program != program) return;
            if (stamp) {
                int tx = program.startTransaction("completion stamp");
                try { program.getOptions(Worker.STAMPS).setString(STAMP, "full"); }
                finally { program.endTransaction(tx, true); }
            }
            if (program.isChanged()) program.save("completion pass", TaskMonitor.DUMMY);
        }
        finally {
            w.lock.writeLock().unlock();
        }
    }
}
