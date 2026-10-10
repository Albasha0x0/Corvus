// Pool design (LIFO reuse, bounded slots, one deadline over wait and run, flushCache after writes) follows
// pyghidra-mcp's decompiler_pool.py, Copyright clearbluejar, Apache License 2.0. See THIRD-PARTY-NOTICES.md.
package ndm.ghidra;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.program.model.listing.Program;

/** Decompiler processes for one program, each opened once and reused, so one slow function does not block the others. */
final class Decompilers {
    private final Program program;
    private final Semaphore slots;
    private final ArrayDeque<DecompInterface> idle = new ArrayDeque<>();
    private final List<DecompInterface> created = new ArrayList<>();
    private boolean closed;

    Decompilers(Program program, int size) {
        this.program = program;
        this.slots = new Semaphore(Math.max(1, size));
    }

    /** Waits up to the deadline for a free decompiler; the caller gives it back with {@link #release}. */
    DecompInterface acquire(long deadlineNanos) throws InterruptedException {
        long wait = deadlineNanos - System.nanoTime();
        if (wait <= 0 || !slots.tryAcquire(wait, TimeUnit.NANOSECONDS))
            throw new Worker.WorkerError("timeout", "timed out waiting for a free decompiler");
        try {
            synchronized (this) {
                if (closed) throw new Worker.WorkerError("failed", "the program is closed");
                DecompInterface d = idle.pollLast();
                if (d != null) return d;
            }
            DecompInterface d = create();
            synchronized (this) {
                if (closed) {
                    d.dispose();
                    throw new Worker.WorkerError("failed", "the program is closed");
                }
                created.add(d);
            }
            return d;
        }
        catch (RuntimeException e) {
            slots.release();
            throw e;
        }
    }

    void release(DecompInterface d) {
        synchronized (this) {
            if (!closed) idle.addLast(d);
        }
        slots.release();
    }

    private DecompInterface create() {
        DecompInterface d = new DecompInterface();
        DecompileOptions options = new DecompileOptions();
        options.grabFromProgram(program);
        d.setOptions(options);
        d.toggleCCode(true);
        d.toggleSyntaxTree(true);
        d.toggleJumpLoads(true);
        d.setSimplificationStyle("decompile");
        if (!d.openProgram(program)) {
            String message = d.getLastMessage();
            d.dispose();
            throw new Worker.WorkerError("unsupported", "the decompiler did not start: " + message);
        }
        return d;
    }

    /** After a change to the program; callers hold the write lock, so no decompiler is busy. */
    synchronized void flush() {
        for (DecompInterface d : created) d.flushCache();
    }

    void dispose() {
        List<DecompInterface> all;
        synchronized (this) {
            closed = true;
            all = new ArrayList<>(created);
            created.clear();
            idle.clear();
        }
        for (DecompInterface d : all) d.dispose();
    }
}
