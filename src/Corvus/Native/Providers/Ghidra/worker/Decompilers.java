// Pool: LIFO reuse, bounded slots, one deadline over wait and run, flushCache after writes.
package corvus.ghidra;

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
    private final int size;
    /** Decompiler response limit (DecompileOptions' max payload, MB); Ghidra's default 50 is too small for large functions. */
    final int payloadMb;
    private final ArrayDeque<DecompInterface> idle = new ArrayDeque<>();
    private final List<DecompInterface> created = new ArrayList<>();
    private boolean closed;

    Decompilers(Program program, int size, int payloadMb) {
        this.program = program;
        this.size = Math.max(1, size);
        this.slots = new Semaphore(this.size);
        this.payloadMb = payloadMb;
    }

    int size() {
        return size;
    }

    /** Waits up to the deadline for a free decompiler; the caller gives it back with {@link #release}. */
    DecompInterface acquire(long deadlineNanos) throws InterruptedException {
        slot(deadlineNanos);
        try {
            synchronized (this) {
                if (closed) throw new Worker.WorkerError("failed", "the program is closed");
                DecompInterface d = idle.pollLast();
                if (d != null) return d;
            }
            DecompInterface d = create(payloadMb);
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

    private void slot(long deadlineNanos) throws InterruptedException {
        long wait = deadlineNanos - System.nanoTime();
        if (wait <= 0 || !slots.tryAcquire(wait, TimeUnit.NANOSECONDS))
            throw new Worker.WorkerError("timeout", "timed out waiting for a free decompiler");
    }

    /** A new decompiler with its own payload limit in a pool slot; the caller ends it with {@link #discard}. */
    DecompInterface acquireFresh(long deadlineNanos, int payload) throws InterruptedException {
        slot(deadlineNanos);
        try {
            DecompInterface d = create(payload);
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

    void discard(DecompInterface d) {
        boolean mine;
        synchronized (this) {
            mine = created.remove(d);
        }
        if (mine) d.dispose();
        slots.release();
    }

    void release(DecompInterface d) {
        synchronized (this) {
            if (!closed) idle.addLast(d);
        }
        slots.release();
    }

    private DecompInterface create(int payload) {
        DecompInterface d = new DecompInterface();
        DecompileOptions options = new DecompileOptions();
        options.grabFromProgram(program);
        options.setMaxPayloadMBytes(payload);
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
