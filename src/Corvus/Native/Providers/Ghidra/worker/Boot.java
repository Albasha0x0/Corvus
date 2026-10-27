package corvus.ghidra;

import ghidra.GhidraApplicationLayout;
import ghidra.GhidraClassLoader;
import ghidra.GhidraLaunchable;

/** Adds the worker jar to Ghidra's class loader, which alone sees Ghidra's modules and extensions, and starts the worker. */
public class Boot implements GhidraLaunchable {
    @Override
    public void launch(GhidraApplicationLayout layout, String[] args) throws Exception {
        watchParent();
        GhidraClassLoader loader = (GhidraClassLoader) ClassLoader.getSystemClassLoader();
        loader.addPath(System.getProperty("corvus.worker.jar"));
        GhidraLaunchable worker = (GhidraLaunchable) Class.forName("corvus.ghidra.Worker", true, loader).getDeclaredConstructor().newInstance();
        worker.launch(layout, args);
    }

    /** Ends the worker within a second of its parent: stdin is not read during the seconds Ghidra takes to initialize. */
    private static void watchParent() {
        long parent = ProcessHandle.current().parent().map(ProcessHandle::pid).orElse(-1L);
        if (parent < 0) return;
        Thread watch = new Thread(() -> {
            while (true) {
                try {
                    Thread.sleep(1000);
                }
                catch (InterruptedException e) {
                    return;
                }
                // POSIX re-parents an orphan; on Windows parent() is empty once the parent has exited.
                if (ProcessHandle.current().parent().map(ProcessHandle::pid).orElse(-1L) != parent) Runtime.getRuntime().halt(3);
            }
        }, "parent watch");
        watch.setDaemon(true);
        watch.start();
    }
}
