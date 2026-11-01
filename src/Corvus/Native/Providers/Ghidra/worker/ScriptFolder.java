package corvus.ghidra;

import java.io.File;

/**
 * Script source and class folders of one worker, so workers sharing a home
 * never evict each other.
 */
final class ScriptFolder {
    private final File root;

    /** Roots the scripts of this worker at home/scripts/worker. */
    ScriptFolder(File home, String worker) {
        root = new File(new File(home, "scripts"), worker);
    }

    /**
     * Returns the folders of this process under the user home, emptied on
     * creation; the folders of workers that have ended are deleted.
     */
    static ScriptFolder current() {
        // A process id keeps workers on one home apart; a reused id starts clean.
        String worker = Long.toString(ProcessHandle.current().pid());
        ScriptFolder folder = new ScriptFolder(new File(System.getProperty("user.home")), worker);
        delete(folder.root);
        sweep(folder.root.getParentFile());
        return folder;
    }

    /** Deletes the folder of each worker in scripts whose process has ended. */
    static void sweep(File scripts) {
        File[] workers = scripts.listFiles(File::isDirectory);
        if (workers == null) return;
        for (File w : workers) {
            long pid;
            try { pid = Long.parseLong(w.getName()); }
            catch (NumberFormatException e) { continue; }
            if (ProcessHandle.of(pid).isEmpty()) delete(w);
        }
    }

    /** Returns the folder of the script with this source hash; it may not exist. */
    File of(String key) {
        return new File(root, key);
    }

    /** Deletes the folder of the script with this source hash; a missing one is ignored. */
    void evict(String key) {
        delete(of(key));
    }

    private static void delete(File dir) {
        File[] files = dir.listFiles();
        if (files != null) for (File f : files) {
            if (f.isDirectory()) delete(f);
            else if (!f.delete()) f.deleteOnExit();
        }
        if (!dir.delete()) dir.deleteOnExit();
    }
}
