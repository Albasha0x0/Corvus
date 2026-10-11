package corvus.ghidra;

import java.io.File;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import generic.jar.ResourceFile;
import ghidra.app.plugin.core.osgi.BundleHost;
import ghidra.app.script.GhidraScript;
import ghidra.app.script.GhidraScriptLoadException;
import ghidra.app.script.GhidraScriptProvider;
import ghidra.app.script.GhidraScriptUtil;
import ghidra.app.script.GhidraState;
import ghidra.app.script.ScriptControls;
import ghidra.program.util.ProgramLocation;

/** A Java GhidraScript run against the open program inside one transaction; output captured. */
final class ScriptOps {
    private static final Pattern PUBLIC_CLASS = Pattern.compile("public\\s+class\\s+(\\w+)");
    private static final int MAX_OUTPUT = 200_000;

    private ScriptOps() {
    }

    /**
     * Compiles code (a GhidraScript class, or the body of run() with its imports first) in a private directory under the
     * worker's home, runs it within timeout seconds holding the write lock, commits only when it returns normally and saves.
     * Result: stdout, stderr, error (compile or run failure, null on success), committed.
     */
    static JsonElement run(Worker w, Worker.Request r) throws Exception {
        String code = r.args.has("code") ? r.args.get("code").getAsString() : "";
        double timeout = r.args.has("timeout") ? r.args.get("timeout").getAsDouble() : 120;
        File dir = new File(System.getProperty("user.home"), "scripts" + File.separator + Long.toHexString(System.nanoTime()));
        String className = "UserScript_" + Long.toHexString(System.nanoTime());
        String source;
        if (code.contains("extends GhidraScript")) {
            Matcher m = PUBLIC_CLASS.matcher(code);
            if (!m.find()) throw new Worker.WorkerError("invalid_argument", "a script class must be declared 'public class Name extends GhidraScript'");
            className = m.group(1);
            source = code;
        }
        else source = wrap(code, className);
        if (!dir.mkdirs()) throw new Worker.WorkerError("io_error", "cannot create " + dir);
        File file = new File(dir, className + ".java");
        Files.writeString(file.toPath(), source, StandardCharsets.UTF_8);
        StringWriter out = new StringWriter(), err = new StringWriter();
        PrintWriter outWriter = new PrintWriter(out, true), errWriter = new PrintWriter(err, true);
        ResourceFile bundleDir = new ResourceFile(dir);
        BundleHost host = bundleHost();
        Thread timer = deadline(r.monitor, timeout);
        String error = null;
        boolean committed = false;
        w.lock.writeLock().lock();
        try {
            if (w.program == null) throw new Worker.WorkerError("invalid_argument", "no program is open");
            host.enable(bundleDir);
            int tx = w.program.startTransaction("script");
            try {
                ResourceFile scriptFile = new ResourceFile(file);
                GhidraScriptProvider provider = GhidraScriptUtil.getProvider(scriptFile);
                if (provider == null) throw new Worker.WorkerError("unsupported", "Ghidra has no Java script provider here");
                GhidraScript script = provider.getScriptInstance(scriptFile, errWriter);
                GhidraState state = new GhidraState(null, w.project.getProject(), w.program, new ProgramLocation(w.program, w.program.getImageBase()), null, null);
                script.execute(state, new ScriptControls(outWriter, errWriter, r.monitor));
                committed = true;
            }
            catch (GhidraScriptLoadException e) {
                error = "compile: " + e.getMessage();
            }
            catch (Worker.WorkerError e) {
                throw e;
            }
            catch (Exception e) {
                error = r.monitor.isCancelled() ? "the script was cancelled or ran past " + timeout + " s" : trace(e);
            }
            finally {
                w.program.endTransaction(tx, committed);
            }
            if (committed && w.program.isChanged()) w.program.save("Corvus script", ghidra.util.task.TaskMonitor.DUMMY);
        }
        finally {
            try {
                if (w.decompilers != null) w.decompilers.flush();
            }
            finally {
                w.lock.writeLock().unlock();
                timer.interrupt();
                host.remove(bundleDir);
                delete(dir);
            }
        }
        if (r.monitor.isCancelled()) r.monitor.clearCanceled();
        JsonObject o = new JsonObject();
        o.addProperty("stdout", clip(out.toString()));
        o.addProperty("stderr", clip(err.toString()));
        o.addProperty("error", error == null ? null : clip(error));
        o.add("result", null);
        o.addProperty("committed", committed);
        return o;
    }

    /** A GhidraScript class around a run() body; import lines move to the top of the file. */
    static String wrap(String body, String className) {
        StringBuilder imports = new StringBuilder("import ghidra.app.script.GhidraScript;\n");
        StringBuilder run = new StringBuilder();
        for (String line : body.split("\n", -1)) {
            String t = line.strip();
            if (t.startsWith("import ") && t.endsWith(";")) imports.append(t).append('\n');
            else run.append(line).append('\n');
        }
        return imports + "public class " + className + " extends GhidraScript {\n    @Override\n    public void run() throws Exception {\n" + run + "    }\n}\n";
    }

    /** The scripting bundle host; a headless worker has no script manager to create it. */
    private static synchronized BundleHost bundleHost() {
        BundleHost host = GhidraScriptUtil.getBundleHost();
        return host != null ? host : GhidraScriptUtil.acquireBundleHostReference();
    }

    private static Thread deadline(Worker.Monitor monitor, double seconds) {
        Thread t = new Thread(() -> {
            try {
                Thread.sleep((long) (seconds * 1000));
                monitor.cancel();
            }
            catch (InterruptedException e) {
                // finished in time
            }
        }, "script deadline");
        t.setDaemon(true);
        t.start();
        return t;
    }

    private static String trace(Throwable e) {
        StringWriter s = new StringWriter();
        e.printStackTrace(new PrintWriter(s));
        String[] lines = s.toString().split("\n");
        StringBuilder b = new StringBuilder();
        for (int i = 0; i < lines.length && i < 12; i++) b.append(lines[i].stripTrailing()).append('\n');
        return b.toString();
    }

    private static String clip(String s) {
        return s.length() <= MAX_OUTPUT ? s : s.substring(0, MAX_OUTPUT) + "\n[clipped at " + MAX_OUTPUT + " characters]";
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
