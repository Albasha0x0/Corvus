package corvus.ghidra;

import java.io.File;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.Map;
import javax.tools.JavaCompiler;
import javax.tools.StandardJavaFileManager;
import javax.tools.ToolProvider;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import generic.jar.ResourceFile;
import ghidra.app.script.GhidraScript;
import ghidra.app.script.GhidraScriptLoadException;
import ghidra.app.script.GhidraScriptProvider;
import ghidra.app.script.GhidraScriptUtil;
import ghidra.app.script.GhidraState;
import ghidra.app.script.ScriptControls;
import ghidra.program.util.ProgramLocation;

/** A Java or Python GhidraScript run against the open program inside one transaction; output captured. */
final class ScriptOps {
    private static final Pattern PUBLIC_CLASS = Pattern.compile("public\\s+class\\s+(\\w+)");
    private static final int MAX_OUTPUT = 200_000;
    private static final Pattern PACKAGE = Pattern.compile("^\\s*package\\s+([\\w.]+)\\s*;", Pattern.MULTILINE);
    private static final int MAX_COMPILED = 32;
    /** Compiled script classes by source hash, least recently run first: a repeat skips compilation (about 2 s). */
    private static final Map<String, Class<?>> COMPILED = new LinkedHashMap<>(16, 0.75f, true) {
        @Override
        protected boolean removeEldestEntry(Map.Entry<String, Class<?>> eldest) {
            if (size() <= MAX_COMPILED) return false;
            delete(new File(System.getProperty("user.home"), "scripts" + File.separator + eldest.getKey()));
            return true;
        }
    };

    /** A compile failure with javac's diagnostics. */
    private static final class CompileError extends Exception {
        CompileError(String message) {
            super(message);
        }
    }

    private ScriptOps() {
    }

    /**
     * Compiles code (a GhidraScript class, or the body of run() with its imports first) in a private directory under the
     * worker's home, runs it within timeout seconds holding the write lock, commits only when it returns normally and saves.
     * Result: stdout, stderr, error (compile or run failure, null on success), committed.
     */
    static JsonElement run(Worker w, Worker.Request r) throws Exception {
        String code = r.args.has("code") ? r.args.get("code").getAsString() : "";
        String[] scriptArgs = new String[0];
        if (r.args.has("args") && r.args.get("args").isJsonArray()) {
            var list = r.args.getAsJsonArray("args");
            scriptArgs = new String[list.size()];
            for (int i = 0; i < scriptArgs.length; i++) scriptArgs[i] = list.get(i).getAsString();
        }
        String name = r.args.has("name") && !r.args.get("name").isJsonNull() ? r.args.get("name").getAsString().trim() : null;
        String userDir = r.args.has("user_dir") && !r.args.get("user_dir").isJsonNull() ? r.args.get("user_dir").getAsString() : null;
        boolean python = r.args.has("language") && !r.args.get("language").isJsonNull() && "python".equals(r.args.get("language").getAsString()) || name != null && name.endsWith(".py");
        double timeout = r.args.has("timeout") ? r.args.get("timeout").getAsDouble() : 120;
        if (python) return runPython(w, r, name != null ? installed(name, userDir, ".py") : null, code, scriptArgs, timeout);
        if (name != null) code = Files.readString(installed(name, userDir, ".java").toPath(), StandardCharsets.UTF_8);
        String key = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(code.getBytes(StandardCharsets.UTF_8))).substring(0, 16);
        File dir = new File(System.getProperty("user.home"), "scripts" + File.separator + key);
        String className = "UserScript_" + key;
        String source;
        if (code.contains("extends GhidraScript")) {
            Matcher m = PUBLIC_CLASS.matcher(code);
            if (!m.find()) throw new Worker.WorkerError("invalid_argument", "a script class must be declared 'public class Name extends GhidraScript'");
            className = m.group(1);
            source = code;
        }
        else source = wrap(code, className);
        Matcher pkg = PACKAGE.matcher(source);
        String qualified = pkg.find() ? pkg.group(1) + "." + className : className;
        File file = new File(dir, className + ".java");
        StringWriter out = new StringWriter(), err = new StringWriter();
        PrintWriter outWriter = new PrintWriter(out, true), errWriter = new PrintWriter(err, true);
        String error = null;
        Class<?> compiled = null;
        try {
            compiled = compile(key, qualified, source, dir, file);
        }
        catch (CompileError e) {
            error = "compile: " + e.getMessage();
        }
        final Class<?> loaded = compiled;
        final String compileError = error;
        return execute(w, r, timeout, scriptArgs, out, err, outWriter, errWriter, () -> {
            if (loaded == null) throw new CompileError(compileError.substring("compile: ".length()));
            GhidraScript script = (GhidraScript) loaded.getDeclaredConstructor().newInstance();
            script.setSourceFile(new ResourceFile(file));
            return script;
        });
    }

    private interface ScriptFactory {
        GhidraScript create() throws Exception;
    }

    /**
     * Runs a script within timeout seconds holding the write lock, in one transaction committed only when it returns
     * normally, and saves. Result: stdout, stderr, error (compile or run failure, null on success), committed.
     */
    private static JsonElement execute(Worker w, Worker.Request r, double timeout, String[] scriptArgs, StringWriter out, StringWriter err,
        PrintWriter outWriter, PrintWriter errWriter, ScriptFactory factory) throws Exception {
        String error = null;
        Thread timer = deadline(r.monitor, timeout);
        boolean committed = false;
        w.lock.writeLock().lock();
        try {
            if (w.program == null) throw new Worker.WorkerError("invalid_argument", "no program is open");
            int tx = w.program.startTransaction("script");
            try {
                GhidraScript script = factory.create();
                script.setScriptArgs(scriptArgs);
                GhidraState state = new GhidraState(null, w.project.getProject(), w.program, new ProgramLocation(w.program, w.program.getImageBase()), null, null);
                script.execute(state, new ScriptControls(outWriter, errWriter, r.monitor));
                committed = true;
            }
            catch (CompileError e) {
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

    /**
     * A Python script through PyGhidra's script provider: an installed .py file, or code written to a private file. Only a
     * worker hosted by PyGhidra (the server's Python setting) has the provider's Python runner.
     */
    private static JsonElement runPython(Worker w, Worker.Request r, File installedFile, String code, String[] scriptArgs, double timeout) throws Exception {
        File file = installedFile;
        if (file == null) {
            String key = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(code.getBytes(StandardCharsets.UTF_8))).substring(0, 16);
            File dir = new File(System.getProperty("user.home"), "scripts" + File.separator + key);
            if (!dir.isDirectory() && !dir.mkdirs()) throw new Worker.WorkerError("io_error", "cannot create " + dir);
            file = new File(dir, "user_script_" + key + ".py");
            Files.writeString(file.toPath(), code, StandardCharsets.UTF_8);
        }
        ResourceFile source = new ResourceFile(file);
        GhidraScriptProvider provider = GhidraScriptUtil.getProvider(source);
        if (provider == null) throw new Worker.WorkerError("unsupported", "this Ghidra has no Python script provider (the PyGhidra module is missing)");
        StringWriter out = new StringWriter(), err = new StringWriter();
        PrintWriter outWriter = new PrintWriter(out, true), errWriter = new PrintWriter(err, true);
        GhidraScript script;
        try {
            script = provider.getScriptInstance(source, errWriter);
        }
        catch (GhidraScriptLoadException e) {
            throw new Worker.WorkerError("unsupported", "Python scripts need a worker hosted by PyGhidra: " + e.getMessage());
        }
        return execute(w, r, timeout, scriptArgs, out, err, outWriter, errWriter, () -> script);
    }


    /** An installed script by file name in Ghidra's script directories, then in the user's. */
    private static File installed(String name, String userDir, String extension) throws Exception {
        String file = name.trim();
        if (file.contains("/") || file.contains("\\") || file.contains("..")) throw new Worker.WorkerError("invalid_argument", "name is a script file name, not a path: " + name);
        if (!file.endsWith(extension)) file += extension;
        java.util.List<File> dirs = new java.util.ArrayList<>();
        for (ResourceFile d : ghidra.app.script.GhidraScriptUtil.getSystemScriptDirectories()) dirs.add(d.getFile(false));
        if (userDir != null) dirs.add(new File(userDir));
        for (File d : dirs) {
            File f = d == null ? null : new File(d, file);
            if (f != null && f.isFile()) return f;
        }
        throw new Worker.WorkerError("not_found", "no script " + file + " in Ghidra's script directories" + (userDir != null ? " or " + userDir : ""));
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

    /**
     * The script's class, compiled by javac against the worker's class path into dir/classes once per source hash and loaded
     * by a class loader of its own whose parent is the worker's (Ghidra's classes resolve as they do for the worker).
     */
    private static Class<?> compile(String key, String qualified, String source, File dir, File file) throws Exception {
        synchronized (COMPILED) {
            Class<?> known = COMPILED.get(key);
            if (known != null) return known;
        }
        JavaCompiler javac = ToolProvider.getSystemJavaCompiler();
        if (javac == null) throw new Worker.WorkerError("unsupported", "the Java runtime running Ghidra has no compiler (a JRE, not a JDK)");
        File classes = new File(dir, "classes");
        if (!classes.isDirectory() && !classes.mkdirs()) throw new Worker.WorkerError("io_error", "cannot create " + classes);
        Files.writeString(file.toPath(), source, StandardCharsets.UTF_8);
        String classPath = System.getProperty("java.class.path") + File.pathSeparator + System.getProperty("corvus.worker.jar", "");
        StringWriter diagnostics = new StringWriter();
        try (StandardJavaFileManager files = javac.getStandardFileManager(null, null, StandardCharsets.UTF_8)) {
            boolean ok = javac.getTask(diagnostics, files, null, java.util.List.of("-d", classes.getPath(), "-classpath", classPath, "-proc:none", "-nowarn", "-g"),
                null, files.getJavaFileObjects(file)).call();
            if (!ok) throw new CompileError(diagnostics.toString().strip());
        }
        Class<?> loaded = new URLClassLoader(new URL[] { classes.toURI().toURL() }, ScriptOps.class.getClassLoader()).loadClass(qualified);
        if (!GhidraScript.class.isAssignableFrom(loaded)) throw new CompileError(qualified + " does not extend GhidraScript");
        synchronized (COMPILED) {
            COMPILED.put(key, loaded);
        }
        return loaded;
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
