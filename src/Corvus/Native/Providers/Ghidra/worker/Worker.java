// Ghidra worker: one program per process, requests as JSON lines on stdio.
// fd 1 is kept for the protocol and System.out goes to stderr; a BundleHost is acquired before analysis and the
// program is saved before project disposal on shutdown.
package corvus.ghidra;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileDescriptor;
import java.io.FileOutputStream;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.locks.ReentrantReadWriteLock;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonPrimitive;

import generic.stl.Pair;
import ghidra.GhidraApplicationLayout;
import ghidra.GhidraLaunchable;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.plugin.core.analysis.PdbUniversalAnalyzer;
import ghidra.app.script.GhidraScriptUtil;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.importer.ProgramLoader;
import ghidra.app.util.opinion.LoadException;
import ghidra.app.util.opinion.LoadResults;
import ghidra.base.project.GhidraProject;
import ghidra.framework.Application;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.framework.model.DomainFile;
import ghidra.framework.options.OptionType;
import ghidra.framework.options.Options;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.Category;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.util.GhidraProgramUtilities;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;

public class Worker implements GhidraLaunchable {
    static final int PROTOCOL = 1;
    /** Program options category holding the server's stamps; saved with the program. */
    static final String STAMPS = "Corvus";
    static final String ANALYSIS_STAMP = "analysis";
    private static final long MAX_RESPONSE_CHARS = 32L << 20;
    private static final Gson GSON = new GsonBuilder().disableHtmlEscaping().serializeNulls().create();

    /** An error with a protocol code (the snake_case names of the server's ErrorCode). */
    static final class WorkerError extends RuntimeException {
        final String code;

        WorkerError(String code, String message) {
            super(message);
            this.code = code;
        }
    }

    /** One request in flight; cancel stops its monitor (and through it a running decompiler). */
    static final class Request {
        final long id;
        final String op;
        final JsonObject args;
        final long started = System.nanoTime();
        final Monitor monitor = new Monitor();
        /** System.nanoTime() the request answers by: its time limit less a margin that carries a partial result back in time. */
        final long deadline;
        /** Null, "cancelled" (a cancel op) or "deadline". */
        volatile String stop;

        Request(long id, String op, JsonObject args, double timeoutSeconds) {
            this.id = id;
            this.op = op;
            this.args = args;
            double answerBy = timeoutSeconds > 0 ? Math.max(0.1, timeoutSeconds - Math.min(5.0, Math.max(0.25, timeoutSeconds * 0.1))) : 0;
            this.deadline = answerBy > 0 ? started + (long) (answerBy * 1e9) : Long.MAX_VALUE;
        }

        void stop(String reason) {
            if (stop == null) stop = reason;
            monitor.cancel();
        }

        /** Whether the request was cancelled or reached its deadline: long loops stop and return what they have. */
        boolean stopped() {
            if (stop == null && System.nanoTime() - deadline >= 0) stop("deadline");
            return stop != null || monitor.isCancelled();
        }

        /** Marks a result cut short with why and where to continue. */
        JsonObject partial(JsonObject o, Long next) {
            o.addProperty("partial", stop != null ? stop : "budget");
            if (next != null) o.addProperty("next", next);
            else o.add("next", null);
            return o;
        }
    }

    /** A cancellable monitor that keeps the last stage message for progress events. */
    static final class Monitor extends TaskMonitorAdapter {
        volatile String message = "";

        Monitor() {
            super(true);
        }

        @Override
        public void setMessage(String m) {
            if (m != null) message = m;
        }

        @Override
        public String getMessage() {
            return message;
        }
    }

    private PrintStream out;
    final ConcurrentHashMap<Long, Request> running = new ConcurrentHashMap<>();
    volatile CompletionPass completion;
    private final ExecutorService executor = Executors.newCachedThreadPool(r -> {
        Thread t = new Thread(r, "worker request");
        t.setDaemon(true);
        return t;
    });
    final ReentrantReadWriteLock lock = new ReentrantReadWriteLock();
    GhidraProject project;
    volatile Program program;
    long base;
    /** Opened without auto-analysis: functions are made where they are asked for. */
    volatile boolean noAuto;
    /** Function rows with their reference counts, built after the open; valid while the program's modification number is unchanged. */
    volatile FunctionTable functionTable;

    record FunctionTable(long modification, List<JsonArray> rows, double seconds) {
    }
    Decompilers decompilers;
    int decompileTimeout = 60;

    @Override
    public void launch(GhidraApplicationLayout layout, String[] args) throws Exception {
        out = new PrintStream(new FileOutputStream(FileDescriptor.out), true, StandardCharsets.UTF_8);
        System.setOut(System.err); // engine chatter must not reach the protocol stream
        Application.initializeApplication(layout, new HeadlessGhidraApplicationConfiguration());
        JsonObject ready = new JsonObject();
        ready.addProperty("event", "ready");
        ready.addProperty("protocol", PROTOCOL);
        ready.addProperty("version", Application.getApplicationVersion());
        ready.addProperty("pid", ProcessHandle.current().pid());
        emit(ready);
        Thread heartbeat = new Thread(this::heartbeat, "worker heartbeat");
        heartbeat.setDaemon(true);
        heartbeat.start();

        BufferedReader in = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));
        String line;
        while ((line = in.readLine()) != null) {
            if (line.isBlank()) continue;
            Request r;
            try {
                JsonObject req = JsonParser.parseString(line).getAsJsonObject();
                r = new Request(req.get("id").getAsLong(), req.get("op").getAsString(),
                    req.has("args") && req.get("args").isJsonObject() ? req.getAsJsonObject("args") : new JsonObject(),
                    req.has("timeout") && req.get("timeout").isJsonPrimitive() ? req.get("timeout").getAsDouble() : 0);
            }
            catch (RuntimeException e) {
                emit(error(null, "invalid_argument", "bad request line: " + e.getMessage()));
                continue;
            }
            if (r.op.equals("cancel")) {
                Request target = running.get(r.args.get("id").getAsLong());
                if (target != null) target.stop("cancelled");
                continue;
            }
            CompletionPass pass = completion;
            if (pass != null) pass.activity();
            running.put(r.id, r); // registered before it runs, so a cancel that follows at once finds it
            executor.submit(() -> handle(r));
        }
        // stdin closed: the server is gone. The last save is on disk; the next worker reopens it.
        Runtime.getRuntime().halt(0);
    }

    private void heartbeat() {
        for (long tick = 1;; tick++) {
            try {
                Thread.sleep(250);
            }
            catch (InterruptedException e) {
                return;
            }
            for (Request r : running.values()) r.stopped(); // a deadline cancels the monitor, which stops a running decompiler
            if (tick % 8 != 0) continue;
            for (Request r : running.values()) {
                double elapsed = (System.nanoTime() - r.started) / 1e9;
                if (elapsed < 2) continue;
                JsonObject ev = new JsonObject();
                ev.addProperty("event", "progress");
                ev.addProperty("id", r.id);
                ev.addProperty("op", r.op);
                ev.addProperty("elapsed", Math.round(elapsed * 10) / 10.0);
                ev.addProperty("stage", r.monitor.message);
                emit(ev);
            }
        }
    }

    private void handle(Request r) {
        JsonObject response;
        boolean exit = false;
        try {
            JsonElement result = dispatch(r);
            response = new JsonObject();
            response.addProperty("id", r.id);
            response.addProperty("ok", true);
            response.add("result", result);
            exit = r.op.equals("close");
        }
        catch (WorkerError e) {
            response = error(r.id, e.code, e.getMessage());
        }
        catch (CancelledException e) {
            double seconds = (System.nanoTime() - r.started) / 1e9;
            response = "deadline".equals(r.stop)
                ? error(r.id, "timeout", String.format("'%s' reached its time limit after %.1f s", r.op, seconds))
                : error(r.id, "cancelled", String.format("'%s' was cancelled after %.1f s", r.op, seconds));
        }
        catch (IllegalArgumentException | NullPointerException | ClassCastException | IllegalStateException e) {
            e.printStackTrace(System.err);
            response = error(r.id, "invalid_argument", e.toString());
        }
        catch (Throwable e) {
            e.printStackTrace(System.err);
            response = error(r.id, "failed", e.toString());
        }
        finally {
            running.remove(r.id);
            CompletionPass pass = completion;
            if (pass != null) pass.activity();
        }
        String text = GSON.toJson(response);
        if (text.length() > MAX_RESPONSE_CHARS)
            text = GSON.toJson(error(r.id, "limit_exceeded", "the result of '" + r.op + "' is larger than " + (MAX_RESPONSE_CHARS >> 20) + " MB; ask for less"));
        emitLine(text);
        if (exit) Runtime.getRuntime().halt(0);
    }

    private JsonElement dispatch(Request r) throws Exception {
        switch (r.op) {
            case "hello": return hello();
            case "open": return open(r);
            case "gzf_original": return GzfOps.original(this, r);
            case "completion": return completionStatus();
            case "rebase": return rebase(r);
            // the program's change counter and this worker's identity: a caller's cached tables stay valid while both match
            case "stamp": return read(() -> {
                JsonObject o = new JsonObject();
                o.addProperty("modification", program.getModificationNumber());
                o.addProperty("instance", INSTANCE);
                return o;
            });
            case "functions": return read(() -> CodeOps.functions(this, r));
            case "decompile": return read(() -> CodeOps.decompile(this, r));
            case "disasm": return read(() -> CodeOps.disasm(this, r));
            case "disasm_range": return read(() -> CodeOps.disasmRange(this, r));
            case "blocks": return read(() -> CodeOps.blocks(this, r));
            case "xrefs_to": return read(() -> CodeOps.xrefsTo(this, r));
            case "xrefs_from": return read(() -> CodeOps.xrefsFrom(this, r));
            case "names": return read(() -> CodeOps.names(this, r));
            case "set_name": return write("set name", () -> NameOps.setName(this, r));
            case "set_comment": return write("set comment", () -> NameOps.setComment(this, r));
            case "apply_names": return applyNames(r);
            case "pseudo_comments": return write("pseudo comments", () -> NameOps.pseudoComments(this, r));
            case "type_guess": return read(() -> GuessOps.typeGuess(this, r));
            case "sync_patches": return write("sync patches", () -> PatchOps.sync(this, r));
            case "apply_types": return saving(r, write("apply types", () -> TypeOps.applyTypes(this, r)));
            case "load_pdb": return loadPdb(r);
            case "virtual_targets": return read(() -> CallOps.virtualTargets(this, r));
            case "apply_user_types": return saving(r, write("apply user types", () -> TypeOps.applyUserTypes(this, r)));
            case "frame": return read(() -> FrameOps.frame(this, r));
            case "types": return read(() -> TypeOps.listTypes(this, r));
            case "type": return read(() -> TypeOps.getType(this, r));
            case "get_stamp": return read(() -> getStamp(r));
            case "save": return save(r);
            case "close": return close(r);
            case "sleep": return sleep(r);
            case "decompile_many": return read(() -> BatchOps.decompileMany(this, r));
            case "insn": return read(() -> InsnOps.insn(this, r));
            case "value_slice": return read(() -> SliceOps.valueSlice(this, r));
            case "image_info": return read(() -> InfoOps.imageInfo(this, r));
            case "defined_data": return read(() -> InfoOps.data(this, r));
            case "defined_strings": return read(() -> InfoOps.strings(this, r));
            case "function_info": return read(() -> InfoOps.functionInfo(this, r));
            case "make_function": return write("function on request", () -> CodeOps.makeFunction(this, r));
            case "namespaces": return read(() -> InfoOps.namespaces(this, r));
            case "script": return ScriptOps.run(this, r);
            case "field_xrefs": return read(() -> FieldOps.fieldXrefs(this, r));
            case "export_gzf": return InfoOps.exportPacked(this, r);
            case "export_types": return read(() -> InfoOps.exportTypes(this, r));
            case "function_table": return functionTableState();
            case "analyzers": return read(() -> analyzers());
            case "reanalyze": return reanalyze(r);
            case "function_candidates": return read(() -> ControlOps.functionCandidates(this, r));
            case "set_marks": return write("set marks", () -> ControlOps.setMarks(this, r));
            case "set_thumb": return write("set thumb", () -> ControlOps.setThumb(this, r));
            case "emulate": return read(() -> EmuOps.emulate(this, r));
            default: throw new WorkerError("invalid_argument", "unknown op '" + r.op + "'");
        }
    }

    // --- locking: reads share the program, writes hold it alone inside one transaction ---

    <T> T read(Callable<T> body) throws Exception {
        lock.readLock().lock();
        try {
            needProgram();
            return body.call();
        }
        finally {
            lock.readLock().unlock();
        }
    }

    <T> T write(String name, Callable<T> body) throws Exception {
        lock.writeLock().lock();
        try {
            needProgram();
            int tx = program.startTransaction(name);
            boolean commit = false;
            try {
                T result = body.call();
                commit = true;
                return result;
            }
            finally {
                program.endTransaction(tx, commit);
            }
        }
        finally {
            try {
                if (decompilers != null) decompilers.flush();
            }
            finally {
                lock.writeLock().unlock();
            }
        }
    }

    private void needProgram() {
        if (program == null) throw new WorkerError("invalid_argument", "no program is open");
    }

    // --- addresses: RVAs on the wire, relative to the program's image base ---

    AddressSpace space() {
        return program.getAddressFactory().getDefaultAddressSpace();
    }

    Address addr(JsonObject args, String key) {
        JsonElement e = args.get(key);
        if (e == null || !e.isJsonPrimitive() || e.getAsLong() < 0 || e.getAsLong() > 0xFFFFFFFFL)
            throw new WorkerError("invalid_argument", key + " must be an RVA (0 to 0xFFFFFFFF)");
        return space().getAddress(base + e.getAsLong());
    }

    /** RVA of an address in the default space, or null for other spaces and addresses outside 32-bit RVA range. */
    Long rva(Address a) {
        if (a == null || !a.isMemoryAddress() || a.getAddressSpace() != space()) return null;
        long r = a.getOffset() - base;
        return r >= 0 && r <= 0xFFFFFFFFL ? r : null;
    }

    static JsonPrimitive u64(long v) {
        return new JsonPrimitive(new BigInteger(Long.toUnsignedString(v)));
    }

    // --- ops ---

    private JsonElement hello() {
        JsonObject o = new JsonObject();
        o.addProperty("protocol", PROTOCOL);
        o.addProperty("version", Application.getApplicationVersion());
        o.addProperty("java", System.getProperty("java.version"));
        o.addProperty("decompiler", decompilerPresent());
        o.addProperty("pid", ProcessHandle.current().pid());
        o.add("extensions", extensions());
        return o;
    }

    static boolean decompilerPresent() {
        try {
            Application.getOSFile(System.getProperty("os.name").toLowerCase().startsWith("windows") ? "decompile.exe" : "decompile");
            return true;
        }
        catch (Exception e) {
            return false;
        }
    }

    /**
     * Opens the saved program of the project, or imports the input into a new project, analyzes it within the budget
     * and saves. Args: input, project_dir, project_name, program_name, loader_args [[k,v]], options [[k,v]],
     * budget_seconds, pdb, decompilers, decompile_timeout, decompile_payload_mb, analysis ("none": load only).
     */
    // Migration only: a project saved before the rename keeps its stamps under these names and its types under /ndm.
    private static final String INSTANCE = java.util.UUID.randomUUID().toString();
    private static final String LEGACY_STAMPS = "NetDecompilerMcp", LEGACY_KEY_PREFIX = "ndm_", LEGACY_CATEGORY = "ndm";

    /** Moves stamps and the data type category of a project saved before the rename to the current names. */
    static void migrateLegacy(Program program, List<String> warnings) {
        Options old = program.getOptions(LEGACY_STAMPS);
        List<String> names = old.getOptionNames();
        Category category = program.getDataTypeManager().getCategory(new CategoryPath(CategoryPath.ROOT, LEGACY_CATEGORY));
        if (names.isEmpty() && category == null) return;
        int tx = program.startTransaction("rename stamps");
        boolean done = false;
        try {
            Options now = program.getOptions(STAMPS);
            for (String name : names) {
                String key = name.startsWith(LEGACY_KEY_PREFIX) ? name.substring(LEGACY_KEY_PREFIX.length()) : name;
                if (!now.contains(key)) now.setString(key, old.getString(name, null));
                old.removeOption(name);
            }
            if (category != null && program.getDataTypeManager().getCategory(TypeOps.CLASSES.getParent()) == null)
                category.setName(TypeOps.CLASSES.getParent().getName());
            done = true;
        }
        catch (Exception e) {
            warnings.add("the stamps saved before the rename were not moved: " + e.getMessage());
        }
        finally {
            program.endTransaction(tx, done);
        }
    }

    private JsonElement open(Request r) throws Exception {
        lock.writeLock().lock();
        try {
            if (program != null) throw new WorkerError("invalid_argument", "a program is already open");
            JsonObject a = r.args;
            long start = System.nanoTime();
            String dir = a.get("project_dir").getAsString();
            String name = a.get("project_name").getAsString();
            String programName = a.get("program_name").getAsString();
            if (a.has("decompile_timeout")) decompileTimeout = a.get("decompile_timeout").getAsInt();
            noAuto = a.has("analysis") && "none".equals(a.get("analysis").getAsString());
            new File(dir).mkdirs();
            boolean reused = new File(dir, name + ".gpr").exists();
            List<String> warnings = new ArrayList<>();
            boolean complete;
            if (reused) {
                r.monitor.setMessage("load");
                project = GhidraProject.openProject(dir, name, false);
                DomainFile df = project.getProjectData().getFile("/" + programName);
                if (df == null) throw new WorkerError("failed", "the project in " + dir + " holds no program " + programName);
                program = (Program) df.getDomainObject(this, true, false, r.monitor);
                migrateLegacy(program, warnings);
                complete = !noAuto && "complete".equals(program.getOptions(STAMPS).getString(ANALYSIS_STAMP, null));
            }
            else {
                r.monitor.setMessage("import");
                project = GhidraProject.createProject(dir, name, false);
                List<Pair<String, String>> loaderArgs = new ArrayList<>();
                for (JsonElement e : array(a, "loader_args"))
                    loaderArgs.add(new Pair<>(e.getAsJsonArray().get(0).getAsString(), e.getAsJsonArray().get(1).getAsString()));
                MessageLog log = new MessageLog();
                // a Ghidra archive given for the image is imported in its place: its analysis is the database
                boolean packed = a.has("gzf");
                var builder = ProgramLoader.builder()
                        .source(new File(a.get(packed ? "gzf" : "input").getAsString()))
                        .project(project.getProject())
                        .projectFolderPath("/")
                        .name(programName)
                        .loaderArgs(loaderArgs)
                        .log(log)
                        .monitor(r.monitor);
                // a headerless image: the caller names the loader and the language
                try {
                    if (packed) builder = builder.loaders(GzfOps.LOADER);
                    else if (a.has("loader")) builder = builder.loaders(a.get("loader").getAsString());
                }
                catch (ghidra.util.exception.InvalidInputException e) {
                    throw new WorkerError("invalid_argument", "unknown Ghidra loader: " + e.getMessage());
                }
                if (a.has("language")) builder = builder.language(a.get("language").getAsString());
                try (LoadResults<Program> results = builder.load()) {
                    results.getPrimary().save(r.monitor);
                    program = results.getPrimaryDomainObject(this);
                }
                catch (LoadException e) {
                    throw new WorkerError("malformed_input", "Ghidra could not load the file: " + e.getMessage());
                }
                if (packed) {
                    complete = true;
                    int tx = program.startTransaction("archive stamp");
                    try { program.getOptions(STAMPS).setString(ANALYSIS_STAMP, "complete"); }
                    finally { program.endTransaction(tx, true); }
                    program.save("Corvus", r.monitor);
                }
                else {
                    if (a.has("entry")) markEntry(a.get("raw_base").getAsLong(), a.get("entry").getAsLong());
                    complete = !noAuto && analyze(r, a, warnings);
                }
            }
            base = program.getImageBase().getOffset();
            decompilers = new Decompilers(program, a.has("decompilers") ? a.get("decompilers").getAsInt() : 2,
                a.has("decompile_payload_mb") ? a.get("decompile_payload_mb").getAsInt() : 200);
            r.monitor.setMessage("ready");
            startFunctionPass();
            if (complete && a.has("completion") && a.get("completion").getAsBoolean() && !CompletionPass.finished(program)) {
                completion = new CompletionPass(this, program);
                completion.start();
            }
            return info(reused, complete, warnings, (System.nanoTime() - start) / 1e9);
        }
        finally {
            lock.writeLock().unlock();
        }
    }

    /**
     * The function pass: every function's row with its reference count, read in the background in chunks under the read lock
     * (the first listing of a large program loads every function record). A change to the program while it runs drops it;
     * the live listing serves until a table exists.
     */
    /**
     * A raw image loaded at 0: moved to its base (memory moves with the image base, so image base and block agree), then
     * an entry point with its function at the entry offset, where analysis starts.
     */
    private void markEntry(long base, long offset) {
        int tx = program.startTransaction("raw image entry");
        try {
            // real mode: a segment start (segment = linear / 16, offset 0), as the image base must be
            Address start = program.getImageBase().getAddressSpace() instanceof ghidra.program.model.address.SegmentedAddressSpace s
                ? s.getAddress((int)(base >> 4), 0)
                : program.getImageBase().getNewAddress(base);
            if (!program.getImageBase().equals(start)) {
                try {
                    program.setImageBase(start, true);
                }
                catch (Exception e) {
                    throw new WorkerError("failed", "moving the image to " + start + " failed: " + e.getMessage());
                }
            }
            Address entry = start.add(offset);
            program.getSymbolTable().addExternalEntryPoint(entry);
            try {
                program.getSymbolTable().createLabel(entry, "entry", ghidra.program.model.symbol.SourceType.IMPORTED);
            }
            catch (ghidra.util.exception.InvalidInputException e) {
                // the name is fixed and valid
            }
            new ghidra.app.cmd.disassemble.DisassembleCommand(entry, null, true).applyTo(program, TaskMonitor.DUMMY);
            new ghidra.app.cmd.function.CreateFunctionCmd(entry).applyTo(program, TaskMonitor.DUMMY);
        }
        finally {
            program.endTransaction(tx, true);
        }
    }

    private void startFunctionPass() {
        Program p = program;
        Thread t = new Thread(() -> {
            long started = System.nanoTime(), modification = -1;
            List<JsonArray> rows = new ArrayList<>();
            Address next = null;
            try {
                while (true) {
                    lock.readLock().lock();
                    try {
                        if (program != p) return;
                        if (modification < 0) modification = p.getModificationNumber();
                        else if (p.getModificationNumber() != modification) return;
                        var fm = p.getFunctionManager();
                        var rm = p.getReferenceManager();
                        Address from = next;
                        next = null;
                        int n = 0;
                        for (Function f : from == null ? fm.getFunctions(true) : fm.getFunctions(from, true)) {
                            if (n++ == 2000) {
                                next = f.getEntryPoint();
                                break;
                            }
                            if (rva(f.getEntryPoint()) != null) rows.add(CodeOps.functionRow(this, rm, f, true));
                        }
                        if (next == null) {
                            functionTable = new FunctionTable(modification, rows, (System.nanoTime() - started) / 1e9);
                            return;
                        }
                    }
                    finally {
                        lock.readLock().unlock();
                    }
                }
            }
            catch (RuntimeException e) {
                // the live listing serves
            }
        }, "worker function pass");
        t.setDaemon(true);
        t.start();
    }

    /** Whether the function pass's table is ready and current: ready, functions, seconds. */
    private JsonElement functionTableState() {
        FunctionTable t = functionTable;
        JsonObject o = new JsonObject();
        o.addProperty("ready", t != null && program != null && t.modification() == program.getModificationNumber());
        o.addProperty("functions", t != null ? t.rows().size() : 0);
        o.addProperty("seconds", t != null ? t.seconds() : 0);
        return o;
    }

    /**
     * HeadlessAnalyzer's sequence. GhidraProject.analyze skips the transaction and analyzes almost nothing on a fresh
     * import; analyzer options exist only after initializeOptions. A budget that ends cancels the analysis, and what
     * exists is saved as partial.
     */
    private boolean analyze(Request r, JsonObject a, List<String> warnings) throws Exception {
        r.monitor.setMessage("analysis");
        GhidraScriptUtil.acquireBundleHostReference(); // script-based analyzers fail without a bundle host
        AutoAnalysisManager mgr = AutoAnalysisManager.getAnalysisManager(program);
        double budget = a.has("budget_seconds") ? a.get("budget_seconds").getAsDouble() : 0;
        Thread timer = null;
        if (budget > 0) {
            Monitor m = r.monitor;
            timer = new Thread(() -> {
                try {
                    Thread.sleep((long) (budget * 1000));
                    m.cancel();
                }
                catch (InterruptedException e) {
                    // finished in time
                }
            }, "worker analysis budget");
            timer.setDaemon(true);
            timer.start();
        }
        boolean complete;
        int tx = program.startTransaction("Analysis");
        try {
            mgr.initializeOptions();
            Options options = program.getOptions(Program.ANALYSIS_PROPERTIES);
            for (JsonElement e : array(a, "options"))
                setOption(options, e.getAsJsonArray().get(0).getAsString(), e.getAsJsonArray().get(1).getAsString(), warnings);
            if (a.has("pdb") && !a.get("pdb").isJsonNull()) PdbUniversalAnalyzer.setPdbFileOption(program, new File(a.get("pdb").getAsString()));
            mgr.initializeOptions();
            mgr.reAnalyzeAll(null);
            mgr.startAnalysis(r.monitor);
            complete = !r.monitor.isCancelled();
            if (complete) GhidraProgramUtilities.markProgramAnalyzed(program);
            program.getOptions(STAMPS).setString(ANALYSIS_STAMP, complete ? "complete" : "partial");
        }
        finally {
            program.endTransaction(tx, true);
            if (timer != null) timer.interrupt();
        }
        r.monitor.setMessage("save");
        program.save("analysis", TaskMonitor.DUMMY);
        if (!complete) r.monitor.clearCanceled();
        return complete;
    }

    private static void setOption(Options options, String name, String value, List<String> warnings) {
        if (!options.isRegistered(name)) {
            warnings.add("unknown analysis option '" + name + "'");
            return;
        }
        try {
            OptionType type = options.getType(name);
            switch (type) {
                case BOOLEAN_TYPE: options.setBoolean(name, Boolean.parseBoolean(value)); break;
                case INT_TYPE: options.setInt(name, Integer.parseInt(value)); break;
                case LONG_TYPE: options.setLong(name, Long.parseLong(value)); break;
                case DOUBLE_TYPE: options.setDouble(name, Double.parseDouble(value)); break;
                case STRING_TYPE: options.setString(name, value); break;
                case ENUM_TYPE: setEnum(options, name, value); break;
                default: warnings.add("analysis option '" + name + "' has type " + type + ", which cannot be set from text");
            }
        }
        catch (RuntimeException e) {
            warnings.add("analysis option '" + name + "' = '" + value + "': " + e.getMessage());
        }
    }

    @SuppressWarnings({ "unchecked", "rawtypes" })
    private static void setEnum(Options options, String name, String value) {
        Enum current = options.getEnum(name, null);
        if (current == null) throw new IllegalArgumentException("no current value");
        for (Object c : current.getDeclaringClass().getEnumConstants()) {
            Enum e = (Enum) c;
            if (e.name().equalsIgnoreCase(value) || e.toString().equalsIgnoreCase(value)) {
                options.setEnum(name, e);
                return;
            }
        }
        throw new IllegalArgumentException("not a value of " + current.getDeclaringClass().getSimpleName());
    }

    private JsonObject info(boolean reused, boolean complete, List<String> warnings, double seconds) {
        JsonObject o = new JsonObject();
        o.add("imagebase", u64(program.getImageBase().getOffset()));
        o.addProperty("language", program.getLanguageID().getIdAsString());
        o.addProperty("compiler", program.getCompilerSpec().getCompilerSpecID().getIdAsString());
        o.addProperty("processor", program.getLanguage().getProcessor().toString());
        o.addProperty("pointer_size", program.getDefaultPointerSize());
        o.addProperty("format", program.getExecutableFormat());
        o.addProperty("functions", program.getFunctionManager().getFunctionCount());
        o.addProperty("reused", reused);
        o.addProperty("analysis_complete", complete);
        o.addProperty("decompiler", decompilerPresent());
        o.addProperty("seconds", Math.round(seconds * 1000) / 1000.0);
        o.add("extensions", extensions());
        JsonArray w = new JsonArray();
        for (String s : warnings) w.add(s);
        o.add("warnings", w);
        return o;
    }

    /** Names of the extension modules Ghidra loaded (modules under its extension installation directories). */
    private static JsonArray extensions() {
        JsonArray names = new JsonArray();
        var layout = Application.getApplicationLayout();
        for (var module : layout.getModules().values()) {
            var parent = module.getModuleRoot().getParentFile();
            for (var dir : layout.getExtensionInstallationDirs())
                if (parent != null && parent.equals(dir)) names.add(module.getName());
        }
        return names;
    }

    private JsonElement rebase(Request r) throws Exception {
        return write("rebase", () -> {
            long target = new BigInteger(r.args.get("imagebase").getAsString()).longValue();
            if (program.getImageBase().getOffset() != target) program.setImageBase(space().getAddress(target), true);
            base = program.getImageBase().getOffset();
            JsonObject o = new JsonObject();
            o.add("imagebase", u64(base));
            return o;
        });
    }

    private JsonElement applyNames(Request r) throws Exception {
        return saving(r, write("apply names", () -> NameOps.applyNames(this, r)));
    }

    /** Saves the program after a write when the request asks for it (save: true). */
    private JsonElement saving(Request r, JsonElement result) throws Exception {
        if (r.args.has("save") && r.args.get("save").getAsBoolean()) saveProgram(r.monitor);
        return result;
    }

    /** A PDB that loaded is saved with the program at once: loading it again costs minutes. */
    private JsonElement loadPdb(Request r) throws Exception {
        JsonObject result = write("load PDB", () -> TypeOps.loadPdb(this, r));
        if (result.get("loaded").getAsBoolean()) saveProgram(r.monitor);
        return result;
    }

    void setStamp(JsonObject args) {
        if (args.has("stamp_key") && !args.get("stamp_key").isJsonNull()) {
            String stamp = args.has("stamp") && !args.get("stamp").isJsonNull() ? args.get("stamp").getAsString() : "";
            program.getOptions(STAMPS).setString(args.get("stamp_key").getAsString(), stamp);
        }
    }

    private JsonElement getStamp(Request r) {
        JsonObject o = new JsonObject();
        String v = program.getOptions(STAMPS).getString(r.args.get("key").getAsString(), null);
        if (v == null || v.isEmpty()) o.add("stamp", null);
        else o.addProperty("stamp", v);
        return o;
    }

    private JsonElement save(Request r) throws Exception {
        saveProgram(r.monitor);
        return new JsonObject();
    }

    private void saveProgram(TaskMonitor monitor) throws Exception {
        lock.writeLock().lock();
        try {
            needProgram();
            if (program.isChanged()) program.save("Corvus", monitor);
        }
        finally {
            lock.writeLock().unlock();
        }
    }

    /** Saves (when asked) before the decompilers, the program and then the project are released. */
    private JsonElement close(Request r) throws Exception {
        lock.writeLock().lock();
        try {
            if (program != null) {
                boolean save = !r.args.has("save") || r.args.get("save").getAsBoolean();
                try {
                    if (save && program.isChanged()) program.save("Corvus", TaskMonitor.DUMMY);
                }
                finally {
                    if (decompilers != null) decompilers.dispose();
                    program.release(this);
                    program = null;
                }
            }
            if (project != null) project.close();
            project = null;
            return new JsonObject();
        }
        finally {
            lock.writeLock().unlock();
        }
    }

    /** The completion pass: state (off, pending, running, done, ...), functions done and total. */
    private JsonElement completionStatus() {
        CompletionPass pass = completion;
        if (pass != null) return pass.status();
        JsonObject o = new JsonObject();
        o.addProperty("state", program != null && CompletionPass.finished(program) ? "done" : "off");
        return o;
    }

    /** Test hook: holds a request for the given seconds unless cancelled. */
    private JsonElement sleep(Request r) throws Exception {
        long start = System.nanoTime(), end = start + (long) (r.args.get("seconds").getAsDouble() * 1e9);
        while (System.nanoTime() < end) {
            if (r.stopped()) {
                JsonObject o = new JsonObject();
                o.addProperty("slept", (System.nanoTime() - start) / 1e9);
                return r.partial(o, null);
            }
            Thread.sleep(20);
        }
        return new JsonObject();
    }

    // --- analysis control: analyzer options and reanalysis ---

    /** Analysis options of the program: {options: [[name, type, value, description]]} by name. */
    private JsonElement analyzers() {
        Options options = program.getOptions(Program.ANALYSIS_PROPERTIES);
        List<String> names = new ArrayList<>(options.getOptionNames());
        java.util.Collections.sort(names, String.CASE_INSENSITIVE_ORDER);
        JsonArray rows = new JsonArray();
        for (String name : names) {
            Object value = options.getObject(name, null);
            JsonArray row = new JsonArray();
            row.add(name);
            row.add(switch (options.getType(name)) {
                case BOOLEAN_TYPE -> "bool";
                case INT_TYPE, LONG_TYPE -> "int";
                case DOUBLE_TYPE, FLOAT_TYPE -> "number";
                case STRING_TYPE -> "string";
                case ENUM_TYPE -> "enum";
                default -> options.getType(name).name().toLowerCase().replace("_type", "");
            });
            row.add(value == null ? "" : value.toString());
            row.add(options.getDescription(name));
            rows.add(row);
        }
        JsonObject o = new JsonObject();
        o.add("options", rows);
        return o;
    }

    /**
     * Runs auto-analysis again over the program, or [start, end), within budget_seconds; options [[k, v]] apply to this run
     * and are restored after it. A full run that finishes marks the analysis complete (it resumes a partial one). Saved.
     */
    private JsonElement reanalyze(Request r) throws Exception {
        long started = System.nanoTime();
        JsonObject result = write("reanalyze", () -> {
            JsonObject a = r.args;
            List<String> warnings = new ArrayList<>();
            AutoAnalysisManager mgr = AutoAnalysisManager.getAnalysisManager(program);
            mgr.initializeOptions();
            Options options = program.getOptions(Program.ANALYSIS_PROPERTIES);
            java.util.Map<String, Object> previous = new java.util.LinkedHashMap<>();
            for (JsonElement e : array(a, "options")) {
                String name = e.getAsJsonArray().get(0).getAsString();
                if (options.isRegistered(name)) previous.put(name, options.getObject(name, null));
                setOption(options, name, e.getAsJsonArray().get(1).getAsString(), warnings);
            }
            ghidra.program.model.address.AddressSet range = null;
            if (a.has("start") && !a.get("start").isJsonNull()) {
                Address from = addr(a, "start");
                Address to = a.has("end") && !a.get("end").isJsonNull() ? addr(a, "end").subtract(1) : from;
                range = new ghidra.program.model.address.AddressSet(from, to);
            }
            int before = program.getFunctionManager().getFunctionCount();
            double budget = a.has("budget_seconds") ? a.get("budget_seconds").getAsDouble() : 0;
            Monitor m = r.monitor;
            Thread timer = new Thread(() -> {
                try {
                    Thread.sleep((long) (Math.max(1, budget) * 1000));
                    m.cancel();
                }
                catch (InterruptedException e) {
                    // finished in time
                }
            }, "worker reanalysis budget");
            timer.setDaemon(true);
            if (budget > 0) timer.start();
            GhidraScriptUtil.acquireBundleHostReference();
            boolean finished;
            try {
                r.monitor.setMessage("reanalysis");
                mgr.reAnalyzeAll(range);
                mgr.startAnalysis(r.monitor);
                finished = !r.monitor.isCancelled();
            }
            finally {
                timer.interrupt();
                GhidraScriptUtil.releaseBundleHostReference();
                for (var p : previous.entrySet()) options.putObject(p.getKey(), p.getValue());
            }
            if (finished && range == null) {
                GhidraProgramUtilities.markProgramAnalyzed(program);
                program.getOptions(STAMPS).setString(ANALYSIS_STAMP, "complete");
            }
            JsonObject o = new JsonObject();
            o.addProperty("complete", finished);
            o.addProperty("analysis_complete", "complete".equals(program.getOptions(STAMPS).getString(ANALYSIS_STAMP, null)));
            o.addProperty("before", before);
            o.addProperty("after", program.getFunctionManager().getFunctionCount());
            JsonArray w = new JsonArray();
            for (String s : warnings) w.add(s);
            o.add("warnings", w);
            return o;
        });
        r.monitor.setMessage("save");
        saveProgram(TaskMonitor.DUMMY); // the request's monitor is cancelled when the budget ran out
        result.addProperty("seconds", Math.round((System.nanoTime() - started) / 1e6) / 1000.0);
        return result;
    }

    // --- output ---

    static JsonArray array(JsonObject a, String key) {
        return a.has(key) && a.get(key).isJsonArray() ? a.getAsJsonArray(key) : new JsonArray();
    }

    private static JsonObject error(Long id, String code, String message) {
        JsonObject o = new JsonObject();
        if (id == null) o.add("id", null);
        else o.addProperty("id", id);
        o.addProperty("ok", false);
        JsonObject e = new JsonObject();
        e.addProperty("code", code);
        e.addProperty("message", message == null ? code : message);
        o.add("error", e);
        return o;
    }

    private void emit(JsonObject o) {
        emitLine(GSON.toJson(o));
    }

    private synchronized void emitLine(String line) {
        out.print(line);
        out.print('\n');
        out.flush();
    }
}
