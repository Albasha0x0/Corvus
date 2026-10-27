package corvus.ghidra;

import java.io.File;
import java.io.FileOutputStream;
import java.util.ArrayList;
import java.util.List;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.importer.ProgramLoader;
import ghidra.app.util.opinion.LoadException;
import ghidra.app.util.opinion.LoadResults;
import ghidra.base.project.GhidraProject;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.listing.Program;

/** Ghidra archives (.gzf) and projects (.gpr) as inputs: the file a program was imported from, recovered from the bytes the program keeps. */
final class GzfOps {
    private GzfOps() {}

    /** The loader of packed programs, as ProgramLoader names it. */
    static final String LOADER = "GzfLoader";

    /** gzf_original: writes the archive's original file bytes to out_dir. Result: name, sha256, format, stored, path when stored. */
    static JsonElement original(Worker w, Worker.Request r) throws Exception {
        File gzf = new File(r.args.get("gzf").getAsString());
        File scratch = new File(r.args.get("scratch").getAsString());
        File outDir = new File(r.args.get("out_dir").getAsString());
        scratch.mkdirs();
        outDir.mkdirs();
        GhidraProject project = GhidraProject.createProject(scratch.getAbsolutePath(), "gzf", true);
        Object consumer = new Object();
        try {
            Program program;
            try (LoadResults<Program> results = ProgramLoader.builder().source(gzf).project(project.getProject()).projectFolderPath("/")
                    .loaders(LOADER).log(new MessageLog()).monitor(r.monitor).load()) {
                program = results.getPrimaryDomainObject(consumer);
            }
            catch (LoadException e) {
                throw new Worker.WorkerError("malformed_input", "Ghidra could not read the archive: " + e.getMessage());
            }
            try {
                JsonObject o = new JsonObject();
                String path = program.getExecutablePath();
                String name = path == null || path.isEmpty() ? program.getName() : new File(path.replace('\\', '/')).getName();
                o.addProperty("name", name);
                o.addProperty("sha256", program.getExecutableSHA256());
                o.addProperty("format", program.getExecutableFormat());
                List<FileBytes> files = program.getMemory().getAllFileBytes();
                o.addProperty("stored", !files.isEmpty());
                if (!files.isEmpty()) {
                    FileBytes bytes = files.get(0);
                    File out = new File(outDir, name);
                    byte[] buffer = new byte[1 << 20];
                    try (FileOutputStream stream = new FileOutputStream(out)) {
                        for (long at = 0; at < bytes.getSize();) {
                            r.monitor.checkCancelled();
                            int n = bytes.getOriginalBytes(at, buffer, 0, (int)Math.min(buffer.length, bytes.getSize() - at));
                            if (n <= 0) throw new Worker.WorkerError("failed", "the archive's stored file ends early at " + at);
                            stream.write(buffer, 0, n);
                            at += n;
                        }
                    }
                    o.addProperty("path", out.getAbsolutePath());
                }
                return o;
            }
            finally {
                program.release(consumer);
            }
        }
        finally {
            project.close();
        }
    }

    /** gpr_pack: packs a program of the project copy project_dir/name.gpr into out; a user's project is never opened here. Result: program, programs. */
    static JsonElement packProject(Worker w, Worker.Request r) throws Exception {
        String dir = r.args.get("project_dir").getAsString();
        String name = r.args.get("name").getAsString();
        String wanted = r.args.has("program") && !r.args.get("program").isJsonNull() ? r.args.get("program").getAsString() : null;
        File out = new File(r.args.get("out").getAsString());
        GhidraProject project;
        try {
            project = GhidraProject.openProject(dir, name, false);
        }
        catch (Exception e) {
            throw new Worker.WorkerError("malformed_input", "Ghidra could not open the project: " + e);
        }
        try {
            List<DomainFile> programs = new ArrayList<>();
            collect(project.getRootFolder(), programs, r);
            List<String> paths = new ArrayList<>();
            for (DomainFile f : programs) paths.add(f.getPathname());
            DomainFile chosen = null;
            if (wanted != null) {
                String path = wanted.startsWith("/") ? wanted : "/" + wanted;
                for (DomainFile f : programs) if (f.getPathname().equals(path) || f.getName().equals(wanted)) { chosen = f; break; }
                if (chosen == null) throw new Worker.WorkerError("not_found", "the project has no program " + wanted + "; its programs: " + String.join(", ", paths));
            }
            else if (programs.size() == 1) chosen = programs.get(0);
            else if (programs.isEmpty()) throw new Worker.WorkerError("not_found", "the project holds no program");
            else throw new Worker.WorkerError("ambiguous", "the project holds " + programs.size() + " programs: " + String.join(", ", paths));
            if (out.exists() && !out.delete()) throw new Worker.WorkerError("io_error", "cannot replace " + out);
            chosen.packFile(out, r.monitor);
            JsonObject o = new JsonObject();
            o.addProperty("program", chosen.getPathname());
            com.google.gson.JsonArray all = new com.google.gson.JsonArray();
            for (String p : paths) all.add(p);
            o.add("programs", all);
            return o;
        }
        finally {
            project.close();
        }
    }

    private static void collect(DomainFolder folder, List<DomainFile> into, Worker.Request r) throws Exception {
        r.monitor.checkCancelled();
        for (DomainFile f : folder.getFiles())
            if ("Program".equals(f.getContentType())) into.add(f);
        for (DomainFolder sub : folder.getFolders()) collect(sub, into, r);
    }
}
