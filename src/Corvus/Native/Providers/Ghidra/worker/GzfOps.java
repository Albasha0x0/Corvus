package corvus.ghidra;

import java.io.File;
import java.io.FileOutputStream;
import java.util.List;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.importer.ProgramLoader;
import ghidra.app.util.opinion.LoadException;
import ghidra.app.util.opinion.LoadResults;
import ghidra.base.project.GhidraProject;
import ghidra.program.database.mem.FileBytes;
import ghidra.program.model.listing.Program;

/** Ghidra archives (.gzf) as inputs: the file a program was imported from, recovered from the bytes the program keeps. */
final class GzfOps {
    private GzfOps() {}

    /** The loader of packed programs, as ProgramLoader names it. */
    static final String LOADER = "GzfLoader";

    /**
     * Unpacks gzf into a throwaway project under scratch and writes the original file's bytes (the program's first file
     * bytes) to out_dir under its recorded name (gzf_original). Result: name, sha256 and format as recorded, stored (whether
     * the bytes were there), path when stored.
     */
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
}
