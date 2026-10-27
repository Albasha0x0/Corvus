package corvus.ghidra;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.TreeMap;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonNull;
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;

import ghidra.framework.Application;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.ArchiveType;
import ghidra.program.model.data.Array;
import ghidra.program.model.data.BuiltInDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.DataTypeWriter;
import ghidra.program.model.data.FileDataTypeManager;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.SourceArchive;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.lang.Language;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.GhidraClass;
import ghidra.program.model.listing.Library;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;

/** Read views of the program as Ghidra holds it; callers hold the read lock. Row shapes match the IDA worker's. */
final class InfoOps {
    private static final int MAX_ENTRY_POINTS = 64;

    private InfoOps() {
    }

    /** The engine's description of the image (image_info). */
    static JsonElement imageInfo(Worker w, Worker.Request r) {
        Language lang = w.program.getLanguage();
        JsonObject o = new JsonObject();
        o.addProperty("version", Application.getApplicationVersion());
        o.addProperty("processor", lang.getProcessor().toString());
        o.addProperty("language", lang.getLanguageID().getIdAsString());
        o.addProperty("compiler", w.program.getCompilerSpec().getCompilerSpecID().getIdAsString());
        o.addProperty("format", w.program.getExecutableFormat());
        o.addProperty("pointer_size", w.program.getDefaultPointerSize());
        o.addProperty("endian", lang.isBigEndian() ? "big" : "little");
        o.addProperty("functions", w.program.getFunctionManager().getFunctionCount());
        int externals = 0;
        for (var it = w.program.getFunctionManager().getExternalFunctions(); it.hasNext(); it.next()) externals++;
        o.addProperty("external_functions", externals);
        JsonArray entries = new JsonArray();
        AddressIterator ai = w.program.getSymbolTable().getExternalEntryPointIterator();
        while (ai.hasNext() && entries.size() < MAX_ENTRY_POINTS) {
            Long rva = w.rva(ai.next());
            if (rva != null) entries.add(rva);
        }
        o.add("entry_points", entries);
        o.addProperty("md5", w.program.getExecutableMD5());
        o.addProperty("sha256", w.program.getExecutableSHA256());
        JsonArray blocks = new JsonArray();
        for (MemoryBlock b : w.program.getMemory().getBlocks()) {
            JsonArray row = new JsonArray();
            row.add(b.getName());
            row.add(Worker.u64(b.getStart().getOffset()));
            row.add(Worker.u64(b.getSize()));
            row.add((b.isRead() ? "r" : "-") + (b.isWrite() ? "w" : "-") + (b.isExecute() ? "x" : "-"));
            row.add(b.isInitialized());
            blocks.add(row);
        }
        o.add("blocks", blocks);
        o.addProperty("changed", w.program.isChanged());
        o.addProperty("analysis", w.program.getOptions(Worker.STAMPS).getString(Worker.ANALYSIS_STAMP, null));
        return o;
    }

    /** Defined data in address order (defined_data): total, rows [rva, size, type, label or null, value or null, is string] up to max. */
    static JsonElement data(Worker w, Worker.Request r) throws Exception {
        int max = r.args.has("max") ? r.args.get("max").getAsInt() : 200_000;
        SymbolTable symbols = w.program.getSymbolTable();
        JsonArray rows = new JsonArray();
        int total = 0;
        DataIterator it = w.program.getListing().getDefinedData(true);
        while (it.hasNext()) {
            r.monitor.checkCancelled();
            Data d = it.next();
            Long rva = w.rva(d.getAddress());
            if (rva == null) continue;
            total++;
            if (rows.size() >= max) continue;
            JsonArray row = new JsonArray();
            row.add(rva);
            row.add(d.getLength());
            row.add(d.getDataType().getDisplayName());
            Symbol s = symbols.getPrimarySymbol(d.getAddress());
            row.add(s != null && s.getSource() != SourceType.DEFAULT ? new JsonPrimitive(s.getName(true)) : JsonNull.INSTANCE);
            String value = d.getDefaultValueRepresentation();
            row.add(value == null || value.isEmpty() ? JsonNull.INSTANCE : new JsonPrimitive(clip(value, 120)));
            row.add(d.hasStringValue());
            rows.add(row);
        }
        JsonObject o = new JsonObject();
        o.addProperty("total", total);
        o.add("rows", rows);
        return o;
    }

    /** Defined data holding a string, any string type (defined_strings): rows [rva, size, type, text] up to max. */
    static JsonElement strings(Worker w, Worker.Request r) throws Exception {
        int max = r.args.has("max") ? r.args.get("max").getAsInt() : 200_000;
        JsonArray rows = new JsonArray();
        DataIterator it = w.program.getListing().getDefinedData(true);
        while (it.hasNext() && rows.size() < max) {
            r.monitor.checkCancelled();
            Data d = it.next();
            if (!d.hasStringValue() || !(d.getValue() instanceof String text)) continue;
            Long rva = w.rva(d.getAddress());
            if (rva == null) continue;
            JsonArray row = new JsonArray();
            row.add(rva);
            row.add(d.getLength());
            row.add(d.getDataType().getName());
            row.add(clip(text, 400));
            rows.add(row);
        }
        JsonObject o = new JsonObject();
        o.add("rows", rows);
        return o;
    }

    /** The function containing rva as Ghidra records it (function_info); field names match the IDA worker's. */
    static JsonElement functionInfo(Worker w, Worker.Request r) {
        Function f = CodeOps.functionAt(w, w.addr(r.args, "rva"));
        JsonObject o = new JsonObject();
        o.addProperty("start", w.rva(f.getEntryPoint()));
        o.addProperty("name", f.getName());
        Namespace ns = f.getParentNamespace();
        o.addProperty("namespace", ns == null || ns.isGlobal() ? null : ns.getName(true));
        o.addProperty("prototype", f.getPrototypeString(false, true));
        o.addProperty("convention", f.getCallingConventionName());
        o.addProperty("signature_source", f.getSignatureSource().toString().toLowerCase());
        JsonArray ranges = new JsonArray();
        for (AddressRange range : f.getBody().getAddressRanges()) {
            Long start = w.rva(range.getMinAddress()), last = w.rva(range.getMaxAddress());
            if (start == null || last == null) continue;
            JsonArray pair = new JsonArray();
            pair.add(start);
            pair.add(last + 1);
            ranges.add(pair);
        }
        o.add("ranges", ranges);
        if (f.isThunk() && f.getThunkedFunction(true) instanceof Function target) {
            o.addProperty("thunk_target", w.rva(target.getEntryPoint()));
            o.addProperty("thunk_name", target.getName(true));
        }
        o.addProperty("external", f.isExternal());
        o.addProperty("noreturn", f.hasNoReturn());
        int purge = f.getStackPurgeSize();
        if (purge != Function.UNKNOWN_STACK_DEPTH_CHANGE && purge != Function.INVALID_STACK_DEPTH_CHANGE) o.addProperty("stack_purge", purge);
        JsonArray params = new JsonArray();
        for (Parameter p : f.getParameters()) {
            JsonArray row = new JsonArray();
            row.add(p.getName());
            row.add(p.getDataType().getDisplayName());
            row.add(p.getVariableStorage().toString());
            params.add(row);
        }
        o.add("params", params);
        o.addProperty("return_type", f.getReturnType().getDisplayName());
        Parameter ret = f.getReturn();
        o.addProperty("return_storage", ret == null ? null : ret.getVariableStorage().toString());
        o.addProperty("varargs", f.hasVarArgs());
        return o;
    }

    /** Non-global namespaces by qualified name (namespaces): rows [name, kind, functions directly in it, vftable rva or null]. */
    static JsonElement namespaces(Worker w, Worker.Request r) throws Exception {
        TreeMap<String, Object[]> found = new TreeMap<>(); // name -> {kind, functions, vftable}
        SymbolTable st = w.program.getSymbolTable();
        for (Symbol s : st.getAllSymbols(true)) {
            r.monitor.checkCancelled();
            Namespace parent = s.getParentNamespace();
            for (Namespace ns = parent; ns != null && !ns.isGlobal(); ns = ns.getParentNamespace()) {
                if (ns instanceof Function) continue;
                Object[] e = found.computeIfAbsent(ns.getName(true), k -> new Object[] { null, 0, null });
                e[0] = ns instanceof GhidraClass ? "class" : ns instanceof Library ? "library" : "namespace";
            }
            String name = s.getName();
            if (parent != null && !parent.isGlobal() && (name.equals("vftable") || name.equals("vtable") || name.startsWith("vftable_")) && !s.isExternal()) {
                Object[] e = found.get(parent.getName(true));
                if (e != null && e[2] == null) e[2] = w.rva(s.getAddress());
            }
        }
        for (Function f : w.program.getFunctionManager().getFunctions(true)) {
            Namespace ns = f.getParentNamespace();
            if (ns != null && !ns.isGlobal() && found.get(ns.getName(true)) instanceof Object[] e) e[1] = (Integer) e[1] + 1;
        }
        JsonArray rows = new JsonArray();
        for (var e : found.entrySet()) {
            JsonArray row = new JsonArray();
            row.add(e.getKey());
            row.add((String) e.getValue()[0]);
            row.add((Integer) e.getValue()[1]);
            if (e.getValue()[2] instanceof Long rva) row.add(rva);
            else row.add(JsonNull.INSTANCE);
            rows.add(row);
        }
        JsonObject o = new JsonObject();
        o.add("rows", rows);
        return o;
    }

    /** Error and Warning bookmarks: counts per type, then up to max rows [type, rva, category, comment], errors first. */
    static JsonElement bookmarks(Worker w, Worker.Request r) {
        int max = r.args.has("max") ? r.args.get("max").getAsInt() : 5;
        var manager = w.program.getBookmarkManager();
        JsonObject o = new JsonObject();
        JsonArray rows = new JsonArray();
        for (String type : new String[] { ghidra.program.model.listing.BookmarkType.ERROR, ghidra.program.model.listing.BookmarkType.WARNING }) {
            o.addProperty(type.toLowerCase(), manager.getBookmarkCount(type));
            var it = manager.getBookmarksIterator(type);
            while (it.hasNext() && rows.size() < max) {
                var b = it.next();
                JsonArray row = new JsonArray();
                row.add(type);
                row.add(w.rva(b.getAddress()));
                row.add(b.getCategory());
                row.add(b.getComment());
                rows.add(row);
            }
        }
        o.add("rows", rows);
        return o;
    }

    /** export_gzf: saves and packs the program into path under the write lock, so no change lands between; the project is untouched. Result: path, size. */
    static JsonElement exportPacked(Worker w, Worker.Request r) throws Exception {
        java.io.File out = new java.io.File(r.args.get("path").getAsString());
        w.lock.writeLock().lock();
        try {
            if (w.program == null) throw new Worker.WorkerError("invalid_argument", "no program is open");
            if (w.program.isChanged()) w.program.save("Corvus", r.monitor);
            if (out.exists() && !out.delete()) throw new Worker.WorkerError("io_error", "cannot replace " + out);
            w.program.getDomainFile().packFile(out, r.monitor);
        }
        finally {
            w.lock.writeLock().unlock();
        }
        JsonObject o = new JsonObject();
        o.addProperty("path", out.getAbsolutePath());
        o.addProperty("size", out.length());
        return o;
    }

    /** export_types: the program's own data types (not archive or built-in ones) as a C header (h) or data type archive (gdt). Result: path, size, types. */
    static JsonElement exportTypes(Worker w, Worker.Request r) throws Exception {
        java.io.File out = new java.io.File(r.args.get("path").getAsString());
        boolean archive = "gdt".equals(r.args.get("format").getAsString());
        DataTypeManager dtm = w.program.getDataTypeManager();
        List<DataType> own = new ArrayList<>();
        for (Iterator<DataType> all = dtm.getAllDataTypes(); all.hasNext();) {
            r.monitor.checkCancelled();
            DataType dt = all.next();
            if (dt instanceof BuiltInDataType || dt instanceof Pointer || dt instanceof Array) continue;
            SourceArchive source = dt.getSourceArchive();
            if (source != null && source.getArchiveType() != ArchiveType.PROGRAM) continue;
            own.add(dt);
        }
        if (out.exists() && !out.delete()) throw new Worker.WorkerError("io_error", "cannot replace " + out);
        if (archive) {
            FileDataTypeManager file = FileDataTypeManager.createFileArchive(out);
            try {
                int tx = file.startTransaction("export");
                try {
                    for (DataType dt : own) file.resolve(dt, DataTypeConflictHandler.REPLACE_HANDLER);
                }
                finally {
                    file.endTransaction(tx, true);
                }
                file.save();
            }
            finally {
                file.close();
            }
        }
        else
            try (java.io.Writer writer = new java.io.OutputStreamWriter(new java.io.FileOutputStream(out), java.nio.charset.StandardCharsets.UTF_8)) {
                new DataTypeWriter(dtm, writer).write(own, r.monitor);
            }
        JsonObject o = new JsonObject();
        o.addProperty("path", out.getAbsolutePath());
        o.addProperty("size", out.length());
        o.addProperty("types", own.size());
        return o;
    }

    static String clip(String s, int max) {
        return s.length() <= max ? s : s.substring(0, max) + "...";
    }

    static Address at(Worker w, long rva) {
        return w.space().getAddress(w.base + rva);
    }
}
