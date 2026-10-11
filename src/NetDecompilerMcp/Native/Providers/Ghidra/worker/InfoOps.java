package ndm.ghidra;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonNull;
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;

import ghidra.framework.Application;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.lang.Language;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.mem.MemoryBlock;
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

    static String clip(String s, int max) {
        return s.length() <= max ? s : s.substring(0, max) + "...";
    }

    static Address at(Worker w, long rva) {
        return w.space().getAddress(w.base + rva);
    }
}
