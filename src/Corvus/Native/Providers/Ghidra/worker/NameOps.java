package corvus.ghidra;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

/** Name and comment writes; callers run them inside {@link Worker#write}. */
final class NameOps {
    private NameOps() {
    }

    private static String primaryName(Worker w, Address a) {
        Symbol s = w.program.getSymbolTable().getPrimarySymbol(a);
        return s == null ? "" : s.getName();
    }

    /** Names a function or a label; an empty name drops user names. A name used at another address is a conflict. */
    static JsonElement setName(Worker w, Worker.Request r) throws Exception {
        Address a = w.addr(r.args, "rva");
        String name = r.args.has("name") && !r.args.get("name").isJsonNull() ? r.args.get("name").getAsString() : "";
        SymbolTable st = w.program.getSymbolTable();
        for (Symbol s : name.isEmpty() ? java.util.List.<Symbol> of() : st.getGlobalSymbols(name))
            if (!s.getAddress().equals(a))
                throw new Worker.WorkerError("conflict", "the name " + name + " is already used at rva 0x" + Long.toHexString(s.getAddress().getOffset() - w.base).toUpperCase());
        try {
            apply(w, a, name);
        }
        catch (InvalidInputException e) {
            throw new Worker.WorkerError("invalid_argument", "Ghidra rejected the name '" + name + "': " + e.getMessage());
        }
        catch (DuplicateNameException e) {
            throw new Worker.WorkerError("conflict", e.getMessage());
        }
        JsonObject o = new JsonObject();
        o.addProperty("name", primaryName(w, a));
        return o;
    }

    /** Ghidra refuses blanks in names ("-[Class sel]" from ObjC metadata): retried with '_' for each. */
    private static void applyLenient(Worker w, Address a, String name) throws InvalidInputException, DuplicateNameException {
        try {
            apply(w, a, name);
        }
        catch (InvalidInputException e) {
            String plain = name.replace(' ', '_');
            if (plain.equals(name)) throw e;
            apply(w, a, plain);
        }
    }

    private static void apply(Worker w, Address a, String name) throws InvalidInputException, DuplicateNameException {
        Function f = w.program.getFunctionManager().getFunctionAt(a);
        SymbolTable st = w.program.getSymbolTable();
        if (!name.isEmpty()) {
            if (f != null) f.setName(name, SourceType.USER_DEFINED);
            else st.createLabel(a, name, SourceType.USER_DEFINED).setPrimary();
            return;
        }
        if (f != null && f.getSymbol().getSource() != SourceType.DEFAULT) f.setName(null, SourceType.DEFAULT);
        for (Symbol s : st.getSymbols(a))
            if (s.getSource() == SourceType.USER_DEFINED && !s.isDynamic() && f == null) s.delete();
    }

    static JsonElement setComment(Worker w, Worker.Request r) {
        Address a = w.addr(r.args, "rva");
        boolean repeatable = r.args.has("repeatable") && r.args.get("repeatable").getAsBoolean();
        CommentType type = repeatable ? CommentType.REPEATABLE : CommentType.EOL;
        String text = r.args.has("text") && !r.args.get("text").isJsonNull() ? r.args.get("text").getAsString() : "";
        Listing listing = w.program.getListing();
        listing.setComment(a, type, text.isEmpty() ? null : text);
        String now = listing.getComment(type, a);
        JsonObject o = new JsonObject();
        o.addProperty("comment", now == null ? "" : now);
        return o;
    }

    /** A comment kind on the wire (eol, pre, plate); null for anything else. */
    private static CommentType kind(String kind) {
        return switch (kind) {
            case "eol" -> CommentType.EOL;
            case "pre" -> CommentType.PRE;
            case "plate" -> CommentType.PLATE;
            default -> null;
        };
    }

    /**
     * items: [[rva, text; "" removes]]: the decompiler shows pre-comments above the statement made from the instruction
     * holding the address. Rows [rva, applied, anchor rva, error].
     */
    static JsonObject pseudoComments(Worker w, Worker.Request r) {
        Listing listing = w.program.getListing();
        JsonArray rows = new JsonArray();
        for (JsonElement e : Worker.array(r.args, "items")) {
            JsonArray item = e.getAsJsonArray();
            long rva = item.get(0).getAsLong();
            String text = item.get(1).isJsonNull() ? "" : item.get(1).getAsString();
            Address a = w.space().getAddress(w.base + rva);
            JsonArray row = new JsonArray();
            row.add(rva);
            var unit = listing.getCodeUnitContaining(a);
            if (unit == null || w.program.getFunctionManager().getFunctionContaining(a) == null) {
                row.add(false);
                row.add(com.google.gson.JsonNull.INSTANCE);
                row.add("no function contains rva 0x" + Long.toHexString(rva).toUpperCase());
            }
            else {
                listing.setComment(unit.getAddress(), CommentType.PRE, text.isEmpty() ? null : text);
                row.add(true);
                row.add(w.rva(unit.getAddress()));
                row.add(com.google.gson.JsonNull.INSTANCE);
            }
            rows.add(row);
        }
        w.decompilers.flush();
        JsonObject o = new JsonObject();
        o.add("items", rows);
        return o;
    }

    /**
     * items: [[rva, name or null, comment or null, make_function, comment kind (optional: eol, pre, plate)]]; an empty name or comment removes it. Names are
     * forced (Ghidra allows the same label name at several addresses); a comment at a function start is the function's.
     */
    static JsonObject applyNames(Worker w, Worker.Request r) {
        long start = System.nanoTime();
        FunctionManager fm = w.program.getFunctionManager();
        Listing listing = w.program.getListing();
        int named = 0, nameFailures = 0, commented = 0, created = 0;
        JsonArray failures = new JsonArray();
        for (JsonElement e : Worker.array(r.args, "items")) {
            JsonArray item = e.getAsJsonArray();
            long rva = item.get(0).getAsLong();
            Address a = w.space().getAddress(w.base + rva);
            if (item.get(3).getAsInt() != 0 && fm.getFunctionContaining(a) == null
                    && new CreateFunctionCmd(a).applyTo(w.program, r.monitor)) created++;
            if (!item.get(1).isJsonNull()) {
                String name = item.get(1).getAsString();
                try {
                    applyLenient(w, a, name);
                    named++;
                }
                catch (InvalidInputException | DuplicateNameException | RuntimeException ex) {
                    nameFailures++;
                    if (failures.size() < 20) failures.add("rva 0x" + Long.toHexString(rva).toUpperCase() + ": " + name);
                }
            }
            if (!item.get(2).isJsonNull()) {
                String comment = item.get(2).getAsString();
                CommentType kind = item.size() > 4 && !item.get(4).isJsonNull() ? kind(item.get(4).getAsString()) : null;
                Function f = fm.getFunctionAt(a);
                if (kind != null) listing.setComment(a, kind, comment.isEmpty() ? null : comment);
                else if (f != null) f.setComment(comment.isEmpty() ? null : comment);
                else listing.setComment(a, CommentType.REPEATABLE, comment.isEmpty() ? null : comment);
                commented++;
            }
        }
        w.setStamp(r.args);
        JsonObject o = new JsonObject();
        o.addProperty("named", named);
        o.addProperty("name_failures", nameFailures);
        o.addProperty("commented", commented);
        o.addProperty("functions_created", created);
        o.addProperty("seconds", Math.round((System.nanoTime() - start) / 1e6) / 1000.0);
        o.add("failures", failures);
        return o;
    }
}
