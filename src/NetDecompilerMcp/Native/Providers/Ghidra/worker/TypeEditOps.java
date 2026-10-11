// The user's type renames and deletions as apply_user_types items, kept in the program and applied again after
// declarations.
package ndm.ghidra;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.util.exception.DuplicateNameException;

/** Edits made inside {@link TypeOps#applyUserTypes}, so they share its transaction, stamp and save. */
final class TypeEditOps {
    private TypeEditOps() {
    }

    /** Program option: the user's type edits as JSON [[name, new name or null]], applied again after declarations. */
    static final String USER_TYPE_EDITS = "ndm_user_type_edits";

    /** type_edits, when given, is the whole kept list [[name, new name or null]]: applied in order, and the ones that applied are kept. */
    static void apply(Worker w, Worker.Request r, JsonArray items) {
        if (!r.args.has("type_edits") || r.args.get("type_edits").isJsonNull()) return;
        JsonArray kept = new JsonArray();
        for (JsonElement e : r.args.getAsJsonArray("type_edits")) {
            JsonArray t = e.getAsJsonArray();
            JsonArray item = edit(w, t.get(0).getAsString(), t.get(1).isJsonNull() ? null : t.get(1).getAsString());
            if (item.get(3).getAsBoolean()) kept.add(t);
            items.add(item);
        }
        w.program.getOptions(Worker.STAMPS).setString(USER_TYPE_EDITS, kept.toString());
    }

    /** The user's type edits again, after declarations made the old names again. */
    static void reapply(Worker w) {
        String kept = w.program.getOptions(Worker.STAMPS).getString(USER_TYPE_EDITS, "");
        if (kept == null || kept.isEmpty()) return;
        for (JsonElement e : JsonParser.parseString(kept).getAsJsonArray()) {
            JsonArray t = e.getAsJsonArray();
            edit(w, t.get(0).getAsString(), t.get(1).isJsonNull() ? null : t.get(1).getAsString());
        }
    }

    /** The named types (structs, unions, enums, typedefs, function definitions) called name, in any category. */
    static List<DataType> named(Worker w, String name) {
        List<DataType> found = new ArrayList<>();
        w.program.getDataTypeManager().findDataTypes(name, found);
        found.removeIf(dt -> TypeOps.kind(dt) == null || !dt.getName().equals(name));
        return found;
    }

    /**
     * Renames or (newName null) deletes the types called name; a type already gone is no change, and a rename onto an
     * existing type deletes the old one (a declaration made it again).
     */
    static JsonArray edit(Worker w, String name, String newName) {
        List<DataType> types = named(w, name);
        if (types.isEmpty()) return FrameOps.item("type_edit", 0, name, true, null, null, null, "no type " + name);
        DataTypeManager dtm = w.program.getDataTypeManager();
        boolean renamed = false, deleted = false;
        for (DataType dt : types) {
            if (newName != null && named(w, newName).isEmpty()) {
                try {
                    dt.setName(newName);
                    renamed = true;
                    continue;
                }
                catch (DuplicateNameException e) {
                    // the new name exists in this category: drop the old type below
                }
                catch (ghidra.util.InvalidNameException e) {
                    return FrameOps.item("type_edit", 0, name, false, "Ghidra refused the name " + newName + ": " + e.getMessage(), null, null, null);
                }
            }
            if (!dtm.remove(dt)) return FrameOps.item("type_edit", 0, name, false, "Ghidra did not delete " + dt.getPathName(), null, null, null);
            deleted = true;
        }
        if (renamed || newName == null) rekeyEnums(w, name, newName);
        String text = renamed ? "renamed " + name + " to " + newName : newName == null ? "deleted " + name : newName + " exists; deleted " + name;
        return FrameOps.item("type_edit", 0, name, true, null, null, null, deleted && renamed ? text + " (and another " + name + ")" : text);
    }

    /** The kept enum member edits of a renamed type follow it; a deleted type's are dropped. */
    private static void rekeyEnums(Worker w, String name, String newName) {
        var options = w.program.getOptions(Worker.STAMPS);
        String kept = options.getString(EditOps.USER_ENUMS, "");
        if (kept == null || kept.isEmpty()) return;
        String prefix = name + "::";
        JsonObject edits = JsonParser.parseString(kept).getAsJsonObject(), moved = new JsonObject();
        boolean changed = false;
        for (Map.Entry<String, JsonElement> e : edits.entrySet()) {
            if (!e.getKey().startsWith(prefix)) moved.add(e.getKey(), e.getValue());
            else {
                changed = true;
                if (newName != null) moved.add(newName + "::" + e.getKey().substring(prefix.length()), e.getValue());
            }
        }
        if (changed) options.setString(EditOps.USER_ENUMS, moved.toString());
    }
}
