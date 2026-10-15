// The user's type renames and deletions and struct and union member edits as apply_user_types items, kept in the
// program and applied again after declarations.
package corvus.ghidra;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.CharDataType;
import ghidra.program.model.data.Composite;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.Union;
import ghidra.util.exception.DuplicateNameException;

/** Edits made inside {@link TypeOps#applyUserTypes}, so they share its transaction, stamp and save. */
final class TypeEditOps {
    private TypeEditOps() {
    }

    /** Program option: the user's type edits as JSON [[name, new name or null]], applied again after declarations. */
    static final String USER_TYPE_EDITS = "user_type_edits";

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
        if (renamed || newName == null) rekeyMembers(w, name, newName);
        String text = renamed ? "renamed " + name + " to " + newName : newName == null ? "deleted " + name : newName + " exists; deleted " + name;
        return FrameOps.item("type_edit", 0, name, true, null, null, null, deleted && renamed ? text + " (and another " + name + ")" : text);
    }

    /** The kept enum and struct member edits of a renamed type follow it; a deleted type's are dropped. */
    private static void rekeyMembers(Worker w, String name, String newName) {
        var options = w.program.getOptions(Worker.STAMPS);
        for (String option : new String[] { EditOps.USER_ENUMS, USER_FIELDS }) {
            String kept = options.getString(option, "");
            if (kept == null || kept.isEmpty()) continue;
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
            if (changed) options.setString(option, moved.toString());
        }
    }

    /** Program option: the user's struct and union member edits as JSON {"type::member or @0xoffset": [name, offset, type or null]} in the order made. */
    static final String USER_FIELDS = "user_fields";

    private static JsonObject userFields(Worker w) {
        String kept = w.program.getOptions(Worker.STAMPS).getString(USER_FIELDS, "");
        return kept == null || kept.isEmpty() ? new JsonObject() : JsonParser.parseString(kept).getAsJsonObject();
    }

    /**
     * fields [[type, member name or null, offset or null, type or null, op or null]]; the applied ones are kept. op insert
     * moves later members down (no type: the member is cut and they move back), resize sets the size to offset, gaps names
     * the unnamed gaps (no type: removes those names).
     */
    static void fields(Worker w, Worker.Request r, JsonArray items) {
        for (JsonElement e : Worker.array(r.args, "fields")) {
            JsonArray f = e.getAsJsonArray();
            String type = f.get(0).getAsString();
            String name = f.get(1).isJsonNull() ? null : f.get(1).getAsString();
            Integer offset = f.get(2).isJsonNull() ? null : f.get(2).getAsInt();
            String fieldType = f.get(3).isJsonNull() ? null : f.get(3).getAsString();
            String op = f.size() > 4 && !f.get(4).isJsonNull() ? f.get(4).getAsString() : null;
            JsonArray item = op == null ? field(w, type, name, offset, fieldType) : layout(w, type, name, offset, fieldType, op);
            if (item.get(3).getAsBoolean()) {
                JsonObject kept = userFields(w);
                String member = name != null ? name : "@0x" + Integer.toHexString(offset == null ? 0 : offset).toUpperCase();
                String key = type + "::" + (op == null ? member : op.equals("insert") ? "+" + member : "!" + op);
                kept.remove(key);
                JsonArray value = new JsonArray();
                value.add(name);
                value.add(offset);
                value.add(fieldType);
                value.add(op);
                kept.add(key, value);
                w.program.getOptions(Worker.STAMPS).setString(USER_FIELDS, kept.toString());
            }
            items.add(item);
        }
    }

    /** The user's member edits again, after declarations replaced the structs. */
    static void reapplyFields(Worker w) {
        for (Map.Entry<String, JsonElement> e : userFields(w).entrySet()) {
            int sep = e.getKey().indexOf("::");
            JsonArray v = e.getValue().getAsJsonArray();
            String type = sep > 0 ? e.getKey().substring(0, sep) : null, name = v.get(0).isJsonNull() ? null : v.get(0).getAsString();
            Integer offset = v.get(1).isJsonNull() ? null : v.get(1).getAsInt();
            String fieldType = v.get(2).isJsonNull() ? null : v.get(2).getAsString();
            String op = v.size() > 3 && !v.get(3).isJsonNull() ? v.get(3).getAsString() : null;
            if (type != null) {
                if (op == null) field(w, type, name, offset, fieldType);
                else layout(w, type, name, offset, fieldType, op);
            }
        }
    }

    /**
     * A member by name, else by offset: a null type removes it; else it is retyped in place (and renamed), or placed at
     * offset (moving a named member there; overlapped members are replaced), or appended. A packed structure edited at an
     * offset, or losing a member, keeps its current layout unpacked.
     */
    static JsonArray field(Worker w, String typeName, String name, Integer offset, String type) {
        String target = typeName + "." + (name != null ? name : "+0x" + Integer.toHexString(offset).toUpperCase());
        Composite c = null;
        for (DataType dt : named(w, typeName))
            if (dt instanceof Composite found) {
                c = found;
                break;
            }
        if (c == null) return fieldItem(target, offset, false, "no struct or union named " + typeName, null);
        DataTypeComponent at = null;
        for (DataTypeComponent m : c.getDefinedComponents())
            if (name != null && name.equals(m.getFieldName())) at = m;
        if (at == null && offset != null)
            for (DataTypeComponent m : c.getDefinedComponents())
                if (m.getOffset() == offset) at = m;
        try {
            if (type == null) {
                if (at == null) return fieldItem(target, offset, true, null, "no member " + target);
                String old = at.getFieldName() != null ? at.getFieldName() : at.getDefaultFieldName();
                if (c instanceof Structure s) {
                    // the other members keep their offsets, as in IDA
                    if (s.isPackingEnabled()) s.setPackingEnabled(false);
                    s.clearComponent(at.getOrdinal());
                }
                else c.delete(at.getOrdinal());
                return fieldItem(target, offset, true, null, "removed " + old);
            }
            DataType dt = TypeOps.parseType(w, type);
            if (dt == null) return fieldItem(target, offset, false, "the type '" + type + "' does not parse (types it names must be declared first)", null);
            int len = dt.getLength();
            if (len <= 0) return fieldItem(target, offset, false, type + " has no fixed size", null);
            String member = name != null ? name : at != null && at.getFieldName() != null ? at.getFieldName() : "field_" + Integer.toHexString(offset).toUpperCase();
            DataTypeComponent made;
            if (c instanceof Union u) {
                int ordinal = at != null ? at.getOrdinal() : u.getNumComponents();
                if (at != null) u.delete(ordinal);
                made = u.insert(ordinal, dt, len, member, null);
            }
            else {
                Structure s = (Structure) c;
                if (at != null && offset == null && s.isPackingEnabled()) made = s.replace(at.getOrdinal(), dt, len, member, null);
                else if (at == null && offset == null) made = s.add(dt, len, member, null);
                else {
                    int place = offset != null ? offset : at.getOffset();
                    if (s.isPackingEnabled()) s.setPackingEnabled(false);
                    if (at != null && at.getOffset() != place) s.clearComponent(at.getOrdinal());
                    if (place + len > s.getLength()) s.growStructure(place + len - s.getLength());
                    for (int o = place; o < place + len; o++) s.clearAtOffset(o);
                    made = s.replaceAtOffset(place, dt, len, member, null);
                }
            }
            return fieldItem(target, offset, true, null, typeName + "." + made.getFieldName() + ": " + made.getDataType().getDisplayName() + " at +0x" +
                Integer.toHexString(made.getOffset()).toUpperCase());
        }
        catch (IllegalArgumentException | IndexOutOfBoundsException e) {
            return fieldItem(target, offset, false, "Ghidra refused " + target + ": " + e.getMessage(), null);
        }
    }

    /** A layout edit of a struct (see fields); each is a no-op when its result is already there, as kept edits replay. */
    static JsonArray layout(Worker w, String typeName, String name, Integer offset, String type, String op) {
        String target = typeName + "." + (op.equals("insert") ? (name != null ? name : "+0x" + Integer.toHexString(offset).toUpperCase()) : op);
        Structure s = null;
        for (DataType dt : named(w, typeName))
            if (dt instanceof Structure found) {
                s = found;
                break;
            }
        if (s == null) return fieldItem(target, offset, false, "no struct named " + typeName, null);
        try {
            if (s.isPackingEnabled()) s.setPackingEnabled(false);
            switch (op) {
                case "resize": {
                    int was = s.getLength();
                    if (offset == was) return fieldItem(target, offset, true, null, typeName + " is 0x" + Integer.toHexString(was).toUpperCase() + " bytes");
                    if (offset > was) s.growStructure(offset - was);
                    else {
                        for (DataTypeComponent m : s.getDefinedComponents())
                            if (m.getEndOffset() >= offset)
                                return fieldItem(target, offset, false, typeName + "." + label(m) + " ends at +0x" + Integer.toHexString(m.getEndOffset() + 1).toUpperCase() +
                                    ", past the new size; remove it first", null);
                        s.setLength(offset);
                    }
                    return fieldItem(target, offset, true, null, typeName + " is 0x" + Integer.toHexString(s.getLength()).toUpperCase() + " bytes (was 0x" +
                        Integer.toHexString(was).toUpperCase() + ")");
                }
                case "insert": {
                    DataTypeComponent at = null;
                    for (DataTypeComponent m : s.getDefinedComponents())
                        if (name != null ? name.equals(m.getFieldName()) : m.getOffset() == offset) at = m;
                    if (type == null) {
                        if (at == null) return fieldItem(target, offset, true, null, "no member " + target);
                        String old = label(at);
                        int len = at.getLength();
                        s.deleteAtOffset(at.getOffset());
                        return fieldItem(target, offset, true, null, "cut " + old + "; the members after it moved back " + len + " bytes");
                    }
                    DataType dt = TypeOps.parseType(w, type);
                    if (dt == null) return fieldItem(target, offset, false, "the type '" + type + "' does not parse (types it names must be declared first)", null);
                    int len = dt.getLength();
                    if (len <= 0) return fieldItem(target, offset, false, type + " has no fixed size", null);
                    if (at != null && at.getOffset() == offset && at.getDataType().isEquivalent(dt))
                        return fieldItem(target, offset, true, null, typeName + "." + label(at) + " is already at +0x" + Integer.toHexString(offset).toUpperCase());
                    DataTypeComponent made = s.insertAtOffset(offset, dt, len, name, null);
                    return fieldItem(target, offset, true, null, typeName + "." + made.getFieldName() + ": " + made.getDataType().getDisplayName() + " at +0x" +
                        Integer.toHexString(made.getOffset()).toUpperCase() + "; the members after it moved down " + len + " bytes");
                }
                case "gaps": {
                    int count = 0;
                    if (type == null) {
                        for (DataTypeComponent m : s.getDefinedComponents())
                            if (m.getFieldName() != null && m.getFieldName().matches("gap_[0-9A-F]+")) {
                                s.clearComponent(m.getOrdinal());
                                count++;
                            }
                        return fieldItem(target, offset, true, null, count + " named gap(s) of " + typeName + " cleared");
                    }
                    int start = -1;
                    for (int o = 0; o <= s.getLength(); o++) {
                        DataTypeComponent m = o < s.getLength() ? s.getComponentContaining(o) : null;
                        boolean undefined = o < s.getLength() && (m == null || m.getDataType() == DataType.DEFAULT);
                        if (undefined && start < 0) start = o;
                        if (!undefined && start >= 0) {
                            int n = o - start;
                            s.replaceAtOffset(start, new ArrayDataType(CharDataType.dataType, n, 1), n, "gap_" + Integer.toHexString(start).toUpperCase(), null);
                            count++;
                            start = -1;
                        }
                    }
                    return fieldItem(target, offset, true, null, count + " gap(s) of " + typeName + " named gap_<offset>");
                }
                default:
                    return fieldItem(target, offset, false, "unknown layout edit '" + op + "'", null);
            }
        }
        catch (IllegalArgumentException | IndexOutOfBoundsException e) {
            return fieldItem(target, offset, false, "Ghidra refused " + target + ": " + e.getMessage(), null);
        }
    }

    private static String label(DataTypeComponent m) {
        return m.getFieldName() != null ? m.getFieldName() : m.getDefaultFieldName();
    }

    private static JsonArray fieldItem(String target, Integer offset, boolean applied, String error, String text) {
        return FrameOps.item("field", 0, target, applied, error, null, offset, text);
    }
}
